#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""Wild-benchmark runner: analyze pre-built `.o` files from a Cargo target/release tree.

Usage:
    PYTHONPATH=. python3 benchmark/scripts/run_wild.py \\
        --root benchmark/wild_rust/<crate>/target/release \\
        --label <crate>_v3 \\
        --out benchmark/results/wild_<crate>_v3.json

Prerequisites: the crate must already be built with debuginfo:
    RUSTFLAGS="-C debuginfo=2" cargo build --release

This script:
  1. Walks the target/release tree and finds every .o under deps/ and
     build/.
  2. For each .o, runs `objdump -d -l --no-show-raw-insn` and parses
     the disassembly through the same AssemblyParser the source-level
     analyzer uses. The DWARF `.loc` info embedded in the .o gives us
     `file:line` attribution per instruction; the analyzer's existing
     classifier maps each (file, line, function, mnemonic) to a
     triage hint.
  3. Aggregates totals and emits JSON with the same shape as
     run_benchmark.py's output (no GT in this case; we report
     errors/warnings/triage-hint distribution).

Build-validity precondition (lifted from the C harness's mbedTLS
silent-failure incident): refuse to print headlines when there are zero
.o files, or when total instructions analyzed is below 1000. This
guards against the case where the user forgot to run `cargo build` or
where `cargo build` failed silently and produced an empty target tree.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ct_analyzer.analyzer import (  # noqa: E402
    AssemblyParser,
    Severity,
)

# Directories under target/release we should NOT analyze: tests, benches,
# fuzz, examples are non-production. Plus the build/ subtree which holds
# host-side build-script outputs.
_SKIP_DIR_RE = re.compile(
    r"(?:^|/)(?:tests?|benches?|fuzz|examples|build/|incremental/)"
)


@dataclass
class WildResult:
    label: str
    timestamp: float
    root: str
    n_objects: int = 0
    n_instructions: int = 0
    error_count: int = 0
    warning_count: int = 0
    error_count_user: int = 0
    warning_count_user: int = 0
    triage_breakdown: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
    warnings_sampled: list = field(default_factory=list)
    # Clustered view of warnings: instead of N individual reports, group
    # by (triage_hint, file, function). The reviewer reads the whole
    # function once, decides for the cluster, and moves on.
    warning_clusters: list = field(default_factory=list)
    cluster_count: int = 0
    build_valid: bool = False


_NORMALIZE_NUM_RE = re.compile(r"\b\d+\b")
_NORMALIZE_HEX_RE = re.compile(r"\b0[xX][0-9a-fA-F]+\b")
_NORMALIZE_IDENT_RE = re.compile(
    r"\b[a-z_][a-zA-Z0-9_]*\b"
)
_KEEP_KEYWORDS = frozenset({
    "if", "else", "while", "for", "in", "match", "let", "mut", "fn", "pub",
    "self", "as", "true", "false", "return", "break", "continue", "loop",
    "ref", "move", "and", "or", "not", "is_empty", "is_none", "is_some",
    "is_zero", "is_negative", "len", "iter", "iter_mut", "into_iter",
    "next", "unwrap", "expect", "ok", "err",
})


def _normalize_pattern(line: str) -> str:
    """Reduce a source line to a structural pattern.

    Examples:
      `if rem > 0 {`           -> `if NAME > NUM {`
      `if remaining > 0u8 {`   -> `if NAME > NUM {`
      `match self.0.insert(u)` -> `match self.NUM.insert(NAME)`
      `if a.len() != b.len()`  -> `if NAME.len() != NAME.len()`

    Goal: collapse syntactic variants of the same source-level event
    so a reviewer can decide once for the whole class.
    """
    if not line:
        return ""
    s = line.strip()
    s = _NORMALIZE_HEX_RE.sub("HEX", s)
    s = _NORMALIZE_NUM_RE.sub("NUM", s)
    # Replace identifiers with NAME, keeping keywords / common method names.
    def _sub(m: "re.Match") -> str:
        ident = m.group(0)
        return ident if ident in _KEEP_KEYWORDS else "NAME"
    s = _NORMALIZE_IDENT_RE.sub(_sub, s)
    # Collapse runs of NAME, NAME -> NAME.
    s = re.sub(r"(?:NAME[\s,.]+){2,}", "NAME ", s)
    s = re.sub(r"\s+", " ", s)
    return s


def cluster_warnings(violations: list[dict], by: str = "function") -> list[dict]:
    """Group warnings into review-able clusters.

    `by` selects the clustering granularity:

      - "function": (triage_hint, file, function). The reviewer reads
        each function once. Reduction depends on how many warnings
        each function emits; typically 1.5-3x.

      - "file": (triage_hint, file). The reviewer reads each file
        once and decides whether every warning in it follows a known
        pattern. Higher reduction (3-10x), more aggressive.

      - "pattern": (triage_hint, normalized_source_line). The reviewer
        decides per source-pattern, ignoring location. Most aggressive
        (5-20x), best when many functions share idioms.

    Each cluster output is:
        {
          "triage_hint": "...",
          "key": {...},                 # the key fields (file, function, pattern)
          "count": N,
          "mnemonics": ["JE", "JNE"],
          "distinct_locations": [{file, function, line}, ...],   # up to 3 examples
          "representative_snippet": [...],
          "representative_line": int,
          "representative_function": "...",
          "representative_file": "...",
        }
    """
    if by not in ("function", "file", "pattern"):
        raise ValueError(f"unknown clustering key: {by}")

    by_key: dict[tuple, dict] = {}
    for v in violations:
        hint = v.get("triage_hint") or "unknown"
        file_path = v.get("file") or ""
        function = v.get("function") or ""
        snippet = v.get("source_snippet") or []
        cited = snippet[len(snippet) // 2] if snippet else ""

        if by == "function":
            key = ("function", hint, file_path, function)
        elif by == "file":
            key = ("file", hint, file_path)
        else:  # pattern
            key = ("pattern", hint, _normalize_pattern(cited))

        slot = by_key.setdefault(
            key,
            {
                "triage_hint": hint,
                "key_kind": by,
                "count": 0,
                "mnemonics_set": set(),
                "distinct_locations": [],
                "representative_snippet": snippet or None,
                "representative_line": v.get("line"),
                "representative_function": function,
                "representative_file": file_path,
                "representative_pattern": _normalize_pattern(cited) if by == "pattern" else None,
            },
        )
        slot["count"] += 1
        for m in (v.get("mnemonic") or "").split("/"):
            if m:
                slot["mnemonics_set"].add(m)
        if len(slot["distinct_locations"]) < 5:
            loc = {
                "file": file_path,
                "function": function,
                "line": v.get("line"),
            }
            if loc not in slot["distinct_locations"]:
                slot["distinct_locations"].append(loc)
        if slot["representative_snippet"] is None and snippet:
            slot["representative_snippet"] = snippet
            slot["representative_line"] = v.get("line")

    out: list[dict] = []
    for slot in by_key.values():
        slot["mnemonics"] = sorted(slot.pop("mnemonics_set"))
        out.append(slot)
    out.sort(key=lambda c: -c["count"])
    return out


def collect_object_files(root: Path) -> list[Path]:
    """Find every .o file under the cargo target/release tree, excluding
    test / bench / fuzz outputs."""
    objs: list[Path] = []
    for ext in (".o", ".rcgu.o"):
        for p in root.rglob(f"*{ext}"):
            rel = str(p.relative_to(root))
            if _SKIP_DIR_RE.search(rel):
                continue
            objs.append(p)
    # Deduplicate (rcgu.o files match both globs).
    return sorted(set(objs))


def disassemble(obj: Path) -> str | None:
    """Run `objdump -d -l --no-show-raw-insn` and return the asm text."""
    try:
        proc = subprocess.run(
            ["objdump", "-d", "-l", "--no-show-raw-insn", str(obj)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            return None
        return proc.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def normalize_objdump_to_parser(objdump_text: str) -> str:
    """Adapt `objdump -d -l` output for AssemblyParser.

    The parser was built for rustc's `--emit=asm` output (AT&T syntax,
    `.file`/`.loc` directives, mangled symbol labels). objdump's format
    is similar but uses a different symbol marker (`<symbol>:` with
    angle brackets) and intersperses disassembled lines with lines like
    `/path/to/file.rs:42`. We rewrite to look like rustc asm:

      `<_ZN5crate3foo17h...>:`            -> `_ZN5crate3foo17h...:`
      `/abs/path/file.rs:42`              -> `\\t.file 1 \"/abs/path/file.rs\"\\n\\t.loc 1 42`

    The rest passes through. Imperfect but enough for the parser's
    pattern matching; instruction mnemonics are unchanged.
    """
    out_lines: list[str] = []
    file_id_map: dict[str, int] = {}
    next_file_id = 1

    sym_re = re.compile(r"^(?:[0-9a-f]+\s+)?<([^>]+)>:\s*$")
    loc_re = re.compile(r"^([\w./_-]+\.[a-zA-Z]+):(\d+)\s*$")
    # Strip the leading `<hex>:\t` address marker that objdump prepends to
    # every instruction. Without this the AssemblyParser thinks the
    # address is the mnemonic.
    addr_re = re.compile(r"^\s*[0-9a-f]+:\s*")

    for line in objdump_text.splitlines():
        m = sym_re.match(line)
        if m:
            sym = m.group(1)
            out_lines.append(f"{sym}:")
            continue
        m = loc_re.match(line)
        if m:
            current_file = m.group(1)
            try:
                current_line = int(m.group(2))
            except ValueError:
                continue
            if current_file not in file_id_map:
                file_id_map[current_file] = next_file_id
                next_file_id += 1
                out_lines.append(f'\t.file {file_id_map[current_file]} "{current_file}"')
            out_lines.append(f"\t.loc {file_id_map[current_file]} {current_line} 0")
            continue
        # Strip leading "  abc:\t" address marker on instruction lines.
        line = addr_re.sub("\t", line, count=1)
        out_lines.append(line)
    return "\n".join(out_lines)


def is_user_source(file_path: str | None) -> bool:
    if not file_path:
        return False
    if "/rustc/" in file_path:
        return False
    if "/.cargo/registry/" in file_path:
        return False
    if "/.cargo/git/" in file_path:
        return False
    return True


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--label", required=True)
    p.add_argument("--max-warnings-sample", type=int, default=200)
    p.add_argument("--no-precise-warnings", action="store_true")
    args = p.parse_args()

    if not args.root.is_dir():
        sys.stderr.write(f"--root not a directory: {args.root}\n")
        return 2

    objs = collect_object_files(args.root)
    print(f"=== {args.label} ===", file=sys.stderr)
    print(f"  root: {args.root}", file=sys.stderr)
    print(f"  found {len(objs)} candidate .o files", file=sys.stderr)

    if not objs:
        result = WildResult(
            label=args.label,
            timestamp=time.time(),
            root=str(args.root),
            n_objects=0,
            build_valid=False,
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(asdict(result), indent=2))
        sys.stderr.write(
            "BUILD-VALIDITY FAILURE: zero object files. Did you run "
            "`RUSTFLAGS=\"-C debuginfo=2\" cargo build --release` in the "
            "crate root?\n"
        )
        return 3

    all_violations: list[dict] = []
    total_instructions = 0
    n_disassembled = 0

    for i, obj in enumerate(objs):
        if i % 25 == 0:
            print(f"  [{i}/{len(objs)}] {obj.name}", file=sys.stderr)
        asm = disassemble(obj)
        if asm is None:
            continue
        text = normalize_objdump_to_parser(asm)
        parser = AssemblyParser(
            "x86_64",
            "rustc",
            rust_user_crate=None,  # match any non-stdlib crate
            include_stdlib=False,
            strict=False,
            precise_warnings=not args.no_precise_warnings,
        )
        functions, viols = parser.parse(text, include_warnings=True)
        for f in functions:
            total_instructions += f.get("instructions", 0)
        n_disassembled += 1
        AssemblyParser._attach_triage_metadata(viols)
        for v in viols:
            all_violations.append(
                {
                    "function": v.function,
                    "file": v.file,
                    "line": v.line,
                    "address": v.address,
                    "instruction": v.instruction,
                    "mnemonic": v.mnemonic,
                    "reason": v.reason,
                    "severity": v.severity.value,
                    "triage_hint": v.triage_hint,
                    "source_snippet": v.source_snippet,
                    "object": str(obj.relative_to(args.root)),
                }
            )

    errors = [v for v in all_violations if v["severity"] == "error"]
    warnings = [v for v in all_violations if v["severity"] == "warning"]
    errors_user = [v for v in errors if is_user_source(v.get("file"))]
    warnings_user = [v for v in warnings if is_user_source(v.get("file"))]
    triage = Counter(v.get("triage_hint") or "unknown" for v in all_violations)

    # Build clustered views at three granularities. Reviewers can pick
    # the one that matches their workflow:
    #   - function-clusters: reviewer reads each function once.
    #   - file-clusters:     reviewer scans each file for a pattern.
    #   - pattern-clusters:  reviewer decides per source-shape (most aggressive).
    clusters_user_fn = cluster_warnings(warnings_user, by="function")
    clusters_user_file = cluster_warnings(warnings_user, by="file")
    clusters_user_pattern = cluster_warnings(warnings_user, by="pattern")
    # All-warnings clustered at function granularity, for the dep-review crowd.
    clusters_all = cluster_warnings(warnings, by="function")

    # Build-validity precondition.
    build_valid = n_disassembled > 0 and total_instructions >= 1000

    # Sampled warnings (deterministic by seed=44 to match the convention).
    import random
    rng = random.Random(44)
    sample_pool = warnings_user if warnings_user else warnings
    sample_n = min(args.max_warnings_sample, len(sample_pool))
    sampled = rng.sample(sample_pool, sample_n) if sample_pool else []

    result = WildResult(
        label=args.label,
        timestamp=time.time(),
        root=str(args.root),
        n_objects=n_disassembled,
        n_instructions=total_instructions,
        error_count=len(errors),
        warning_count=len(warnings),
        error_count_user=len(errors_user),
        warning_count_user=len(warnings_user),
        triage_breakdown=dict(triage),
        errors=errors,
        warnings_sampled=sampled,
        warning_clusters=(
            clusters_user_fn if warnings_user else clusters_all
        ),
        cluster_count=len(clusters_user_fn) if warnings_user else len(clusters_all),
        build_valid=build_valid,
    )
    # Attach all three granularities for downstream tooling.
    result_dict = asdict(result)
    result_dict["clusters_user_function"] = clusters_user_fn
    result_dict["clusters_user_file"] = clusters_user_file
    result_dict["clusters_user_pattern"] = clusters_user_pattern
    result_dict["clusters_all_function"] = clusters_all

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result_dict, indent=2))

    print("", file=sys.stderr)
    if not build_valid:
        print(
            "BUILD-VALIDITY FAILURE: refusing to print headlines.\n"
            f"  n_objects={n_disassembled}  n_instructions={total_instructions}\n"
            f"  Expected n_objects>0 and n_instructions>=1000.\n"
            f"  Did `cargo build --release` actually run? Check the target tree.",
            file=sys.stderr,
        )
        return 3

    print(
        f"Totals: errors={len(errors)} (user={len(errors_user)})  "
        f"warnings={len(warnings)} (user={len(warnings_user)})  "
        f"objs={n_disassembled}  insns={total_instructions}",
        file=sys.stderr,
    )
    n_user = max(1, len(warnings_user))
    print(
        f"User-warning clustering ({len(warnings_user)} reports):\n"
        f"  by function: {len(clusters_user_fn):>5} clusters  "
        f"({n_user/max(1,len(clusters_user_fn)):.1f}x reduction)\n"
        f"  by file:     {len(clusters_user_file):>5} clusters  "
        f"({n_user/max(1,len(clusters_user_file)):.1f}x reduction)\n"
        f"  by pattern:  {len(clusters_user_pattern):>5} clusters  "
        f"({n_user/max(1,len(clusters_user_pattern)):.1f}x reduction)",
        file=sys.stderr,
    )
    print("Triage breakdown:", file=sys.stderr)
    for hint, n in triage.most_common():
        print(f"  {n:>5}  {hint}", file=sys.stderr)
    print(f"  -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
