#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""Unified wild-mode benchmark runner.

Dispatches by ``--language={c,go,rust}`` into the language-specific
harness:

  * c    -- walks .o files under a built C/C++ library tree and runs
            objdump + the analyzer with the tuned filter stack.
  * go   -- runs ``go build -gcflags=-S`` against each target package
            from a workspace and parses the gc-S listing.
  * rust -- walks .o files under a Cargo target/release tree, runs
            objdump, normalises the output for the rustc parser
            branch, and clusters warnings by function/file/pattern.

The three result-JSON schemas differ deliberately (different sources
of truth, different aggregation needs) and are preserved byte-for-byte
from the pre-unification scripts.

Usage:
    PYTHONPATH=. python3 benchmark/scripts/run_wild.py --language c \\
        --root benchmark/wild/libsodium --label libsodium
    PYTHONPATH=. python3 benchmark/scripts/run_wild.py --language go \\
        --workspace benchmark/wild_go/workspace \\
        --target stdlib:crypto/internal/fips140/mlkem --label go_stdlib
    PYTHONPATH=. python3 benchmark/scripts/run_wild.py --language rust \\
        --root benchmark/wild_rust/<crate>/target/release \\
        --label <crate> --out benchmark/results/wild_<crate>.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PLUGIN))
sys.path.insert(0, str(PLUGIN / "benchmark" / "scripts"))


# ---------------------------------------------------------------------------
# C / C++ path: unchanged from the pre-unification run_wild.py.
# ---------------------------------------------------------------------------

from ct_analyzer.analyzer import (  # noqa: E402
    AssemblyParser,
    Severity,
    analyze_assembly,
)
from ct_analyzer.filters import apply_filters  # noqa: E402


def _c_find_object_files(root: Path) -> list[Path]:
    """All .o files under root, deduplicated by base path."""
    return sorted(set(root.rglob("*.o")))


def _c_disassemble(obj: Path) -> str:
    """Run objdump -d -l on the .o, return assembly text.
    The -l flag emits DWARF-derived `/path/to/file.c:NN` line markers
    before each instruction group, which the analyzer parser uses to
    attribute each finding back to a source file."""
    try:
        return subprocess.check_output(
            ["objdump", "-d", "-l", "--no-show-raw-insn", str(obj)],
            text=True, errors="replace", timeout=30,
        )
    except subprocess.TimeoutExpired:
        return ""
    except subprocess.CalledProcessError:
        return ""


def _c_analyze_object(obj: Path, filters: list[str]) -> tuple[list[dict], int, int]:
    """Disassemble + analyze one .o.  Returns (findings, n_funcs, n_instrs)."""
    asm = _c_disassemble(obj)
    if not asm:
        return [], 0, 0
    with tempfile.NamedTemporaryFile("w", suffix=".s", delete=False) as f:
        f.write(asm)
        asm_path = f.name
    try:
        report = analyze_assembly(asm_path, "x86_64", include_warnings=True)
    except Exception:
        return [], 0, 0
    finally:
        Path(asm_path).unlink(missing_ok=True)

    # Source-level filters (memcmp-source, non-secret) work too, because
    # the analyzer now consumes objdump -l line markers and stamps each
    # violation with v.file.  apply_filters falls back to v.file when
    # source_path is None.
    kept, _ = apply_filters(report.violations, filters)

    findings = []
    for v in kept:
        findings.append({
            "object": str(obj),
            "function": v.function,
            "file": v.file,
            "line": v.line,
            "mnemonic": v.mnemonic,
            "severity": v.severity.value,
            "reason": v.reason,
        })
    return findings, report.total_functions, report.total_instructions


def main_c(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="run_wild.py --language=c")
    ap.add_argument("--root", required=True, help="Library root directory (built)")
    ap.add_argument("--label", required=True, help="Library label for output")
    ap.add_argument("--filter",
                    default="ct-funcs,compiler-helpers,div-public,loop-backedge,memcmp-source,non-secret,aggregate",
                    help="Filters to apply.  When the .o files were built "
                         "with -g, DWARF line markers from `objdump -l` give "
                         "every violation a .file attribute, so the source-"
                         "level filters memcmp-source / non-secret can run.")
    ap.add_argument("--out", default=None, help="Write findings JSON to this path")
    ap.add_argument("--limit", type=int, default=0,
                    help="If >0, only analyze the first N .o files (smoke test)")
    args = ap.parse_args(argv)

    filters = [s.strip() for s in args.filter.split(",") if s.strip()]
    root = Path(args.root).resolve()

    obj_files = _c_find_object_files(root)
    # Filter out CMake compiler probe artifacts and obvious non-crypto dirs
    obj_files = [
        o for o in obj_files
        if "CMakeFiles/3" not in str(o) and "/test/" not in str(o)
        and "/tests/" not in str(o) and "/fuzz" not in str(o)
        and "/programs/" not in str(o) and "/bench/" not in str(o)
    ]
    if args.limit > 0:
        obj_files = obj_files[:args.limit]

    print(f"== {args.label}: {len(obj_files)} objects ==", file=sys.stderr)
    if len(obj_files) == 0:
        print(f"FATAL: no .o files under {root}.  Did the build succeed?  "
              "Run `git submodule update --init --recursive` and re-build "
              "before treating zero findings as a property of the code.",
              file=sys.stderr)
        return 2

    all_findings: list[dict] = []
    total_funcs = 0
    total_instrs = 0
    for i, obj in enumerate(obj_files, 1):
        if i % 50 == 0:
            print(f"  [{i}/{len(obj_files)}] processed; running findings: {len(all_findings)}", file=sys.stderr)
        findings, nfunc, ninstr = _c_analyze_object(obj, filters)
        all_findings.extend(findings)
        total_funcs += nfunc
        total_instrs += ninstr

    if total_instrs < 1000:
        print(f"FATAL: only {total_instrs} instructions parsed across "
              f"{len(obj_files)} objects.  Either the build produced empty "
              "objects, or the parser failed.  Refusing to report as a "
              "headline number.", file=sys.stderr)
        return 2

    by_mnemonic = Counter(f["mnemonic"] for f in all_findings)
    by_severity = Counter(f["severity"] for f in all_findings)
    by_object = Counter(Path(f["object"]).name for f in all_findings)

    out = {
        "label": args.label,
        "n_objects": len(obj_files),
        "n_functions": total_funcs,
        "n_instructions": total_instrs,
        "n_findings": len(all_findings),
        "by_mnemonic": dict(by_mnemonic.most_common()),
        "by_severity": dict(by_severity),
        "by_object": dict(by_object.most_common(20)),
        "findings": all_findings,
    }
    print(f"\n=== {args.label} ===")
    print(f"  objects        : {len(obj_files)}")
    print(f"  functions      : {total_funcs}")
    print(f"  instructions   : {total_instrs}")
    print(f"  total findings : {len(all_findings)}")
    print(f"  per 1k instrs  : {len(all_findings) * 1000 / max(1, total_instrs):.2f}")
    print(f"  by severity    : {dict(by_severity)}")
    print(f"  top mnemonics  : {dict(by_mnemonic.most_common(10))}")
    print(f"  top objects    :")
    for k, v in by_object.most_common(10):
        print(f"    {v:>4}  {k}")

    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=2))
        print(f"  wrote {args.out}")
    return 0


# ---------------------------------------------------------------------------
# Go path: unchanged from the pre-unification run_wild_go.py.
# ---------------------------------------------------------------------------

_GO_DEFAULT_FILTERS = [
    "compiler-helpers", "memcmp-source", "ct-funcs",
    "non-secret", "div-public", "loop-backedge",
    "go-bounds-check", "go-stack-grow", "go-public-line",
    "aggregate",
]


def _go_run_build_S(pkg: str, workspace: Path, opt: str = "default") -> str:
    """Run `go build -gcflags=-S <pkg>` from the workspace and return stderr
    (which is where the gc compiler's -S listing goes)."""
    env = os.environ.copy()
    env["GOOS"] = env.get("GOOS", "linux")
    env["GOARCH"] = env.get("GOARCH", "amd64")
    env["CGO_ENABLED"] = "0"
    gcflag_parts = ["-S"]
    if opt == "O0":
        gcflag_parts.extend(["-N", "-l"])
    gcflags = " ".join(gcflag_parts)

    with tempfile.TemporaryDirectory() as tmpdir:
        bin_path = os.path.join(tmpdir, "discard")
        # `all=` prefix forces the flag onto every package being compiled
        # (otherwise -S only applies to the top-level package). We want
        # only the target package's symbols, so we use the unprefixed
        # form.
        cmd = ["go", "build", "-o", bin_path, "-gcflags", gcflags, pkg]
        result = subprocess.run(
            cmd, capture_output=True, text=True, env=env,
            cwd=str(workspace), timeout=300,
        )
    return result.stderr


def _go_analyze_package(pkg: str, label_prefix: str, workspace: Path,
                        filters: list[str]) -> dict:
    """Build + analyze + filter one package. Returns a per-package report
    dict with findings, instruction count, function count, and any
    build error."""
    asm = _go_run_build_S(pkg, workspace, opt="default")
    parser = AssemblyParser("x86_64", "go")
    funcs, viols = parser.parse(asm, include_warnings=True)
    n_instr = sum(f["instructions"] for f in funcs)
    if n_instr == 0:
        return {
            "package": pkg, "label_prefix": label_prefix,
            "n_functions": 0, "n_instructions": 0,
            "build_error": (asm[:400] + "..." if len(asm) > 400 else asm),
            "findings": [],
        }
    kept, _ = apply_filters(viols, filters)
    findings = []
    for v in kept:
        findings.append({
            "package": pkg,
            "function": v.function,
            "file": v.file,
            "line": v.line,
            "address": v.address,
            "mnemonic": v.mnemonic,
            "severity": v.severity.value,
            "reason": v.reason,
        })
    return {
        "package": pkg,
        "label_prefix": label_prefix,
        "n_functions": len(funcs),
        "n_instructions": n_instr,
        "findings": findings,
    }


def main_go(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="run_wild.py --language=go")
    ap.add_argument("--workspace", required=True,
                    help="Go workspace dir with go.mod that imports the targets")
    ap.add_argument("--target", action="append", default=[],
                    help="Repeatable: <label>:<pkg-path>, e.g. stdlib:crypto/sha256")
    ap.add_argument("--filter",
                    default=",".join(_GO_DEFAULT_FILTERS),
                    help="Comma-separated filter set")
    ap.add_argument("--label", required=True, help="Output label")
    ap.add_argument("--out", default=None, help="Write JSON to this path")
    args = ap.parse_args(argv)

    workspace = Path(args.workspace).resolve()
    if not (workspace / "go.mod").exists():
        print(f"FATAL: {workspace}/go.mod not found", file=sys.stderr)
        return 2
    filters = [s.strip() for s in args.filter.split(",") if s.strip()]

    targets = []
    for t in args.target:
        if ":" not in t:
            print(f"FATAL: --target expects label:pkg, got {t!r}", file=sys.stderr)
            return 2
        lp, pkg = t.split(":", 1)
        targets.append((lp, pkg))
    if not targets:
        print("FATAL: at least one --target required", file=sys.stderr)
        return 2

    print(f"== {args.label}: {len(targets)} packages ==", file=sys.stderr)
    per_pkg: list[dict] = []
    failed: list[str] = []
    for label_prefix, pkg in targets:
        print(f"  building+analyzing {pkg}...", file=sys.stderr)
        r = _go_analyze_package(pkg, label_prefix, workspace, filters)
        per_pkg.append(r)
        if r.get("build_error") and r["n_instructions"] == 0:
            failed.append(pkg)

    total_funcs = sum(r["n_functions"] for r in per_pkg)
    total_instr = sum(r["n_instructions"] for r in per_pkg)
    all_findings = [f for r in per_pkg for f in r["findings"]]

    # Build-validity preconditions
    if failed and len(failed) == len(targets):
        print(f"FATAL: every package failed to build:", file=sys.stderr)
        for f in failed:
            print(f"  - {f}", file=sys.stderr)
        return 2
    if total_instr < 1000:
        print(f"FATAL: only {total_instr} instructions parsed across "
              f"{len(targets)} packages. Refusing to report headline.",
              file=sys.stderr)
        return 2
    if failed:
        print(f"WARNING: {len(failed)} packages failed to build "
              f"(treating as 0 findings each):", file=sys.stderr)
        for f in failed:
            print(f"  - {f}", file=sys.stderr)

    by_severity = Counter(f["severity"] for f in all_findings)
    by_mnemonic = Counter(f["mnemonic"] for f in all_findings)
    by_pkg = {r["package"]: len(r["findings"]) for r in per_pkg}

    out = {
        "label": args.label,
        "n_packages": len(targets),
        "n_packages_failed": len(failed),
        "n_functions": total_funcs,
        "n_instructions": total_instr,
        "n_findings": len(all_findings),
        "findings_per_1k_instr": (
            round(len(all_findings) * 1000 / max(1, total_instr), 2)
        ),
        "by_severity": dict(by_severity),
        "by_mnemonic": dict(by_mnemonic.most_common()),
        "by_package": by_pkg,
        "per_package": [
            {k: v for k, v in r.items() if k != "findings"} for r in per_pkg
        ],
        "findings": all_findings,
    }

    print(f"\n=== {args.label} ===")
    print(f"  packages       : {len(targets)} ({len(failed)} failed)")
    print(f"  functions      : {total_funcs}")
    print(f"  instructions   : {total_instr}")
    print(f"  total findings : {len(all_findings)}")
    print(f"  per 1k instrs  : {out['findings_per_1k_instr']}")
    print(f"  by severity    : {dict(by_severity)}")
    print(f"  top mnemonics  : {dict(by_mnemonic.most_common(10))}")
    print(f"  top packages by finding count:")
    for pkg, n in sorted(by_pkg.items(), key=lambda kv: -kv[1])[:10]:
        print(f"    {n:>5}  {pkg}")

    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=2))
        print(f"  wrote {args.out}")
    return 0


# ---------------------------------------------------------------------------
# Rust path: unchanged from the pre-unification run_wild_rust.py.
# ---------------------------------------------------------------------------

# Directories under target/release we should NOT analyze: tests, benches,
# fuzz, examples are non-production. Plus the build/ subtree which holds
# host-side build-script outputs.
_RUST_SKIP_DIR_RE = re.compile(
    r"(?:^|/)(?:tests?|benches?|fuzz|examples|build/|incremental/)"
)


@dataclass
class _RustWildResult:
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


_RUST_NORMALIZE_NUM_RE = re.compile(r"\b\d+\b")
_RUST_NORMALIZE_HEX_RE = re.compile(r"\b0[xX][0-9a-fA-F]+\b")
_RUST_NORMALIZE_IDENT_RE = re.compile(
    r"\b[a-z_][a-zA-Z0-9_]*\b"
)
_RUST_KEEP_KEYWORDS = frozenset({
    "if", "else", "while", "for", "in", "match", "let", "mut", "fn", "pub",
    "self", "as", "true", "false", "return", "break", "continue", "loop",
    "ref", "move", "and", "or", "not", "is_empty", "is_none", "is_some",
    "is_zero", "is_negative", "len", "iter", "iter_mut", "into_iter",
    "next", "unwrap", "expect", "ok", "err",
})


def _rust_normalize_pattern(line: str) -> str:
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
    s = _RUST_NORMALIZE_HEX_RE.sub("HEX", s)
    s = _RUST_NORMALIZE_NUM_RE.sub("NUM", s)
    # Replace identifiers with NAME, keeping keywords / common method names.
    def _sub(m: "re.Match") -> str:
        ident = m.group(0)
        return ident if ident in _RUST_KEEP_KEYWORDS else "NAME"
    s = _RUST_NORMALIZE_IDENT_RE.sub(_sub, s)
    # Collapse runs of NAME, NAME -> NAME.
    s = re.sub(r"(?:NAME[\s,.]+){2,}", "NAME ", s)
    s = re.sub(r"\s+", " ", s)
    return s


def _rust_cluster_warnings(violations: list[dict], by: str = "function") -> list[dict]:
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
            key = ("pattern", hint, _rust_normalize_pattern(cited))

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
                "representative_pattern": _rust_normalize_pattern(cited) if by == "pattern" else None,
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


def _rust_collect_object_files(root: Path) -> list[Path]:
    """Find every .o file under the cargo target/release tree, excluding
    test / bench / fuzz outputs."""
    objs: list[Path] = []
    for ext in (".o", ".rcgu.o"):
        for p in root.rglob(f"*{ext}"):
            rel = str(p.relative_to(root))
            if _RUST_SKIP_DIR_RE.search(rel):
                continue
            objs.append(p)
    # Deduplicate (rcgu.o files match both globs).
    return sorted(set(objs))


def _rust_disassemble(obj: Path) -> str | None:
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


def _rust_normalize_objdump_to_parser(objdump_text: str) -> str:
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


def _rust_is_user_source(file_path: str | None) -> bool:
    if not file_path:
        return False
    if "/rustc/" in file_path:
        return False
    if "/.cargo/registry/" in file_path:
        return False
    if "/.cargo/git/" in file_path:
        return False
    return True


def main_rust(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="run_wild.py --language=rust")
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--label", required=True)
    p.add_argument("--max-warnings-sample", type=int, default=200)
    p.add_argument("--no-precise-warnings", action="store_true")
    args = p.parse_args(argv)

    if not args.root.is_dir():
        sys.stderr.write(f"--root not a directory: {args.root}\n")
        return 2

    objs = _rust_collect_object_files(args.root)
    print(f"=== {args.label} ===", file=sys.stderr)
    print(f"  root: {args.root}", file=sys.stderr)
    print(f"  found {len(objs)} candidate .o files", file=sys.stderr)

    if not objs:
        result = _RustWildResult(
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
        asm = _rust_disassemble(obj)
        if asm is None:
            continue
        text = _rust_normalize_objdump_to_parser(asm)
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
    errors_user = [v for v in errors if _rust_is_user_source(v.get("file"))]
    warnings_user = [v for v in warnings if _rust_is_user_source(v.get("file"))]
    triage = Counter(v.get("triage_hint") or "unknown" for v in all_violations)

    # Build clustered views at three granularities. Reviewers can pick
    # the one that matches their workflow:
    #   - function-clusters: reviewer reads each function once.
    #   - file-clusters:     reviewer scans each file for a pattern.
    #   - pattern-clusters:  reviewer decides per source-shape (most aggressive).
    clusters_user_fn = _rust_cluster_warnings(warnings_user, by="function")
    clusters_user_file = _rust_cluster_warnings(warnings_user, by="file")
    clusters_user_pattern = _rust_cluster_warnings(warnings_user, by="pattern")
    # All-warnings clustered at function granularity, for the dep-review crowd.
    clusters_all = _rust_cluster_warnings(warnings, by="function")

    # Build-validity precondition.
    build_valid = n_disassembled > 0 and total_instructions >= 1000

    # Sampled warnings (deterministic by seed=44 to match the convention).
    import random
    rng = random.Random(44)
    sample_pool = warnings_user if warnings_user else warnings
    sample_n = min(args.max_warnings_sample, len(sample_pool))
    sampled = rng.sample(sample_pool, sample_n) if sample_pool else []

    result = _RustWildResult(
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


# ---------------------------------------------------------------------------
# Top-level dispatcher.
# ---------------------------------------------------------------------------

def main() -> int:
    pre = argparse.ArgumentParser(
        description="Unified wild-mode benchmark runner.",
        add_help=False,
    )
    pre.add_argument(
        "--language", required=True, choices=("c", "go", "rust"),
        help="Source language to benchmark; selects the wild-mode harness.",
    )
    args, remaining = pre.parse_known_args()
    if args.language == "c":
        return main_c(remaining)
    if args.language == "go":
        return main_go(remaining)
    return main_rust(remaining)


if __name__ == "__main__":
    sys.exit(main())
