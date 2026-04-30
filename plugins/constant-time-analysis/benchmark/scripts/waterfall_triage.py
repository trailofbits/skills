#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""Waterfall triage: classify every user warning into one of five phases.

Phase 1: mechanical dismissal by triage_hint or source path  (~ 1 sec/item)
Phase 2: function-name / source-path patterns                 (~ 5 sec/item)
Phase 3: source-snippet pattern matching                       (~30 sec/item)
Phase 4: function-context (argument-name secrecy heuristic)    (~ 5 min/item)
Phase 5: full source/caller review                              (10+ min/item)

The model's premise: spend the LEAST time on cases that can be dispatched
mechanically. Reserve real reasoning for the few items that survive to
Phase 4-5. The output is a structured report showing per-phase counts
and dumping every Phase-5 item with maximum context for human review.

Run:
    PYTHONPATH=. python3 benchmark/scripts/waterfall_triage.py \\
        --result benchmark/results/wild_*_v3.json \\
        --out benchmark/results/waterfall.json
"""

from __future__ import annotations

import argparse
import glob
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Phase 1: mechanical dismissal.
# Cost: O(1) attribute check, no source reading.
# ---------------------------------------------------------------------------

_DEP_PATH_MARKERS = ("/rustc/", "/.cargo/registry/", "/.cargo/git/")


def phase1_dismiss(violation: dict) -> tuple[str, str] | None:
    """Return (verdict, rationale) if dismissable in Phase 1, else None.

    Verdict is "FP" | "TP" | "needs_review".
    """
    hint = (violation.get("triage_hint") or "").lower()
    if hint.endswith("_likely_fp"):
        return ("FP", f"triage_hint={hint}")
    file_path = violation.get("file") or ""
    if any(m in file_path for m in _DEP_PATH_MARKERS):
        return ("FP", f"source-path-in-dependency: {file_path[:60]}")
    return None


# ---------------------------------------------------------------------------
# Phase 2: cheap path/name dismissal.
# Cost: regex match on function name and file path.
# ---------------------------------------------------------------------------

_PHASE2_PATH_RE = re.compile(
    r"(?:^|/)(?:tests?|benches?|fuzz|examples|build\.rs|build/|incremental/)"
)
_PHASE2_FUNCTION_PATTERNS = [
    # Trait method names that mean formatting / debug, not crypto.
    (re.compile(r"::(?:fmt|Display|Debug|Octal|Hex|Binary)::"), "formatting trait method"),
    (re.compile(r"::Format::|::Formatter::"), "formatting machinery"),
    # Drop / Clone glue.
    (re.compile(r"::Drop::drop\b"), "destructor (drop) glue"),
    (re.compile(r"::Clone::clone\b"), "clone glue"),
    # CPU feature detection -- runtime-once, public.
    (re.compile(r"::cpuid::|::cpu_features?::|is_(?:x86|aarch64)_feature_detected|::auto_detect"), "runtime CPU feature detection"),
    # ASN.1 / DER / PKCS#1 / PKCS#8 / PEM parsing -- public encodings.
    (re.compile(r"^der::|::der::|^asn1::|::asn1::|::pkcs[18]::|::pem::|::pkcs::|encoding::|::oid::"), "ASN.1/DER/PEM parsing of public encoding"),
    # CSPRNG seeding / random_core public-input plumbing.
    (re.compile(r"::rand_core::|::OsRng::|::ThreadRng::"), "RNG plumbing, public output"),
    # Logging / tracing.
    (re.compile(r"::trace_macros::|::log_internal::|::__private_api::"), "logging/tracing macro internals"),
    # Allocator / Vec / String capacity bookkeeping.
    (re.compile(r"::alloc::|::Vec::|::String::|::with_capacity|::reserve"), "allocator/capacity bookkeeping"),
]


def phase2_dismiss(violation: dict) -> tuple[str, str] | None:
    function = violation.get("function") or ""
    file_path = violation.get("file") or ""
    if _PHASE2_PATH_RE.search(file_path):
        return ("FP", f"non-production source dir: {file_path[:60]}")
    for pat, rationale in _PHASE2_FUNCTION_PATTERNS:
        if pat.search(function):
            return ("FP", rationale)
    return None


# ---------------------------------------------------------------------------
# Phase 3: source-snippet pattern matching.
# Cost: regex on cited source line content.
# ---------------------------------------------------------------------------

_PHASE3_PATTERNS = [
    # Derive macros: the JE/JNE attributed to a `#[derive(...)]` line
    # comes from auto-generated PartialEq/Eq/Hash trait impls. The
    # equality is on STRUCT FIELDS that are public types (enum tags,
    # u32 IDs, etc.). Phase-3 dismiss without further thought.
    (re.compile(r"^\s*#\[derive\("),
     "auto-derived PartialEq/Eq/Hash on public-type fields"),
    # Logging / tracing macros: format-string lazy evaluation emits
    # JE/JNE in the formatter machinery, not on user data.
    (re.compile(r"\b(?:warn|debug|trace|info|error|eprintln|println|panic)\s*!"),
     "logging/tracing macro internals"),
    # `let Some(x) = expr else { ... }`: the else-branch is a control-flow
    # check on whether the producer returned a value, not on a secret.
    (re.compile(r"^\s*let\s+Some\s*\([^)]*\)\s*=.*\belse\s*\{?"),
     "let-else Option destructure (control flow, not data)"),
    # `assert!`, `assert_eq!`, `debug_assert!`, `assert_ne!` -- panic on
    # failure. The branch is the panic-or-continue path; not a timing
    # oracle (program dies on the bad path).
    (re.compile(r"^\s*(?:debug_)?assert(?:_eq|_ne|_matches)?\s*!"),
     "assert!-style panic-or-continue"),
    # Enum-variant dispatch (broadened: trailing `{` is optional, can
    # be on next line).
    (re.compile(r"^\s*match\s+"),
     "match dispatch (typically on public enum)"),
    # Optional unwrapping with `.ok_or`, `.expect`, `.unwrap_or`.
    (re.compile(r"\.ok_or\b|\.unwrap_or\b|\.expect\b\s*\(|\.unwrap\s*\(\s*\)"),
     "Result/Option unwrap (control flow on absence)"),
    (re.compile(r"^\s*if\s+let\s+"),
     "if-let pattern match (variant dispatch)"),
    # Presence / state checks.
    (re.compile(r"\.is_empty\s*\(\s*\)|\.is_some\s*\(\s*\)|\.is_none\s*\(\s*\)|\.is_ok\s*\(\s*\)|\.is_err\s*\(\s*\)"),
     "presence/state check (is_empty/is_some/etc.)"),
    (re.compile(r"\.is_identity\s*\(\s*\)|\.is_zero\s*\(\s*\)|\.is_negative\s*\(\s*\)|\.is_odd\s*\(\s*\)|\.is_even\s*\(\s*\)"),
     "predicate on public group element / structural value"),
    # Iterator-end branches.
    (re.compile(
        r"\.iter(?:_mut)?\s*\(\s*\)|\.into_iter\s*\(\s*\)|\.windows\s*\(|"
        r"\.chunks(?:_mut|_exact)?\s*\(|\.zip\s*\(|\.enumerate\s*\(\s*\)|"
        r"\.any_left\s*\(\s*\)|\.has_next\s*\(\s*\)|\.next\s*\(\s*\)"),
     "iterator-end branch on public-length container"),
    # `while x != 0` / `while x > 0` / `while sub.any_left()`.
    (re.compile(r"^\s*while\s+\w+(?:\.\w+\(\))*\s*[!=<>]*[!=<>]\s*\d+\b|"
                r"^\s*while\s+\w+(?:\.\w+\([^)]*\))+\s*\{?"),
     "while-loop with literal/method-call bound (typically public)"),
    # Closing brace -- function-epilogue branch.
    (re.compile(r"^\s*\}\s*$"),
     "function epilogue (return path)"),
    # Public-key/identity/group constants comparison.
    (re.compile(r"==\s*(?:G|H|ZERO|ONE|MINUS_ONE|IDENTITY|NEUTRAL|GENERATOR|TLSv1_\d+)\b|"
                r"==\s*\w+::(?:[A-Z][a-zA-Z0-9_]*::)*[A-Z][A-Z_]*\b"),
     "comparison against public group constant or enum variant"),
    # Found-one loop pattern (Miller loop bit scan)
    (re.compile(r"^\s*if\s+(?:found_one|self\.found_one|self\.[a-z_]+)\s*\{"),
     "Miller-loop double-and-add bit scan (public Hamming weight)"),
    # Bit testing on a loop-derived index (square-and-multiply on public exponent).
    (re.compile(r"if\s+\(\s*\*?\w+\s*>>\s*\w+\s*\)\s*&\s*1\s*==\s*1"),
     "square-and-multiply bit test (public exponent in vartime context)"),
    # `match get_selected_backend()` / runtime backend dispatch.
    (re.compile(r"^\s*match\s+get_selected_backend|backend::auto|::dispatch\b"),
     "runtime backend / SIMD-feature dispatch"),
    # Structural-metadata method comparisons. The receiver methods named
    # `len`, `size`, `bits_precision`, `bit_size`, `width`, `version`,
    # `group`, `group_id`, `protocol_version`, `typ`, `payload_type` all
    # return PUBLIC structural metadata in audited Rust crypto.
    (re.compile(
        r"\.\s*(?:len|size|bits_precision|bit_size|bit_len|byte_len|"
        r"width|height|stride|capacity|"
        r"version|protocol_version|group|group_id|kind|typ|"
        r"payload_type|content_type|alg|algorithm|oid|tag_kind)\s*\(\s*\)"),
     "comparison against structural metadata accessor (public)"),
    # `if x.method()? != y.method()?` style with the `?` operator.
    (re.compile(r"\?\s*[!=<>]"), "comparison after ?-propagation (control flow)"),
    # Length / capacity arithmetic check (e.g. `if k < t_len + 11`).
    (re.compile(r"^\s*if\s+\w+\s*[<>]=?\s*\w+\s*\+\s*\d+\s*\{?$"),
     "public-length arithmetic check"),
    # Wire-format byte tests (public bytes from the wire).
    (re.compile(r"^\s*if\s+\w+\s*\[\s*\w+\s*\]\s*[!=<>]+\s*0?[xX]?[0-9a-fA-F]"),
     "wire-format byte / index test (public input bytes)"),
    # `if condition && !other_condition` style chains -- aggregate
    # control flow, often on protocol state.
    (re.compile(r"^\s*!?\(?\s*(?:self|this)\.\w+(?:\.\w+)*\s*&&"),
     "compound state-machine condition on `self`"),
]


# Files whose path itself implies vartime / non-secret-data context.
# Branches in these files are by-construction on public operands.
_VARTIME_FILE_PATHS = re.compile(
    r"/(?:vartime|verif(?:y|ication)|public|kx|protocol|frame|deframer|"
    r"handshake|server_hello|client_hello|extension|alert|key_exchange|"
    r"key_update|connection|conn|message|payload|encoding|deframer|"
    r"transcript|kernel)/|"
    r"/vartime[_.]|"
    r"_vartime\.rs$|"
    r"vartime\.rs$"
)
# Function names hosted on stateful protocol-machine receivers (Receiver,
# Connection, State, Tls12State, ...). Operations on TLS state are public.
_PROTOCOL_RECEIVER_RE = re.compile(
    r"::(?:Tls12State|Tls13State|TlsState|HandshakeHashOrBuffer|"
    r"ServerConnection|ClientConnection|ConnectionCommon|"
    r"Connection|Reader|Writer|Deframer|"
    r"ChunkVecBuffer|VecInput|VecOutput|"
    r"Tls12CipherSuite|Tls13CipherSuite|"
    r"ExpectClientHello|ExpectServerHello|ExpectFinished|"
    r"ExpectCertificate|ExpectCertificateRequest|ExpectTraffic|"
    r"CryptoProvider|SupportedKxGroup|FfdheGroup|"
    r"Accepted|KernelConnection|KeyUpdater)::"
)


def phase3_dismiss(violation: dict) -> tuple[str, str] | None:
    snippet = violation.get("source_snippet") or []
    if not snippet:
        return None
    cited = snippet[len(snippet) // 2]
    for pat, rationale in _PHASE3_PATTERNS:
        if pat.search(cited):
            return ("FP", rationale)
    # Path-based vartime detection: a file whose path contains `vartime`,
    # `protocol`, `handshake`, `frame`, etc. is operating on PUBLIC wire
    # data by definition.
    file_path = violation.get("file") or ""
    if _VARTIME_FILE_PATHS.search(file_path):
        return ("FP", f"vartime/protocol-handling source path: {file_path[:60]}")
    # Function attribution to a protocol-state receiver -- methods on
    # `Tls12State`, `ConnectionCommon<Side>`, etc. operate on public TLS
    # state machines.
    function = violation.get("function") or ""
    if _PROTOCOL_RECEIVER_RE.search(function):
        return ("FP", "method on TLS protocol-state receiver (public state)")
    return None


# ---------------------------------------------------------------------------
# Phase 4: function-context heuristic.
# Cost: scan the snippet's first line (or its preamble) for a `fn` signature.
# ---------------------------------------------------------------------------

# Argument names that strongly suggest a non-secret operand. The convention
# is well-established in audited Rust crypto: `m`, `msg`, `data`, `aad`,
# `info`, `salt`, `label`, `context`, `domain` are public; anything that
# transports cryptographic secret material gets named `key`, `sk`, `d`,
# `nonce` (sometimes), `mac_key`, `secret`, `priv`.
_PUBLIC_ARG_NAMES = re.compile(
    r"\b(?:m|msg|message|data|input|aad|info|salt|label|context|domain|"
    r"public_?key|pk|signature|sig|R|s|tag|hash|digest|"
    r"len|size|count|limit|threshold|capacity|bound|"
    r"chunk_size|block_size|window|w|bits|bit_idx|byte_idx|bit_offset|"
    r"radix|base|width|height|stride|block_pos|byte_pos)\b"
)
_SECRET_ARG_NAMES = re.compile(
    r"\b(?:secret|secret_key|sk|priv(?:ate)?_?key|d|key_material|"
    r"nonce_secret|seed_secret|mac_key|hmac_key|prk|ikm|"
    r"plaintext|secret_scalar|scalar(?!_pos)|exponent|exp(?!ected))\b"
)
_FN_SIGNATURE_RE = re.compile(
    r"(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?fn\s+"
    r"(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)"
)


def phase4_dismiss(violation: dict) -> tuple[str, str] | None:
    """Read the function signature from the snippet; if all args look public,
    dismiss as FP. If any arg name suggests a secret, fall through to Phase 5.
    """
    snippet = violation.get("source_snippet") or []
    if not snippet:
        return None
    blob = "\n".join(snippet)
    m = _FN_SIGNATURE_RE.search(blob)
    if not m:
        return None
    fn_name, args = m.group(1), m.group(2)
    has_secret = bool(_SECRET_ARG_NAMES.search(args))
    has_public = bool(_PUBLIC_ARG_NAMES.search(args))
    if has_secret:
        # Surface to Phase 5 -- secret-named arg present.
        return None
    if has_public and not has_secret:
        return ("FP", f"function `{fn_name}` arg names all public ({args[:60]}…)")
    # Function signature visible but no arg-name signal. Fall through.
    return None


# ---------------------------------------------------------------------------
# Waterfall driver.
# ---------------------------------------------------------------------------

PHASES = [
    ("phase1_hint_or_dep_path", phase1_dismiss),
    ("phase2_path_or_func_name", phase2_dismiss),
    ("phase3_snippet_pattern", phase3_dismiss),
    ("phase4_function_signature", phase4_dismiss),
]


@dataclass
class TriagedItem:
    crate: str
    function: str
    file: str
    line: int | None
    mnemonic: str
    triage_hint: str | None
    snippet: list[str] | None
    exit_phase: int  # 1..5
    verdict: str  # FP, TP, needs_review
    rationale: str


def triage_violation(crate: str, v: dict) -> TriagedItem:
    for i, (label, fn) in enumerate(PHASES, start=1):
        result = fn(v)
        if result is None:
            continue
        verdict, rationale = result
        return TriagedItem(
            crate=crate,
            function=v.get("function", ""),
            file=v.get("file", ""),
            line=v.get("line"),
            mnemonic=v.get("mnemonic", ""),
            triage_hint=v.get("triage_hint"),
            snippet=v.get("source_snippet"),
            exit_phase=i,
            verdict=verdict,
            rationale=rationale,
        )
    # Survived all phases -> Phase 5.
    return TriagedItem(
        crate=crate,
        function=v.get("function", ""),
        file=v.get("file", ""),
        line=v.get("line"),
        mnemonic=v.get("mnemonic", ""),
        triage_hint=v.get("triage_hint"),
        snippet=v.get("source_snippet"),
        exit_phase=5,
        verdict="needs_review",
        rationale="survived phases 1-4; needs source/caller review",
    )


def crate_label_from_filename(path: str) -> str:
    name = Path(path).stem
    if name.startswith("wild_"):
        name = name[5:]
    if name.endswith("_v3"):
        name = name[:-3]
    return name


def run(args) -> int:
    files = []
    for spec in args.result:
        files.extend(sorted(glob.glob(spec)))
    if not files:
        sys.stderr.write(f"no files matched: {args.result}\n")
        return 2

    all_items: list[TriagedItem] = []
    for path in files:
        crate = crate_label_from_filename(path)
        rep = json.loads(Path(path).read_text())
        # Triage every user warning -- not just the sample.
        warnings_user = [
            v for v in (rep.get("errors", []) + rep.get("warnings_sampled", []))
            if v.get("severity") in ("error", "warning")
        ]
        # We use the full clusters as the de-duped pool: every distinct
        # (file, function) cluster contributes its representative item.
        # If clusters are unavailable, fall back to warnings_sampled.
        clusters = rep.get("clusters_user_function") or []
        if clusters:
            pool = []
            for cl in clusters:
                pool.append({
                    "function": cl.get("function") or cl.get("representative_function") or "",
                    "file": cl.get("file") or cl.get("representative_file") or "",
                    "line": cl.get("representative_line"),
                    "mnemonic": "/".join(cl.get("mnemonics", [])),
                    "triage_hint": cl.get("triage_hint"),
                    "source_snippet": cl.get("representative_snippet"),
                    "severity": "warning",
                    "_cluster_count": cl.get("count", 1),
                })
        else:
            pool = warnings_user
        # Also include errors directly.
        pool = pool + rep.get("errors", [])
        for v in pool:
            all_items.append(triage_violation(crate, v))

    # Aggregate.
    from collections import Counter
    by_crate_phase: dict[str, Counter] = {}
    by_phase = Counter()
    by_verdict = Counter()
    for it in all_items:
        by_crate_phase.setdefault(it.crate, Counter())[it.exit_phase] += 1
        by_phase[it.exit_phase] += 1
        by_verdict[it.verdict] += 1

    # Print summary.
    print("=" * 78, file=sys.stderr)
    print(f"Waterfall triage of {len(all_items)} items across {len(files)} crates",
          file=sys.stderr)
    print("=" * 78, file=sys.stderr)
    print(f"\nPer-phase exit counts (lower phase = cheaper to dispatch):",
          file=sys.stderr)
    for p in (1, 2, 3, 4, 5):
        n = by_phase.get(p, 0)
        pct = (n / max(1, len(all_items))) * 100
        print(f"  Phase {p}: {n:>5}  ({pct:>5.1f}%)", file=sys.stderr)

    print(f"\nVerdicts:", file=sys.stderr)
    for v, n in by_verdict.most_common():
        print(f"  {v:<14} {n:>5}", file=sys.stderr)

    print(f"\nPer-crate breakdown:", file=sys.stderr)
    print(f"  {'crate':<32} {'P1':>5} {'P2':>5} {'P3':>5} {'P4':>5} {'P5':>5} {'total':>6}",
          file=sys.stderr)
    for crate in sorted(by_crate_phase):
        c = by_crate_phase[crate]
        total = sum(c.values())
        print(
            f"  {crate[:32]:<32} {c.get(1,0):>5} {c.get(2,0):>5} {c.get(3,0):>5} "
            f"{c.get(4,0):>5} {c.get(5,0):>5} {total:>6}",
            file=sys.stderr,
        )

    # Phase-5 items -- the pile that needs real review.
    phase5 = [it for it in all_items if it.exit_phase == 5]
    print(f"\nPhase 5 ({len(phase5)} items requiring source/caller review):",
          file=sys.stderr)
    for it in phase5:
        snip = it.snippet or []
        cited = (snip[len(snip) // 2] if snip else "").strip()
        print(
            f"  [{it.crate}] {it.function[:55]:<55} "
            f"{it.mnemonic:<10} | {cited[:80]}",
            file=sys.stderr,
        )

    out = {
        "n_items": len(all_items),
        "by_phase": dict(by_phase),
        "by_verdict": dict(by_verdict),
        "by_crate_phase": {k: dict(v) for k, v in by_crate_phase.items()},
        "phase5_items": [asdict(it) for it in phase5],
        "all_items": [asdict(it) for it in all_items],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2))
    print(f"\n  -> {args.out}", file=sys.stderr)
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--result", nargs="+", required=True, help="wild result JSON files (glob ok)")
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
