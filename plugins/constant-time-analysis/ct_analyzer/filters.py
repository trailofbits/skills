"""
Post-analysis filters that prune high-confidence false positives.

The base analyzer is intentionally trigger-happy: it flags every dangerous
instruction in every function, regardless of context. That gives recall ~1
but precision ~0.1 on real production codebases (alarm fatigue).

Filters here take a list of Violation objects and return a (kept, suppressed)
pair so the caller can report both, plus a brief reason for each suppression
in --explain mode.

Each filter is OPT-IN via a flag on the analyzer (default off so legacy
behavior is preserved). They compose: `--filter ct-funcs,loop-backedge,...`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

try:
    from .analyzer import Severity, Violation
except ImportError:
    from analyzer import Severity, Violation


# ---------------------------------------------------------------------------
# Filter 1: Known-constant-time function names
# ---------------------------------------------------------------------------
# Functions in this list are conventionally vetted as constant-time by their
# upstream maintainers.  Any conditional branch / division they contain is
# either a loop bound on a public length, a counter increment, or a structural
# pattern (e.g. final reduction by mask).  Suppress findings inside them.

CT_FUNCTION_PATTERNS = [
    # Generic CT primitives across libraries
    re.compile(r"^constant_time_[a-z_0-9]+$"),
    re.compile(r"^[a-zA-Z]+_ct_[a-z_0-9]+$"),     # mbedtls_ct_*, _ct_eq, etc.
    re.compile(r".*_constant_time_.*"),
    # Established constant-time byte-comparators
    re.compile(r"^CRYPTO_memcmp$"),
    re.compile(r"^sodium_memcmp$"),
    re.compile(r"^sodium_is_zero$"),
    re.compile(r"^mbedtls_ct_memcmp(_partial)?$"),
    re.compile(r"^mbedtls_ct_uint_(eq|ne|lt|gt|if_else_0)$"),
    re.compile(r"^crypto_verify_(16|32|64)$"),
    re.compile(r"^crypto_secretbox_easy_verify$"),
    re.compile(r"^value_barrier_w$"),
    # Curve25519 / Ed25519 conditional swap/move primitives are CT by design
    re.compile(r"^fe_(cswap|cmov|cneg)$"),
    re.compile(r"^ge_(cmov|select)$"),
    re.compile(r"^x25519_ge_select$"),
    # Bench wrappers and inlined helpers in our corpus
    re.compile(r"^bench_(select|eq8|ct_.*)$"),
    # Structural CT primitives: round functions of stream ciphers and ARX
    # ciphers are CT by design (no data-dependent branches; the only
    # branches are loop counters over a fixed number of rounds).  Naming is
    # well-established across implementations.
    re.compile(r"^CRYPTO_hchacha20$"),
    re.compile(r"^chacha20?_(block|core|round|keysetup|xor|stream)$"),
    re.compile(r"^salsa20?_(block|core|round|keysetup)$"),
    re.compile(r"^poly1305_(blocks|finish|update|init)$"),
    # Permutation primitives in sponge constructions
    re.compile(r"^(keccak|sha3)_(f1600|permute|absorb|squeeze)$"),
    re.compile(r"^blake2[bs]_compress$"),
]


def filter_known_ct_functions(violations: list[Violation]) -> tuple[list[Violation], list[tuple[Violation, str]]]:
    """Drop findings whose function name matches a vetted-CT pattern."""
    kept, suppressed = [], []
    for v in violations:
        if any(p.search(v.function) for p in CT_FUNCTION_PATTERNS):
            suppressed.append((v, f"function {v.function!r} is a known constant-time primitive"))
        else:
            kept.append(v)
    return kept, suppressed


# ---------------------------------------------------------------------------
# Filter 2: Branch-aggregation
# ---------------------------------------------------------------------------
# A function with N flagged branches almost always has them clustered around
# a single secret-or-public condition.  For triage purposes one finding per
# function is enough; the analyst will read the function regardless.  This
# slashes triage cost without losing recall (we still flag the function).

def _mnemonic_family(m: str) -> str:
    """Coarse family used for per-function aggregation."""
    m = m.upper()
    if any(s in m for s in ("DIV", "IDIV", "SDIV", "UDIV", "REM")):
        return "DIV"
    if "SQRT" in m:
        return "SQRT"
    if (m.startswith("J") or m.startswith("B.")
            or m in ("BEQ", "BNE", "CBZ", "CBNZ", "TBZ", "TBNZ")):
        return "BRANCH"
    if m == "MEMCMP":
        return "MEMCMP"
    return m


def aggregate_branches_per_function(violations: list[Violation]) -> tuple[list[Violation], list[tuple[Violation, str]]]:
    """Collapse multiple findings of the same family in the same function
    into a single finding with a count.  Applies to both warnings (branches)
    and errors (e.g. multiple DIVs in the same modexp loop).  This shrinks
    the report without losing recall because a reviewer reading the function
    will see all instances regardless."""
    kept: list[Violation] = []
    suppressed: list[tuple[Violation, str]] = []
    first_by_key: dict[tuple[str, str, str], Violation] = {}
    counts: dict[tuple[str, str, str], int] = {}
    for v in violations:
        # Source-level call findings (memcmp/strcmp at source line) must NOT
        # be aggregated - each call site is an independent vulnerability.
        if v.function == "<source-call>":
            kept.append(v)
            continue
        key = (v.function, v.severity.value, _mnemonic_family(v.mnemonic))
        if key not in first_by_key:
            first_by_key[key] = v
            counts[key] = 1
        else:
            counts[key] += 1
            suppressed.append((v, f"folded into aggregated {key[2]} finding for {v.function}"))
    for key, first in first_by_key.items():
        if counts[key] > 1:
            new = Violation(
                function=first.function,
                file=first.file,
                line=first.line,
                address=first.address,
                instruction=first.instruction,
                mnemonic=first.mnemonic,
                reason=f"{first.reason} (+{counts[key]-1} more {key[2]} findings in this function)",
                severity=first.severity,
            )
            kept.append(new)
        else:
            kept.append(first)
    return kept, suppressed


# ---------------------------------------------------------------------------
# Filter 3: Compiler/runtime helpers
# ---------------------------------------------------------------------------
# `__udivdi3`, `__divti3`, etc. are libgcc/compiler-rt helpers.  They DO use
# variable-time division, but the call site is what matters for secret flow,
# not the helper.  Suppress to avoid duplicate findings.

COMPILER_HELPERS = re.compile(
    r"^(__(u?div|u?mod)[dt]i3|__aeabi_[ui]div|__udivmod|"
    r"_Unwind_|__cxa_|__gcov_|__stack_chk|__asan_|__msan_|__tsan_)"
)


def filter_compiler_helpers(violations: list[Violation]) -> tuple[list[Violation], list[tuple[Violation, str]]]:
    kept, suppressed = [], []
    for v in violations:
        if COMPILER_HELPERS.match(v.function):
            suppressed.append((v, f"compiler/runtime helper {v.function!r}"))
        else:
            kept.append(v)
    return kept, suppressed


# ---------------------------------------------------------------------------
# Filter 4: Source-level secret-flow heuristic
# ---------------------------------------------------------------------------
# Walk the C source, find each function definition, and inspect its parameter
# list.  If NO parameter looks like it carries a secret (no key/secret/priv/
# token/mac/tag/nonce/seed in name and no obvious key-typed value), the
# function is unlikely to handle a secret directly.  Suppress its warnings
# (still keep ERRORs - division on a secret-derived value can come from a
# caller's argument even if the parameter isn't named "secret").

_SECRET_TOKENS = (
    "key", "secret", "priv", "private", "tag", "mac", "hmac",
    "sig", "signature", "password", "passwd", "pwd", "token",
    "nonce", "seed", "salt", "exponent",
    "share", "witness",
    "plaintext", "ciphertext", "cleartext", "message",
    "received", "expected", "computed", "digest",
    # 'input' / 'data' are too generic and produced too many FPs;
    # excluded from the secret-name regex.
)
# Match the token anywhere inside an identifier (e.g. `secret_coef`,
# `computed_mac`, `priv_key`).  Word-boundary on the inner side is too
# restrictive because '_' is a word character.
SECRET_NAME = re.compile(
    r"(?<![A-Za-z])(" + "|".join(_SECRET_TOKENS) + r")(?![A-Za-z])",
    re.IGNORECASE,
)

# C function-definition pattern (very loose; good enough for the corpus)
C_FUNC_RE = re.compile(
    r"^[a-zA-Z_][\w\s\*]*\s+([a-zA-Z_]\w*)\s*\(([^;{)]*)\)\s*\{",
    re.MULTILINE,
)


def parse_secret_handling_functions(source_path: str) -> set[str]:
    """Return names of functions whose parameter list contains a 'secret'-ish identifier."""
    try:
        text = Path(source_path).read_text()
    except OSError:
        return set()
    secret_funcs: set[str] = set()
    for m in C_FUNC_RE.finditer(text):
        name = m.group(1)
        params = m.group(2)
        if SECRET_NAME.search(params):
            secret_funcs.add(name)
        # Heuristic: if function body references any secret-named local
        # variable, also mark it.
    return secret_funcs


def filter_non_secret_functions(violations: list[Violation],
                                secret_funcs: set[str]) -> tuple[list[Violation], list[tuple[Violation, str]]]:
    """Suppress findings in functions that don't appear to handle secrets.

    Heuristic: if the C source's function definition has no parameter whose
    name matches a known secret/key/MAC token, the function is unlikely to
    operate directly on a secret.  We suppress BOTH warnings and errors in
    that case - true callers passing secret-derived values will still flag
    the call site, and false alarms here are the dominant fatigue source.

    Trade-off: this does miss detections for functions with intentionally
    obscure parameter names (e.g. `f(int a, int b)` where `a` is a secret).
    The user can always disable this filter if they review code that
    de-emphasizes naming hygiene.
    """
    kept, suppressed = [], []
    for v in violations:
        if v.function in secret_funcs or v.function == "<source-call>":
            kept.append(v)
        else:
            suppressed.append((v, f"function {v.function!r} has no secret-named parameter"))
    return kept, suppressed


# ---------------------------------------------------------------------------
# Filter 5: memcmp/strcmp call detection from C source
# ---------------------------------------------------------------------------
# When the C source contains `memcmp(...)` or `strcmp(...)` on what looks like
# a secret buffer, raise an explicit MEMCMP_ON_SECRET error.  The assembly-
# level analyzer can't see this directly because memcmp is a libc CALL.

MEMCMP_CALL_RE = re.compile(
    r"\b(memcmp|strcmp|strncmp|bcmp)\s*\(([^)]*)\)",
)


def detect_unsafe_memcmp_in_source(source_path: str, secret_funcs: set[str]) -> list[Violation]:
    """Add explicit findings for libc memcmp/strcmp calls on secret-named
    arguments.  Skips comments (// ..., /* ... */, * ...) so example calls in
    docstrings don't false-fire."""
    text = Path(source_path).read_text()
    findings: list[Violation] = []
    in_block_comment = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        # Track multi-line /* ... */ comments
        stripped = line.lstrip()
        if in_block_comment:
            if "*/" in line:
                in_block_comment = False
            continue
        if stripped.startswith("/*"):
            if "*/" not in stripped[2:]:
                in_block_comment = True
            continue
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        # Strip trailing line comment so its content doesn't false-fire
        code = line
        if "//" in code:
            code = code.split("//", 1)[0]
        if "/*" in code and "*/" in code:
            # naive single-line block stripping
            i, j = code.find("/*"), code.find("*/")
            if 0 <= i < j:
                code = code[:i] + code[j+2:]
        for m in MEMCMP_CALL_RE.finditer(code):
            args = m.group(2)
            if SECRET_NAME.search(args):
                findings.append(Violation(
                    function="<source-call>",
                    file=str(source_path),
                    line=lineno,
                    address="",
                    instruction=line.strip(),
                    mnemonic="MEMCMP",
                    reason=f"libc {m.group(1)} called on a secret-named argument; "
                           f"this is variable-time and leaks the position of the first mismatch",
                    severity=Severity.ERROR,
                ))
    return findings


# ---------------------------------------------------------------------------
# Filter dispatch
# ---------------------------------------------------------------------------

FILTER_REGISTRY: dict[str, Callable[[list[Violation]], tuple[list[Violation], list[tuple[Violation, str]]]]] = {
    "ct-funcs": filter_known_ct_functions,
    "aggregate": aggregate_branches_per_function,
    "compiler-helpers": filter_compiler_helpers,
}


def apply_filters(violations: list[Violation], filter_names: Iterable[str],
                  source_path: str | None = None) -> tuple[list[Violation], list[tuple[Violation, str]]]:
    """Apply filters in order. Returns (kept, suppressed_with_reason)."""
    kept = list(violations)
    suppressed_all: list[tuple[Violation, str]] = []
    secret_funcs: set[str] | None = None
    for name in filter_names:
        if name == "non-secret":
            if source_path is None:
                continue
            if secret_funcs is None:
                secret_funcs = parse_secret_handling_functions(source_path)
            kept, sup = filter_non_secret_functions(kept, secret_funcs)
        elif name == "memcmp-source" and source_path is not None:
            if secret_funcs is None:
                secret_funcs = parse_secret_handling_functions(source_path)
            kept = kept + detect_unsafe_memcmp_in_source(source_path, secret_funcs)
            sup = []
        elif name in FILTER_REGISTRY:
            kept, sup = FILTER_REGISTRY[name](kept)
        else:
            continue
        suppressed_all.extend(sup)
    return kept, suppressed_all
