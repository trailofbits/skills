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
    # --- v2: production-naming patterns ---
    # Discovered by triaging 84 wild findings across libsodium/BoringSSL/mbedTLS:
    # the dominant FP class is *protocol/serialization/setup* code, not crypto
    # operations on secrets. These regexes target the function-name conventions
    # that show up across all three libraries.
    #
    # ASN.1 / DER codec: format-driven, no secret-dependent control flow on
    # the SECRET; the branches are all about the public DER structure.
    re.compile(r"^i2[doc]_[A-Za-z0-9_]+$"),
    re.compile(r"^d2i_[A-Za-z0-9_]+(_fp)?$"),
    re.compile(r"^[A-Za-z0-9_]+_(marshal|unmarshal|parse|encode|decode|to_bytes|from_bytes|to_str|from_str|to_string)(_[a-z_]+)?$"),
    re.compile(r"^ASN1_[A-Za-z0-9_]+$"),
    re.compile(r"^X509_[A-Za-z0-9_]+$"),
    re.compile(r"^OID_[A-Za-z0-9_]+$"),
    re.compile(r"^pkcs(7|8|12)_[a-z_0-9]+$"),
    # OID lookup, name hashing for indexes
    re.compile(r"^[A-Za-z0-9_]+_get_oid_by_[a-z_]+$"),
    # Init / cleanup / alloc / free / dup / copy: setup code, public sizes
    re.compile(r"^[A-Za-z0-9_]+_(init|init_ex|cleanup|free|alloc|dup|copy|new|destroy|clear|reset)$"),
    re.compile(r"^[A-Za-z0-9_]+_(set|get|set_ex|get_ex|set0|get0|set1|get1)_[a-z_]+$"),
    # Protocol-level marshalling for ML-KEM / ML-DSA public keys (private-key
    # variants are NOT covered - only "public_key", "public_seed", etc.)
    re.compile(r"^BCM_[a-z0-9_]+_(marshal|unmarshal)_public_key$"),
    re.compile(r"^[A-Za-z0-9_]+_public[a-z_0-9]*$"),  # _public, _public_seed, ...
    # Stack and hash-table helpers - non-crypto containers
    re.compile(r"^sk_[a-zA-Z0-9_]+$"),
    re.compile(r"^OPENSSL_lh_[a-z_]+$"),
    re.compile(r"^lh_[a-zA-Z0-9_]+$"),
    re.compile(r"^_ZN4bssl(13|17|19|20|23)?OPENSSL_lh_[A-Za-z0-9_]+"),
    # I/O wrappers
    re.compile(r"^BIO_[a-zA-Z0-9_]+$"),
    re.compile(r"^DH_[a-zA-Z0-9_]+$"),
    re.compile(r"^DSA_(dup|dup_DH|free|new|print)[a-zA-Z0-9_]*$"),
    # Curve / group / cipher *setup* functions (precomp tables, key schedules
    # are handled below by the round/keysetup pattern)
    re.compile(r"^[a-zA-Z0-9_]+_(precomp|init_precomp|keysetup|key_schedule|key_setup|key_expansion|setup)$"),
    # Cipher-mode loop wrappers - the BLOCK ops they call do the actual CT
    # work; the wrapper just iterates over public block count
    re.compile(r"^[a-zA-Z0-9_]+_(crypt_ctr|crypt_cbc|crypt_ecb|crypt_ofb|crypt_xts|update|finish|cmac_update|cmac_finish|cmac_starts|cmac_ext)$"),
    re.compile(r"^[a-zA-Z0-9_]+_(starts|set_iv|update_ad|reset_state)$"),
    # KDF wrappers: cost params and output length are public
    re.compile(r"^[a-zA-Z0-9_]+_(pbkdf2|hkdf|hkdf_ext|pbkdf2_hmac|pbkdf2_hmac_ext|pbes2_ext|kdf|kdf_ext)$"),
    re.compile(r"^EVP_PBE_[a-z]+$"),
    re.compile(r"^HKDF_(extract|expand|derive)$"),
    # Hashing / sponge update (the squeeze function rate is public)
    re.compile(r"^[a-zA-Z0-9_]+_(absorb|squeeze|update|finish|finalize|process_block)$"),
    # mbedTLS-specific intentional-CT naming
    re.compile(r"^mbedtls_[a-z0-9_]+_ct$"),
    re.compile(r"^mbedtls_[a-z0-9_]+_cond_[a-z_]+$"),
    re.compile(r"^mbedtls_mpi_safe_[a-z_]+$"),
    re.compile(r"^mbedtls_mpi_core_[a-z_]+$"),
    # libsodium prefix conventions for round / setup / public ops
    re.compile(r"^_?sodium_[a-z0-9_]+_(round|key_schedule|invert_key_schedule[0-9]*|softaes|ctx)$"),
    re.compile(r"^_?sodium_(allocarray|pad|unpad|bin2[a-z]+|[a-z]+2bin|memzero|stackzero)$"),
    re.compile(r"^crypto_(verify_(16|32|64))$"),
    # Random uniform sampling: the public range is the divisor; the dividend
    # is rejection-sampled fresh randomness whose timing variation does not
    # reveal anything secret about the caller.
    re.compile(r"^randombytes_uniform$"),
    re.compile(r"^[a-zA-Z0-9_]+_uniform[0-9]*$"),
    # Public group element operations; secret-bearing ops are usually the
    # Montgomery ladder which we don't suppress
    re.compile(r"^ecp_(add_mixed|safe_invert_jac|mod_p[0-9]+|point_cmp|point_(read|write|init|free))$"),
    re.compile(r"^[a-zA-Z0-9_]+_points?_mul_public$"),
    # Rejection sampling on PUBLIC inputs (matrix A from rho in ML-DSA/ML-KEM
    # is derived from a public seed, not the secret signing key)
    re.compile(r"^_ZN5mldsa[0-9]+_GLOBAL__N_1[0-9]+scalar_uniform[A-Za-z0-9_]+$"),
    # Padding mode getters (NOT general "_padding" suffix - Lucky13's
    # `lucky13_validate_padding` is a real CT-violation function and must
    # NOT be silenced)
    re.compile(r"^get_(no|pkcs7|iso7816|zero|one_and_zeros)_padding$"),
    # CCM / GCM tag pre-computation (the actual CT MAC body is the inner
    # multiply, called from here; the wrapper itself iterates over public
    # block count)
    re.compile(r"^calc_tag_pre$"),
    re.compile(r"^[a-zA-Z0-9_]+_polyval_(nohw|hw)$"),
    # libsodium internal Ed25519 / Ristretto255 / X25519 byte-conversion -
    # all designed CT
    re.compile(r"^_?sodium_(ge25519|x25519|ristretto255)_[a-z_0-9]+$"),
    re.compile(r"^ge25519_[a-z_0-9]+$"),
    re.compile(r"^ristretto255_[a-z_0-9]+$"),
    # std::__rotate and friends - C++ template instantiations that are not
    # crypto code at all (relaxed: the mangled name has unbounded suffixes)
    re.compile(r"^_ZNSt\d+_?V?\d*[0-9_]*__(rotate|merge|sort|copy|move|fill|find)"),
    # Generic _check_ argument validators that DON'T do crypto themselves
    # (NB: not _validate_ - Lucky13's validate_padding is a real-CT function)
    re.compile(r"^[a-zA-Z0-9_]+_check_(arg|args|len|size|bounds|input|range|format)$"),
    # Resize / clear / move - allocator-class operations
    re.compile(r"^mbedtls_mpi_resize_clear$"),
    # OpenSSL/BoringSSL bignum helpers documented as variable-time-with-
    # public-divisor.  Source comments say so explicitly:
    #   "BN_div_word: callers must not pass secret divisors"
    #   "BN_div: variable-time"
    #   "bn_mod_u16_consttime: comment says p and d are public values"
    #   "BN_mod_exp_mont_word: divisor is the small public modulus word"
    #   "BN_mod_exp_mont_consttime: bound checks INT_MAX/sizeof, never the secret"
    re.compile(r"^BN_div(_word)?(\.part\.[0-9]+)?$"),
    re.compile(r"^BN_mod_exp_mont_(word|consttime)$"),
    re.compile(r"^_ZN4bssl20bn_mod_u16_consttime[A-Za-z0-9_]*"),
    # PKCS#12 KDF: iteration count and output length are public parameters
    re.compile(r"^_ZN4bssl14pkcs12_key_gen"),
    # Ipv4/v6 codec - bin <-> dotted-decimal, not crypto
    re.compile(r"^ip_(write|read)_(num|str|addr)$"),
    # Argon2 / scrypt fill-segment workhorses: the DIV is on cost params
    # (lanes, passes) which are public Argon2/scrypt configuration knobs.
    # If the password is the secret, the loop iteration count is a public
    # function of the cost params, not of the password.
    re.compile(r"^_?sodium_argon2_(fill_segment|ctx)(_(ref|sse|ssse3|avx2|avx512f))?$"),
    re.compile(r"^_?sodium_(escrypt_kdf|escrypt_kdf_nosse|escrypt_kdf_sse|pickparams)$"),
    re.compile(r"^pickparams$"),
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

# C function-definition pattern (very loose; good enough for the corpus).
# Allows ONE-LINE-ONLY signatures - multi-line ones are handled by
# _build_function_ranges via _C_FUNC_HEADER which is opening-only.
C_FUNC_RE = re.compile(
    r"^[a-zA-Z_][\w\s\*]*\s+([a-zA-Z_]\w*)\s*\(([^;{)]*)\)\s*\{",
    re.MULTILINE,
)
# Pattern for the *start* of a function header (multi-line signatures
# common in mbedTLS / BoringSSL); we then scan forward for the {
_C_FUNC_HEADER = re.compile(
    r"^(?:static\s+|extern\s+|inline\s+|__attribute__\([^)]*\)\s+|"
    r"const\s+|signed\s+|unsigned\s+|volatile\s+)*"
    r"[a-zA-Z_][\w\s\*]*\s+([a-zA-Z_]\w*)\s*\("
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


# Names indicating self-test / unit-test scaffolding within production .c
# files (mbedTLS, BoringSSL, libsodium all bundle these gated by macros).
# memcmp() inside them compares against test vectors, not exploitable
# secrets, so suppress.
_TEST_FUNC_RE = re.compile(
    r"^(test_|.*_test$|.*_self_test$|.*_test_[a-z_]+|"
    r".*_test_helper$|.*_unit_test|.*_test_internal|"
    r".*_known_answer|.*_kat|.*_check_test|"
    r"check_.*_test$|run_test.*|.*_self_check$)",
    re.IGNORECASE,
)


def _build_function_ranges(text: str) -> list[tuple[int, int, str]]:
    """Return [(start_line, end_line, func_name), ...] by tracking braces.
    Handles multi-line function signatures (signature open paren on one line,
    matching brace several lines later)."""
    ranges: list[tuple[int, int, str]] = []
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        m = _C_FUNC_HEADER.match(lines[i])
        if not m:
            i += 1
            continue
        # Scan for opening '{'; bail if we hit a ';' first (it's a prototype)
        name = m.group(1)
        start = i + 1
        j = i
        found_open = False
        while j < n and j < i + 30:           # cap multi-line search
            if ";" in lines[j] and "{" not in lines[j]:
                break                          # prototype, not definition
            if "{" in lines[j]:
                found_open = True
                break
            j += 1
        if not found_open:
            i += 1
            continue
        # Now track brace depth from j onwards until depth returns to 0
        # after at least one `{` has been seen.
        depth = 0
        end = j + 1
        seen_open = False
        while j < n:
            opens = lines[j].count("{")
            closes = lines[j].count("}")
            depth += opens - closes
            if opens > 0:
                seen_open = True
            if seen_open and depth <= 0:
                end = j + 1
                break
            j += 1
        else:
            end = n  # ran off end of file without closing - record what we have
        ranges.append((start, end, name))
        i = max(end, i + 1)            # never go backwards
    return ranges


def _enclosing_function(ranges: list[tuple[int, int, str]], lineno: int) -> str | None:
    for start, end, name in ranges:
        if start <= lineno <= end:
            return name
    return None


def detect_unsafe_memcmp_in_source(source_path: str, secret_funcs: set[str]) -> list[Violation]:
    """Add explicit findings for libc memcmp/strcmp calls on secret-named
    arguments.  Skips comments (// ..., /* ... */, * ...) so example calls in
    docstrings don't false-fire.  Skips calls whose enclosing function looks
    like a self-test / known-answer-test scaffold."""
    text = Path(source_path).read_text()
    func_ranges = _build_function_ranges(text)
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
            if not SECRET_NAME.search(args):
                continue
            enclosing = _enclosing_function(func_ranges, lineno)
            if enclosing and _TEST_FUNC_RE.match(enclosing):
                continue            # self-test / KAT scaffold, not production
            findings.append(Violation(
                function=enclosing or "<source-call>",
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

# ---------------------------------------------------------------------------
# Filter 6 (v2): Divisor-source heuristic
# ---------------------------------------------------------------------------
# Most "wild" DIV/IDIV findings on production crypto code are on PUBLIC
# sizing parameters: % blocksize, INT_MAX / sizeof(...), hash-table modulo,
# count*size overflow checks. The divisor in those cases comes from an
# immediate constant (`mov $K, %reg`) or a rip-relative .rodata load
# (`mov disp(%rip), %reg`) just before the DIV. If we can see that pattern
# in the preceding instructions, we're confident the divisor is public.
#
# Conservative: we only suppress when we POSITIVELY identify the immediate-
# load pattern. Unknown source -> keep the finding.

# AT&T syntax: divq %r13   (operand is the divisor); for IDIV the dividend
# is the implicit RAX:RDX, the operand is the divisor.
_DIV_OPERAND = re.compile(r"^\s*[ui]?div[lqwb]?\s+([^\s,]+)")
# Match `mov $0x10, %rcx`  or `mov $K, %reg` or `mov disp(%rip), %reg`.
_LOAD_IMM = re.compile(r"^\s*(mov[lqwb]?|movabs[qb]?)\s+\$0?[xX]?[0-9a-fA-F]+\s*,\s*([^\s,]+)$")
_LOAD_RIP = re.compile(r"^\s*mov[lqwb]?\s+[-+]?\w*\(.*%rip.*\)\s*,\s*([^\s,]+)$")
# `xor %eax,%eax` zeroes a register - equivalent to immediate 0 load.
_XOR_SAME = re.compile(r"^\s*xor[lqwb]?\s+([^\s,]+)\s*,\s*\1\s*$")
# `and $imm, %reg` - the result is bounded by an immediate mask
_AND_IMM = re.compile(r"^\s*and[lqwb]?\s+\$0?[xX]?[0-9a-fA-F]+\s*,\s*([^\s,]+)$")


def _normalize_reg(operand: str) -> str:
    """Normalize register name across width variants: rax/eax/ax/al -> rax."""
    operand = operand.strip().lstrip("%")
    # Handle x86 width suffixes; this is heuristic, not canonical
    aliases = {
        "rax": "rax", "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
        "rbx": "rbx", "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
        "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
        "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
        "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
        "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
        "rbp": "rbp", "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
        "rsp": "rsp", "esp": "rsp", "sp": "rsp", "spl": "rsp",
    }
    for n in range(8, 16):
        for suffix in ("", "d", "w", "b"):
            aliases[f"r{n}{suffix}"] = f"r{n}"
    return aliases.get(operand, operand)


def filter_div_with_public_divisor(violations: list[Violation]) -> tuple[list[Violation], list[tuple[Violation, str]]]:
    """Suppress DIV/IDIV findings where context_before shows the divisor was
    just loaded from an immediate or rip-relative .rodata constant. These
    are public sizing-parameter divisions (% blocksize, INT_MAX / sizeof,
    hash-table modulo, etc.) - the dominant FP class on production code."""
    kept, suppressed = [], []
    for v in violations:
        m_div = _DIV_OPERAND.search(v.instruction)
        if not m_div or not v.context_before:
            kept.append(v)
            continue
        divisor = _normalize_reg(m_div.group(1))
        # Walk backwards from the most recent preceding instruction
        public_source = None
        for prev in reversed(v.context_before):
            if (m := _LOAD_IMM.search(prev)) and _normalize_reg(m.group(2)) == divisor:
                public_source = "immediate"
                break
            if (m := _LOAD_RIP.search(prev)) and _normalize_reg(m.group(1)) == divisor:
                public_source = "rip-relative"
                break
            if (m := _XOR_SAME.search(prev)) and _normalize_reg(m.group(1)) == divisor:
                public_source = "zero"
                break
            if (m := _AND_IMM.search(prev)) and _normalize_reg(m.group(1)) == divisor:
                public_source = "and-immediate"
                break
            # If the divisor was redefined by some other instruction, stop -
            # we can't tell where it came from.
            if re.search(rf"\s*([a-z]+)\s+[^,]*,\s*%?{re.escape(divisor.split(']')[0])}\s*$", prev):
                break
            # Also stop if we see a call - aliasing through ABI
            if re.search(r"^\s*call\s", prev):
                break
        if public_source:
            suppressed.append((v, f"divisor traces to {public_source} immediately preceding"))
        else:
            kept.append(v)
    return kept, suppressed


# ---------------------------------------------------------------------------
# Filter 7 (v2): Loop back-edge heuristic
# ---------------------------------------------------------------------------
# A conditional branch whose target address is *behind* the branch is a
# loop back-edge: the loop counter exited the body and we're re-entering.
# Counters in compiled crypto code are almost always public (block index,
# limb index, round number). When we can see the target address in the
# instruction text and it's < the branch's address, suppress.

_BR_TARGET = re.compile(r"^\s*[jb][a-z.]*\s+([0-9a-fA-F]+)\s*<")  # `je 1234 <foo+0x10>`
_INSN_ADDR = re.compile(r"^\s*([0-9a-fA-F]+):")


def filter_loop_backedges(violations: list[Violation]) -> tuple[list[Violation], list[tuple[Violation, str]]]:
    kept, suppressed = [], []
    for v in violations:
        if v.severity != Severity.WARNING:
            kept.append(v)
            continue
        m_t = _BR_TARGET.search(v.instruction)
        m_a = _INSN_ADDR.search(v.instruction)
        if not (m_t and m_a):
            kept.append(v)
            continue
        try:
            tgt = int(m_t.group(1), 16)
            cur = int(m_a.group(1), 16)
        except ValueError:
            kept.append(v)
            continue
        # Backward branch with small displacement (< 1KB) = loop back-edge
        if 0 < cur - tgt < 1024:
            suppressed.append((v, f"backward branch -{cur - tgt:#x} bytes (loop back-edge)"))
        else:
            kept.append(v)
    return kept, suppressed


FILTER_REGISTRY: dict[str, Callable[[list[Violation]], tuple[list[Violation], list[tuple[Violation, str]]]]] = {
    "ct-funcs": filter_known_ct_functions,
    "aggregate": aggregate_branches_per_function,
    "compiler-helpers": filter_compiler_helpers,
    "div-public": filter_div_with_public_divisor,
    "loop-backedge": filter_loop_backedges,
}


def apply_filters(violations: list[Violation], filter_names: Iterable[str],
                  source_path: str | None = None) -> tuple[list[Violation], list[tuple[Violation, str]]]:
    """Apply filters in order. Returns (kept, suppressed_with_reason).

    Per-finding source attribution: if source_path is None but individual
    Violation objects carry a .file attribute (populated by the parser
    from `objdump -l` line markers), the source-level filters use the
    finding's own .file.  This lets the wild-mode runner exploit DWARF
    debug info from -g builds without forcing every finding through the
    same source path.
    """
    kept = list(violations)
    suppressed_all: list[tuple[Violation, str]] = []
    secret_funcs_by_file: dict[str, set[str]] = {}
    if source_path:
        secret_funcs_by_file[source_path] = parse_secret_handling_functions(source_path)

    def _secret_funcs_for(v: Violation) -> set[str] | None:
        path = source_path or v.file
        if not path or not Path(path).exists():
            return None
        if path not in secret_funcs_by_file:
            secret_funcs_by_file[path] = parse_secret_handling_functions(path)
        return secret_funcs_by_file[path]

    for name in filter_names:
        if name == "non-secret":
            # Only suppress WARNINGS in non-secret-named functions.  Errors
            # (DIV/IDIV/SQRT) stay because they may be reachable from a
            # secret-handling caller even when the immediate function has
            # only public-looking params - mbedtls_mpi_mod_int(r, A, b) is
            # the canonical case: documented variable-time helper, called
            # during RSA prime-gen sieving where A is the secret candidate.
            new_kept, sup = [], []
            for v in kept:
                if v.severity != Severity.WARNING:
                    new_kept.append(v)
                    continue
                sf = _secret_funcs_for(v)
                if sf is None:
                    new_kept.append(v)        # unknown source = keep
                    continue
                if v.function in sf or v.function == "<source-call>":
                    new_kept.append(v)
                else:
                    sup.append((v, f"warning in {v.function!r} has no secret-named parameter (source: {v.file})"))
            kept = new_kept
        elif name == "memcmp-source":
            # Scan each unique source file referenced by findings (or the
            # one global source_path).
            sources_to_scan: set[str] = set()
            if source_path:
                sources_to_scan.add(source_path)
            for v in kept:
                if v.file and Path(v.file).exists():
                    sources_to_scan.add(v.file)
            extra: list[Violation] = []
            for sp in sources_to_scan:
                sf = secret_funcs_by_file.setdefault(
                    sp, parse_secret_handling_functions(sp))
                extra.extend(detect_unsafe_memcmp_in_source(sp, sf))
            kept = kept + extra
            sup = []
        elif name in FILTER_REGISTRY:
            kept, sup = FILTER_REGISTRY[name](kept)
        else:
            continue
        suppressed_all.extend(sup)
    return kept, suppressed_all
