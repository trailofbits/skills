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

    # ----------------------------------------------------------------------
    # Go-language patterns (mirror of the C/C++ block above).
    #
    # Go symbols in disassembly use the full package path with slashes,
    # plus dotted method-receiver syntax: e.g.
    #     crypto/subtle.ConstantTimeCompare
    #     crypto/sha256.(*digest).Write
    #     crypto/internal/fips140/mlkem.fieldReduceOnce
    # We anchor each regex with the package path so we don't accidentally
    # match a C symbol of the same shape.
    # ----------------------------------------------------------------------
    # crypto/subtle: the universal CT vocabulary in Go. Anything inside
    # this package is hand-verified constant-time by the stdlib team.
    re.compile(r"^crypto/subtle\.\w+$"),
    re.compile(r"^crypto/subtle\.\(\*\w+\)\.\w+$"),
    # FIPS 140 module: Go 1.24+ ships an isolated, hand-CT'd implementation
    # of the FIPS algorithms. Symbols all live under crypto/internal/fips140.
    re.compile(r"^crypto/internal/fips140(/[\w/]+)?\.\w+$"),
    re.compile(r"^crypto/internal/fips140(/[\w/]+)?\.\(\*\w+\)\.\w+$"),
    # Curve25519 and edwards25519 internal: by-design CT, used in TLS,
    # x509 cert validation, and ed25519 signing.
    re.compile(r"^crypto/internal/edwards25519(/\w+)?\.\w+$"),
    re.compile(r"^crypto/internal/edwards25519(/\w+)?\.\(\*\w+\)\.\w+$"),
    re.compile(r"^crypto/ecdh\.\w+$"),
    re.compile(r"^crypto/ecdh\.\(\*\w+\)\.\w+$"),
    # NIST curves: CT-coded P-224/256/384/521 implementations.
    re.compile(r"^crypto/internal/nistec(/[\w/]+)?\.\w+$"),
    re.compile(r"^crypto/internal/nistec(/[\w/]+)?\.\(\*\w+\)\.\w+$"),
    # x/crypto curves (older paths still used in production).
    re.compile(r"^golang\.org/x/crypto/curve25519(/[\w/]+)?\.\w+$"),
    re.compile(r"^golang\.org/x/crypto/curve25519(/[\w/]+)?\.\(\*\w+\)\.\w+$"),
    re.compile(r"^golang\.org/x/crypto/internal/poly1305\.\w+$"),
    re.compile(r"^golang\.org/x/crypto/internal/poly1305\.\(\*\w+\)\.\w+$"),
    re.compile(r"^golang\.org/x/crypto/chacha20(/\w+)?\.\w+$"),
    re.compile(r"^golang\.org/x/crypto/chacha20(/\w+)?\.\(\*\w+\)\.\w+$"),
    re.compile(r"^golang\.org/x/crypto/chacha20poly1305\.\w+$"),
    re.compile(r"^golang\.org/x/crypto/chacha20poly1305\.\(\*\w+\)\.\w+$"),
    re.compile(r"^golang\.org/x/crypto/salsa20(/\w+)?\.\w+$"),
    # crypto/cipher: stream/block-mode wrappers. They iterate over public
    # block counts and dispatch the underlying cipher; the cipher itself
    # is its own package. The wrappers are CT.
    re.compile(r"^crypto/cipher\.\w+$"),
    re.compile(r"^crypto/cipher\.\(\*\w+\)\.\w+$"),
    # Hash function packages: SHA-2 family is ARX, no data branches, branch
    # at block-boundary is a public byte-counter.
    re.compile(r"^crypto/sha(1|256|512|3)\.\w+$"),
    re.compile(r"^crypto/sha(1|256|512|3)\.\(\*\w+\)\.\w+$"),
    re.compile(r"^crypto/hmac\.\w+$"),
    re.compile(r"^crypto/hmac\.\(\*\w+\)\.\w+$"),
    re.compile(r"^golang\.org/x/crypto/blake2[bs]\.\w+$"),
    re.compile(r"^golang\.org/x/crypto/blake2[bs]\.\(\*\w+\)\.\w+$"),
    # KDF wrappers: HKDF / HMAC iteration count is on a public output length.
    re.compile(r"^golang\.org/x/crypto/hkdf\.\w+$"),
    re.compile(r"^golang\.org/x/crypto/pbkdf2\.\w+$"),
    re.compile(r"^golang\.org/x/crypto/argon2\.\w+$"),
    re.compile(r"^golang\.org/x/crypto/scrypt\.\w+$"),
    # Signature schemes (everything past the call into the scalar mul is
    # in nistec / edwards25519, which we already allow above).
    re.compile(r"^crypto/ed25519\.\w+$"),
    re.compile(r"^crypto/ed25519\.\(\*\w+\)\.\w+$"),
    re.compile(r"^crypto/ecdsa\.\w+$"),
    re.compile(r"^crypto/ecdsa\.\(\*\w+\)\.\w+$"),
    re.compile(r"^crypto/mlkem\.\w+$"),
    re.compile(r"^crypto/mlkem\.\(\*\w+\)\.\w+$"),
    # CIRCL: Cloudflare's research crypto library. The kem/sign/dh packages
    # are all CT-vetted; only their internal NTT / poly helpers might fail.
    re.compile(r"^github\.com/cloudflare/circl/(kem|sign|dh|hpke|oprf|secretsharing)/[\w/]+\.\w+$"),
    re.compile(r"^github\.com/cloudflare/circl/(kem|sign|dh|hpke|oprf|secretsharing)/[\w/]+\.\(\*\w+\)\.\w+$"),
    re.compile(r"^github\.com/cloudflare/circl/(internal|math)/[\w/]+\.\w+$"),
    re.compile(r"^github\.com/cloudflare/circl/(internal|math)/[\w/]+\.\(\*\w+\)\.\w+$"),
    # Go runtime: the gc / scheduler / memequal / map ops have data-dependent
    # branches by design but DON'T process user secrets. They show up in
    # disassembly because every Go program statically links the runtime.
    re.compile(r"^runtime\.\w+$"),
    re.compile(r"^runtime/internal/[\w/]+\.\w+$"),
    re.compile(r"^internal/[\w/]+\.\w+$"),
    # Generic Go method receivers on common stdlib container types
    re.compile(r"^(bytes|bufio|fmt|sort|strings|strconv|errors|sync|sync/atomic)\.\w+$"),
    re.compile(r"^(bytes|bufio|fmt|sort|strings|strconv|errors|sync|sync/atomic)\.\(\*\w+\)\.\w+$"),
    # Encoding wrappers (DER/PEM/JSON): structurally driven by public format
    re.compile(r"^encoding/[\w/]+\.\w+$"),
    re.compile(r"^encoding/[\w/]+\.\(\*\w+\)\.\w+$"),
    re.compile(r"^crypto/x509(/[\w/]+)?\.\w+$"),
    re.compile(r"^crypto/x509(/[\w/]+)?\.\(\*\w+\)\.\w+$"),
    # Random source: rejection sampling on uniform output is FIPS-acceptable.
    re.compile(r"^crypto/rand\.\w+$"),
    re.compile(r"^crypto/rand\.\(\*\w+\)\.\w+$"),
    # Stack-growth helper inside every Go function prologue. The CMPQ/JLS
    # pair compares SP against runtime metadata - never user data.
    re.compile(r"^runtime\.morestack(_noctxt)?$"),
    re.compile(r"^runtime\.deferreturn$"),
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
    will see all instances regardless.

    Cross-family fold: when a function has at least one DIV-class ERROR,
    we also fold its BRANCH-class warnings into the DIV finding. The Go
    gc compiler implements signed `/` as `cmp; jne; cdq; idiv` -- the
    sign-check JNE is a compiler-emitted branch that the same IDIV
    finding already covers from a reviewer's standpoint."""
    kept: list[Violation] = []
    suppressed: list[tuple[Violation, str]] = []
    first_by_key: dict[tuple[str, str, str], Violation] = {}
    counts: dict[tuple[str, str, str], int] = {}

    # Pass 1: collect (function, line) pairs that have a DIV-class error.
    # The cross-family fold targets the BRANCH warnings the Go signed-
    # divide idiom emits IMMEDIATELY around each IDIV (`cmp; jne; cdq;
    # idiv`) -- those branches share the source line of the divide.
    # We do NOT fold branches at other lines in the function (e.g.
    # `if exp_secret & 1` in rsa_squareandmultiply, which is a real
    # secret-bit branch on a different line from the % m).
    div_lines_per_func: dict[str, set[int]] = {}
    for v in violations:
        if v.severity == Severity.ERROR and _mnemonic_family(v.mnemonic) == "DIV":
            div_lines_per_func.setdefault(v.function, set()).add(v.line or -1)

    for v in violations:
        if v.function == "<source-call>":
            kept.append(v)
            continue
        # Cross-family fold: only when the warning's line matches an
        # existing DIV finding's line in the same function.
        div_lines = div_lines_per_func.get(v.function, set())
        if (v.severity == Severity.WARNING
                and _mnemonic_family(v.mnemonic) == "BRANCH"
                and v.line in div_lines):
            suppressed.append((
                v,
                f"folded into same-line DIV finding for {v.function} "
                f"(signed-divide bookkeeping branch)",
            ))
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
    if _looks_like_go(source_path):
        return _parse_go_secret_funcs(text)
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

# ---------------------------------------------------------------------------
# Go-source helpers
# ---------------------------------------------------------------------------
# Go function signatures: `func Name(params)` with optional method receiver
# `func (r *Type) Name(params)`. Parameter names always precede their type.
# Multi-line signatures are common in stdlib code.
_GO_FUNC_HEADER = re.compile(
    r"^\s*func\s+(?:\(\s*\w+\s+[*\w.]+\s*\)\s+)?(\w+)\s*\("
)
# bytes.Equal / bytes.Compare are documented as variable-time (the runtime
# memequal_varlen helper has an early-exit fast path). They're the Go
# analog of memcmp/strcmp at the source level.
GO_MEMCMP_CALL_RE = re.compile(
    r"\b(bytes\.Equal|bytes\.Compare|"
    r"runtime\.memequal(?:_varlen)?|"
    r"subtle\.WithDataIndependentTiming)\s*\(([^)]*)\)"
)


def _looks_like_go(source_path: str) -> bool:
    return source_path.endswith(".go")


def _go_params_have_secret(params: str) -> bool:
    """Permissive secret-param check for Go: case-insensitive substring on
    each token. Go params follow camelCase so the C-side word-boundary
    regex (SECRET_NAME) misses suffixes like `receivedMAC`. We accept a
    higher false-secret-match rate (more functions kept under non-secret)
    in exchange for keeping recall on real CT bugs."""
    p = params.lower()
    return any(tok in p for tok in _SECRET_TOKENS)


def _parse_go_secret_funcs(text: str) -> set[str]:
    """Return Go function names whose param list contains a secret-named
    identifier. Stores both the bare name and the canonical Go FQN form
    (`main.<name>`) so the non-secret filter matches violations whose
    function field carries the package prefix."""
    secret_funcs: set[str] = set()
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = _GO_FUNC_HEADER.match(line)
        if not m:
            continue
        name = m.group(1)
        # Capture params spanning to the matching `)` (up to 8 lines)
        params = ""
        depth = 0
        captured = False
        for j in range(i, min(i + 8, len(lines))):
            for ch in lines[j]:
                if ch == "(":
                    depth += 1
                    if depth == 1:
                        continue
                if ch == ")":
                    depth -= 1
                    if depth == 0:
                        captured = True
                        break
                if depth >= 1:
                    params += ch
            if captured:
                break
        if _go_params_have_secret(params):
            secret_funcs.add(name)
            # Add common Go FQN variants the disassembler emits
            secret_funcs.add(f"main.{name}")
    return secret_funcs


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


def _build_go_function_ranges(text: str) -> list[tuple[int, int, str]]:
    """Go-aware version of _build_function_ranges.
    Tracks `func Name(...)` openings and the matching closing brace at
    column 0 (Go style). Method receivers ``func (r *T) Name(...)`` count
    too.  Brace tracking handles inline closures defined inside the body."""
    ranges: list[tuple[int, int, str]] = []
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        m = _GO_FUNC_HEADER.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        start = i + 1
        # Walk forward until we find the body's opening `{`. Allow up to
        # ~10 lines for multi-line signatures.
        j = i
        while j < n and j < i + 12 and "{" not in lines[j]:
            j += 1
        if j >= n:
            i += 1
            continue
        # Track brace depth from j onward.
        depth = 0
        end = j + 1
        seen_open = False
        for k in range(j, n):
            depth += lines[k].count("{") - lines[k].count("}")
            if not seen_open and "{" in lines[k]:
                seen_open = True
            if seen_open and depth <= 0:
                end = k + 1
                break
        else:
            end = n
        ranges.append((start, end, name))
        i = max(end, i + 1)
    return ranges


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
    if _looks_like_go(str(source_path)):
        func_ranges = _build_go_function_ranges(text)
    else:
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
        # Pick the call regex appropriate for this language. The Go regex
        # also catches the C-style memcmp/strcmp because Go's cgo wrappers
        # often forward the same names. Go uses a permissive substring
        # check on the args because camelCase parameter names like
        # `receivedMAC` don't satisfy the C-style word-boundary regex.
        is_go = _looks_like_go(str(source_path))
        if is_go:
            secret_check = _go_params_have_secret
            call_regexes = (GO_MEMCMP_CALL_RE, MEMCMP_CALL_RE)
        else:
            secret_check = lambda s: bool(SECRET_NAME.search(s))
            call_regexes = (MEMCMP_CALL_RE,)
        for call_re in call_regexes:
            for m in call_re.finditer(code):
                args = m.group(2)
                if not secret_check(args):
                    continue
                enclosing = _enclosing_function(func_ranges, lineno)
                if enclosing and _TEST_FUNC_RE.match(enclosing):
                    continue
                fn_name = m.group(1)
                kind = (
                    f"{fn_name} on a secret-named argument; this is variable-"
                    f"time at the runtime level and leaks the position of "
                    f"the first mismatch"
                )
                findings.append(Violation(
                    function=enclosing or "<source-call>",
                    file=str(source_path),
                    line=lineno,
                    address="",
                    instruction=line.strip(),
                    mnemonic="MEMCMP",
                    reason=kind,
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

# Go's gc -S format is different: branch lines look like
#     0x0024 00036 (file.go:18) JGE 41
# where 41 is the *decimal* offset within the function, and the
# instruction's own offset is the second column ("00036"). So a backward
# branch is one where the target int < the instruction's int offset.
_GO_BR = re.compile(
    r"^\s*0x[0-9a-fA-F]+\s+(\d+)\s+\([^)]+\)\s+[JB][A-Z.]+\s+(\d+)\s*$"
)


def filter_loop_backedges(violations: list[Violation]) -> tuple[list[Violation], list[tuple[Violation, str]]]:
    kept, suppressed = [], []
    for v in violations:
        if v.severity != Severity.WARNING:
            kept.append(v)
            continue
        # Try the Go gc-S format first (decimal offsets), then objdump's
        # hex-with-symbol format.
        m_go = _GO_BR.match(v.instruction)
        if m_go:
            try:
                cur = int(m_go.group(1))
                tgt = int(m_go.group(2))
            except ValueError:
                kept.append(v)
                continue
            if 0 < cur - tgt < 1024:
                suppressed.append((v, f"backward Go branch -{cur - tgt} (loop back-edge)"))
                continue
            # Forward branch in Go format: still keep (could be data branch).
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
        if 0 < cur - tgt < 1024:
            suppressed.append((v, f"backward branch -{cur - tgt:#x} bytes (loop back-edge)"))
        else:
            kept.append(v)
    return kept, suppressed


# ---------------------------------------------------------------------------
# Filter 8 (Go-only): panic-helper bounds-check pairing
# ---------------------------------------------------------------------------
# Go's gc compiler implements `slice[i]` as `cmp; jcc <ok>; <panic>`, where
# the panic block calls one of `runtime.panicIndex`, `runtime.panicSlice*`,
# `runtime.panicshift`, etc. The compared values are always public Go
# runtime metadata (slice length, capacity, shift amount), never secret.
# When we see a CALL to one of these helpers in the captured context_after
# of a conditional branch, we suppress the branch.

GO_PANIC_HELPERS = (
    "runtime.panicIndex", "runtime.panicIndexU",
    "runtime.panicSlice", "runtime.panicSliceB", "runtime.panicSliceBU",
    "runtime.panicSliceAlen", "runtime.panicSliceAlenU",
    "runtime.panicSliceAcap", "runtime.panicSliceAcapU",
    "runtime.panicSliceConvert",
    "runtime.panicshift", "runtime.panicdivide",
    "runtime.goPanicIndex", "runtime.goPanicSlice3Alen",
    "runtime.goPanicSlice3B",
)
_GO_PANIC_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(p) for p in GO_PANIC_HELPERS) + r")\b"
)


def filter_go_bounds_checks(violations: list[Violation]) -> tuple[list[Violation], list[tuple[Violation, str]]]:
    """Suppress conditional-branch warnings tagged by the Go parser as
    bounds-check candidates (the parser tags the reason text with the
    sentinel '[BOUNDS_CHECK]' when either the branch target or its
    fall-through reaches a panic-block address)."""
    kept, suppressed = [], []
    for v in violations:
        if v.severity != Severity.WARNING:
            kept.append(v)
            continue
        # Inline-detected bounds check via the parser's sentinel
        if "[BOUNDS_CHECK]" in v.reason:
            v.reason = v.reason.replace(" [BOUNDS_CHECK]", "")
            suppressed.append((v, "Go panic-block target (slice/index/shift bounds check)"))
            continue
        # Fallback: context_after window contains a panic-helper CALL.
        target_block = "\n".join(v.context_after) if v.context_after else ""
        if _GO_PANIC_RE.search(target_block):
            suppressed.append((v, "branch's fall-through targets a Go panic helper"))
        else:
            kept.append(v)
    return kept, suppressed


# ---------------------------------------------------------------------------
# Filter 9 (Go-only): stack-grow check at function prologue
# ---------------------------------------------------------------------------
# Every Go function emits `CMPQ SP, 16(R14); JLS morestack` at offset 0. The
# JLS warning is on a public runtime invariant (stack overflow). Suppress
# any warning whose address is 0 (function prologue) and whose source line
# matches a `func ` declaration.

def filter_go_stack_grow(violations: list[Violation]) -> tuple[list[Violation], list[tuple[Violation, str]]]:
    """Suppress branches Go emits at every function prologue. The pattern is
    `CMPQ SP, 16(R14); JLS morestack` for amd64 (and the analogous SUB/CMP
    sequence on arm64). Two heuristics:

    1. The branch's source line starts with `func ` or `func(`. This
       catches the typical case where the prologue branch's DWARF entry
       points back at the function declaration line.
    2. The branch's source line is 1. The gc compiler attributes
       prologue checks of inlined / generated functions to line 1 of
       the file (which is typically a `package` declaration, never a
       branch in real source). Anything reporting at L1 of a Go file
       is a structural artefact, not a data-dependent branch."""
    kept, suppressed = [], []
    for v in violations:
        if v.severity != Severity.WARNING:
            kept.append(v)
            continue
        # Compiler-generated dispatch wrappers come back with the gc
        # marker `<autogenerated>` instead of a path. They're never real
        # source -- always a stack-grow check at the top of an
        # auto-emitted function.
        if v.file == "<autogenerated>":
            suppressed.append((v, "Go compiler-generated wrapper (autogenerated)"))
            continue
        if not (v.file and v.file.endswith(".go") and v.line):
            kept.append(v)
            continue
        if v.line == 1:
            suppressed.append((v, "Go prologue/inlined branch attributed to L1"))
            continue
        try:
            with open(v.file, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            kept.append(v)
            continue
        if not (1 <= v.line <= len(lines)):
            kept.append(v)
            continue
        src_line = lines[v.line - 1].lstrip()
        if src_line.startswith("func ") or src_line.startswith("func("):
            suppressed.append((v, "Go function-prologue stack-grow check"))
        else:
            kept.append(v)
    return kept, suppressed


# ---------------------------------------------------------------------------
# Filter 10 (Go-only): source-line classifier
# ---------------------------------------------------------------------------
# A conditional branch whose source line is one of Go's well-known
# public-control-flow patterns -- counted loops, range loops, length/
# nil/err checks -- is almost certainly not data-dependent on a secret.
# Compound conditions (`&&` / `||`) are NEVER suppressed because they can
# mix a public bound with a secret data check (e.g. Bleichenbacher's
#     for i < len(em) && em[i] != 0x00
# would be a real CT bug we must keep visible).

_GO_PUBLIC_LINE_PATTERNS = [
    # for i := 0; i < <int-literal>; i++ / i-- / i += K
    re.compile(
        r"^\s*for\s+\w+\s*:?=\s*\d+\s*;\s*\w+\s*[<>]=?\s*"
        r"(?:\d+|len\([\w.\[\]]+\)|cap\([\w.\[\]]+\))\s*;\s*"
        r"\w+\s*(?:\+\+|--|[+\-]=\s*\d+)\s*\{?\s*$"
    ),
    # for i := 0; i < <ident>; i++  (ident is a package-level constant)
    re.compile(
        r"^\s*for\s+\w+\s*:?=\s*\d+\s*;\s*\w+\s*[<>]=?\s*"
        r"[A-Za-z_][\w.]*\s*;\s*"
        r"\w+\s*(?:\+\+|--|[+\-]=\s*\d+)\s*\{?\s*$"
    ),
    # for i := uint16(0); i < K; i++  (typed initializer)
    re.compile(
        r"^\s*for\s+\w+\s*:?=\s*\w+\(\s*\d+\s*\)\s*;\s*\w+\s*[<>]=?\s*"
        r"\w+\s*;\s*\w+\s*(?:\+\+|--)\s*\{?\s*$"
    ),
    # for i := range x
    re.compile(r"^\s*for\s+[\w,\s_]*:?=\s*range\s+[\w.\[\]]+\s*\{?\s*$"),
    # if len(x) <op> y
    re.compile(r"^\s*if\s+len\([\w.\[\]]+\)\s*[!=<>]+\s*[\w.()]+\s*\{?\s*$"),
    # if init-stmt; len(x)/cap(x) <op> y
    re.compile(
        r"^\s*if\s+\w+\s*:?=\s*[\w.()+\-*/\s]+;\s*"
        r"(?:len|cap)\([\w.\[\]]+\)\s*[!=<>]+\s*[\w.]+\s*\{?\s*$"
    ),
    # if cap(x) <op> y
    re.compile(r"^\s*if\s+cap\([\w.\[\]]+\)\s*[!=<>]+\s*[\w.()]+\s*\{?\s*$"),
    # if x == nil / if x != nil
    re.compile(r"^\s*if\s+[\w.\[\]()]+\s*[!=]=\s*nil\s*\{?\s*$"),
    # if err != nil
    re.compile(r"^\s*if\s+\w*[Ee]rr\w*\s*!=\s*nil\s*\{?\s*$"),
    # if init; err != nil  -- e.g. `if err := f(...); err != nil {`
    re.compile(
        r"^\s*if\s+\w*[Ee]rr\w*\s*:?=\s*[^;]+;\s*\w*[Ee]rr\w*\s*!=\s*nil\s*\{?\s*$"
    ),
    # function declaration line (already covered by go-stack-grow but
    # included here for defense in depth)
    re.compile(r"^\s*func\s+\S"),
    # copy() statement on its own line. The branch is the byte-counter
    # bound check inside runtime.memmove, on a public slice length.
    re.compile(r"^\s*copy\s*\("),
    # Boolean check of a feature-flag-named global (Go convention is
    # `fips140only.Enabled`, `cpu.X86.HasAVX2`, `runtime.RaceEnabled`).
    re.compile(r"^\s*if\s+!?\w+\.[A-Z]\w*(?:\.\w+)*\s*\{?\s*$"),
]


def filter_go_public_lines(violations: list[Violation]) -> tuple[list[Violation], list[tuple[Violation, str]]]:
    """Suppress branch warnings whose source line matches a syntactically-
    pure public-control-flow pattern. Compound conditions (`&&`/`||`)
    NEVER match. The classifier is conservative by design -- a real
    Bleichenbacher pattern survives because it has `&&` on its loop
    line."""
    kept, suppressed = [], []
    for v in violations:
        if v.severity != Severity.WARNING:
            kept.append(v)
            continue
        if not (v.file and v.line):
            kept.append(v)
            continue
        try:
            with open(v.file, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            kept.append(v)
            continue
        if not (1 <= v.line <= len(lines)):
            kept.append(v)
            continue
        src_line = lines[v.line - 1].rstrip()
        if "&&" in src_line or "||" in src_line:
            kept.append(v)
            continue
        for pat in _GO_PUBLIC_LINE_PATTERNS:
            if pat.match(src_line):
                suppressed.append((v, f"Go public-control-flow line: {pat.pattern[:50]}"))
                break
        else:
            kept.append(v)
    return kept, suppressed


FILTER_REGISTRY: dict[str, Callable[[list[Violation]], tuple[list[Violation], list[tuple[Violation, str]]]]] = {
    "ct-funcs": filter_known_ct_functions,
    "aggregate": aggregate_branches_per_function,
    "compiler-helpers": filter_compiler_helpers,
    "div-public": filter_div_with_public_divisor,
    "loop-backedge": filter_loop_backedges,
    "go-bounds-check": filter_go_bounds_checks,
    "go-stack-grow": filter_go_stack_grow,
    "go-public-line": filter_go_public_lines,
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
                # Match either the canonical name (C: `validatePadding`) or
                # the Go FQN form (`main.validatePadding`,
                # `crypto/sha256.(*digest).Write`). The Go path adds both
                # forms to secret_funcs upfront, but for the trailing
                # `.method` cases we strip the leading package path here.
                fn = v.function
                fn_short = fn.rsplit(".", 1)[-1]
                if (fn in sf or fn_short in sf
                        or fn == "<source-call>"):
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
