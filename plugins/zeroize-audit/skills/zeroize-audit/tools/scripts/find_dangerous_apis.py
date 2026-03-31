#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""
find_dangerous_apis.py — Token/grep-based scanner for dangerous Rust API patterns.

Scans .rs files for API calls that bypass zeroization guarantees (mem::forget,
Box::leak, ptr::write_bytes, etc.) and async suspension points that expose
secret-named locals to the heap-allocated Future state machine.

Does NOT require compilation — pure source text analysis.

Usage:
    uv run find_dangerous_apis.py --src <source_dir> --out <findings.json>

Exit codes:
    0  — ran successfully (findings may be empty)
    1  — source directory not found
    2  — argument error
"""

import argparse
import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Sensitive name patterns (used for context filtering)
# ---------------------------------------------------------------------------

SENSITIVE_NAME_RE = re.compile(
    # PascalCase type names use \b (no underscore in names like SecretKey).
    # Lowercase keywords use (?<![a-zA-Z])...(?![a-zA-Z]) so that snake_case
    # names like 'secret_key', 'private_key', and 'auth_token' are matched
    # while avoiding spurious hits on words like 'monkey' or 'tokenize'.
    r"(?i)(?:\b(Key|PrivateKey|SecretKey|SigningKey|MasterKey|HmacKey|"
    r"Password|Passphrase|Pin|Token|AuthToken|BearerToken|ApiKey|"
    r"Secret|SharedSecret|PreSharedKey|Nonce|Seed|Entropy|"
    r"Credential|SessionKey|DerivedKey)\b"
    r"|(?<![a-zA-Z])(key|secret|password|token|nonce|seed|private|master|credential)(?![a-zA-Z]))"
)

# ---------------------------------------------------------------------------
# Dangerous API patterns: (regex, category, severity, detail)
# ---------------------------------------------------------------------------

PATTERNS: list[tuple[str, str, str, str]] = [
    (
        r"\bmem::forget\s*\(",
        "MISSING_SOURCE_ZEROIZE",
        "critical",
        "mem::forget() prevents Drop/ZeroizeOnDrop from running — secret never wiped",
    ),
    (
        r"\bManuallyDrop\s*::\s*new\s*\(",
        "MISSING_SOURCE_ZEROIZE",
        "critical",
        "ManuallyDrop::new() suppresses automatic drop — "
        "secret not wiped unless drop() called explicitly",
    ),
    (
        r"\bBox\s*::\s*leak\s*\(",
        "MISSING_SOURCE_ZEROIZE",
        "critical",
        "Box::leak() — leaked allocation is never dropped or zeroed",
    ),
    (
        r"\bBox\s*::\s*into_raw\s*\(",
        "MISSING_SOURCE_ZEROIZE",
        "high",
        "Box::into_raw() — raw pointer escapes Drop; "
        "must call Box::from_raw() + zeroize to reclaim",
    ),
    (
        r"\bptr\s*::\s*write_bytes\s*\(",
        "OPTIMIZED_AWAY_ZEROIZE",
        "high",
        "ptr::write_bytes() is non-volatile — LLVM may eliminate as dead store. "
        "Use zeroize crate or add compiler_fence(SeqCst) after",
    ),
    (
        # Matches both turbofish form (transmute::<T, U>(v)) and type-inferred form (transmute(v))
        r"\bmem\s*::\s*transmute\b",
        "SECRET_COPY",
        "high",
        "mem::transmute creates a bitwise copy — original and transmuted value both exist on stack",
    ),
    (
        r"\bslice\s*::\s*from_raw_parts\s*\(",
        "SECRET_COPY",
        "medium",
        "slice::from_raw_parts creates a slice alias over raw memory — may alias a secret buffer",
    ),
    (
        r"\bmem\s*::\s*take\s*\(",
        "MISSING_SOURCE_ZEROIZE",
        "medium",
        "mem::take() replaces the value in-place without zeroing the original location",
    ),
    (
        r"\bmem\s*::\s*uninitialized\s*\(",
        "MISSING_SOURCE_ZEROIZE",
        "critical",
        "mem::uninitialized() is deprecated and unsafe — "
        "may expose prior secret bytes from stack memory",
    ),
]

# Pre-compile all pattern regexes at module load time (avoids recompiling per file).
_COMPILED_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(pattern), category, severity, detail)
    for pattern, category, severity, detail in PATTERNS
]

# ---------------------------------------------------------------------------
# Finding counter
# ---------------------------------------------------------------------------

_finding_counter = [0]


def make_finding(
    category: str,
    severity: str,
    detail: str,
    file: str,
    line: int,
    symbol: str = "",
    confidence: str = "likely",
) -> dict:
    _finding_counter[0] += 1
    fid = f"F-RUST-SRC-{_finding_counter[0]:04d}"
    return {
        "id": fid,
        "language": "rust",
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "detail": detail,
        "symbol": symbol,
        "location": {"file": file, "line": line},
        "evidence": [{"source": "source_grep", "detail": detail}],
    }


# ---------------------------------------------------------------------------
# Context sensitivity check
# ---------------------------------------------------------------------------


def has_sensitive_context(lines: list[str], center_idx: int, window: int = 15) -> bool:
    """Return True if any sensitive name appears within `window` lines of `center_idx`.

    `center_idx` is a 0-based array index (i.e. ``lineno - 1``).  Callers must
    NOT pass 1-based line numbers here or the window will be off by one.
    """
    start = max(0, center_idx - window)
    end = min(len(lines), center_idx + window + 1)
    context = "\n".join(lines[start:end])
    return bool(SENSITIVE_NAME_RE.search(context))


# ---------------------------------------------------------------------------
# Grep-based pattern scanner
# ---------------------------------------------------------------------------

_BLOCK_COMMENT_START = re.compile(r"/\*")
_BLOCK_COMMENT_END = re.compile(r"\*/")


def _is_commented_out(line: str, in_block_comment: bool) -> tuple[bool, bool]:
    """Return (skip_this_line, updated_in_block_comment).

    Handles single-line `//` comments and block `/* ... */` comments. A line
    that merely *contains* a comment start (e.g. `foo(); /* note */`) is NOT
    fully skipped — only lines where the match site is inside the comment region
    would be skipped. For simplicity this implementation skips the entire line
    when it starts with `//` (after stripping) or when we are inside a block
    comment. This is intentionally conservative: it may miss a pattern on the
    same source line as an unrelated comment, but that is a very rare case.
    """
    stripped = line.strip()
    if in_block_comment:
        if _BLOCK_COMMENT_END.search(line):
            return True, False  # end of block comment on this line; skip line
        return True, True  # still inside block comment
    if stripped.startswith("//"):
        return True, False  # single-line comment
    if stripped.startswith("/*"):
        if _BLOCK_COMMENT_END.search(line):
            return True, False  # block comment opens and closes on this line
        return True, True  # block comment opens; skip remainder
    # Mid-line block comment: code precedes the /* (e.g. `code(); /* comment ...`).
    # Do not skip this line (the match site may be in the code portion), but mark
    # subsequent lines as inside a block comment.
    if _BLOCK_COMMENT_START.search(stripped) and not _BLOCK_COMMENT_END.search(stripped):
        return False, True
    return False, False


def scan_file_patterns(path: Path, source: str) -> list[dict]:
    findings: list[dict] = []
    lines = source.splitlines()
    in_block_comment = False

    for compiled, category, severity, detail in _COMPILED_PATTERNS:
        in_block_comment = False  # reset per pattern pass
        for lineno, line in enumerate(lines, start=1):
            skip, in_block_comment = _is_commented_out(line, in_block_comment)
            if skip:
                continue
            if not compiled.search(line):
                continue
            actual_severity = severity
            actual_confidence = "likely"
            if not has_sensitive_context(lines, lineno - 1):  # lineno-1 → 0-based
                actual_confidence = "needs_review"
            findings.append(
                make_finding(
                    category,
                    actual_severity,
                    detail,
                    str(path),
                    lineno,
                    confidence=actual_confidence,
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Async secret suspension detector
# ---------------------------------------------------------------------------


def scan_async_suspension(path: Path, source: str) -> list[dict]:
    """
    Detect: async fn body where a secret-named local is bound before an .await.

    Heuristic:
    1. Find async fn declarations.
    2. Within each async fn body (between opening { and matching }), find let bindings
       whose variable name matches SENSITIVE_NAME_RE.
    3. Check whether any .await appears after the binding within the same fn body.
    4. If so, emit NOT_ON_ALL_PATHS (high).
    """
    findings: list[dict] = []
    lines = source.splitlines()

    # Find all async fn start lines
    async_fn_re = re.compile(r"\basync\s+fn\s+\w+")
    let_binding_re = re.compile(r"\blet\s+(?:mut\s+)?(\w+)\s*[=:]")
    await_re = re.compile(r"\.await\b")

    i = 0
    while i < len(lines):
        if async_fn_re.search(lines[i]):
            # Find the body: scan for opening brace
            body_lines: list[tuple[int, str]] = []
            depth = 0
            in_body = False
            for j in range(i, min(i + 500, len(lines))):
                # Count braces, skipping string literals and line comments
                in_str = False
                k = 0
                line_text = lines[j]
                while k < len(line_text):
                    ch = line_text[k]
                    if in_str:
                        if ch == "\\" and k + 1 < len(line_text):
                            k += 2  # skip escape sequence
                            continue
                        elif ch == '"':
                            in_str = False
                    else:
                        if ch == '"':
                            in_str = True
                        elif ch == "/" and k + 1 < len(line_text) and line_text[k + 1] == "/":
                            break  # rest of line is a comment
                        elif ch == "{":
                            depth += 1
                            in_body = True
                        elif ch == "}":
                            depth -= 1
                    k += 1
                if in_body:
                    body_lines.append((j + 1, lines[j]))  # 1-based line number
                if in_body and depth == 0:
                    i = j + 1
                    break
            else:
                i += 1
                continue

            # Within body, find secret-named bindings followed by .await
            secret_bindings: list[tuple[int, str]] = []  # (lineno, varname)
            for lineno, line in body_lines:
                m = let_binding_re.search(line)
                if m and SENSITIVE_NAME_RE.search(m.group(1)):
                    secret_bindings.append((lineno, m.group(1)))

            for bind_line, varname in secret_bindings:
                # Check if .await appears after this binding in the fn body
                for lineno, line in body_lines:
                    if lineno > bind_line and await_re.search(line):
                        findings.append(
                            make_finding(
                                "NOT_ON_ALL_PATHS",
                                "high",
                                f"Secret local '{varname}' is live across an .await suspension "
                                "point in an async fn — stored in the heap-allocated Future state "
                                "machine; ZeroizeOnDrop covers stack variables only",
                                str(path),
                                bind_line,
                            )
                        )
                        break  # one finding per binding is enough
            continue
        i += 1

    return findings


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------


def scan_directory(src_dir: Path) -> list[dict]:
    findings: list[dict] = []
    for rs_file in sorted(src_dir.rglob("*.rs")):
        try:
            source = rs_file.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"find_dangerous_apis.py: warning: cannot read {rs_file}: {e}", file=sys.stderr)
            continue
        findings.extend(scan_file_patterns(rs_file, source))
        findings.extend(scan_async_suspension(rs_file, source))
    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Token/grep-based scanner for dangerous Rust API patterns"
    )
    parser.add_argument("--src", required=True, help="Source directory to scan (.rs files)")
    parser.add_argument("--out", required=True, help="Output findings JSON path")
    args = parser.parse_args()

    src_dir = Path(args.src)
    if not src_dir.is_dir():
        print(f"find_dangerous_apis.py: source directory not found: {src_dir}", file=sys.stderr)
        return 1

    findings = scan_directory(src_dir)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    print(f"find_dangerous_apis.py: {len(findings)} finding(s) written to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
