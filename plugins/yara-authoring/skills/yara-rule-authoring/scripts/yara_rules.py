"""Dependency-free parsing and analysis of YARA-X rule sources.

Shared by yara_lint.py and atom_analyzer.py. Deliberately imports nothing outside
the standard library so it can be unit tested without the yara-x wheel; the two
CLI wrappers add YARA-X compilation on top of what lives here.

The parsers are hand-written scanners rather than regexes because YARA string
values routinely contain the delimiters a regex would trip over -- `\\/` inside a
regex pattern, `\\"` inside a text string, `{0,30}` inside a quantifier.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

# A string this long or longer makes `nocase` expensive enough to mention.
NOCASE_LENGTH_THRESHOLD = 20

# Minimum bytes for YARA to extract a usable 4-byte atom.
MIN_ATOM_BYTES = 4

DESCRIPTION_MIN_CHARS = 60
DESCRIPTION_MAX_CHARS = 400

VALID_CATEGORY_PREFIXES = frozenset(
    {
        "MAL",
        "HKTL",
        "WEBSHELL",
        "EXPL",
        "VULN",
        "SUSP",
        "PUA",
        "GEN",
        "APT",
        "CRIME",
        "RANSOM",
        "RAT",
        "MINER",
        "STEALER",
        "LOADER",
        "C2",
    }
)

# Substrings that show up in goodware often enough to be worth flagging.
FP_PRONE_STRINGS = (
    "CreateRemoteThread",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "NtCreateThread",
    "VirtualAlloc",
    "VirtualProtect",
    "powershell.exe",
    "explorer.exe",
    "notepad.exe",
    "ADVAPI32.dll",
    "KERNEL32.dll",
    "C:\\Windows\\System32",
    "C:\\Windows",
    "USER32.dll",
    "ntdll.dll",
    "cmd.exe",
    "https://",
    "http://",
    "%08x",
    "%s",
    "%d",
    "%x",
)

DEPRECATED_PATTERNS = {
    "entrypoint": "Use pe.entry_point instead of deprecated entrypoint",
    "PEiD": "PEiD-style signatures are obsolete; use modern detection",
}

# Checks that cost close to nothing and belong at the front of a condition.
CHEAP_CHECK_RE = re.compile(
    r"\bfilesize\b|\bu?int(?:8|16|32)(?:be)?\s*\(|\b\w+\.is_\w+\b",
)

# Anything that reads pattern-match state or a parsed module structure.
EXPENSIVE_CHECK_RE = re.compile(
    r"[$#@!]\w*|\bfor\b|\b(?:any|all|none|\d+)\s+of\b|\b\w+\.\w+",
)


# The complete set of codes yara_lint.py can emit. references/style-guide.md
# publishes this table for users; test_yara_rules.py asserts the two agree, so a
# check added here without a doc entry (or vice versa) fails the build.
#
# E007 (unescaped `{` in regex) is retired: YARA-X's own compiler reports it as
# E000 with the exact source location and a suggested fix.
ISSUE_CODES = {
    "E000": "YARA-X compilation error",
    "E001": "Missing required metadata field (description, author, date)",
    "E002": "Text string shorter than 4 bytes",
    "E003": "Hex string shorter than 4 bytes",
    "E006": "base64 modifier on a string shorter than 3 characters",
    "E008": "Negative array indexing, unsupported in YARA-X",
    "W001": "Rule name does not follow CATEGORY_PLATFORM_FAMILY_DATE",
    "W002": "Description does not start with 'Detects'",
    "W003": "Description shorter than 60 characters",
    "W004": "Missing 'reference' metadata",
    "W005": "String contains an FP-prone substring",
    "W006": "Hex string starts with a wildcard",
    "W007": "Deprecated feature used in condition",
    "W008": "Unbounded regex quantifier (.* or .+)",
    "W009": "Condition reaches pattern or module state before any cheap pre-filter",
    "I001": "Unrecognized category prefix",
    "I002": "Description longer than 400 characters",
    "I003": "nocase on a string longer than 20 characters",
    "I004": "xor without an explicit key range",
}


@dataclass
class Issue:
    """A linting issue."""

    rule: str
    severity: str  # error, warning, info
    code: str
    message: str
    line: int | None = None

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "line": self.line,
        }


@dataclass
class LintResult:
    """Result of linting a file."""

    file: str
    issues: list[Issue] = field(default_factory=list)
    parse_error: str | None = None
    rules: int = 0

    @property
    def error_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "error")

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "warning")


@dataclass
class AtomIssue:
    """An issue with atom quality."""

    string_id: str
    severity: str  # error, warning, info
    message: str
    suggestion: str | None = None


@dataclass
class StringAnalysis:
    """Analysis of a single string's atom quality."""

    string_id: str
    string_type: str
    raw_value: str
    byte_count: int
    issues: list[AtomIssue]
    best_atom: str | None = None


@dataclass
class YaraString:
    """One entry from a rule's `strings:` section."""

    name: str
    value: str
    type: str  # text, byte, regex
    modifiers: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Scanners
# --------------------------------------------------------------------------- #


def _scan_quoted(text: str, start: int) -> tuple[str | None, int]:
    """Scan a double-quoted YARA text string starting at `start`.

    Honours backslash escapes so `"say \\"hi\\""` reads as one value.
    """
    pos = start + 1
    while pos < len(text):
        char = text[pos]
        if char == "\\":
            pos += 2
            continue
        if char == '"':
            return text[start + 1 : pos], pos + 1
        if char == "\n":
            break
        pos += 1
    return None, start + 1


def _scan_regex(text: str, start: int) -> tuple[str | None, int]:
    """Scan a `/pattern/` regex literal starting at `start`.

    Escaped slashes and slashes inside a character class do not terminate the
    pattern -- the reason a naive `/[^/]*/` regex mis-parses most URL patterns.
    """
    pos = start + 1
    in_class = False
    while pos < len(text):
        char = text[pos]
        if char == "\\":
            pos += 2
            continue
        if char == "\n":
            break
        if in_class:
            if char == "]":
                in_class = False
        elif char == "[":
            in_class = True
        elif char == "/":
            return text[start + 1 : pos], pos + 1
        pos += 1
    return None, start + 1


def _scan_hex(text: str, start: int) -> tuple[str | None, int]:
    """Scan a `{ ... }` hex string starting at `start`."""
    depth = 0
    pos = start
    while pos < len(text):
        char = text[pos]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1 : pos], pos + 1
        pos += 1
    return None, start + 1


def _modifiers_after(text: str, pos: int) -> list[str]:
    """Read the modifier tokens trailing a string value, minus any comment."""
    newline = text.find("\n", pos)
    rest = text[pos:] if newline == -1 else text[pos:newline]
    rest = re.sub(r"/\*.*?\*/", " ", rest)
    rest = rest.split("//", 1)[0]
    return rest.split()


def strip_comments(source: str) -> str:
    """Blank out `//` and `/* */` comments, preserving offsets and line breaks."""
    out = list(source)
    pos = 0
    while pos < len(source):
        char = source[pos]
        if char == '"':
            _, pos = _scan_quoted(source, pos)
            continue
        if char == "/" and pos + 1 < len(source):
            following = source[pos + 1]
            if following == "/":
                end = source.find("\n", pos)
                end = len(source) if end == -1 else end
                for i in range(pos, end):
                    out[i] = " "
                pos = end
                continue
            if following == "*":
                end = source.find("*/", pos + 2)
                end = len(source) if end == -1 else end + 2
                for i in range(pos, end):
                    if out[i] != "\n":
                        out[i] = " "
                pos = end
                continue
        pos += 1
    return "".join(out)


# --------------------------------------------------------------------------- #
# Rule structure
# --------------------------------------------------------------------------- #


def extract_rule_names(content: str) -> list[str]:
    """Extract rule names from YARA source."""
    return re.findall(r"(?:private\s+|global\s+)*rule\s+(\w+)\s*[:{]", strip_comments(content))


def extract_rule_body(content: str, rule_name: str) -> str:
    """Return the body of `rule_name`, between its outermost braces.

    Brace counting skips text strings, regex literals and comments, so a `}`
    inside `$s = "}"` or a `{0,30}` quantifier does not truncate the body.
    """
    clean = strip_comments(content)
    header = re.search(rf"\brule\s+{re.escape(rule_name)}\s*(?::[^{{]*)?\{{", clean)
    if not header:
        return ""

    pos = header.end()
    depth = 1
    last_significant = "{"
    while pos < len(clean) and depth > 0:
        char = clean[pos]
        if char == '"':
            _, pos = _scan_quoted(clean, pos)
            last_significant = '"'
            continue
        if char == "/" and last_significant == "=":
            _, pos = _scan_regex(clean, pos)
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return clean[header.end() : pos]
        if not char.isspace():
            last_significant = char
        pos += 1
    return clean[header.end() : pos]


def _section(body: str, name: str, followers: tuple[str, ...]) -> str:
    """Return the text of a `name:` section, up to the next section keyword."""
    stop = "|".join(rf"{f}\s*:" for f in followers)
    match = re.search(rf"\b{name}\s*:\s*(.*?)(?={stop}|$)", body, re.DOTALL)
    return match.group(1) if match else ""


def extract_metadata(content: str, rule_name: str) -> dict[str, str]:
    """Extract the `meta:` key/value pairs of a rule."""
    section = _section(extract_rule_body(content, rule_name), "meta", ("strings", "condition"))
    return dict(re.findall(r'(\w+)\s*=\s*"([^"]*)"', section))


def extract_strings(content: str, rule_name: str) -> list[YaraString]:
    """Extract the `strings:` entries of a rule, in source order."""
    section = _section(extract_rule_body(content, rule_name), "strings", ("condition",))
    strings: list[YaraString] = []

    for match in re.finditer(r"(\$\w*)\s*=\s*", section):
        pos = match.end()
        if pos >= len(section):
            break
        delimiter = section[pos]
        if delimiter == '"':
            value, end = _scan_quoted(section, pos)
            kind = "text"
        elif delimiter == "{":
            value, end = _scan_hex(section, pos)
            kind = "byte"
        elif delimiter == "/":
            value, end = _scan_regex(section, pos)
            kind = "regex"
        else:
            continue
        if value is None:
            continue
        strings.append(
            YaraString(
                name=match.group(1),
                value=value.strip() if kind == "byte" else value,
                type=kind,
                modifiers=_modifiers_after(section, end),
            )
        )
    return strings


def extract_condition(content: str, rule_name: str) -> str:
    """Return a rule's condition text, comments already stripped."""
    body = extract_rule_body(content, rule_name)
    match = re.search(r"\bcondition\s*:\s*(.*)", body, re.DOTALL)
    return match.group(1).strip() if match else ""


# --------------------------------------------------------------------------- #
# Lint checks
# --------------------------------------------------------------------------- #


def check_naming_convention(rule_name: str) -> Iterator[Issue]:
    """Check if rule name follows the style guide convention."""
    parts = rule_name.split("_")

    if len(parts) < 3:
        yield Issue(
            rule=rule_name,
            severity="warning",
            code="W001",
            message=f"Rule name '{rule_name}' should follow CATEGORY_PLATFORM_FAMILY_DATE format",
        )
        return

    if parts[0] not in VALID_CATEGORY_PREFIXES:
        valid = ", ".join(sorted(VALID_CATEGORY_PREFIXES))
        yield Issue(
            rule=rule_name,
            severity="info",
            code="I001",
            message=f"Unrecognized category prefix '{parts[0]}'; expected one of: {valid}",
        )


def check_metadata(rule_name: str, metadata: dict[str, str]) -> Iterator[Issue]:
    """Check for required and well-formed metadata."""
    for field_name in ("description", "author", "date"):
        if field_name not in metadata:
            yield Issue(
                rule=rule_name,
                severity="error",
                code="E001",
                message=f"Missing required metadata field: {field_name}",
            )

    if "description" in metadata:
        desc = metadata["description"]
        if not desc.startswith("Detects"):
            yield Issue(
                rule=rule_name,
                severity="warning",
                code="W002",
                message="Description should start with 'Detects'",
            )
        if len(desc) < DESCRIPTION_MIN_CHARS:
            yield Issue(
                rule=rule_name,
                severity="warning",
                code="W003",
                message=f"Description too short ({len(desc)} chars); aim for 60-400 characters",
            )
        if len(desc) > DESCRIPTION_MAX_CHARS:
            yield Issue(
                rule=rule_name,
                severity="info",
                code="I002",
                message=f"Description quite long ({len(desc)} chars); consider trimming to <400",
            )

    if "reference" not in metadata:
        yield Issue(
            rule=rule_name,
            severity="warning",
            code="W004",
            message="Missing 'reference' metadata; add URL to analysis or source",
        )


def check_strings(rule_name: str, strings: list[YaraString]) -> Iterator[Issue]:
    """Check strings for anti-patterns and quality issues."""
    for string in strings:
        if string.type == "text":
            yield from _check_text_string(rule_name, string)
        elif string.type == "byte":
            yield from _check_hex_string(rule_name, string)
        elif string.type == "regex":
            yield from _check_regex_string(rule_name, string)


def _check_text_string(rule_name: str, string: YaraString) -> Iterator[Issue]:
    if len(string.value) < MIN_ATOM_BYTES:
        yield Issue(
            rule=rule_name,
            severity="error",
            code="E002",
            message=f"String {string.name} is only {len(string.value)} bytes; "
            f"minimum {MIN_ATOM_BYTES} bytes for good atoms",
        )

    lowered = string.value.lower()
    for fp_string in FP_PRONE_STRINGS:
        if fp_string.lower() in lowered:
            yield Issue(
                rule=rule_name,
                severity="warning",
                code="W005",
                message=f"String {string.name} contains FP-prone pattern '{fp_string}'",
            )
            break

    if "base64" in string.modifiers and len(string.value) < 3:
        yield Issue(
            rule=rule_name,
            severity="error",
            code="E006",
            message=f"String {string.name} uses 'base64' but is only {len(string.value)} "
            "chars; YARA-X requires 3+ characters for base64 modifier",
        )


def _check_hex_string(rule_name: str, string: YaraString) -> Iterator[Issue]:
    byte_count = sum(len(run) for run in hex_string_runs(string.value))
    if byte_count < MIN_ATOM_BYTES:
        yield Issue(
            rule=rule_name,
            severity="error",
            code="E003",
            message=f"Hex string {string.name} has only {byte_count} bytes; "
            f"minimum {MIN_ATOM_BYTES} for good atoms",
        )

    if re.match(r"^\s*\?\?", string.value):
        yield Issue(
            rule=rule_name,
            severity="warning",
            code="W006",
            message=f"Hex string {string.name} starts with wildcard; "
            "move fixed bytes first for better atoms",
        )


def _check_regex_string(rule_name: str, string: YaraString) -> Iterator[Issue]:
    if re.search(r"(?<!\\)\.[*+](?!\?)", string.value):
        yield Issue(
            rule=rule_name,
            severity="warning",
            code="W008",
            message=f"Regex {string.name} has an unbounded quantifier (.* or .+); "
            "use a bounded repetition such as .{0,100}",
        )


def check_string_modifiers(rule_name: str, strings: list[YaraString]) -> Iterator[Issue]:
    """Check string modifiers for performance concerns."""
    for string in strings:
        if "nocase" in string.modifiers and len(string.value) > NOCASE_LENGTH_THRESHOLD:
            yield Issue(
                rule=rule_name,
                severity="info",
                code="I003",
                message=f"String {string.name} uses 'nocase' on long string; performance impact",
            )

        if "xor" in string.modifiers:
            yield Issue(
                rule=rule_name,
                severity="info",
                code="I004",
                message=f"String {string.name} uses 'xor' without a range; "
                "generates 255 patterns -- prefer xor(0xNN) when the key is known",
            )


def check_condition(rule_name: str, condition: str) -> Iterator[Issue]:
    """Check a condition for deprecated features and YARA-X incompatibilities."""
    if not condition:
        return

    for pattern, message in DEPRECATED_PATTERNS.items():
        if pattern.lower() in condition.lower():
            yield Issue(rule=rule_name, severity="warning", code="W007", message=message)

    if re.search(r"@\w+\s*\[\s*-\d+\s*\]", condition):
        yield Issue(
            rule=rule_name,
            severity="error",
            code="E008",
            message="Negative array indexing (e.g., @a[-1]) not supported in YARA-X; "
            "use @a[#a - 1] instead",
        )


def check_condition_order(rule_name: str, condition: str) -> Iterator[Issue]:
    """Flag conditions that reach pattern or module state before any cheap pre-filter.

    Cheap means `filesize`, a `uintNN()` magic-byte read, or a module's `is_*`
    file-type gate. If an expensive term comes first -- or there is no cheap
    filter at all -- every scanned file pays for it.
    """
    if not condition:
        return

    cheap = CHEAP_CHECK_RE.search(condition)
    redacted = CHEAP_CHECK_RE.sub(lambda m: " " * len(m.group()), condition)
    expensive = EXPENSIVE_CHECK_RE.search(redacted)

    if expensive is None:
        return
    if cheap is None or expensive.start() < cheap.start():
        term = expensive.group().strip()
        yield Issue(
            rule=rule_name,
            severity="warning",
            code="W009",
            message=f"Condition reaches '{term}' before any cheap pre-filter; "
            "lead with filesize or a uintNN magic-byte check",
        )


def lint_source(content: str) -> list[Issue]:
    """Run every style check over a YARA source string."""
    issues: list[Issue] = []
    for rule_name in extract_rule_names(content):
        issues.extend(check_naming_convention(rule_name))
        issues.extend(check_metadata(rule_name, extract_metadata(content, rule_name)))

        strings = extract_strings(content, rule_name)
        issues.extend(check_strings(rule_name, strings))
        issues.extend(check_string_modifiers(rule_name, strings))

        condition = extract_condition(content, rule_name)
        issues.extend(check_condition(rule_name, condition))
        issues.extend(check_condition_order(rule_name, condition))
    return issues


# --------------------------------------------------------------------------- #
# Atom analysis
# --------------------------------------------------------------------------- #

# Repeated byte patterns that generate poor atoms.
REPEATED_PATTERNS = (
    (b"\x00\x00\x00\x00", "null bytes (0x00000000)"),
    (b"\x90\x90\x90\x90", "NOP sled (0x90909090)"),
    (b"\xcc\xcc\xcc\xcc", "INT3 padding (0xCCCCCCCC)"),
    (b"\xff\xff\xff\xff", "all 0xFF bytes"),
    (b"\x20\x20\x20\x20", "spaces (0x20202020)"),
)

# Common 4-byte sequences that appear in many files.
COMMON_SEQUENCES = (
    b"This",
    b"prog",
    b"MODE",
    b"rich",
    b".tex",
    b".dat",
    b".rsr",
    b"MZ\x90\x00",
    b"http",
    b"HTTP",
)

# One hex token: wildcard byte, nibble wildcard, literal byte, jump, or grouping.
_HEX_TOKEN_RE = re.compile(r"\?\?|[0-9A-Fa-f]\?|\?[0-9A-Fa-f]|[0-9A-Fa-f]{2}|\[[^\]]*\]|[()|]")


@dataclass
class HexRun:
    """A contiguous stretch of a hex string with no jump or alternation in it."""

    data: bytes
    wildcards: list[int]

    def __len__(self) -> int:
        return len(self.data)


def hex_string_runs(hex_str: str) -> list[HexRun]:
    """Split a YARA hex string into contiguous runs of adjacent bytes.

    Jumps (`[2-4]`) and alternations (`( 90 00 | 00 00 )`) break adjacency, so the
    bytes on either side are not a candidate atom together and must not be
    concatenated into one.
    """
    runs: list[HexRun] = []
    data = bytearray()
    wildcards: list[int] = []

    def flush() -> None:
        if data:
            runs.append(HexRun(bytes(data), list(wildcards)))
        data.clear()
        wildcards.clear()

    for match in _HEX_TOKEN_RE.finditer(hex_str.strip().strip("{}")):
        token = match.group()
        if token == "??" or "?" in token:
            wildcards.append(len(data))
            data.append(0x00)
        elif re.fullmatch(r"[0-9A-Fa-f]{2}", token):
            data.append(int(token, 16))
        else:
            flush()
    flush()
    return runs


def score_atom(atom: bytes) -> int:
    """Score a 4-byte atom for quality (0-100)."""
    if len(atom) != MIN_ATOM_BYTES:
        return 0

    score = 100

    unique = len(set(atom))
    if unique == 1:
        score -= 80
    elif unique == 2:
        score -= 40

    score -= atom.count(0x00) * 15

    for pattern, _ in REPEATED_PATTERNS:
        if pattern in atom:
            score -= 60
            break

    for seq in COMMON_SEQUENCES:
        if seq in atom:
            score -= 30
            break

    if all(0x20 <= b <= 0x7E for b in atom):
        score -= 10

    return max(0, score)


def find_best_atom(data: bytes, wildcard_positions: list[int]) -> tuple[str | None, int]:
    """Find the highest-scoring wildcard-free 4-byte window in a byte sequence."""
    best_atom = None
    best_score = 0
    wildcards = set(wildcard_positions)

    for i in range(len(data) - MIN_ATOM_BYTES + 1):
        if wildcards & set(range(i, i + MIN_ATOM_BYTES)):
            continue
        atom = data[i : i + MIN_ATOM_BYTES]
        score = score_atom(atom)
        if score > best_score:
            best_score = score
            best_atom = atom.hex().upper()

    return best_atom, best_score


def _atom_score_issues(string_id: str, score: int) -> Iterator[AtomIssue]:
    if score < 30:
        yield AtomIssue(
            string_id=string_id,
            severity="error",
            message=f"Best atom score is {score}/100; string will cause slow scanning",
            suggestion="Choose a more unique string or add distinguishing bytes",
        )
    elif score < 60:
        yield AtomIssue(
            string_id=string_id,
            severity="warning",
            message=f"Best atom score is {score}/100; may cause performance issues",
        )


def analyze_text_string(string_id: str, value: str, modifiers: list[str]) -> StringAnalysis:
    """Analyze a text string for atom quality."""
    issues: list[AtomIssue] = []
    byte_count = len(value)

    if byte_count < MIN_ATOM_BYTES:
        issues.append(
            AtomIssue(
                string_id=string_id,
                severity="error",
                message=f"String is only {byte_count} bytes; no valid 4-byte atom possible",
                suggestion="Use a longer string (4+ bytes minimum)",
            )
        )
        return StringAnalysis(string_id, "text", value, byte_count, issues)

    if "base64" in modifiers and byte_count < 3:
        issues.append(
            AtomIssue(
                string_id=string_id,
                severity="error",
                message=f"String uses 'base64' but is only {byte_count} chars; "
                "YARA-X requires 3+ characters for base64 modifier",
                suggestion="Use a string of 3+ characters with base64 modifier",
            )
        )

    data = value.encode("utf-8", errors="surrogateescape")
    best_atom, score = find_best_atom(data, [])
    issues.extend(_atom_score_issues(string_id, score))

    if "nocase" in modifiers and byte_count > NOCASE_LENGTH_THRESHOLD:
        issues.append(
            AtomIssue(
                string_id=string_id,
                severity="info",
                message="'nocase' on long string doubles atom generation",
                suggestion="Consider if case-insensitivity is truly needed",
            )
        )

    if "wide" in modifiers and "ascii" in modifiers:
        issues.append(
            AtomIssue(
                string_id=string_id,
                severity="info",
                message="'wide ascii' doubles matching; ensure both encodings are needed",
            )
        )

    return StringAnalysis(string_id, "text", value, byte_count, issues, best_atom)


def analyze_hex_string(string_id: str, value: str) -> StringAnalysis:
    """Analyze a hex string for atom quality."""
    issues: list[AtomIssue] = []
    runs = hex_string_runs(value)
    byte_count = sum(len(run) for run in runs)

    if byte_count < MIN_ATOM_BYTES:
        issues.append(
            AtomIssue(
                string_id=string_id,
                severity="error",
                message=f"Hex string is only {byte_count} bytes; no valid 4-byte atom possible",
                suggestion="Use a longer hex pattern (4+ bytes minimum)",
            )
        )
        return StringAnalysis(string_id, "byte", value, byte_count, issues)

    first = runs[0]
    if {0, 1} <= set(first.wildcards):
        issues.append(
            AtomIssue(
                string_id=string_id,
                severity="warning",
                message="Hex string starts with wildcards; atoms will be extracted from middle/end",
                suggestion="Move fixed bytes to the beginning if possible",
            )
        )

    wildcard_count = sum(len(run.wildcards) for run in runs)
    if wildcard_count and wildcard_count / byte_count > 0.5:
        issues.append(
            AtomIssue(
                string_id=string_id,
                severity="warning",
                message=f"High wildcard density ({wildcard_count / byte_count:.0%}); "
                "may limit atom options",
            )
        )

    best_atom, score = None, 0
    for run in runs:
        atom, run_score = find_best_atom(run.data, run.wildcards)
        if atom is not None and run_score > score:
            best_atom, score = atom, run_score

    if best_atom is None:
        issues.append(
            AtomIssue(
                string_id=string_id,
                severity="error",
                message="No valid 4-byte atom found (wildcards or jumps break every window)",
                suggestion="Reduce wildcards or add a longer run of fixed bytes",
            )
        )
    else:
        issues.extend(_atom_score_issues(string_id, score))

    return StringAnalysis(string_id, "byte", value, byte_count, issues, best_atom)


def analyze_rule(rule_name: str, content: str) -> Iterator[StringAnalysis]:
    """Analyze the atom quality of every text and hex string in a rule.

    Regex patterns are skipped: their atoms come out of the compiled automaton,
    not the source text, so scoring them here would be guesswork.
    """
    for string in extract_strings(content, rule_name):
        if string.type == "text":
            yield analyze_text_string(string.name, string.value, string.modifiers)
        elif string.type == "byte":
            yield analyze_hex_string(string.name, string.value)


# --------------------------------------------------------------------------- #
# Scan targets
# --------------------------------------------------------------------------- #

RULE_SUFFIXES = (".yar", ".yara")


def collect_rule_files(path: Path) -> tuple[list[Path], str | None]:
    """Resolve a CLI path into the rule files to inspect.

    Returns `(files, error)`. `error` is set whenever there is nothing to
    inspect, so a directory holding no rules fails loudly instead of reporting
    a clean run over zero files.
    """
    if not path.exists():
        return [], f"{path} does not exist"

    if path.is_file():
        return [path], None

    if not path.is_dir():
        return [], f"{path} is neither a file nor a directory"

    files = sorted(p for p in path.rglob("*") if p.suffix in RULE_SUFFIXES and p.is_file())
    if not files:
        suffixes = " or ".join(RULE_SUFFIXES)
        return [], f"no {suffixes} files found under {path}; nothing was inspected"
    return files, None


def coverage_error(rule_counts: dict[str, int]) -> str | None:
    """Return an error message when a run inspected no rules at all.

    Judged over the whole run, not per file. A rule-less file inside a larger
    run is normal -- rulesets commonly keep a shared `import "pe"` header in its
    own file -- so failing per file would reject a healthy directory. Only a run
    that found nothing anywhere is reporting a clean result over zero items.
    """
    if not rule_counts:
        return "no files were inspected"
    if sum(rule_counts.values()) == 0:
        names = ", ".join(sorted(rule_counts))
        return f"no rules found in {names}; nothing was inspected"
    return None


def rule_less_files(rule_counts: dict[str, int]) -> list[str]:
    """Files that held no rules, for reporting as a note rather than a failure."""
    return sorted(name for name, count in rule_counts.items() if count == 0)


def select_exit_code(results: list[LintResult], *, strict: bool) -> int:
    """Exit 1 on any error, any unreadable file, or -- under --strict -- any warning."""
    if any(r.parse_error for r in results):
        return 1
    if sum(r.error_count for r in results) > 0:
        return 1
    if strict and sum(r.warning_count for r in results) > 0:
        return 1
    return 0
