"""Static signatures for the vectors in skills/agentic-actions-auditor/references.

These are deliberately crude. They exist to measure how often each vector occurs in a
corpus and to give the eval suite a ground truth that is not a reading of the YAML, not
to replace the skill. Every signature is paired with a fixture that must match and a
safe twin that must not; run self_test() before trusting any count.

Vectors C, E and G have no signature here on purpose. C (the prompt tells the agent to
fetch attacker content at runtime), E (CI logs fed back as context) and G (a later step
evaluates the agent's output) all depend on what a prompt means or on what a downstream
step does with a value, and a regex that claimed to decide them would report a number
nobody could defend.
"""

from __future__ import annotations

import pathlib
import re
import sys

FIXTURES = pathlib.Path(__file__).parent / "fixtures"

_EVENT = r"github\.event\.(?:issue|pull_request|comment|discussion|review)"


def vector_a(text: str) -> bool:
    """Attacker data reaches env:, and the prompt names the variable rather than the expression."""
    env_block = re.search(r"^\s*env:\s*\n(?:\s+\S+:.*\n)*", text, re.M)
    if not env_block or "prompt" not in text:
        return False
    names = re.findall(rf"^\s+(\w+):\s*\$\{{\{{\s*{_EVENT}", env_block.group(0), re.M)
    if not names:
        return False
    prompt = _prompt_text(text)
    return any(n in prompt for n in names)


def vector_b(text: str) -> bool:
    """The expression sits in the prompt itself."""
    return bool(re.search(rf"\$\{{\{{\s*{_EVENT}", _prompt_text(text)))


def vector_d(text: str) -> bool:
    """pull_request_target combined with a checkout of the PR head."""
    if "pull_request_target" not in text:
        return False
    return bool(re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)", text))


def vector_f(text: str) -> bool:
    """A tool allowlist naming a command that runs a subshell for you.

    Keyed on the fields the actions actually take. An earlier version of this looked for
    an `allowed_tools:` input, which claude-code-action dropped after v0.0.32 and which
    the vector-f reference never claimed; it matched nothing real, and the zero it
    reported over the corpus was its own doing rather than a fact about the corpus.
    """
    expandable = r"echo|printf|cat|env|tee|head|tail|sort|wc"
    # Claude Code Action: claude_args carrying --allowedTools Bash(echo:*)
    if re.search(rf"--allowedTools[^\n]*Bash\((?:{expandable})[:)]", text):
        return True
    # Gemini CLI: settings JSON with coreTools run_shell_command(echo)
    return bool(re.search(rf"run_shell_command\((?:{expandable})\)", text))


def vector_h(text: str) -> bool:
    """A setting that removes the sandbox rather than narrowing it.

    `--dangerously-skip-permissions` and `--permission-mode bypassPermissions` are real
    Claude CLI flags reachable through `claude_args`; `--yolo` and `danger-full-access`
    belong to the Gemini and Codex profiles. `Bash(*)` is here because a wildcard tool
    grant removes the boundary as surely as a flag does.
    """
    return bool(
        re.search(
            r"danger-full-access|--yolo|dangerously-skip-permissions"
            r"|bypassPermissions|Bash\(\*\)",
            text,
        )
    )


def vector_i(text: str) -> bool:
    """A user allowlist set to a wildcard.

    Reports the wildcard wherever it appears. `allowed_non_write_users` is documented as
    taking effect only when `github_token` is also supplied, so a workflow can carry the
    wildcard and still gate on write access; this signature counts that as a hit rather
    than deciding reachability, which keeps the count a ceiling for this vector where the
    others are floors.
    """
    return bool(re.search(r"(allowed[_-]\w*users?|allowlist)\s*:\s*[\"']?\*", text))


VECTORS = {
    "A": ("env var intermediary", vector_a),
    "B": ("direct expression injection", vector_b),
    "D": ("pull_request_target + head checkout", vector_d),
    "F": ("subshell in tool allowlist", vector_f),
    "H": ("sandbox disabled", vector_h),
    "I": ("wildcard user allowlist", vector_i),
}

UNDECIDABLE = {
    "C": "prompt instructs a runtime fetch",
    "E": "CI logs fed back as context",
    "G": "a later step evaluates agent output",
}


def _prompt_text(text: str) -> str:
    """The prompt field's value, block scalar included.

    Reading the whole file instead would let an expression anywhere in the workflow
    count as an expression in the prompt, which is the difference between vector B and
    an ordinary env assignment.
    """
    out = []
    for m in re.finditer(r"^(\s*)prompt:\s*(\|-?|>-?)?[ \t]*(.*)$", text, re.M):
        indent, block, inline = m.group(1), m.group(2), m.group(3)
        if inline:
            out.append(inline)
        if not block:
            continue
        rest = text[m.end() :].splitlines()
        for line in rest:
            if line.strip() and not line.startswith(indent + " "):
                break
            out.append(line)
    return "\n".join(out)


def self_test() -> int:
    """Every signature fires on its fixture and stays quiet on the safe twin.

    A signature that silently stops matching would report a clean corpus forever, so
    the counts this module produces are worth nothing without this passing.
    """
    failures = []
    for key, (desc, fn) in VECTORS.items():
        bad = FIXTURES / f"vector-{key.lower()}-present.yml"
        good = FIXTURES / f"vector-{key.lower()}-absent.yml"
        for path, expected in ((bad, True), (good, False)):
            if not path.exists():
                failures.append(f"{key}: fixture missing: {path.name}")
                continue
            got = fn(path.read_text())
            if got is not expected:
                state = "did not fire on" if expected else "fired on"
                failures.append(f"{key} ({desc}) {state} {path.name}")

    # A and B are the pair most easily confused: the whole point of A is that the
    # prompt holds no expression, so B must stay quiet on A's fixture.
    a_present = (FIXTURES / "vector-a-present.yml").read_text()
    if vector_b(a_present):
        failures.append("B fired on A's fixture, so the prompt-only scope is broken")

    for f in failures:
        print(f"  FAIL {f}")
    print(f"  {len(VECTORS) * 2 + 1 - len(failures)}/{len(VECTORS) * 2 + 1} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(self_test())
