# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Extract diagrams using rg, curl, mmdc, and pdftotext for local PDF inputs."""

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from calcifier import (
    Budget,
    CommandResult,
    agent,
    emit,
    ensure_directory,
    fail,
    output_type,
    prepare_context,
    recipe,
    resource,
    run_command,
    step,
    verify_artifact,
    write_text,
)


@output_type
class Summary:
    parties: str
    round_complexity: str
    key_primitives: str
    authentication: str
    forward_secrecy: str
    notable: str


@output_type
class Diagram:
    mermaid: str
    ascii_diagram: str
    summary: Summary


@output_type
class Stop:
    message: str


def summary_rows(value: Summary) -> tuple[tuple[str, str], ...]:
    return (
        ("Parties", value.parties),
        ("Round complexity", value.round_complexity),
        ("Key primitives", value.key_primitives),
        ("Authentication", value.authentication),
        ("Forward secrecy", value.forward_secrecy),
        ("Notable", value.notable),
    )


def execute(argv: list[str], *, no_match: bool = False, mutating: bool = False) -> str:
    result: CommandResult = run_command(argv, timeout_seconds=180, mutating=mutating)
    if result.exit_code != 0 and not (no_match and result.exit_code == 1):
        fail("Command failed: " + " ".join(argv) + "\n" + result.stderr)
    return result.stdout


@step
def validate_diagram(value: Diagram) -> int:
    lines = value.mermaid.strip().splitlines()
    if not lines or lines[0] != "sequenceDiagram":
        fail("Mermaid must start with sequenceDiagram, without Markdown fences.")
    declared: list[str] = []
    used: set[str] = set()
    stack: list[str] = []
    messages = 0
    phases = any(line.strip().startswith("rect ") for line in lines)
    arrow = (
        r"([A-Za-z0-9_]+)\s*(?:-->>|->>|-->|->|--x|-x|--\)|-\))"
        r"\s*[+-]?([A-Za-z0-9_]+)\s*:.+"
    )
    for line in lines[1:]:
        text = line.strip()
        declaration = re.match(r"(?:participant|actor)\s+([A-Za-z0-9_]+)", text)
        message = re.fullmatch(arrow, text)
        token = text.partition(" ")[0]
        if declaration:
            declared.append(declaration.group(1))
        elif token in {"rect", "loop", "alt", "opt", "par", "critical"}:
            stack.append(token)
        elif text == "end":
            if not stack:
                fail("Unmatched Mermaid end statement.")
            stack.pop()
        elif message:
            if phases and "rect" not in stack:
                fail("A message appears outside a phase block.")
            used.update(message.groups())
            messages += 1
    if stack or not messages or set(declared) != used or len(set(declared)) != len(declared):
        fail("Unclosed blocks, zero messages, duplicate IDs, or unused/undeclared parties.")
    if not value.ascii_diagram.strip() or not all(
        text.strip() for _, text in summary_rows(value.summary)
    ):
        fail("The ASCII diagram and all six summary fields must be nonempty.")
    return messages


@recipe(
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="protocol-diagrams",
)
def crypto_protocol_diagram(
    protocol_name: str,
    source_paths: list[str],
    spec_text: str = "",
    spec_url: str = "",
    request: str = "",
) -> str:
    if not protocol_name.strip() or not (source_paths or spec_text.strip() or spec_url):
        fail("Provide a protocol name and actual source/spec input; use [] for inline input.")
    stem = re.sub(r"[^a-z0-9]+", "-", protocol_name.lower()).strip("-") or "protocol"
    names = (stem + ".md", stem + ".mmd", stem + ".svg")
    destination = ensure_directory(".", output_files=names)
    references = (
        resource("references/spec-parsing-patterns.md"),
        resource("references/protocol-patterns.md"),
        resource("references/mermaid-sequence-syntax.md"),
        resource("references/ascii-sequence-diagram.md"),
    )
    views = list(references)
    files = list(references)
    observations: dict[str, str] = {}
    provided = [Path(path).resolve() for path in source_paths]
    directory = Path(".").resolve()
    if provided:
        directory = provided[0] if provided[0].is_dir() else provided[0].parent
    for path in provided:
        if not (path.is_file() or path.is_dir()):
            fail("Source path is not a regular file or directory: " + str(path))
        views.append(path)
        if path.is_file():
            if path.stat().st_size == 0:
                fail("Empty source file: " + str(path))
            if path.suffix.lower() == ".pdf":
                observations[str(path)] = execute(["pdftotext", "-layout", str(path), "-"])
                if not observations[str(path)].strip():
                    fail("PDF extraction inspected no text: " + str(path))
            else:
                files.append(path)
        elif not any(item.is_file() for item in path.rglob("*") if ".git" not in item.parts):
            fail("The inspection scope contains no files outside .git: " + str(path))
        if path.suffix.lower() not in {".pdf", ".pv", ".spthy"}:
            for label, pattern, extra in (
                (
                    "entry-points",
                    "handshake|session_init|round[_0-9]|setup|keygen|send_msg|recv_msg",
                    [],
                ),
                (
                    "crypto",
                    "sign|verify|encrypt|decrypt|dh|ecdh|kdf|hkdf|hmac|hash|commit|reveal|share",
                    ["--type-add", "src:*.{py,rs,go,ts,js,cpp,c}", "-t", "src"],
                ),
            ):
                observations[label + ":" + str(path)] = execute(
                    ["rg", "-l", pattern, *extra, str(path)], no_match=True
                )
    if spec_url:
        if urlsplit(spec_url).scheme not in {"http", "https"}:
            fail("Specification URLs must use HTTP or HTTPS.")
        observations["url_spec"] = execute(
            [
                "curl",
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--proto",
                "=http,https",
                "--proto-redir",
                "=http,https",
                "--max-time",
                "120",
                "--url",
                spec_url,
            ]
        )
        if not observations["url_spec"].strip():
            fail("Fetching the specification produced an empty inspection scope.")
    context = prepare_context(
        task=json.dumps(
            {
                "protocol_name": protocol_name,
                "source_paths": [str(path) for path in provided],
                "pasted_spec": spec_text,
                "spec_url": spec_url,
                "request": request,
            },
            ensure_ascii=False,
        ),
        instructions=(
            "Apply the original SKILL.md workflow to all supplied inputs in one session. "
            "Classify inputs and preserve the prescribed ordering, including spec before "
            "implementation when both exist. Perform interpretation and semantic checks; "
            "search matches are only priorities and never restrict the complete target. "
            "Use complete embedded context directly; read complete backing files when "
            "not embedded or when a file check is required. References are supplied whole. "
            "The manifest omits the examples: honor the study requirement for unfamiliar "
            "inputs, locating a supplied relevant example or explaining the blocker. "
            "Return Diagram with unfenced Mermaid, only the ASCII drawing body, and all "
            "summary fields. Python owns file writing, structural checks and rendering. "
            "Return Stop for ambiguity with the source's clarification question, for "
            "inaccessible or incomplete sources, missing prerequisites, or unsuitable "
            "requests. Do not invent omitted steps or claim unperformed checks complete. "
            "Do not modify files. Keep the original reasoning workflow intact."
        ),
        prior_results=json.dumps(observations, ensure_ascii=False),
        files=tuple(files),
        readable_roots=tuple(views),
    )
    result = agent(
        "worker",
        "Complete the assigned protocol interpretation and return Diagram or Stop.",
        working_directory=directory,
        readable_paths=tuple(views),
        required_capabilities=("commands",),
        output=Diagram | Stop,
        timeout=3600,
        context=context,
    )
    if isinstance(result, Stop):
        emit(result, name="requires-input")
        fail(result.message or "The protocol workflow requires additional input.")
    validate_diagram(result)
    mermaid_path = write_text(names[1], result.mermaid.strip() + "\n")
    execute(
        ["mmdc", "-i", str(mermaid_path), "-o", str(destination / names[2])],
        mutating=True,
    )
    summary = "## Protocol Summary\n\n" + "\n".join(
        f"- **{label}:** {text}" for label, text in summary_rows(result.summary)
    )
    markdown = (
        f"# {protocol_name} Sequence Diagram\n\n```mermaid\n"
        + result.mermaid.strip()
        + "\n```\n\n"
        + summary
        + "\n"
    )
    markdown_path = write_text(names[0], markdown)
    response = (
        f"```text\nProtocol: {protocol_name}\nOutput:   {markdown_path}\n\n"
        f"{result.ascii_diagram.strip()}\n```\n\n{summary}"
    )
    for name in names:
        verify_artifact(destination / name)
    emit({"files": [str(destination / name) for name in names]}, name="files")
    return emit(response, name="protocol-diagram")


if __name__ == "__main__":
    raise SystemExit(crypto_protocol_diagram.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("42ce173ea95fe0c0736ad5799e4d1bff8feaa12fa69abe208b831de1268d2bdf"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/code-slice-worker.md",
        "sha256": ("6b427cf3aa5caf357cd0fb18eca324b4207706bcd7e79eaff157590cd5816cb7"),
        "size": 1912,
        "source": "../../agents/code-slice-worker.md",
    },
    {
        "path": "references/ascii-sequence-diagram.md",
        "sha256": ("3eebba0a3fbfe4205f7f165c5030e42b45d0277d4b33fa979469ead0565cd7b1"),
        "size": 2365,
        "source": None,
    },
    {
        "path": "references/mermaid-sequence-syntax.md",
        "sha256": ("a7fad0d407bf498e5fed25fbf0e14431b3c0e178b9c788d9fd9e8cf56ed5c8d8"),
        "size": 7703,
        "source": None,
    },
    {
        "path": "references/protocol-patterns.md",
        "sha256": ("73b20f76afc1f9e06028e821f1c49bc69ca279ce622a76294a9f7c438966fb96"),
        "size": 11132,
        "source": None,
    },
    {
        "path": "references/spec-parsing-patterns.md",
        "sha256": ("0be275fc4015a21538985213531800827860c8a3cec8c303c60a5ec0a3a6088d"),
        "size": 11888,
        "source": None,
    },
]
_CALCIFIER_INTERFACE = {
    "text": (
        "The destination repository uses Ruff rules E, F, I, UP, B,"
        " and SIM, target-version py311, and line-length 100. The g"
        "enerated recipe must satisfy those checks, including B007,"
        " B905, and SIM102. Keep the Python 3.13 minimum required b"
        "y Calcifier in its generated PEP 723 header. This skill is"
        " distributed independently: do not require another unmerge"
        "d skill recipe. Referenced prose and explicitly provided r"
        "esources may be packaged, while the generated recipe belon"
        "gs only to the requested skill. Repository contribution ru"
        "le: a checker that inspects zero items must fail with an e"
        "xplanation rather than return a successful clean report. T"
        "his applies to an empty inspection scope, not to a complet"
        "ed inspection that finds zero issues."
    ),
    "sha256": ("12c73b0662a6bdb615688c499f4e3e22540e4788549e5ad24bb7e01f76c25fcc"),
}
_CALCIFIER_SUBRECIPES = []
