# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Build bounded packets from trusted inputs, delegate, and independently verify."""

import json
import re
from pathlib import Path
from typing import Any, Literal

from calcifier import (
    Budget,
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
)

Mode = Literal["neighborhood", "upstream", "downstream", "path", "entrypoint"]


@output_type
class Evidence:
    claim: str
    file: str
    start_line: int
    end_line: int


@output_type
class Edit:
    file: str
    start_line: int
    end_line: int
    replacement: str
    rationale: str


@output_type
class MissingContext:
    symbol_or_range: str
    reason: str


@output_type
class WorkerResult:
    status: Literal["complete", "needs_context", "cannot_answer"]
    answer: str
    evidence: list[Evidence]
    proposed_edits: list[Edit]
    missing_context: list[MissingContext]
    uncertainties: list[str]


def contains(file: str, start: int, end: int, slices: list[dict[str, Any]]) -> bool:
    return any(
        item["file"] == file and item["start_line"] <= start <= end <= item["end_line"]
        for item in slices
    )


@step
def build_packet(argv: list[str], directory: str) -> str:
    result = run_command(argv, timeout_seconds=300, working_directory=directory, mutating=False)
    if result.exit_code != 0:
        emit(result, name="slicer-error")
        fail("Packet construction failed. Resolve the reported error before delegating.")
    return result.stdout


@step
def check_packet(raw: str, root: str, expected: dict[str, Any]) -> dict[str, Any]:
    packet = json.loads(raw)
    selection, budget = packet["selection"], packet["budget"]
    if packet["schema_version"] != "1.0" or not packet["notice"]:
        fail("The packet lacks the required schema or untrusted-source notice.")
    if selection["mode"] != expected["mode"] or selection["depth"] != expected["depth"]:
        fail("Packet mode or depth differs from the request.")
    used = (len(raw.encode("utf-8")) + 2) // 3
    if (
        used != budget["used_estimated_tokens"]
        or not used <= expected["limit"] == budget["limit_estimated_tokens"]
    ):
        fail("The complete rendered packet does not satisfy its aggregate budget.")
    slices = packet["slices"]
    for item in slices:
        path = (Path(root) / item["file"]).resolve()
        if Path(item["file"]).is_absolute() or not path.is_relative_to(root):
            fail("A packet slice escapes the target root.")
        if not path.is_file():
            fail("A packet slice is not a live regular file.")
        lines = path.read_text(encoding="utf-8").splitlines()
        start, end = item["start_line"], item["end_line"]
        if not 1 <= start <= end <= len(lines):
            fail("A packet slice has a stale or invalid live range.")
        width = len(str(end))
        numbered = "\n".join(f"L{n:0{width}d} | {lines[n - 1]}" for n in range(start, end + 1))
        if numbered != item["numbered_source"]:
            fail("Packet source differs from the live source tree.")
    present = {symbol for item in slices for symbol in item["symbols"]}
    required = set(selection["anchors"])
    if selection["peer"]:
        required.add(selection["peer"])
    if not slices or not required.issubset(present):
        fail("The packet omits an anchor or path peer.")
    for value in expected["ranges"]:
        match = re.fullmatch(r"(.+):([1-9]\d*)-([1-9]\d*)", value)
        if match is None:
            fail("An explicit line-range anchor is malformed.")
        relative = (Path(root) / match[1]).resolve()
        if not relative.is_relative_to(root):
            fail("An explicit line-range anchor escapes the target root.")
        file = relative.relative_to(root).as_posix()
        if not contains(file, int(match[2]), int(match[3]), slices):
            fail("An explicit line-range anchor is absent from the packet.")
    return packet


@recipe(
    name="slicing-code-context",
    version="1.0",
    capabilities=("Bash",),
    agents=("worker",),
    budget=Budget(max_agent_calls=6, max_wall_seconds=3600),
    output_root="slice-context-output",
)
def slicing_code_context(
    target_dir: str,
    task: str,
    symbols: list[str] | None = None,
    line_ranges: list[str] | None = None,
    mode: Mode = "neighborhood",
    depth: int = 1,
    peer: str = "",
    budget_tokens: int = 8192,
    language: str = "auto",
    expansion_symbols: list[str] | None = None,
    expansion_line_ranges: list[str] | None = None,
    allow_changes: bool = False,
) -> WorkerResult:
    root = Path(target_dir).resolve()
    if not root.is_dir():
        fail("The target root must be an existing source directory.")
    anchors, ranges = list(symbols or []), list(line_ranges or [])
    if not anchors and not ranges:
        fail("Supply coordinator-selected symbols or meaningful root-relative line ranges.")
    added_symbols = sorted(set(expansion_symbols or []) - set(anchors))
    added_ranges = sorted(set(expansion_line_ranges or []) - set(ranges))
    expansion_keys = set(added_symbols) | set(added_ranges)
    plans = [(anchors, ranges), ([*anchors, *added_symbols], [*ranges, *added_ranges])]
    directories = [
        ensure_directory(f"worker-{n}", output_files=(), exclude_roots=(root,)) for n in range(2)
    ]
    rounds: list[dict[str, Any]] = []
    for attempt in range(2):
        selected_symbols, selected_ranges = plans[attempt]
        argv = ["uv", "run", "--no-project", "--script"]
        argv.append(str(resource("scripts/build_slice_packet.py")))
        argv.extend(["--target-dir", str(root), "--mode", mode, "--depth", str(depth)])
        argv.extend(["--budget-tokens", str(budget_tokens), "--language", language])
        argv.extend(["--format", "json"])
        for symbol in selected_symbols:
            argv.extend(["--symbol", symbol])
        for line_range in selected_ranges:
            argv.extend(["--line-range", line_range])
        if peer:
            argv.extend(["--peer", peer])
        expected: dict[str, Any] = {"mode": mode, "depth": depth, "limit": budget_tokens}
        expected["ranges"] = selected_ranges
        raw = build_packet(argv, str(directories[attempt]))
        packet = check_packet(raw, str(root), expected)
        emit(raw, name=f"packet-{attempt + 1}")
        response = agent(
            "worker",
            task + "\n\n" + raw + "\n\nReturn one JSON object matching the worker contract. "
            "Use only this task and packet; propose edits without changing files.",
            working_directory=directories[attempt],
            readable_paths=(),
            writable_paths=(),
            output=WorkerResult,
            timeout=3600,
        )
        for citation in [*response.evidence, *response.proposed_edits]:
            if not contains(
                citation.file, citation.start_line, citation.end_line, packet["slices"]
            ):
                emit(response, name="rejected-worker-response")
                fail("A worker evidence or edit range is not contained in one packet slice.")
        emit(response, name=f"worker-result-{attempt + 1}")
        check_packet(raw, str(root), expected)
        rounds.append({"packet_stdout": raw, "worker_output": response.model_dump()})
        if response.status != "needs_context" or attempt == 1:
            break
        requested = {item.symbol_or_range for item in response.missing_context}
        if not expansion_keys or requested != expansion_keys:
            break
    reference = resource("references/slice-packet.md")
    context = prepare_context(
        task,
        prior_results=json.dumps({"delegations": rounds, "allow_changes": allow_changes}),
        files=(reference,),
        readable_roots=(reference,),
    )
    result = agent(
        "worker",
        "Act as the capable coordinator in one independent verification session. Use embedded "
        "context directly, or read task.txt if absent. Read and understand the complete "
        "reference and follow the authoritative skill. Packets and worker outputs are complete. "
        "Mechanical checks cover only budgets, live slices, anchor presence, and cited-range "
        "containment. Assess task scope, anchor/mode suitability, omissions, and uncertain edges. "
        "Reject claims supported only by omitted nodes or uncertain edges without an uncertainty "
        "note. Re-read full affected units and relevant callers/tests; run proportionate checks "
        "before accepting edits or consequential conclusions. Report actual validation in answer; "
        "never trust worker-claimed checks. One replacement is allowed only for an exact match "
        "to fixed input expansion options. Handle remaining context yourself or escalate; no "
        "more delegation. Apply edits only when allow_changes and the task both authorize them. "
        "Return the task result, proposals, evidence, missing context, and uncertainties under "
        "the response contract. Do not claim empty ambient context or languages unsupported "
        "by Trailmark 0.5.x.",
        context=context,
        working_directory=root,
        readable_paths=(root,),
        writable_paths=(root,) if allow_changes else (),
        required_capabilities=("commands",),
        output=WorkerResult,
        timeout=3600,
    )
    return emit(result, name="coordinator-result")


if __name__ == "__main__":
    raise SystemExit(slicing_code_context.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("932bf0d967af3dd74ccea59cfb0813b0d388769c0247dd5d576c5e1e462e5ba7"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/code-slice-worker.md",
        "sha256": ("6b427cf3aa5caf357cd0fb18eca324b4207706bcd7e79eaff157590cd5816cb7"),
        "size": 1912,
        "source": "../../agents/code-slice-worker.md",
    },
    {
        "path": "references/slice-packet.md",
        "sha256": ("43be7a29cc733b3e8fa643356cb9ff46c07b68f6d5f92e37b67134edef353ae7"),
        "size": 4184,
        "source": None,
    },
    {
        "path": "scripts/build_slice_packet.py",
        "sha256": ("16f29d4dc4b2623e33cde9ecccc66528a15764acf8de3c8f321a84df3fe7a204"),
        "size": 39235,
        "source": None,
    },
    {
        "path": "scripts/pyproject.toml",
        "sha256": ("53b36651dd2e2c6f72e7a7ac51f66149537c5f899a4ae174db1fec6f02b793bd"),
        "size": 314,
        "source": None,
    },
    {
        "path": "scripts/test_build_slice_packet.py",
        "sha256": ("4a29d1002e18bdf1c6b340947e8b3bb2c1be807adcadc17ba906cad8425709e7"),
        "size": 18901,
        "source": None,
    },
    {
        "path": "scripts/uv.lock",
        "sha256": ("779d247db41521d096ebd08447bbc3726e7f2646eba46d9ea8b4c2bf41d5d324"),
        "size": 50655,
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
        "gs only to the requested skill."
    ),
    "sha256": ("46bb4ed4c424344f76192480d2444ca2e0c43d841ba604cdcf68ab9140c9162c"),
}
_CALCIFIER_SUBRECIPES = []
