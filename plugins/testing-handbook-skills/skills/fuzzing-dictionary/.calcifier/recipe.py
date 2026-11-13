# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Build focused fuzzing dictionaries and prepare fuzzer commands."""

import codecs
import re
import sys
from pathlib import Path
from typing import Literal

from calcifier import (
    Budget,
    agent,
    emit,
    ensure_directory,
    fail,
    output_type,
    prepare_context,
    recipe,
    run_command,
    step,
    verify_artifact,
    write_json,
    write_text,
)


@output_type
class Evidence:
    candidate_hex: list[str]
    origins: list[str]
    manuals: dict[str, str]


@output_type
class Decision:
    apply: bool
    selected_indices: list[int]
    additional_hex: list[str]
    guidance: str


@output_type
class Report:
    dictionary: str
    entries: int
    working_directory: str
    commands: dict[str, list[str]]
    guidance: str
    checks: str


QUOTED = re.compile(r'"((?:[^"\\\r\n]|\\.)*)"')
ESCAPED = re.compile(r'(?:[^"\\]|\\(?:[\\"abfnrtv]|x[0-9a-fA-F]{2}|[0-7]{1,3}))*')
SEED_SCRIPT = (
    "import json, sys\n"
    "from pathlib import Path\n"
    "values = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))\n"
    "for index, value in enumerate(values):\n"
    "    (Path(sys.argv[2]) / f'token-{index:04d}').write_bytes(bytes.fromhex(value))\n"
)


def parse_dictionary(text: str) -> list[bytes]:
    entries: list[bytes] = []
    for number, line in enumerate(text.splitlines(), 1):
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        match = re.fullmatch(r'(?:[A-Za-z_]\w*(?:@\d+)?\s*=\s*)?"((?:[^"\\]|\\.)*)"', item)
        if match is None or ESCAPED.fullmatch(match[1]) is None:
            fail(f"Invalid dictionary syntax or escape at line {number}.")
        value = codecs.escape_decode(match[1].encode("utf-8"))[0]
        if not value:
            fail(f"Empty dictionary token at line {number}.")
        entries.append(value)
    if not entries:
        fail("Dictionary validation inspected zero entries.")
    return entries


def checked_file(root: Path, name: str) -> Path:
    path = (root / name).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        fail(f"Input is not a regular file within the project: {name}")
    return path


@step
def extract(root: str, inputs: dict[str, tuple[str, ...]]) -> Evidence:
    directory = Path(root)
    found: dict[str, set[str]] = {}
    manual_text: dict[str, str] = {}

    def add(value: bytes, origin: str) -> None:
        if value:
            found.setdefault(value.hex(), set()).add(origin)

    for name in inputs["sources"]:
        text = checked_file(directory, name).read_text(encoding="utf-8")
        for match in QUOTED.finditer(text):
            if ESCAPED.fullmatch(match[1]) is not None:
                add(codecs.escape_decode(match[1].encode("utf-8"))[0], name)
    for name in inputs["dictionaries"]:
        for value in parse_dictionary(checked_file(directory, name).read_text(encoding="utf-8")):
            add(value, name)
    for kind, names in (("binary", inputs["binaries"]), ("manual", inputs["manuals"])):
        for name in names:
            if kind == "binary":
                argv = ["strings", "-a", str(checked_file(directory, name))]
            else:
                argv = ["env", "MANPAGER=cat", "PAGER=cat", "man", name]
            result = run_command(argv, timeout_seconds=30, working_directory=root, mutating=False)
            if result.exit_code:
                fail(f"Extraction failed for {name}: {result.stderr}")
            if kind == "binary":
                for line in result.stdout.splitlines():
                    add(line.encode("utf-8"), name)
            else:
                text = re.sub(r".\x08", "", result.stdout)
                manual_text[name] = text
                for option in re.findall(r"(?m)^\s*(--?[\w][\w-]*)", text):
                    add(option.encode("utf-8"), f"man:{name}")
    keys = sorted(found)
    return Evidence(keys, ["; ".join(sorted(found[key])) for key in keys], manual_text)


@recipe(
    name="fuzzing_dictionary",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="fuzzing-dictionary-output",
)
def fuzzing_dictionary(
    target: str,
    fuzz_argv: list[str],
    fuzzer: Literal["libfuzzer", "afl++", "cargo-fuzz", "go-fuzz"] = "libfuzzer",
    project_dir: str = ".",
    sources: tuple[str, ...] = (),
    binaries: tuple[str, ...] = (),
    manuals: tuple[str, ...] = (),
    dictionaries: tuple[str, ...] = (),
    maximum_entries: int = 200,
) -> Report:
    root = Path(project_dir).resolve()
    if not root.is_dir() or not target.strip() or not fuzz_argv or maximum_entries < 1:
        fail("Provide a project, target, baseline argv and positive entry limit.")
    if any(arg == "-x" or arg.startswith("-dict=") for arg in fuzz_argv):
        fail("Baseline argv must omit dictionary flags and start with the fuzzer executable.")
    if fuzzer == "go-fuzz" and any(arg.startswith("-workdir") for arg in fuzz_argv):
        fail("For go-fuzz, omit -workdir; the recipe creates the seeded work directory.")
    seed_names = tuple(f"token-{i:04d}" for i in range(maximum_entries))
    outputs = ("dictionary.dict", "report.json")
    if fuzzer == "go-fuzz":
        outputs += ("seed-data.json", *(f"corpus/{name}" for name in seed_names))
    inputs = dict(sources=sources, binaries=binaries, manuals=manuals, dictionaries=dictionaries)
    evidence = extract(str(root), inputs)
    files = tuple(checked_file(root, name) for name in (*sources, *dictionaries))
    context = prepare_context(
        f"Target: {target}\nFuzzer: {fuzzer}\nBaseline argv: {fuzz_argv!r}\n"
        f"Maximum entries: {maximum_entries}\nDeclared inputs: {inputs!r}",
        prior_results=evidence.model_dump_json(),
        files=files,
        readable_roots=(root,),
    )
    decision = agent(
        "worker",
        "Follow the full source skill for this target and every declared input. Use embedded "
        "context directly; read backing files if absent or checking. Extraction is heuristic: "
        "inspect complete inputs and verify token bytes. Decide applicability, then return "
        "zero-based selected_indices into candidate_hex and additional_hex as hex byte strings. "
        "Respect maximum_entries; prefer 50-200 focused tokens. Include integration, max_len, "
        "applicable auto-dictionary, troubleshooting and with/without coverage comparisons. "
        "Explain skips; analyze only. Do not change files or claim unperformed builds or runs.",
        working_directory=root,
        readable_paths=(root,),
        required_capabilities=("commands",),
        output=Decision,
        context=context,
        timeout=3600,
    )
    if not decision.guidance.strip():
        fail("The applicability and integration guidance is missing.")
    if not decision.apply:
        report = Report("", 0, str(root), {"baseline": fuzz_argv}, decision.guidance, "Skipped.")
        return emit(report, name="dictionary-report")
    values: list[bytes] = []
    for index in decision.selected_indices:
        if not 0 <= index < len(evidence.candidate_hex):
            fail("The agent selected an unknown candidate index.")
        values.append(bytes.fromhex(evidence.candidate_hex[index]))
    for value in decision.additional_hex:
        if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", value) is None:
            fail("Additional tokens must be nonempty hexadecimal byte strings.")
        values.append(bytes.fromhex(value))
    values = list(dict.fromkeys(values))
    if not values or len(values) > maximum_entries:
        fail("Selection must contain 1 to maximum_entries distinct nonempty tokens.")
    lines = ["# Reviewed target tokens; scope and usage are recorded in report.json."]
    lines += ['"' + "".join(f"\\x{byte:02X}" for byte in value) + '"' for value in values]
    text = "\n".join(lines) + "\n"
    if parse_dictionary(text) != values:
        fail("Dictionary byte round-trip validation failed.")
    destination = ensure_directory(".", output_files=outputs)
    dictionary = destination / "dictionary.dict"
    write_text("dictionary.dict", text)
    command = list(fuzz_argv)
    if fuzzer == "afl++":
        command = [fuzz_argv[0], "-x", str(dictionary), *fuzz_argv[1:]]
    elif fuzzer == "go-fuzz":
        corpus = ensure_directory("corpus", output_files=seed_names)
        write_json("seed-data.json", [value.hex() for value in values])
        result = run_command(
            [sys.executable, "-c", SEED_SCRIPT, str(destination / "seed-data.json"), str(corpus)],
            timeout_seconds=30,
            working_directory=destination,
            mutating=True,
        )
        if result.exit_code:
            fail(f"Corpus seeding failed: {result.stderr}")
        command.append(f"-workdir={destination}")
    else:
        if fuzzer == "cargo-fuzz" and "--" not in command:
            command.append("--")
        command.append(f"-dict={dictionary}")
    verify_artifact(dictionary)
    report = Report(
        str(dictionary),
        len(values),
        str(root),
        {"baseline": fuzz_argv, "with_dictionary": command},
        decision.guidance,
        "Byte round trip checked; fuzzer loading and coverage unmeasured.",
    )
    write_json("report.json", report.model_dump())
    return emit(report, name="dictionary-report")


if __name__ == "__main__":
    raise SystemExit(fuzzing_dictionary.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("b71fa7cab36ca466647123efa07c665c1968661f6d5060d9ac0cbb7f7599f7e0"),
}
_CALCIFIER_RESOURCES = []
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
