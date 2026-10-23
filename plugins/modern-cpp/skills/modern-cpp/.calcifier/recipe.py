# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Apply modern C++ guidance to a concrete task with explicit filesystem access."""

import json
from pathlib import Path
from typing import Literal

from calcifier import (
    Budget,
    agent,
    emit,
    fail,
    output_type,
    prepare_context,
    recipe,
    resource,
    step,
)

REFERENCE_NAMES = (
    "references/anti-patterns.md",
    "references/compiler-hardening.md",
    "references/cpp20-features.md",
    "references/cpp23-features.md",
    "references/cpp26-features.md",
    "references/safe-idioms.md",
)


@output_type
class CppAnswer:
    answer: str


@step
def inventory_scope(
    directory: str,
    targets: tuple[str, ...],
    allow_missing: bool,
) -> list[str]:
    """Inventory existing files without selecting semantic review candidates."""
    root = Path(directory).resolve()
    found: set[str] = set()
    for target in targets or (".",):
        selected = (root / target).resolve()
        if not selected.is_relative_to(root):
            fail(f"Target escapes the project directory: {target}")
        if ".git" in selected.relative_to(root).parts:
            fail(f"Git metadata is outside the task scope: {target}")
        if not selected.exists():
            if allow_missing:
                continue
            fail(f"Target does not exist: {target}")
        if selected.is_file():
            candidates = (selected,)
        elif selected.is_dir():
            candidates = selected.rglob("*")
        else:
            fail(f"Target is not a regular file or directory: {target}")
        for candidate in candidates:
            if ".git" in candidate.relative_to(root).parts:
                continue
            if not candidate.is_file():
                continue
            resolved = candidate.resolve()
            if not resolved.is_relative_to(root):
                fail(f"Scope contains a file escaping the project: {candidate}")
            found.add(candidate.relative_to(root).as_posix())
    return sorted(found)


@recipe(
    version="1",
    name="modern_cpp",
    agents=("worker",),
    capabilities=(),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def modern_cpp(
    task: str,
    project_directory: str = ".",
    mode: Literal["advise", "review", "edit"] = "review",
    targets: tuple[str, ...] = (),
) -> CppAnswer:
    """Advise, review, or edit using the authoritative modern-cpp skill."""
    if not task.strip():
        fail("Provide a concrete C++ task.")
    root = Path(project_directory).resolve()
    if not root.is_dir():
        fail("The project directory must be an existing directory.")
    inventory = inventory_scope(str(root), targets, mode == "edit")
    if mode == "review" and not inventory:
        fail("The review scope contains no files; an empty inspection cannot be clean.")

    references = tuple(resource(name) for name in REFERENCE_NAMES)
    observations = {
        "mode": mode,
        "project_directory": str(root),
        "requested_targets": list(targets) if targets else ["."],
        "existing_files": inventory,
        "reference_files": {
            name: str(path) for name, path in zip(REFERENCE_NAMES, references, strict=True)
        },
    }
    context = prepare_context(
        task,
        instructions=(
            "Perform the user's task under the authoritative modern-cpp skill. "
            "Keep its connected reasoning, applicability decisions, priorities, "
            "feature tiers, cautions, and checks in this session. The mode grants "
            "editing only when it is 'edit'; 'review' and 'advise' are read-only. "
            "Targets define the task scope; the project is available for context. "
            "The inventory is mechanical preparation, not a semantic candidate "
            "filter or evidence that an inspection has happened. Inspect the whole "
            "declared target relevant to the task. Reference files are available "
            "in full through your filesystem view. Use their complete supplied "
            "text directly, or read the complete applicable files when needed; "
            "access alone does not complete their interpretation. Preserve user "
            "constraints and resolve uncertain C++ choices through the original "
            "guidance, without inventing a migration or build-system procedure. "
            "For review, an empty applicable inspection must be explained as "
            "incomplete or out of scope, never reported as a successful clean review. "
            "Return the complete user-facing answer, including actual findings or "
            "changes and any unresolved limitations. State verification only when "
            "it was performed. Use the embedded assignment directly; read task.txt "
            "from the context bundle if the assignment was not embedded."
        ),
        prior_results=json.dumps(observations, ensure_ascii=False),
    )
    result = agent(
        "worker",
        "Complete the supplied task and return its complete answer in CppAnswer.",
        working_directory=root,
        readable_paths=(root, *references),
        writable_paths=(root,) if mode == "edit" else (),
        required_capabilities=("commands",) if mode == "edit" else (),
        output=CppAnswer,
        timeout=3600,
        context=context,
    )
    if not result.answer.strip():
        fail("The agent returned no user-facing answer.")
    return emit(result, name="modern-cpp-answer")


if __name__ == "__main__":
    raise SystemExit(modern_cpp.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("a3a886fc425c591202b18165aa587111fafdd9250c37a71bbc48f7285fcd3c3e"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/anti-patterns.md",
        "sha256": ("b0c4cdfbcaf90653b603aece91d1695b61592851acd39e93a79c40c92f54b35c"),
        "size": 5630,
        "source": None,
    },
    {
        "path": "references/compiler-hardening.md",
        "sha256": ("7965180ea742a1c59db75f4c8df8fa1f5a8cdf67d8d1a30f6b8b9705cdcb3902"),
        "size": 7471,
        "source": None,
    },
    {
        "path": "references/cpp20-features.md",
        "sha256": ("5498d853cdfb0be5e29c3c1bd55121cc166a0e0cb972d7733e8cbd5aa94a99b7"),
        "size": 7138,
        "source": None,
    },
    {
        "path": "references/cpp23-features.md",
        "sha256": ("feb1b1b5d80eecdbbde5396c3e0675ddba2c13c4c5d187b3b36d9b716e648015"),
        "size": 7150,
        "source": None,
    },
    {
        "path": "references/cpp26-features.md",
        "sha256": ("9984022424fedfe5ba97b2f17f83007ec14f394d8e7054d559951c7dd04118cb"),
        "size": 7696,
        "source": None,
    },
    {
        "path": "references/safe-idioms.md",
        "sha256": ("9c46fd20cfc0ea24ce49dfec13cd9f463528a4b4c691b78eb90df84c1682ed9a"),
        "size": 8316,
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
