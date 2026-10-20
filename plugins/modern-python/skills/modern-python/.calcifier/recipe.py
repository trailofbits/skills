from pathlib import Path
from typing import Literal
from uuid import uuid4

from calcifier import (
    Budget,
    agent,
    emit,
    fail,
    output_type,
    prepare_context,
    recipe,
    resource,
    run_command,
    step,
)

REFERENCE_PATHS = (
    "references/dependabot.md",
    "references/migration-checklist.md",
    "references/pep723-scripts.md",
    "references/prek.md",
    "references/pyproject.md",
    "references/ruff-config.md",
    "references/security-setup.md",
    "references/testing.md",
    "references/uv-commands.md",
    "templates/dependabot.yml",
    "templates/pre-commit-config.yaml",
)
EXCLUDED = {".git", ".venv", "venv", "__pycache__", ".ruff_cache", ".ty"}


@output_type
class WorkResult:
    outcome: Literal["completed", "needs_input", "blocked"]
    report: str
    changed_files: list[str]
    verification: list[str]
    remaining_work: list[str]
    questions: list[str]


@step
def inventory(directory: str) -> list[str]:
    root = Path(directory)
    pending = [root]
    files: list[str] = []
    while pending:
        current = pending.pop()
        for entry in sorted(current.iterdir()):
            if entry.is_symlink() or entry.name in EXCLUDED:
                continue
            if entry.is_dir():
                pending.append(entry)
            elif entry.is_file():
                files.append(str(entry.relative_to(root)))
    return sorted(files)


@step
def migration_backup(directory: str) -> str:
    probe = run_command(
        ["git", "rev-parse", "--show-toplevel"],
        working_directory=directory,
        timeout_seconds=30,
        mutating=False,
    )
    if probe.exit_code != 0:
        fail("Migration requires a Git repository so a backup branch can be created first.")
    branch = "modern-python-backup-" + uuid4().hex
    result = run_command(
        ["git", "branch", branch],
        working_directory=directory,
        timeout_seconds=30,
    )
    if result.exit_code != 0:
        fail("Could not create migration backup branch: " + result.stderr)
    return branch


@recipe(
    name="modern_python",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def modern_python(
    task: str,
    directory: str,
    mode: Literal["script", "new-project", "new-package", "migrate", "configure"],
    bootstrap: Literal["undecided", "manual", "cookiecutter"] = "undecided",
) -> WorkResult:
    root = Path(directory).resolve()
    if not root.is_dir():
        fail("directory must identify an existing writable project or workspace directory.")
    files = inventory(str(root))
    backup = ""
    if mode == "migrate":
        backup = migration_backup(str(root))
    references = tuple(resource(path) for path in REFERENCE_PATHS)
    context = prepare_context(
        task=task,
        prior_results=(
            f"Requested mode: {mode}\nBootstrap preference: {bootstrap}\n"
            f"Backup branch: {backup}\n"
            "Complete file inventory, excluding Git internals, environments, and caches:\n"
            + "\n".join(files)
        ),
    )
    result = agent(
        "worker",
        "Carry out the requested modern-python work in this workspace, following the "
        "authoritative source skill and its references. Keep assessment, implementation, "
        "migration cleanup, and verification connected in this session and in their "
        "source-stated order. The inventory is mechanical preparation, not a semantic "
        "selection of relevant files. Inspect the complete applicable project or script. "
        "Read applicable reference and template files in full from the declared readable "
        "paths before interpreting or applying them. Use embedded task context directly; "
        "read task.txt if the context was not embedded. Respect exclusions and user wishes "
        "about legacy tooling and Python compatibility. For a new full project, an "
        "undecided bootstrap preference requires asking whether to use the Trail of Bits "
        "cookiecutter template before bootstrapping; return needs_input with that question. "
        "Otherwise implement the authorized work, including configuration, dependency "
        "management through uv, applicable migration cleanup, and source-required checks. "
        "Review every imported dependency before adding it; do not directly edit dependency "
        "sections. Resolve current stable hook versions and action SHAs when needed; "
        "do not leave placeholders. Preserve unrelated changes and do not overwrite dirty "
        "work on the assumption that the backup branch contains it. Do not commit or "
        "modify Git internals. Report actual checks, failures, unresolved choices, and "
        "remaining work accurately. Return completed only when the requested work and "
        "applicable checks are complete. Do not publish or run application example code "
        "unless the task calls for it.",
        working_directory=root,
        readable_paths=references,
        writable_paths=(root,),
        context=context,
        output=WorkResult,
        timeout=3600,
    )
    if not result.report.strip():
        fail("The worker returned no report.")
    emit(result, name="modern-python")
    if backup:
        emit(backup, name="backup-branch")
    return result


if __name__ == "__main__":
    raise SystemExit(modern_python.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("ef774b925eb1d1fc12e4f5ddc3f5ad925ecd795315827447228c70cc44c6170c"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/dependabot.md",
        "sha256": ("d3678e32472305c0ef136bca99b26c3f75554d63675930e396f26a91a97451ad"),
        "size": 1800,
        "source": None,
    },
    {
        "path": "references/migration-checklist.md",
        "sha256": ("58c947e6200a91f350c9adc898af7fc6263fda41d36ae81ffd4dd923b3a1015e"),
        "size": 3071,
        "source": None,
    },
    {
        "path": "references/pep723-scripts.md",
        "sha256": ("c348b136613a4fed8f623d6013c0c6413d2c24f2973b2e5f85b80ecc68646045"),
        "size": 5134,
        "source": None,
    },
    {
        "path": "references/prek.md",
        "sha256": ("4be1c181c71aab64ba58573242a1c451d576a5c61ceeb400bb5827f4e1f9532a"),
        "size": 5951,
        "source": None,
    },
    {
        "path": "references/pyproject.md",
        "sha256": ("aec906835ec687024700d31e5c146baaabc9524129384304857b3aa81809401b"),
        "size": 5694,
        "source": None,
    },
    {
        "path": "references/ruff-config.md",
        "sha256": ("8d247862f1beaf76816ed6775f5a0c8dc96d74c7f2b71bbf1aaedc4937373b17"),
        "size": 5476,
        "source": None,
    },
    {
        "path": "references/security-setup.md",
        "sha256": ("32d6754a87d5006f923706d10446cc617cb22d36cfc30b55d39bd7f4c61d864c"),
        "size": 6504,
        "source": None,
    },
    {
        "path": "references/testing.md",
        "sha256": ("82e36068fbf28a9615d3c96e5d946e304ce8f89ae1ba7475d20934501d55b0d9"),
        "size": 5214,
        "source": None,
    },
    {
        "path": "references/uv-commands.md",
        "sha256": ("348cd69e8c780a0c7d54a2fac3c2956c7efe5630229782753da1685416672cdc"),
        "size": 4653,
        "source": None,
    },
    {
        "path": "templates/dependabot.yml",
        "sha256": ("a85ede8ff9cc3a2f63cb1fba24e65c36a5885ecc95722af15157dc5258f28a12"),
        "size": 958,
        "source": None,
    },
    {
        "path": "templates/pre-commit-config.yaml",
        "sha256": ("18efd067e75cba5fc71705c2f90c548a03c3cded4cd2a7f9b4a1d617e115db0d"),
        "size": 2259,
        "source": None,
    },
]
_CALCIFIER_SUBRECIPES = []
