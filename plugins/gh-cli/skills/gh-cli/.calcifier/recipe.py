from pathlib import Path

from calcifier import Budget, agent, emit, recipe


@recipe(
    name="gh_cli",
    agents=("worker",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def gh_cli(task: str, working_directory: str = ".") -> str:
    directory = Path(working_directory).resolve()
    result = agent(
        "worker",
        "Complete the user's task using the authoritative gh-cli skill guidance. "
        "Keep interpretation, execution, and verification in this session. "
        "Determine whether the task concerns GitHub or is solved by local git. "
        "For GitHub content, prefer authenticated gh commands; for repository "
        "files, prefer cloning and reading locally. Follow the source guidance "
        "on avoiding contents endpoints and unauthenticated fetches. "
        "The referenced hook implementation is not packaged; inspect it only "
        "if available in the provided filesystem and relevant to the task. "
        "Perform authorized work and report the concrete result, verification, "
        "and any unresolved blockers. Never claim an operation succeeded without "
        "evidence. Agents must not commit; if a commit is required, report that "
        "remaining action explicitly.\n\nUser task:\n{task}",
        task=task,
        working_directory=directory,
        readable_paths=(directory,),
        writable_paths=(directory,),
        output=str,
        timeout=3600,
    )
    return emit(result, name="result")


if __name__ == "__main__":
    raise SystemExit(gh_cli.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("3810c9ff56ae9a26f4c6c1e0d058a946cd97e800441630208007a0983b9cfc49"),
}
_CALCIFIER_RESOURCES = []
_CALCIFIER_SUBRECIPES = []
