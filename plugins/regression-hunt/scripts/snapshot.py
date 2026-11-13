"""Export two explicit Git revisions without changing the source checkout."""

import argparse
import json
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO


def _git(
    repository: Path,
    *arguments: str,
    output: BinaryIO | None = None,
    input_data: bytes | None = None,
) -> bytes:
    """Run a read-only Git command, raising an actionable error on failure."""
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        input=input_data,
        stdout=output if output is not None else subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip()
        raise ValueError(f"git {arguments[0]} failed in {repository}: {detail}")
    return result.stdout or b""


def _extract_archive(archive: BinaryIO, destination: Path) -> None:
    """Extract Git archive entries while rejecting escapes and unsupported data."""
    with tarfile.open(fileobj=archive, mode="r:") as contents:
        for member in contents:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or ".git" in path.parts:
                raise ValueError(f"Unsafe archive path: {member.name}")
            if not (member.isdir() or member.isfile() or member.issym()):
                raise ValueError(f"Unsupported archive entry: {member.name}")
            if member.isfile():
                stream = contents.extractfile(member)
                if stream is None:
                    raise ValueError(f"Cannot read archive entry: {member.name}")
                with stream:
                    prefix = stream.read(1024)
                if prefix.split(b"\n", 1)[0].rstrip(b"\r") == (
                    b"version https://git-lfs.github.com/spec/v1"
                ):
                    raise ValueError(
                        f"Git LFS pointer at {member.name}; materialize and document LFS "
                        "content separately before proceeding."
                    )
            contents.extract(member, destination, filter="data")


def _export_tree(repository: Path, revision: str, destination: Path) -> None:
    """Export a revision without fetching dependencies or running content filters."""
    entries = _git(repository, "ls-tree", "-r", "-t", "-z", revision).split(b"\0")
    if any(entry.startswith(b"160000 ") for entry in entries):
        raise ValueError(
            f"Revision {revision} contains submodules; materialize and document their "
            "pinned contents separately before proceeding."
        )
    paths = b"\0".join(entry.split(b"\t", 1)[1] for entry in entries if entry)
    attributes = _git(
        repository,
        "check-attr",
        f"--source={revision}",
        "-z",
        "--stdin",
        "export-ignore",
        "export-subst",
        input_data=paths + b"\0" if paths else b"",
    ).split(b"\0")
    if any(value not in (b"unspecified", b"unset") for value in attributes[2::3]):
        raise ValueError(
            f"Revision {revision} uses export-ignore/export-subst; Git archive would alter "
            "its contents. Prepare an independently verified snapshot instead."
        )
    destination.mkdir()
    with tempfile.TemporaryFile() as archive:
        _git(repository, "archive", "--format=tar", revision, output=archive)
        archive.seek(0)
        _extract_archive(archive, destination)


def snapshot(repository: Path, s0_ref: str, s1_ref: str, output: Path) -> None:
    """Publish pristine exports and change evidence for two pinned Git commits.

    Args:
        repository: Existing source checkout; it is only read.
        s0_ref: Explicit baseline commit or revision expression.
        s1_ref: Explicit candidate commit or revision expression.
        output: New directory outside the source checkout, with an existing parent.

    Raises:
        ValueError: Revisions, output location, or source contents are unsupported.
        OSError: An external command or filesystem operation fails.
        tarfile.TarError: An archive is malformed or unsafe.
    """
    if output.exists() or output.is_symlink():
        raise ValueError(f"Output already exists: {output}; choose a new directory.")
    repository = Path(_git(repository, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    output = output.resolve()
    if output.is_relative_to(repository):
        raise ValueError("Output must be outside the source checkout.")
    revisions = [
        _git(repository, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")
        .decode()
        .strip()
        for ref in (s0_ref, s1_ref)
    ]
    s0, s1 = revisions
    if s0 == s1:
        raise ValueError("S0 and S1 resolve to the same commit; choose distinct revisions.")
    metadata = {
        "repository": str(repository),
        "s0": s0,
        "s1": s1,
        "tree0": _git(repository, "rev-parse", f"{s0}^{{tree}}").decode().strip(),
        "tree1": _git(repository, "rev-parse", f"{s1}^{{tree}}").decode().strip(),
    }
    with tempfile.TemporaryDirectory(prefix=f".{output.name}-", dir=output.parent) as temporary:
        staging = Path(temporary) / "snapshot"
        staging.mkdir()
        _export_tree(repository, s0, staging / "S0")
        _export_tree(repository, s1, staging / "S1")
        patch = _git(repository, "diff", "--binary", "--no-ext-diff", "--no-textconv", s0, s1, "--")
        (staging / "change.patch").write_bytes(patch)
        message = _git(repository, "log", "--no-show-signature", "--format=fuller", f"{s0}..{s1}")
        if not message:
            message = b"Selected range has no commits; S1 commit follows.\n\n" + _git(
                repository, "show", "--no-patch", "--no-show-signature", "--format=fuller", s1
            )
        (staging / "change-message.txt").write_bytes(message)
        (staging / "source.json").write_text(
            json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
        )
        if output.exists() or output.is_symlink():
            raise ValueError(
                f"Output appeared during preparation: {output}; choose a new directory."
            )
        staging.rename(output)


def main() -> None:
    """Parse the explicit snapshot request and report errors without a traceback."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("s0_ref")
    parser.add_argument("s1_ref")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        snapshot(args.repository, args.s0_ref, args.s1_ref, args.output)
    except (ValueError, OSError, tarfile.TarError) as error:
        parser.exit(1, f"snapshot: {error}\n")


if __name__ == "__main__":
    main()
