"""Seal and verify file-based stage evidence; this script never starts agents."""

import argparse
import hashlib
import json
from pathlib import Path


class IntegrityError(ValueError):
    """Sealed or recorded evidence no longer matches what was saved."""


def local(root: Path, name: str) -> Path:
    """Resolve a campaign-relative path without following symlinks outside the campaign."""
    path = Path(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"Expected a campaign-relative path: {name!r}")
    target = root / path
    for parent in (target, *target.parents):
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError(f"Symlink evidence is not accepted: {name}")
    return target


def digest(path: Path) -> str:
    """Return the SHA-256 of a file, streaming large logs."""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(root: Path, name: str) -> dict:
    """Read a JSON object from a confined path."""
    value = json.loads(local(root, name).read_text())
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {name}")
    return value


def files(root: Path, names: list[str]) -> dict[str, str]:
    """Expand evidence files/directories into a sorted hash manifest."""
    found = {}
    for name in names:
        path = local(root, name)
        if not path.exists():
            raise ValueError(f"Missing evidence: {name}")
        children = sorted(path.rglob("*")) if path.is_dir() else [path]
        for child in children:
            relative = child.relative_to(root).as_posix()
            safe = local(root, relative)
            if safe.is_file():
                found[relative] = digest(safe)
    return found


def manifest(root: Path, name: str) -> dict:
    """Bind a stage record to its complete inputs and outputs."""
    record = read(root, name)
    for field in ("inputs", "artifacts"):
        value = record.get(field)
        if not isinstance(value, list) or any(not isinstance(p, str) for p in value):
            raise ValueError(f"{name}: {field} must be a list of relative paths")
    if not record.get("agent") or not record.get("stage"):
        raise ValueError(f"{name}: record stage and actual agent handle")
    inputs = files(root, record["inputs"])
    artifacts = files(root, record["artifacts"])
    if name in inputs or name in artifacts or name + ".seal.json" in inputs | artifacts:
        raise ValueError(f"{name}: do not include the record or its seal in its own package")
    dependencies = {}
    for path in record["inputs"]:
        seal_path = local(root, path + ".seal.json")
        if seal_path.is_file():
            dependencies[path] = digest(seal_path)
    return {
        "record": digest(local(root, name)),
        "inputs": inputs,
        "artifacts": artifacts,
        "dependencies": dependencies,
    }


def verify(root: Path, name: str, stack: tuple[str, ...] = ()) -> dict:
    """Verify all files and sealed prerequisites; reject changed evidence and cycles."""
    if name in stack:
        raise ValueError(f"Cyclic evidence dependency: {name}")
    try:
        saved = read(root, name + ".seal.json")
        current = manifest(root, name)
    except (OSError, ValueError) as error:
        raise IntegrityError(f"Missing or unreadable evidence for {name}: {error}") from error
    if saved != current:
        raise IntegrityError(f"Stale or changed evidence: {name}; create a new reviewed attempt")
    for dependency in saved["dependencies"]:
        verify(root, dependency, (*stack, name))
    return read(root, name)


def seal(root: Path, name: str) -> None:
    """Seal a new record only after verifying its sealed prerequisites."""
    target = local(root, name + ".seal.json")
    if target.exists():
        verify(root, name)
        return
    value = manifest(root, name)
    for dependency in value["dependencies"]:
        verify(root, dependency)
    with target.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main() -> None:
    """Seal or verify one stage record, reporting actionable failures."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("seal", "verify"))
    parser.add_argument("campaign", type=Path)
    parser.add_argument("record")
    args = parser.parse_args()
    try:
        root = args.campaign.resolve(strict=True)
        if args.action == "seal":
            seal(root, args.record)
        else:
            verify(root, args.record)
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(1, f"Evidence error: {error}\n")
    print(f"{args.action}: {args.record}")


if __name__ == "__main__":
    main()
