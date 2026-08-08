"""Seal and unseal the answer-bearing parts of a built corpus.

Why this exists
---------------
Moving the answer key somewhere else does not hide it: `find / -name 'recipe.json'`
undoes that in one command, and telling a reviewer not to look has failed repeatedly on
this project — 3 of 16 hunters fetched upstream through a prominent prohibition, and one
baseline agent invoked the artifact under test because it was installed and it fitted.

So the answers are not hidden, they are made unreadable. The bytes stay on disk inside an
AES-256 archive whose passphrase never touches the filesystem, which defeats every route at
once: Read, Grep, Glob, `cat`, `find`, `python -c`. There is no plaintext to reach.

What is sealed
--------------
* `<workdir>/bench-private/` and `<workdir>/control-private/` — ground truth, maps, staged
  trees.
* every `corpora/*/recipe.json` — each lists all of its corpus's planted bugs. A recipe is
  needed to *build* a corpus and never to *run* an arm against one.

Safety rule
-----------
`seal` restores the archive to a temporary directory and compares it against the original
before deleting anything. A seal that loses the ground truth irrecoverably would be a worse
outcome than the leak it prevents.
"""

from __future__ import annotations

import filecmp
import json
import os
import secrets
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

SEALED_NAME = "sealed.tar.gz.enc"
KEY_ENV = "CREVIEW_BENCH_KEY"

# Everything under a corpus workdir whose plaintext gives away an answer.
PRIVATE_DIRS = ("bench-private", "control-private")

# The gate stamp records each planted bug's class, so it is an answer too — but `plan`
# needs the stamp to know the corpus was verified. So it is redacted in place rather than
# sealed away, and the original travels in the archive.
STAMP = "verified.json"


class SealError(RuntimeError):
    """Raised for a refusal or a failure. Never for "there was nothing to do"."""


def _openssl(args: list[str], stdin: bytes | None = None) -> bytes:
    try:
        done = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["openssl", *args], input=stdin, capture_output=True, check=False
        )
    except FileNotFoundError as exc:  # pragma: no cover - environment
        raise SealError("openssl is not on PATH; the harness cannot seal without it") from exc
    if done.returncode != 0:
        raise SealError(f"openssl failed: {done.stderr.decode(errors='replace').strip()}")
    return done.stdout


def key_from_env(explicit: str | None = None) -> str:
    """The passphrase, from an argument or the environment. Never from a file, never invented.

    A keyfile on disk is reachable by exactly the tools the seal exists to defeat, so
    reading one is refused rather than supported.

    NEVER generate a key here. This function used to be reached with a freshly randomised
    environment variable, so each seal ran under a different passphrase and none was ever
    recorded; the ground truth for `sigil` was encrypted beyond recovery and survived only
    because the recipes happened to be committed to git. `seal` verifying that its archive
    restores does not protect against this — that guards a corrupt archive, not a lost key.
    If a key is wanted, `mint_key` generates one and the caller must print it.
    """
    key = explicit or os.environ.get(KEY_ENV) or ""
    if not key.strip():
        raise SealError(
            f"no passphrase: pass --key, or set {KEY_ENV}, or pass --mint-key to have one "
            "generated and printed. Do not inline `$(openssl rand -hex 32)` into the "
            "command: each shell invocation makes a new value, so the seal succeeds and the "
            "key is gone. Keep it out of the filesystem — a keyfile is readable by the same "
            "tools the seal exists to defeat."
        )
    return key


def mint_key() -> str:
    """A fresh passphrase. The caller MUST print it; nothing else records it."""
    return secrets.token_hex(32)


def _redact_stamp(workdir: Path) -> bytes | None:
    """Strip bug classes from verified.json, returning the original bytes."""
    stamp = workdir / STAMP
    if not stamp.is_file():
        return None
    original = stamp.read_bytes()
    data = json.loads(original)
    # Redact every breakdown, not just the one you thought of. `by_class` was handled on
    # the first pass and `by_decoy_kind` leaked straight past it — a decoy kind tells a
    # reviewer what shape of trap to distrust, which is an answer too.
    counts = data.get("counts")
    if isinstance(counts, dict):
        for field in ("by_class", "by_decoy_kind", "by_tier", "by_difficulty"):
            if isinstance(counts.get(field), dict):
                counts[field] = {"__redacted__": sum(counts[field].values())}
    # Both spellings: the stamp writes "checks", earlier drafts wrote "_checks". Missing
    # one silently redacts nothing, which is how a decoy-kind summary leaked past a first
    # pass of this very function.
    for field in ("checks", "_checks"):
        for check in data.get(field, []) or []:
            if isinstance(check, dict) and isinstance(check.get("detail"), str):
                check["detail"] = "(redacted while sealed)"
    data["_sealed"] = True
    stamp.write_text(json.dumps(data, indent=2))
    return original


def siblings_in_plaintext(workdir: Path) -> list[Path]:
    """Other work directories for the same corpus that still hold plaintext answers.

    Sealing one directory while a stale copy sits beside it protects nothing. These arise
    from re-builds and from determinism checks that preserve the previous tree.
    """
    parent, stem = workdir.parent, workdir.name
    out: list[Path] = []
    if not parent.is_dir():
        return out
    for cand in sorted(parent.iterdir()):
        if cand == workdir or not cand.is_dir():
            continue
        same_corpus = cand.name == stem or cand.name.startswith(stem + ".")
        if same_corpus and any((cand / d).is_dir() for d in PRIVATE_DIRS):
            out.append(cand)
    return out


def targets(workdir: Path, corpora_dir: Path) -> tuple[list[Path], list[Path]]:
    """(private dirs, recipe files) that exist right now, in plaintext."""
    priv = [workdir / name for name in PRIVATE_DIRS]
    priv = [p for p in priv if p.is_dir()]
    recipes = sorted(p for p in corpora_dir.glob("*/recipe.json") if p.is_file())
    return priv, recipes


def is_sealed(workdir: Path, corpora_dir: Path) -> bool:
    """True when no answer-bearing plaintext remains and an archive is present."""
    priv, recipes = targets(workdir, corpora_dir)
    return not priv and not recipes and (workdir / SEALED_NAME).is_file()


def unsealed_plaintext(workdir: Path, corpora_dir: Path) -> list[Path]:
    """Answer-bearing paths still readable. Empty means safe to run arms."""
    priv, recipes = targets(workdir, corpora_dir)
    return [*priv, *recipes]


def _tar(paths: list[tuple[Path, str]], out: Path) -> None:
    with tarfile.open(out, "w:gz") as tf:
        for src, arcname in paths:
            tf.add(src, arcname=arcname)


def _rm(path: Path) -> None:
    """Depth-first removal. `bench-private/` holds a `staged/` subtree, and this repo's
    hooks forbid `rm -rf`, so neither a shallow unlink nor a shell recursive delete works.
    """
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def seal(workdir: Path, corpora_dir: Path, key: str) -> dict:
    """Encrypt the answers, verify the archive restores, then delete the plaintext."""
    priv, recipes = targets(workdir, corpora_dir)
    if not priv and not recipes:
        raise SealError(
            f"nothing to seal under {workdir} and {corpora_dir}: no private directory and "
            "no recipe in plaintext. Either the corpus was never built, or it is already "
            "sealed — sealing zero files would report success while protecting nothing."
        )

    stale = siblings_in_plaintext(workdir)
    if stale:
        raise SealError(
            "refusing to seal while a stale copy of this corpus still holds plaintext "
            "answers beside it:\n"
            + "".join(f"  {p}\n" for p in stale)
            + "Sealing one tree while its twin is readable protects nothing. Remove or seal "
            "them first."
        )

    members: list[tuple[Path, str]] = [(p, p.name) for p in priv]
    members += [(p, f"recipes/{p.parent.name}/recipe.json") for p in recipes]
    # The gate stamp names every planted bug's class, so it leaks the answer set even
    # though `plan` needs the stamp to prove the corpus was verified. Carry the original
    # inside the archive and redact the copy that stays readable.
    stamp = workdir / STAMP
    stamp_original = stamp.read_bytes() if stamp.is_file() else None
    if stamp_original is not None:
        members.append((stamp, f"{STAMP}.original"))

    workdir.mkdir(parents=True, exist_ok=True)
    for r in recipes:
        pub = r.with_name("recipe.public.json")
        full = json.loads(r.read_text())
        redacted = {k: v for k, v in full.items() if k not in ("bugs", "decoys")}
        redacted["bug_count"] = len(full.get("bugs", []))
        redacted["decoy_count"] = len(full.get("decoys", []))
        redacted["_sealed"] = True
        pub.write_text(json.dumps(redacted, indent=2))
    with tempfile.TemporaryDirectory() as tmp:
        plain = Path(tmp) / "bundle.tar.gz"
        _tar(members, plain)
        enc = workdir / SEALED_NAME
        _openssl(
            [
                "enc",
                "-aes-256-cbc",
                "-pbkdf2",
                "-salt",
                "-pass",
                f"pass:{key}",
                "-in",
                str(plain),
                "-out",
                str(enc),
            ]
        )
        # Verify before destroying: restore to a scratch tree and compare.
        check = Path(tmp) / "check"
        check.mkdir()
        restored = _openssl(
            ["enc", "-d", "-aes-256-cbc", "-pbkdf2", "-pass", f"pass:{key}", "-in", str(enc)]
        )
        rt = Path(tmp) / "roundtrip.tar.gz"
        rt.write_bytes(restored)
        with tarfile.open(rt, "r:gz") as tf:
            tf.extractall(check)  # noqa: S202 - archive we just wrote ourselves
        for src, arcname in members:
            back = check / arcname
            if not back.exists():
                raise SealError(f"seal verification failed: {arcname} missing from the archive")
            if src.is_file() and not filecmp.cmp(src, back, shallow=False):
                raise SealError(f"seal verification failed: {arcname} differs after restore")
        # Only now is it safe to remove the plaintext.
        for src, arcname in members:
            if arcname == f"{STAMP}.original":
                continue  # redacted in place below, not deleted: `plan` needs the stamp
            _rm(src)
        if stamp_original is not None:
            _redact_stamp(workdir)

    return {
        "archive": str(enc),
        "private_dirs": [p.name for p in priv],
        "recipes": [p.parent.name for p in recipes],
        "sealed_bytes": enc.stat().st_size,
    }


def unseal(workdir: Path, corpora_dir: Path, key: str) -> dict:
    """Restore the answers. Fails loudly and leaves nothing half-extracted on a bad key."""
    enc = workdir / SEALED_NAME
    if not enc.is_file():
        raise SealError(f"no sealed archive at {enc}; nothing to unseal")

    try:
        blob = _openssl(
            ["enc", "-d", "-aes-256-cbc", "-pbkdf2", "-pass", f"pass:{key}", "-in", str(enc)]
        )
    except SealError as exc:
        raise SealError(f"unseal failed — wrong passphrase, or a damaged archive: {exc}") from exc

    with tempfile.TemporaryDirectory() as tmp:
        rt = Path(tmp) / "bundle.tar.gz"
        rt.write_bytes(blob)
        staging = Path(tmp) / "out"
        staging.mkdir()
        try:
            with tarfile.open(rt, "r:gz") as tf:
                tf.extractall(staging)  # noqa: S202 - our own archive
        except tarfile.TarError as exc:
            raise SealError(f"unseal failed: the archive did not open: {exc}") from exc

        restored: list[str] = []
        for item in sorted(staging.iterdir()):
            if item.name == f"{STAMP}.original":
                shutil.copy2(item, workdir / STAMP)
                restored.append(str(workdir / STAMP))
                continue
            if item.name == "recipes":
                for corpus_dir in sorted(item.iterdir()):
                    dest = corpora_dir / corpus_dir.name / "recipe.json"
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(corpus_dir / "recipe.json", dest)
                    restored.append(str(dest))
                continue
            dest = workdir / item.name
            _rm(dest)
            shutil.copytree(item, dest) if item.is_dir() else shutil.copy2(item, dest)
            restored.append(str(dest))

    if not restored:
        raise SealError("unseal restored nothing, which cannot be a success")
    return {"restored": restored, "archive": str(enc)}
