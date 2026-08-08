"""Build a benchmark corpus from a recipe: fetch, inject, de-identify, emit.

Two variants come out of the same recipe:

- `bench` — decoys **and** bugs. This is what the arms review.
- `control` — decoys only, no bugs. Any finding that claims an injected bug here is
  a false positive by construction, because at that site there is nothing to find.

The answer key is written to a **separate private directory** that must not sit
inside the corpus tree. A ground-truth file inside the tree is an answer key the
reviewer can read, and this harness exists because reviewers read answer keys.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
import urllib.request
from pathlib import Path
from typing import Any

from . import deidentify as deid_mod
from . import inject as inject_mod
from .recipe import RecipeError

BENCH = "bench"
CONTROL = "control"


class CorpusError(Exception):
    """The corpus cannot be built as specified. Callers exit non-zero."""


def cache_dir() -> Path:
    env = os.environ.get("C_REVIEW_BENCH_CACHE")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".cache" / "c-review-bench"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _select(root: Path, globs: list[str]) -> dict[str, str]:
    texts: dict[str, str] = {}
    for pattern in globs:
        for path in sorted(root.glob(pattern)):
            if not path.is_file():
                continue
            rel = str(path.relative_to(root))
            texts[rel] = path.read_text(encoding="utf-8", errors="replace")
    if not texts:
        raise CorpusError(
            f"file selection {globs} matched nothing under {root}. A corpus of zero files "
            f"would build, verify vacuously and grade every arm 0/0."
        )
    return texts


def fetch_base(recipe: dict[str, Any], allow_network: bool = True) -> dict[str, str]:
    """The base tree as {relative path: text}, before any injection."""
    base = recipe["base"]
    if base["kind"] == "authored":
        root = Path(recipe["_dir"]) / base["source_dir"]
        if not root.is_dir():
            raise CorpusError(f"authored corpus source directory missing: {root}")
        return _select(root, base.get("files") or ["**/*.c", "**/*.h"])

    url, want = base["url"], base["sha256"]
    cache = cache_dir()
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / f"{recipe['id']}-{want[:12]}.tar.gz"
    if not archive.is_file():
        if not allow_network:
            raise CorpusError(
                f"{archive} is not cached and network use was refused. Run the build once with "
                f"network, or pre-seed the cache directory ({cache})."
            )
        tmp = archive.with_suffix(".part")
        try:
            with urllib.request.urlopen(url, timeout=120) as response, tmp.open("wb") as out:
                shutil.copyfileobj(response, out)
        except OSError as exc:
            raise CorpusError(f"fetching {url} failed: {exc}") from exc
        tmp.replace(archive)
    got = _sha256_file(archive)
    if got != want:
        raise CorpusError(
            f"{archive} sha256 is {got}, recipe pins {want}. Refusing to build: an unpinned base "
            f"means the recipe's anchors and line numbers describe a different tree."
        )

    extracted = cache / f"{recipe['id']}-{want[:12]}-src"
    if not extracted.is_dir():
        strip = int(base.get("strip_components", 1))
        with tarfile.open(archive) as tar:
            staging = cache / f"{recipe['id']}-{want[:12]}-staging"
            if staging.is_dir():
                shutil.rmtree(staging)
            try:
                tar.extractall(staging, filter="data")
            except TypeError:  # pragma: no cover - Python without the filter argument
                tar.extractall(staging)  # noqa: S202
        root = staging
        for _ in range(strip):
            children = [c for c in root.iterdir() if c.is_dir()]
            if len(children) != 1:
                raise CorpusError(
                    f"cannot strip {strip} component(s): {root} has {len(children)} dirs"
                )
            root = children[0]
        root.rename(extracted)
        shutil.rmtree(staging, ignore_errors=True)
    return _select(extracted, base["files"])


def _patches_for(recipe: dict[str, Any], variant: str) -> list[dict[str, Any]]:
    if variant == BENCH:
        return list(recipe["decoys"]) + list(recipe["bugs"])
    if variant == CONTROL:
        return list(recipe["decoys"])
    raise CorpusError(f"unknown variant {variant!r}")


def _apply(
    texts: dict[str, str], patches: list[dict[str, Any]]
) -> tuple[dict[str, str], dict[str, int]]:
    by_file: dict[str, list[dict[str, Any]]] = {}
    for patch in patches:
        if patch["file"] not in texts:
            raise CorpusError(
                f"patch {patch['id']} targets {patch['file']!r}, which is not in the selected "
                f"file set: {sorted(texts)[:8]}{'...' if len(texts) > 8 else ''}"
            )
        by_file.setdefault(patch["file"], []).append(patch)
    out = dict(texts)
    sites: dict[str, int] = {}
    for path, group in by_file.items():
        patched = inject_mod.apply_patches(path, texts[path], group)
        out[path] = patched.text
        for site in patched.sites:
            sites[site.id] = site.line
    return out, sites


def _anchor_lines(texts: dict[str, str], items: list[dict[str, Any]]) -> dict[str, int]:
    """Where each item's anchor sits in an *unpatched* tree (used for the control)."""
    lines: dict[str, int] = {}
    for item in items:
        text = texts.get(item["file"])
        if text is None:
            raise CorpusError(f"{item['id']}: {item['file']} is not in the selected file set")
        count = text.count(item["anchor"])
        if count != 1:
            raise CorpusError(
                f"{item['id']}: anchor occurs {count} time(s) in the control tree, needs exactly 1"
            )
        offset = text.index(item["anchor"])
        lines[item["id"]] = text.count("\n", 0, offset) + 1
    return lines


def _render_template(text: str, mapping: dict[str, str], file_map: dict[str, str]) -> str:
    """Apply the identifier and filename maps to a file the recipe supplies verbatim.

    A hand-written smoke test calls the base project's API by its original names, so
    it has to be renamed along with everything else or it will not compile.
    """
    rendered = deid_mod.rename_words(text, mapping)
    for original, renamed in sorted(file_map.items(), key=lambda kv: -len(kv[0])):
        rendered = rendered.replace(Path(original).name, Path(renamed).name)
    return rendered


def _build_script(sources: list[str], cflags: list[str]) -> str:
    return (
        "#!/bin/sh\n"
        "# Compile every translation unit. Objects only: this is a library.\n"
        "set -eu\n"
        'out="${1:-./build}"\n'
        'mkdir -p "$out"\n'
        f"for f in {' '.join(sources)}; do\n"
        f'  cc {" ".join(cflags)} -c "$f" -o "$out/$(basename "$f" .c).o"\n'
        "done\n"
        'echo "built $(ls "$out" | wc -l | tr -d " ") object(s)"\n'
    )


def _check_script(sources: list[str], main: str, cflags: list[str], run_args: str) -> str:
    return (
        "#!/bin/sh\n"
        "# Behaviour check on benign input. Exits non-zero if the library misbehaves.\n"
        "set -eu\n"
        'tmp="$(mktemp -d)"\n'
        "trap 'rm -rf \"$tmp\"' EXIT\n"
        f'cc {" ".join(cflags)} -o "$tmp/smoke" {" ".join(sources)} {main}\n'
        f'"$tmp/smoke" {run_args}\n'
    )


def build(
    recipe: dict[str, Any],
    variant: str,
    dest: Path,
    private: Path,
    allow_network: bool = True,
) -> dict[str, Any]:
    """Emit one corpus variant plus its private answer key. Returns the manifest."""
    dest, private = Path(dest).resolve(), Path(private).resolve()
    if private == dest or dest in private.parents or private in dest.parents:
        raise CorpusError(
            f"the private answer key would land inside (or above) the corpus tree "
            f"({private} vs {dest}). Put it somewhere the reviewer is not pointed at."
        )

    base_texts = fetch_base(recipe, allow_network=allow_network)
    patched, injected_lines = _apply(base_texts, _patches_for(recipe, variant))
    control_anchor_lines = _anchor_lines(patched, recipe["bugs"]) if variant == CONTROL else {}

    deid_cfg = recipe["deidentify"]
    if deid_cfg.get("required"):
        corpus = deid_mod.deidentify_tree(
            patched,
            seed=f"{recipe['id']}\x00{deid_cfg['seed']}",
            rename_files=bool(deid_cfg.get("rename_files", True)),
            reserved_extra=set(deid_cfg.get("reserved_extra") or ()),
            string_scrub=[tuple(pair) for pair in deid_cfg.get("string_scrub") or ()],
        )
    else:
        corpus = deid_mod.Corpus(
            files={
                path: deid_mod.Deidentified(
                    text=text if text.endswith("\n") else text + "\n",
                    line_map=list(range(1, len(text.splitlines()) + 1)),
                )
                for path, text in patched.items()
            },
            identifier_map={},
            file_map={path: path for path in patched},
        )

    if dest.exists():
        shutil.rmtree(dest)
    for rel, file in corpus.files.items():
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(file.text, encoding="utf-8")

    def final(path: str) -> str:
        return corpus.file_map[path]

    def final_line(path: str, line: int) -> int:
        return corpus.files[final(path)].map_line(line)

    sources = sorted(final(p) for p in corpus.file_map if p.endswith(".c"))
    build_cfg = recipe["build"]
    source_globs = build_cfg["sources"]
    selected_sources = [s for s in sources if any(Path(s).match(g) for g in source_globs)]
    if not selected_sources:
        raise CorpusError(f"build.sources {source_globs} selected none of {sources}")
    (dest / "build.sh").write_text(
        _build_script(selected_sources, build_cfg["cflags"]), encoding="utf-8"
    )
    (dest / "build.sh").chmod(0o755)

    for rel, template in (recipe["base"].get("extra_files") or {}).items():
        rendered = _render_template(template, corpus.identifier_map, corpus.file_map)
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            rendered if rendered.endswith("\n") else rendered + "\n", encoding="utf-8"
        )

    behaviour = recipe.get("behaviour_check")
    if behaviour:
        main_rel = behaviour["main"]
        if behaviour.get("main_template"):
            rendered = _render_template(
                behaviour["main_template"], corpus.identifier_map, corpus.file_map
            )
            (dest / main_rel).parent.mkdir(parents=True, exist_ok=True)
            (dest / main_rel).write_text(rendered, encoding="utf-8")
        (dest / "check.sh").write_text(
            _check_script(
                selected_sources,
                main_rel,
                behaviour.get("cflags") or build_cfg["cflags"],
                behaviour.get("run_args", ""),
            ),
            encoding="utf-8",
        )
        (dest / "check.sh").chmod(0o755)

    items: list[dict[str, Any]] = []
    for bug in recipe["bugs"]:
        record = {
            "id": bug["id"],
            "bug_class": bug["bug_class"],
            "difficulty": bug["difficulty"],
            "file": final(bug["file"]),
            "base_file": bug["file"],
            "function": corpus.identifier_map.get(bug["function"], bug["function"]),
            "base_function": bug["function"],
            "mechanism": bug["mechanism"],
            "mechanism_all_of": bug["mechanism_all_of"],
            "attacker_control": bug["attacker_control"],
            "call_path": [
                {
                    "from": corpus.identifier_map.get(edge["from"], edge["from"]),
                    "to": corpus.identifier_map.get(edge["to"], edge["to"]),
                    "kind": edge.get("kind", "direct"),
                }
                for edge in bug["call_path"]
            ],
        }
        if variant == BENCH:
            record["line"] = final_line(bug["file"], injected_lines[bug["id"]])
        else:
            record["line"] = final_line(bug["file"], control_anchor_lines[bug["id"]])
            record["present"] = False
        items.append(record)

    decoy_records = [
        {
            "id": decoy["id"],
            "decoy_kind": decoy["decoy_kind"],
            "file": final(decoy["file"]),
            "line": final_line(decoy["file"], injected_lines[decoy["id"]]),
            "function": corpus.identifier_map.get(decoy["function"], decoy["function"]),
            "safe_because": decoy["safe_because"],
        }
        for decoy in recipe["decoys"]
    ]

    manifest = {
        "corpus": recipe["id"],
        "tier": recipe["tier"],
        "variant": variant,
        "threat_model": recipe.get("threat_model", "REMOTE"),
        "attacker_controls": recipe.get("attacker_controls", ""),
        "scope_subpath": recipe.get("scope_subpath", "."),
        "tree": str(dest),
        "deidentified": bool(deid_cfg.get("required")),
        "deidentify_note": deid_cfg.get("not_required_because", ""),
        "files": sorted(corpus.files),
        "source_files": selected_sources,
        "lines_of_code": sum(len(f.text.splitlines()) for f in corpus.files.values()),
        "file_sha256": {
            rel: hashlib.sha256(file.text.encode()).hexdigest()
            for rel, file in sorted(corpus.files.items())
        },
        "entry_points": [
            {
                "function": corpus.identifier_map.get(e["function"], e["function"]),
                "file": final(e["file"]) if e["file"] in corpus.file_map else e["file"],
                "why": e["why"],
            }
            for e in recipe["entry_points"]
        ],
        "items": items,
        "decoys": decoy_records,
        "known_extra_findings": [
            {
                "file": final(extra["file"]) if extra["file"] in corpus.file_map else extra["file"],
                "function": corpus.identifier_map.get(extra["function"], extra["function"]),
                "note": extra["note"],
            }
            for extra in recipe.get("known_extra_findings") or ()
        ],
        "identifier_map_size": len(corpus.identifier_map),
    }

    private.mkdir(parents=True, exist_ok=True)
    (private / "ground_truth.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    (private / "maps.json").write_text(
        json.dumps({"identifier_map": corpus.identifier_map, "file_map": corpus.file_map}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    # The pre-de-identification tree, for the reachability check and for debugging a
    # recipe. Private, because it is the diff that would give the injections away.
    staged = private / "staged"
    if staged.exists():
        shutil.rmtree(staged)
    for rel, text in patched.items():
        target = staged / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return manifest


def load_ground_truth(private: Path) -> dict[str, Any]:
    path = Path(private) / "ground_truth.json"
    if not path.is_file():
        raise CorpusError(f"no ground truth at {path}; build the corpus first")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RecipeError(f"{path} is not valid JSON: {exc}") from exc
