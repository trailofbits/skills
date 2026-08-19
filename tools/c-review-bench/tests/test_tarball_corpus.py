#!/usr/bin/env python3
"""End-to-end test of the path the two real-C corpora use, which `sigil` does not.

`sigil` is authored, so it skips fetching, digest pinning and de-identification
entirely. Those are exactly the steps the medium and large corpora depend on, and an
untested fetch-and-rename pipeline would fail on the first recipe someone writes — or
worse, succeed while leaving upstream identifiers in the tree.

So this builds a miniature upstream: a two-file C project with a copyright banner, a
recognisable project name in its identifiers, filenames and error strings, packed into
a real `.tar.gz` and served over `file://`. Then it runs the whole gate over it and
asserts that the emitted corpus compiles, still works, and no longer looks like the
thing it came from.
"""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import sys
import tarfile
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from lib import corpus as corpus_mod  # noqa: E402
from lib import recipe as recipe_mod  # noqa: E402
from lib import verify  # noqa: E402

needs_cc = pytest.mark.skipif(
    shutil.which("cc") is None, reason="the compile gate needs a C compiler"
)

WIDGET_H = """/* widgetlib 3.2.1 — Copyright 2004 The Widget Foundation. */
#ifndef WIDGETLIB_H
#define WIDGETLIB_H

#include <stddef.h>

#define WIDGET_SLOT_MAX 8

typedef struct {
  unsigned char slots[WIDGET_SLOT_MAX];
  size_t slot_count;
} widget_bank;

int widget_bank_load(widget_bank *bank, const unsigned char *wire, size_t wire_len);
const char *widget_last_error(void);

#endif
"""

WIDGET_C = """/* widgetlib 3.2.1 — Copyright 2004 The Widget Foundation. */
#include "widgetlib.h"

#include <string.h>

static const char *widget_error_text = "widgetlib: slot count out of range";

const char *widget_last_error(void) {
  return widget_error_text;
}

int widget_bank_load(widget_bank *bank, const unsigned char *wire, size_t wire_len) {
  size_t declared;

  if (bank == NULL || wire == NULL) {
    return -1;
  }
  if (wire_len < 1) {
    return -1;
  }
  declared = wire[0];
  if (declared > WIDGET_SLOT_MAX) {
    return -2;
  }
  if (wire_len < 1 + declared) {
    return -1;
  }
  memset(bank, 0, sizeof(*bank));
  memcpy(bank->slots, wire + 1, declared);
  bank->slot_count = declared;
  return 0;
}
"""

SMOKE_TEMPLATE = """#include "widgetlib.h"

#include <stdio.h>
#include <string.h>

int main(void) {
  const unsigned char wire[4] = {3, 10, 20, 30};
  widget_bank bank;

  if (widget_bank_load(&bank, wire, sizeof(wire)) != 0) {
    fprintf(stderr, "load failed\\n");
    return 1;
  }
  if (bank.slot_count != 3 || bank.slots[2] != 30) {
    fprintf(stderr, "wrong contents\\n");
    return 1;
  }
  if (widget_last_error() == NULL) {
    return 1;
  }
  printf("ok\\n");
  return 0;
}
"""


def make_tarball(path: Path) -> str:
    """A real .tar.gz with one stripped top-level directory, like a GitHub tarball."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, text in (("widgetlib.h", WIDGET_H), ("widgetlib.c", WIDGET_C)):
            data = text.encode()
            info = tarfile.TarInfo(f"widgetlib-3.2.1/{name}")
            info.size = len(data)
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(data))
    payload = buffer.getvalue()
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def build_recipe(tarball: Path, digest: str) -> dict:
    return recipe_mod.validate(
        {
            "id": "widget",
            "tier": "medium",
            "_dir": str(tarball.parent),
            "threat_model": "REMOTE",
            "attacker_controls": "the wire bytes",
            "base": {
                "kind": "tarball",
                "url": tarball.resolve().as_uri(),
                "sha256": digest,
                "strip_components": 1,
                "files": ["*.c", "*.h"],
            },
            "deidentify": {
                "required": True,
                "seed": "widget-test-v1",
                "rename_files": True,
                "forbidden_strings": ["widget", "Widget", "3.2.1", "Foundation"],
                "string_scrub": [[r"\\b\\d+\\.\\d+\\.\\d+\\b", "0.1.0"]],
            },
            "build": {
                "sources": ["*.c"],
                "cflags": ["-O1", "-w", "-I.", "-Werror=implicit-function-declaration"],
            },
            "behaviour_check": {
                "main": "smoke.c",
                "main_template": SMOKE_TEMPLATE,
                "cflags": ["-O1", "-w", "-I.", "-Werror=implicit-function-declaration"],
            },
            "entry_points": [
                {
                    "function": "widget_bank_load",
                    "file": "widgetlib.c",
                    "why": "decodes untrusted wire bytes handed in by the caller",
                }
            ],
            "bugs": [
                {
                    "id": "W-B01",
                    "bug_class": "off-by-one",
                    "difficulty": "EASY",
                    "file": "widgetlib.c",
                    "function": "widget_bank_load",
                    "mechanism": (
                        "The slot bound is off by one, so a declared count one past the array "
                        "size is accepted and the copy writes one byte beyond the slots array."
                    ),
                    "attacker_control": "the first wire byte",
                    "mechanism_all_of": [["off by one", "off-by-one"], ["slot", "bound", "array"]],
                    "call_path": [{"from": "widget_bank_load", "to": "widget_bank_load"}],
                    "anchor": "  if (declared > WIDGET_SLOT_MAX) {",
                    "replacement": "  if (declared > WIDGET_SLOT_MAX + 1) {",
                    "site_marker": "  if (declared > WIDGET_SLOT_MAX + 1) {",
                }
            ],
            "decoys": [
                {
                    "id": "W-D01",
                    "decoy_kind": "extra-init",
                    "file": "widgetlib.c",
                    "function": "widget_last_error",
                    "safe_because": (
                        "the accessor returns a pointer to a static string and the initialiser "
                        "adds a local that nothing reads, so no caller can observe it."
                    ),
                    "anchor": "const char *widget_last_error(void) {\n  return widget_error_text;",
                    "replacement": (
                        "const char *widget_last_error(void) {\n"
                        "  const char *text = widget_error_text;\n\n"
                        "  return text;"
                    ),
                }
            ],
        }
    )


@pytest.fixture(scope="module")
def gated(tmp_path_factory):
    root = tmp_path_factory.mktemp("widget")
    tarball = root / "widgetlib-3.2.1.tar.gz"
    digest = make_tarball(tarball)
    recipe = build_recipe(tarball, digest)
    stamp = verify.gate(recipe, root / "work", allow_network=True)
    return recipe, root, stamp


@needs_cc
def test_a_tarball_corpus_passes_the_whole_gate(gated):
    _recipe, _root, stamp = gated
    failures = [c for c in stamp["_checks"] if not c.ok or c.vacuous]
    assert stamp["verified"] is True, [c.line() for c in failures]
    deid = next(c for c in stamp["_checks"] if c.name == "deidentified")
    assert deid.inspected > 0


@needs_cc
def test_nothing_upstream_survives_in_the_emitted_tree(gated):
    _recipe, root, _stamp = gated
    tree = root / "work" / "bench"
    text = "\n".join(p.read_text(encoding="utf-8") for p in sorted(tree.rglob("*")) if p.is_file())
    for tell in ("widget", "Widget", "Copyright", "Foundation", "3.2.1", "WIDGETLIB_H"):
        assert tell not in text, tell
    assert not (tree / "widgetlib.c").exists()
    assert any(p.suffix == ".c" for p in tree.iterdir())
    # The system header stays, and so does every reserved name the code needs.
    assert "#include <stddef.h>" in text
    assert "memcpy" in text and "size_t" in text


@needs_cc
def test_the_ground_truth_survives_renaming_and_points_at_the_injected_line(gated):
    _recipe, root, _stamp = gated
    manifest = corpus_mod.load_ground_truth(root / "work" / "bench-private")
    item = manifest["items"][0]
    assert item["base_function"] == "widget_bank_load"
    assert item["function"] != "widget_bank_load"
    line = (
        (root / "work" / "bench" / item["file"])
        .read_text(encoding="utf-8")
        .splitlines()[item["line"] - 1]
    )
    assert "+ 1" in line  # the injected bound, under whatever name the macro now has
    maps = json.loads((root / "work" / "bench-private" / "maps.json").read_text(encoding="utf-8"))
    assert maps["identifier_map"]["widget_bank_load"] == item["function"]


def test_a_wrong_digest_refuses_to_build(tmp_path):
    tarball = tmp_path / "widgetlib-3.2.1.tar.gz"
    make_tarball(tarball)
    recipe = build_recipe(tarball, "0" * 64)
    with pytest.raises(corpus_mod.CorpusError, match="Refusing to build"):
        corpus_mod.build(recipe, corpus_mod.BENCH, tmp_path / "out", tmp_path / "private")


def test_a_private_directory_inside_the_corpus_is_refused(tmp_path):
    tarball = tmp_path / "widgetlib-3.2.1.tar.gz"
    digest = make_tarball(tarball)
    recipe = build_recipe(tarball, digest)
    with pytest.raises(corpus_mod.CorpusError, match="private answer key"):
        corpus_mod.build(recipe, corpus_mod.BENCH, tmp_path / "out", tmp_path / "out" / "answers")


def test_an_uncached_base_with_network_refused_is_an_error(tmp_path, monkeypatch):
    tarball = tmp_path / "widgetlib-3.2.1.tar.gz"
    digest = make_tarball(tarball)
    monkeypatch.setenv("C_REVIEW_BENCH_CACHE", str(tmp_path / "cache"))
    recipe = build_recipe(tarball, digest)
    with pytest.raises(corpus_mod.CorpusError, match="network use was refused"):
        corpus_mod.fetch_base(recipe, allow_network=False)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
