"""Gating and per-pass filtering tests for build_run_plan.build_selection.

These run against the real cluster manifest and plugin root so the prompt-path
existence checks inside build_selection() resolve.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import build_run_plan
from build_run_plan import build_selection

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = PLUGIN_ROOT / "prompts" / "clusters" / "manifest.json"


def load_manifest() -> dict[str, Any]:
    return json.loads(MANIFEST_PATH.read_text())


def make_flags(
    *,
    has_unsafe: bool = False,
    has_ffi: bool = False,
    has_concurrency: bool = False,
    has_async: bool = False,
    has_packed_repr: bool = False,
    has_fs_io: bool = False,
) -> dict[str, bool]:
    return {
        "has_unsafe": has_unsafe,
        "has_ffi": has_ffi,
        "has_concurrency": has_concurrency,
        "has_async": has_async,
        "has_packed_repr": has_packed_repr,
        "has_fs_io": has_fs_io,
    }


def select(flags: dict[str, bool], threat_model: str = "REMOTE") -> list[dict[str, Any]]:
    return build_selection(
        load_manifest(),
        plugin_root=PLUGIN_ROOT,
        flags=flags,
        threat_model=threat_model,
    )


def cluster_by_id(selected: list[dict[str, Any]], cid: str) -> dict[str, Any] | None:
    for c in selected:
        if c["cluster_id"] == cid:
            return c
    return None


def prefixes(cluster: dict[str, Any]) -> list[str]:
    return [p["prefix"] for p in cluster["passes"]]


def test_layout_safety_selected_only_with_packed_repr():
    off = select(make_flags())
    assert cluster_by_id(off, "layout-safety") is None

    on = select(make_flags(has_packed_repr=True))
    layout = cluster_by_id(on, "layout-safety")
    assert layout is not None
    assert prefixes(layout) == ["PACKEDREF"]


def test_packed_ref_not_in_ffi_cluster():
    selected = select(make_flags(has_ffi=True, has_packed_repr=False))
    ffi = cluster_by_id(selected, "ffi-cross-language")
    assert ffi is not None
    assert "PACKEDREF" not in prefixes(ffi)


def test_input_os_safety_gated_on_fs_io():
    off = select(make_flags())
    assert cluster_by_id(off, "input-os-safety") is None

    on = select(make_flags(has_fs_io=True))
    ios = cluster_by_id(on, "input-os-safety")
    assert ios is not None
    assert prefixes(ios) == ["PATHJOIN", "TOCTOU"]


def test_new_gates_are_isolated():
    fs_only = select(make_flags(has_fs_io=True))
    assert cluster_by_id(fs_only, "input-os-safety") is not None
    assert cluster_by_id(fs_only, "layout-safety") is None

    packed_only = select(make_flags(has_packed_repr=True))
    assert cluster_by_id(packed_only, "layout-safety") is not None
    assert cluster_by_id(packed_only, "input-os-safety") is None


def test_info_disclosure_always_on():
    selected = select(make_flags())
    info = cluster_by_id(selected, "info-disclosure")
    assert info is not None
    assert "PTREXPOSE" in prefixes(info)


def test_unsafe_scaffolding_passes_filtered_without_unsafe():
    off = select(make_flags(has_unsafe=False))
    logic_off = cluster_by_id(off, "logic-correctness")
    assert logic_off is not None
    off_prefixes = prefixes(logic_off)
    assert "TRAITADV" not in off_prefixes
    assert "CLOSUREPANIC" not in off_prefixes
    assert "ORDEQHASH" in off_prefixes

    on = select(make_flags(has_unsafe=True))
    logic_on = cluster_by_id(on, "logic-correctness")
    assert logic_on is not None
    on_prefixes = prefixes(logic_on)
    assert "TRAITADV" in on_prefixes
    assert "CLOSUREPANIC" in on_prefixes


def test_data_race_unsafe_passes_filtered():
    off = select(make_flags(has_concurrency=True, has_unsafe=False))
    race_off = cluster_by_id(off, "concurrency-data-race")
    assert race_off is not None
    off_prefixes = prefixes(race_off)
    assert "UNSAFESYNC" not in off_prefixes
    assert "STATICMUT" not in off_prefixes
    assert "ATOMICRACE" in off_prefixes
    assert "SENDSYNCBOUND" in off_prefixes
    assert "SHMRACE" in off_prefixes

    on = select(make_flags(has_concurrency=True, has_unsafe=True))
    race_on = cluster_by_id(on, "concurrency-data-race")
    assert race_on is not None
    on_prefixes = prefixes(race_on)
    assert "UNSAFESYNC" in on_prefixes
    assert "STATICMUT" in on_prefixes


def test_manifest_gates_and_requires_are_known():
    manifest = load_manifest()
    for cluster in manifest["clusters"]:
        assert cluster["gate"] in build_run_plan.GATE_VALUES, cluster["cluster_id"]
        for p in cluster.get("passes", []):
            for req in p.get("requires", []) or []:
                assert req in build_run_plan.KNOWN_REQUIRES, (cluster["cluster_id"], p)


def test_flag_vocabularies_derive_from_capability_flags():
    assert build_run_plan.GATE_VALUES == {"always", *build_run_plan.CAPABILITY_FLAGS}
    assert build_run_plan.KNOWN_REQUIRES == set(build_run_plan.CAPABILITY_FLAGS)
    assert set(make_flags()) == set(build_run_plan.CAPABILITY_FLAGS)


def test_rendered_prefix_lists_every_capability_flag():
    lines = build_run_plan._render_shared_prefix_lines(
        output_dir=Path("/tmp/out"),
        scope_root=".",
        context_roots=".",
        threat_model="REMOTE",
        severity_filter="all",
        flags=make_flags(has_unsafe=True, has_fs_io=True),
        context_md_body="ctx",
    )
    codebase = next(line for line in lines if line.startswith("Codebase: "))
    for flag in build_run_plan.CAPABILITY_FLAGS:
        assert f"{flag}=" in codebase
