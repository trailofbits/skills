"""Gating and per-pass filtering tests for build_run_plan.build_selection.

These run against the real cluster manifest and plugin root so the prompt-path
existence checks inside build_selection() resolve.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

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


def test_full_run_all_flags_end_to_end_snapshot():
    """Golden snapshot of the production fan-out: real manifest, every capability
    flag on, default --max-passes-per-worker 4. Locks the selection->split seam
    (23 workers with these exact chunk ids/sizes), so a manifest edit that grows a
    cluster, or a regression in the selection->split pipeline, cannot silently
    change worker count or chunk ids without failing a test. The two consolidated
    clusters (unsafe-boundary, concurrency-locking) are never chunked — one worker
    each, full pass list."""
    flags = make_flags(
        has_unsafe=True,
        has_ffi=True,
        has_concurrency=True,
        has_async=True,
        has_packed_repr=True,
        has_fs_io=True,
    )
    selected = build_selection(
        load_manifest(), plugin_root=PLUGIN_ROOT, flags=flags, threat_model="REMOTE"
    )
    split = build_run_plan.split_oversized_clusters(selected, max_passes=4)

    expected_ids = [
        "unsafe-boundary",  # consolidated → not chunked (8 passes, one worker)
        "memory-safety-1",
        "memory-safety-2",
        "concurrency-locking",  # consolidated → not chunked (6 passes, one worker)
        "concurrency-data-race-1",
        "concurrency-data-race-2",
        "panic-dos-1",
        "panic-dos-2",
        "recursion-dos-1",
        "recursion-dos-2",
        "recursion-dos-3",
        "error-handling-1",
        "error-handling-2",
        "logic-correctness-1",
        "logic-correctness-2",
        "ffi-cross-language-1",
        "ffi-cross-language-2",
        "layout-safety",
        "async-runtime",
        "static-hygiene",
        "resource-handling",
        "input-os-safety",
        "info-disclosure",
    ]
    expected_sizes = [
        8,  # unsafe-boundary (consolidated, full pass list)
        4,
        4,
        6,  # concurrency-locking (consolidated, full pass list)
        4,
        1,
        4,
        3,
        1,
        1,
        1,
        4,
        1,
        4,
        4,
        4,
        3,
        1,
        3,
        3,
        2,
        2,
        1,
    ]

    assert [c["cluster_id"] for c in split] == expected_ids
    assert [len(c["passes"]) for c in split] == expected_sizes
    assert len(split) == 23
    assert sum(len(c["passes"]) for c in split) == 69  # total bug-class passes unchanged


def test_non_remote_threat_models_select():
    """The non-REMOTE threat models must also drive a valid selection. No pass in
    the manifest is threat-model-gated today, so the cluster set matches REMOTE —
    this exercises the LOCAL_UNPRIVILEGED / BOTH code path that no other test hits."""
    flags = make_flags(has_unsafe=True, has_ffi=True, has_concurrency=True, has_async=True)
    remote = [c["cluster_id"] for c in select(flags, threat_model="REMOTE")]
    assert [c["cluster_id"] for c in select(flags, threat_model="LOCAL_UNPRIVILEGED")] == remote
    assert [c["cluster_id"] for c in select(flags, threat_model="BOTH")] == remote


def test_skip_threat_models_filters_pass(tmp_path):
    """pass_filtered_out drops a pass whose skip_threat_models includes the active
    threat model, and keeps it under another model."""
    prompt = tmp_path / "prompts" / "clusters" / "c.md"
    prompt.parent.mkdir(parents=True)
    prompt.write_text("# c\n", encoding="utf-8")
    sub = tmp_path / "prompts" / "general" / "p.md"
    sub.parent.mkdir(parents=True)
    sub.write_text("# p\n", encoding="utf-8")
    manifest = {
        "version": 1,
        "clusters": [
            {
                "cluster_id": "c",
                "prompt": "prompts/clusters/c.md",
                "consolidated": False,
                "gate": "always",
                "passes": [
                    {
                        "bug_class": "remote-only",
                        "prefix": "RO",
                        "prompt": "prompts/general/p.md",
                        "skip_threat_models": ["LOCAL_UNPRIVILEGED"],
                    },
                    {"bug_class": "always", "prefix": "AL", "prompt": "prompts/general/p.md"},
                ],
            }
        ],
    }
    flags = make_flags()
    local = build_selection(
        manifest, plugin_root=tmp_path, flags=flags, threat_model="LOCAL_UNPRIVILEGED"
    )
    remote = build_selection(manifest, plugin_root=tmp_path, flags=flags, threat_model="REMOTE")
    local_c = cluster_by_id(local, "c")
    remote_c = cluster_by_id(remote, "c")
    assert local_c is not None and remote_c is not None
    assert prefixes(local_c) == ["AL"]
    assert prefixes(remote_c) == ["RO", "AL"]


def _render_cluster(cluster: dict[str, Any]) -> str:
    return build_run_plan.render_worker_prompt(
        worker_n=1,
        cluster=cluster,
        output_dir=Path("/tmp/out"),
        scope_root=".",
        context_roots=".",
        threat_model="REMOTE",
        severity_filter="all",
        flags=make_flags(has_unsafe=True, has_fs_io=True),
        context_md_body="ctx",
    )


def test_spawn_prompt_consolidated_omits_subprompt_section():
    """Contract lock (worker.md self-check): a consolidated cluster's spawn prompt
    must NOT render a 'Sub-prompt paths:' section at all — its absence is
    well-formed, not a missing required field."""
    prompt = _render_cluster(
        {
            "cluster_id": "unsafe-boundary",
            "consolidated": True,
            "cluster_prompt": "/abs/unsafe-boundary.md",
            "passes": [{"bug_class": "transmute-misuse", "prefix": "TRANS"}],
        }
    )
    assert "Sub-prompt paths:" not in prompt
    assert "Pass bug classes: transmute-misuse" in prompt
    assert "Pass prefixes: TRANS" in prompt
    assert "Skip subclasses: (none)" in prompt


def test_spawn_prompt_nonconsolidated_includes_subprompt_section():
    prompt = _render_cluster(
        {
            "cluster_id": "memory-safety",
            "consolidated": False,
            "cluster_prompt": "/abs/memory-safety.md",
            "passes": [
                {
                    "bug_class": "use-after-free",
                    "prefix": "UAF",
                    "prompt": "/abs/general/use-after-free-finder.md",
                }
            ],
        }
    )
    assert "Sub-prompt paths:" in prompt
    assert "  - /abs/general/use-after-free-finder.md" in prompt
    assert "Skip subclasses: (none)" in prompt


def test_spawn_prompt_codebase_line_is_comma_separated():
    """Contract lock (worker.md:27 illustration): the Codebase flags line is
    comma-separated."""
    prompt = _render_cluster(
        {
            "cluster_id": "info-disclosure",
            "consolidated": False,
            "cluster_prompt": "/abs/info-disclosure.md",
            "passes": [
                {
                    "bug_class": "pointer-exposure",
                    "prefix": "PTREXPOSE",
                    "prompt": "/abs/general/pointer-exposure-finder.md",
                }
            ],
        }
    )
    codebase = next(line for line in prompt.splitlines() if line.startswith("Codebase: "))
    assert ", " in codebase
    assert codebase.startswith("Codebase: has_unsafe=true, has_ffi=")


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, *sys.argv[1:]]))
