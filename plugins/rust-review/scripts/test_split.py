"""Unit tests for the cluster-chunking helper in build_run_plan.py.

The helper partitions any cluster whose `passes` list exceeds
`max_passes_per_worker` into contiguous, order-preserving chunks. Each chunk
becomes its own pseudo-cluster entry, carrying the source cluster's prompt
path and `consolidated` flag, with a `-{i}` suffix appended to its
cluster_id (1-indexed). Clusters that fit within the threshold pass through
unchanged.
"""

from __future__ import annotations

import pytest

from build_run_plan import split_oversized_clusters


def _mk_cluster(cid: str, n_passes: int, *, consolidated: bool = False) -> dict:
    """Construct a synthetic cluster entry matching build_selection()'s output shape."""
    return {
        "cluster_id": cid,
        "consolidated": consolidated,
        "cluster_prompt": f"/abs/prompts/clusters/{cid}.md",
        "passes": [
            {"bug_class": f"{cid}-bc-{i}", "prefix": f"{cid.upper()}{i}"}
            for i in range(n_passes)
        ],
    }


# --- Pass-through (single-chunk) cases ---------------------------------------

def test_pass_through_k_equals_one():
    """K=1 < N=4 → 1 chunk, bare cluster_id, byte-identical to input."""
    src = [_mk_cluster("small", 1)]
    out = split_oversized_clusters(src, max_passes=4)
    assert out == src


def test_pass_through_k_equals_n():
    """K=4 == N=4 → still 1 chunk, bare cluster_id, no suffix."""
    src = [_mk_cluster("exact", 4)]
    out = split_oversized_clusters(src, max_passes=4)
    assert len(out) == 1
    assert out[0]["cluster_id"] == "exact"
    assert len(out[0]["passes"]) == 4


def test_pass_through_preserves_consolidated_flag():
    """The `consolidated` flag must round-trip through the splitter even on pass-through."""
    src = [_mk_cluster("c", 3, consolidated=True)]
    out = split_oversized_clusters(src, max_passes=4)
    assert out[0]["consolidated"] is True


# --- Split cases -------------------------------------------------------------

def test_split_k_5_n_4_yields_4_plus_1():
    src = [_mk_cluster("big", 5)]
    out = split_oversized_clusters(src, max_passes=4)
    assert [c["cluster_id"] for c in out] == ["big-1", "big-2"]
    assert [len(c["passes"]) for c in out] == [4, 1]


def test_split_k_8_n_4_yields_4_plus_4():
    src = [_mk_cluster("bigger", 8)]
    out = split_oversized_clusters(src, max_passes=4)
    assert [c["cluster_id"] for c in out] == ["bigger-1", "bigger-2"]
    assert [len(c["passes"]) for c in out] == [4, 4]


def test_split_k_9_n_4_yields_4_4_1():
    src = [_mk_cluster("huge", 9)]
    out = split_oversized_clusters(src, max_passes=4)
    assert [c["cluster_id"] for c in out] == ["huge-1", "huge-2", "huge-3"]
    assert [len(c["passes"]) for c in out] == [4, 4, 1]


def test_split_preserves_pass_order():
    """Chunk i must contain passes[(i-1)*N : i*N] in original manifest order."""
    src = [_mk_cluster("ordered", 9)]
    out = split_oversized_clusters(src, max_passes=4)
    expected_bcs = [f"ordered-bc-{i}" for i in range(9)]
    flat = [p["bug_class"] for c in out for p in c["passes"]]
    assert flat == expected_bcs


def test_split_preserves_cluster_prompt_and_consolidated():
    src = [_mk_cluster("share", 8, consolidated=True)]
    out = split_oversized_clusters(src, max_passes=4)
    for chunk in out:
        assert chunk["cluster_prompt"] == "/abs/prompts/clusters/share.md"
        assert chunk["consolidated"] is True


# --- Identity (disable) case -------------------------------------------------

def test_max_passes_zero_is_identity_no_suffix():
    """N=0 is the explicit 'disable chunking' sentinel — pass through with bare ids."""
    src = [_mk_cluster("a", 8), _mk_cluster("b", 3)]
    out = split_oversized_clusters(src, max_passes=0)
    assert out == src


# --- Multiple clusters in one call -------------------------------------------

def test_mixed_input_handles_each_cluster_independently():
    src = [
        _mk_cluster("small", 2),     # pass-through
        _mk_cluster("split-me", 6),  # 4 + 2
        _mk_cluster("exact", 4),     # pass-through
        _mk_cluster("huge", 9),      # 4 + 4 + 1
    ]
    out = split_oversized_clusters(src, max_passes=4)
    cids = [c["cluster_id"] for c in out]
    sizes = [len(c["passes"]) for c in out]
    assert cids == ["small", "split-me-1", "split-me-2", "exact", "huge-1", "huge-2", "huge-3"]
    assert sizes == [2, 4, 2, 4, 4, 4, 1]


def test_order_of_source_clusters_is_preserved():
    """The relative ordering of source clusters in the input list survives splitting."""
    src = [
        _mk_cluster("alpha", 8),
        _mk_cluster("beta", 3),
        _mk_cluster("gamma", 5),
    ]
    out = split_oversized_clusters(src, max_passes=4)
    cids = [c["cluster_id"] for c in out]
    assert cids == ["alpha-1", "alpha-2", "beta", "gamma-1", "gamma-2"]


# --- Determinism -------------------------------------------------------------

def test_same_input_same_output_repeated_calls():
    src = [_mk_cluster("d", 7)]
    out1 = split_oversized_clusters(src, max_passes=4)
    out2 = split_oversized_clusters(src, max_passes=4)
    assert out1 == out2


# --- Negative input ----------------------------------------------------------

def test_negative_max_passes_raises():
    """Negative N is a CLI input error; helper rejects it explicitly."""
    src = [_mk_cluster("x", 4)]
    with pytest.raises(ValueError):
        split_oversized_clusters(src, max_passes=-1)
