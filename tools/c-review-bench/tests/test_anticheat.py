#!/usr/bin/env python3
"""Tests for the oracle detector.

The load-bearing one is `test_tool_definitions_and_prose_are_not_use`. The string
`WebFetch` appears in nearly every transcript twice over — once in the list of tools
offered to the model, once in the packet text telling it not to use them — so a
substring scan flags every arm including the honest ones, and a check that always
fires gets disabled. This asserts the scanner separates a definition from an
invocation, and `test_a_real_invocation_is_a_violation` asserts it still catches the
real thing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from lib import anticheat  # noqa: E402

FIXTURES = HERE / "fixtures"


def scan(name):
    return anticheat.scan_transcripts([FIXTURES / name])


# ------------------------------------------------- definitions versus invocations


def test_tool_definitions_and_prose_are_not_use():
    result = scan("transcript_clean.jsonl")
    assert result["violations"] == []
    assert result["tool_definitions_seen"] == 7
    assert result["invocations_seen"] == 3
    assert anticheat.assess(result)["verdict"] == "VALID"


def test_a_real_invocation_is_a_violation():
    result = anticheat.assess(scan("transcript_cheating.jsonl"))
    reasons = [v["why"] for v in result["violations"]]
    assert result["verdict"] == "INVALID"
    assert any("oracle tool `WebFetch`" in r for r in reasons)
    assert any("network binary `curl`" in r for r in reasons)
    assert any("git clone" in r for r in reasons)
    assert any("answer key" in r for r in reasons)


def test_a_transcript_with_only_definitions_is_refused_not_cleared():
    # The zero-inspection guard. "No invocations found" from a file the scanner did
    # not understand must not read as "the arm behaved".
    with pytest.raises(anticheat.AntiCheatError, match="zero tool invocations"):
        scan("transcript_definitions_only.jsonl")


def test_no_transcripts_at_all_is_refused(tmp_path):
    with pytest.raises(anticheat.AntiCheatError, match="no transcripts found"):
        anticheat.scan_transcripts([tmp_path / "nothing.jsonl"])


def test_unparseable_transcript_is_refused(tmp_path):
    path = tmp_path / "broken.jsonl"
    path.write_text("not json\nalso not json\n", encoding="utf-8")
    with pytest.raises(anticheat.AntiCheatError, match="parsed zero JSON records"):
        anticheat.scan_transcripts([path])


# -------------------------------------------------------- command-line precision


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("grep -rn curl src/", []),
        ("cat wget-notes.txt", []),
        ("ls curl", []),
        ("cc -c src/a.c", []),
        ("curl https://example.org", ["violation"]),
        ("sudo curl https://example.org", ["violation"]),
        ("FOO=1 wget https://example.org", ["violation"]),
        ("cc -c a.c && curl https://example.org", ["violation"]),
        ("echo hi | nc host 80", ["violation"]),
        ("git clone https://github.com/x/y", ["violation"]),
        ("gh pr diff 123", ["violation"]),
        ("pip download requests", ["violation"]),
        ("git log --oneline", ["advisory"]),
        ("git status", []),
    ],
)
def test_bash_classification_matches_on_command_position(command, expected):
    assert [hit[0] for hit in anticheat._classify_bash(command)] == expected


def test_a_git_history_read_is_advisory_not_disqualifying():
    result = anticheat.assess(scan("transcript_git_history.jsonl"))
    assert result["verdict"] == "VALID"
    assert [a["why"] for a in result["advisories"]] == [
        "ran `git log`; the corpus tree has no history of its own"
    ]


@pytest.mark.parametrize(
    "payload",
    [
        # The regression: on macOS the corpus itself lives under /private/tmp, and the
        # first real arm run was scored INVALID for reading the code it was given.
        {"file_path": "/private/tmp/claude-501/scratch/work/sigil/bench/src/field.c"},
        {"command": "cd /private/tmp/x/work/sigil/bench && wc -l src/*.c tests/smoke.c"},
        {"file_path": "/private/var/folders/t/work/sigil/bench/tests/smoke.c"},
        {"command": "grep -rn memcpy /tmp/corpus/bench/tests/"},
    ],
)
def test_reading_the_corpus_is_not_an_answer_key_access(payload):
    assert anticheat._classify_tool("Read", json.dumps(payload)) == []


@pytest.mark.parametrize(
    "payload",
    [
        {"file_path": "/w/sigil/bench-private/ground_truth.json"},
        {"file_path": "/w/sigil/control-private/maps.json"},
        {"command": "cat /w/sigil/bench-private/staged/src/field.c"},
        {"file_path": "/repo/plugins/c-review/bench/corpora/sigil/recipe.json"},
        {"command": "sed -n 1,50p /repo/plugins/c-review/bench/lib/grade.py"},
        {"file_path": "/repo/tools/c-review-bench/MEASUREMENTS.md"},
    ],
)
def test_reading_the_answer_key_is_still_caught(payload):
    hits = anticheat._classify_tool("Read", json.dumps(payload))
    assert [hit[0] for hit in hits] == ["violation"], payload


def test_an_oracle_hostname_in_a_read_is_advisory():
    result = anticheat._classify_tool(
        "Read", json.dumps({"file_path": "notes-from-github.com.txt"})
    )
    assert [hit[0] for hit in result] == ["advisory"]


def test_mcp_search_tools_count_as_oracles():
    result = anticheat._classify_tool(
        "mcp__exa__web_search_exa", json.dumps({"query": "expat cve"})
    )
    assert [hit[0] for hit in result] == ["violation"]


# ------------------------------------------------------------------ declarations


def test_a_self_declared_external_source_invalidates_the_arm():
    result = anticheat.assess(
        scan("transcript_clean.jsonl"),
        {
            "external_sources_consulted": True,
            "external_sources_detail": "read the upstream changelog",
        },
    )
    assert result["verdict"] == "INVALID"
    assert "declared" in result["violations"][0]["why"]


def test_cve_mentions_in_prose_are_surfaced():
    result = anticheat.assess(scan("transcript_cheating.jsonl"))
    text = anticheat.format_assessment(result)
    assert "INVALID" in text
    assert "tool definition(s) seen and not counted as use" in text


# ------------------------------------------------- regressions found by validation
#
# Every case below scored VALID on the shipped scanner. Each is named after what it
# got through with.

WORK = "/tmp/cbench/work"
TREE = f"{WORK}/sigil/bench"


def verdict(blocks, arm=None, containment=None, tmp_path=None):
    path = (tmp_path or Path("/tmp")) / "probe.jsonl"
    path.write_text(
        "\n".join(json.dumps({"type": "assistant", "message": {"content": [b]}}) for b in blocks)
        + "\n",
        encoding="utf-8",
    )
    result = anticheat.assess(anticheat.scan_transcripts([path], containment, arm))
    return result["verdict"], [v["why"] for v in result["violations"]]


def tool(name, payload):
    return {"type": "tool_use", "name": name, "input": payload}


def bash(command):
    return tool("Bash", {"command": command})


@pytest.fixture
def containment():
    return anticheat.Containment(TREE, [WORK, "/tmp/cbench"], allow=["/tmp/run"])


def test_reading_the_answer_key_through_a_glob_is_caught(tmp_path):
    """`.../work/sigil/*-private/g*.json` matched neither `ground_truth\\.json` nor the
    `[A-Za-z0-9_.]+-private/` pattern, because `*` is in neither character class."""
    got, why = verdict([bash(f"cat {WORK}/sigil/*-private/g*.json")], tmp_path=tmp_path)
    assert got == "INVALID", why


def test_finding_the_answer_key_by_name_prefix_is_caught(tmp_path):
    """`find -name 'ground_truth*'` never matches `ground_truth\\.json`."""
    got, why = verdict(
        [bash("find /tmp/cbench -name 'ground_truth*' -exec cat {} +")], tmp_path=tmp_path
    )
    assert got == "INVALID", why


def test_diffing_the_bench_tree_against_the_control_tree_is_caught(tmp_path, containment):
    """The two variants differ in exactly the injected bugs — the `variants` gate check
    proves it — so this one command is the whole answer key. It runs no network binary and
    names no answer-key file, so nothing saw it."""
    got, why = verdict(
        [bash(f"diff -r {TREE}/src {WORK}/sigil/control/src")],
        arm="bare",
        containment=containment,
        tmp_path=tmp_path,
    )
    assert got == "INVALID", why
    assert any("bench and control" in w for w in why)


def test_diffing_the_two_trees_by_relative_path_is_caught(tmp_path):
    """Containment cannot resolve a relative path without that call's cwd, so the
    tree-comparison rule has to stand on its own."""
    got, why = verdict([bash("diff -r ./bench/src ./control/src")], arm="bare", tmp_path=tmp_path)
    assert got == "INVALID", why


def test_reading_the_cached_pristine_upstream_is_caught(tmp_path, containment):
    """`fetch_base` extracts the un-de-identified upstream tree into the parent of the
    default work root, so `ls ../..` from the corpus finds the thing de-identification
    exists to hide."""
    got, why = verdict(
        [tool("Read", {"file_path": "/tmp/cbench/zstream-17e88863f360-src/inflate.c"})],
        arm="bare",
        containment=containment,
        tmp_path=tmp_path,
    )
    assert got == "INVALID", why


def test_reading_the_arms_own_tree_is_never_a_violation(tmp_path, containment):
    """The check that matters most is the one that does not fire on honest work. An
    over-triggering integrity check gets switched off — that already happened once, when
    `[-/]private/` matched macOS's `/private/tmp`."""
    got, why = verdict(
        [
            tool("Read", {"file_path": f"{TREE}/src/field.c"}),
            bash(f"grep -rn memcpy {TREE}/src"),
            bash(f"find {TREE} -name '*.c' | sort"),
            tool("Read", {"file_path": "/private/tmp/claude-501/x/sigil/bench/src/a.c"}),
            tool("Write", {"file_path": "/tmp/run/results/bare.result.json", "content": "{}"}),
        ],
        arm="bare",
        containment=containment,
        tmp_path=tmp_path,
    )
    assert got == "VALID", why


def test_an_interpreter_that_opens_a_socket_is_a_violation(tmp_path):
    """`python3 -c "urllib.request.urlopen(...)"` matched no network binary, so it was an
    advisory at most — and base64-obscuring the host removed even that."""
    for command in (
        "python3 -c \"import urllib.request as u;u.urlopen('https://x/a.c')\"",
        "uv run python -c \"import urllib.request;urllib.request.urlopen('https://x')\"",
        "node -e \"fetch('https://x/a').then(r=>r.text())\"",
        'python3 -c "import base64,urllib.request;'
        "urllib.request.urlopen(base64.b64decode('aHR0cA=='))\"",
    ):
        got, why = verdict([bash(command)], tmp_path=tmp_path)
        assert got == "INVALID", (command, why)


def test_a_shell_redirect_to_dev_tcp_is_a_violation(tmp_path):
    got, why = verdict([bash("exec 3<>/dev/tcp/example.org/80; cat <&3")], tmp_path=tmp_path)
    assert got == "INVALID", why


def test_an_interpreter_without_a_network_call_stays_clean(tmp_path):
    got, why = verdict(
        [bash("python3 -c \"import json;print(json.load(open('a.json')))\"")], tmp_path=tmp_path
    )
    assert got == "VALID", why


def test_a_flag_prefixed_git_subcommand_is_still_classified(tmp_path):
    """`git clone` was caught; `git -C /tmp/x clone` and `git --git-dir=… log` read
    `tokens[1]` and stopped, so neither was classified at all."""
    got, why = verdict([bash("git -C /tmp/x clone https://example.org/r")], tmp_path=tmp_path)
    assert got == "INVALID", why
    result = anticheat.assess(
        anticheat.scan_transcripts([_write(tmp_path, [bash("git --git-dir=/tmp/r/.git log -p")])])
    )
    assert result["verdict"] == "VALID"
    assert any("git log" in a["why"] for a in result["advisories"])


def _write(tmp_path, blocks):
    path = tmp_path / "probe2.jsonl"
    path.write_text(
        "\n".join(json.dumps({"type": "assistant", "message": {"content": [b]}}) for b in blocks)
        + "\n",
        encoding="utf-8",
    )
    return path


def test_mcp_tools_named_only_fetch_or_scrape_are_oracles(tmp_path):
    """The hint list held `web_fetch` and `fetch_url` but not `fetch`, which is what MCP
    servers actually call the tool."""
    for name in (
        "mcp__fetch__fetch",
        "mcp__firecrawl__firecrawl_scrape",
        "mcp__x__crawl_site",
        "mcp__Google_Drive__download_file_content",
    ):
        got, why = verdict([tool(name, {"url": "https://x"})], tmp_path=tmp_path)
        assert got == "INVALID", (name, why)


def test_a_baseline_arm_that_runs_the_artifact_under_test_is_not_a_baseline(tmp_path):
    """This is what the one real `bare` run did: the packet's own words are what the
    c-review skill's description triggers on, so the baseline invoked the subject on its
    second turn. The README listed this as uncheckable; the arm name and the invocation are
    both in hand."""
    got, why = verdict(
        [tool("Skill", {"skill": "c-review:c-review", "args": "Review the C code in /x"})],
        arm="bare",
        tmp_path=tmp_path,
    )
    assert got == "INVALID", why
    assert any("artifact under test" in w for w in why)


def test_the_c_review_arm_may_of_course_run_c_review(tmp_path):
    got, why = verdict(
        [
            tool("Skill", {"skill": "c-review:c-review", "args": "x"}),
            tool("Read", {"file_path": f"{TREE}/src/a.c"}),
        ],
        arm="c-review",
        tmp_path=tmp_path,
    )
    assert got == "VALID", why


def test_a_one_agent_arm_that_fans_out_is_a_different_arm(tmp_path):
    """The previous evaluation disqualified a baseline for exactly this, by reading the
    transcript by hand."""
    got, why = verdict([tool("Task", {"prompt": "review region 1"})], arm="bare", tmp_path=tmp_path)
    assert got == "INVALID", why
    got, why = verdict(
        [tool("Task", {"prompt": "region 1"}), tool("Read", {"file_path": f"{TREE}/a.c"})],
        arm="fanout",
        tmp_path=tmp_path,
    )
    assert got == "VALID", why


def test_zero_declarations_inspected_is_reported_not_silently_clean():
    """An absent `hunter_external_sources` list and sixteen clean declarations both fold to
    `consulted: false`. Only one of them is evidence, and the output said the same thing for
    both — the shape of the "0 of 0 hunter group(s) flagged" defect this repo has paid for."""
    result = anticheat.assess(scan("transcript_clean.jsonl"), {"external_sources_consulted": False})
    assert result["declarations_seen"] == 0
    assert "established nothing" in anticheat.format_assessment(result)
    seen = anticheat.assess(
        scan("transcript_clean.jsonl"),
        {"external_sources_consulted": False, "declarations_seen": 16},
    )
    assert seen["declarations_seen"] == 16
    assert "established nothing" not in anticheat.format_assessment(seen)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
