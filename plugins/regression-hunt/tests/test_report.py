"""Structural report gates; synthetic fixtures do not represent model experiments."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from evidence import IntegrityError, read, seal
from registry import accept, bind, candidate, initialize, reserve
from report import CHECKS, collect, render, stage
from test_evidence import save

SCRIPT = Path(__file__).parents[1] / "scripts" / "report.py"


class Campaign:
    """Build accepted packages through the same registration path as stage callers."""

    def __init__(self, root, shared=(), unaccepted=()):
        self.root = root
        self.paths = {}
        self.cid = None
        self.shared = set(shared)
        self.unaccepted = set(unaccepted)
        save(root, "scope.json", {"changes": [{"id": "P1", "input": "SHA"}]})
        initialize(root)

    def start(self, role, inputs):
        attempt = reserve(
            self.root,
            {
                "stage": role,
                "change": "P1",
                "inputs": inputs,
                "candidate": self.cid if role in ("reproduce", "replay", "adjudicate") else None,
            },
        )
        aid = attempt["id"]
        raw = f"runtime/{aid}.txt"
        receipt = f"runtime/{aid}.json"
        save(self.root, raw, {"response": "Synthetic host response"})
        if role in self.shared:
            save(
                self.root,
                receipt,
                {
                    "event": "launch",
                    "attempt": aid,
                    "tool": "codex.spawn_agent",
                    "call": {"task_name": role, "fork_turns": "none"},
                    "response": {"task_name": role},
                    "observed_at": "2026-09-30T12:00:00+00:00",
                    "evidence": [raw],
                },
            )
            return bind(self.root, aid, role, agent_record=receipt)
        save(
            self.root,
            receipt,
            {
                "event": "launch",
                "attempt": aid,
                "host": "fixture",
                "session": "session-1",
                "agent": role,
                "context": aid,
                "environment": aid,
                "directory": attempt["directory"],
                "fresh_context": True,
                "isolated": True,
                "observed_at": "2026-09-30T12:00:00+00:00",
                "evidence": [raw],
            },
        )
        return bind(self.root, aid, role, receipt)

    def artifact(self, attempt, name, value):
        path = f"{attempt['directory']}/{name}"
        save(self.root, path, value)
        return path

    def finish(self, attempt, **fields):
        name = f"{attempt['directory']}/result.json"
        save(
            self.root,
            name,
            {
                "attempt": attempt["id"],
                "stage": attempt["stage"],
                "change": "P1",
                "agent": attempt["agent"],
                "candidate": attempt["candidate"],
                "status": "complete",
                "security_review": "SECURITY.md",
                "inputs": attempt["inputs"],
                "artifacts": [],
                **fields,
            },
        )
        seal(self.root, name)
        if attempt["stage"] not in self.unaccepted:
            accept(self.root, attempt["id"], name)
        self.paths[attempt["stage"]] = name

    def prepare(self):
        attempt = self.start("prepare", [])
        source = self.artifact(attempt, "source.json", {"s0": "a" * 40, "s1": "b" * 40})
        self.paths["source"] = source
        self.finish(attempt, artifacts=[source], source=source)
        attempt = self.start("hunt", [self.paths["prepare"]])
        self.cid = candidate(self.root, attempt["id"], "fixture-lead", attempt["agent"])
        name = self.artifact(
            attempt,
            "candidate.json",
            {
                "id": self.cid,
                "key": "fixture-lead",
                "title": "<script>escaped</script>",
            },
        )
        self.paths["candidate"] = name
        self.finish(
            attempt, artifacts=[name], candidates=[self.cid], candidate_files={self.cid: name}
        )

    def experiment(self, role, mutation=None):
        inputs = [self.paths[key] for key in ("prepare", "hunt", "source", "candidate")]
        if role == "replay":
            inputs.append(self.paths["reproduce"])
        attempt = self.start(role, inputs)
        setup, poc, workload, log0, log1 = [
            self.artifact(attempt, name, {"content": "Synthetic fixture"})
            for name in ("setup.json", "payload.json", "input.json", "log0.json", "log1.json")
        ]
        value = {
            "artifacts": [setup, poc, workload, log0, log1],
            "build_dirs": [f"{attempt['directory']}/build"],
            "source": self.paths["source"],
            "setup": setup,
            "poc": poc,
            "workload": workload,
            "runs": [
                {
                    "state": state,
                    "revision": sha * 40,
                    "deployment": "fixture",
                    "command": "fixture",
                    "log": log,
                    "behavior": behavior,
                }
                for state, sha, log, behavior in (
                    ("S0", "a", log0, "correct"),
                    ("S1", "b", log1, "failure"),
                )
            ],
        }
        if mutation:
            mutation(self.root, value)
        self.finish(attempt, **value)

    def decide(self, unknown_check, outcome):
        inputs = [
            self.paths[key] for key in ("prepare", "hunt", "candidate", "reproduce", "replay")
        ]
        attempt = self.start("adjudicate", inputs)
        analysis = self.artifact(attempt, "analysis.json", {"reason": "Synthetic analysis"})
        self.paths["analysis"] = analysis
        checks = {
            key: {
                "conclusion": "SUPPORTED" if key in CHECKS[:3] else "REFUTED",
                "reason": "Synthetic analysis",
                "evidence": [analysis],
            }
            for key in CHECKS
        }
        checks["security_scope"]["conclusion"] = "NOT_APPLICABLE"
        if unknown_check:
            checks[unknown_check]["conclusion"] = "UNKNOWN"
        self.finish(
            attempt,
            artifacts=[analysis],
            outcome=outcome,
            reason="Analysis with evidence",
            evidence=[analysis],
            reproduction=self.paths["reproduce"],
            replay=self.paths["replay"],
            category="FUNCTIONAL_BUG",
            severity="Low",
            likelihood="Low",
            severity_reason="Narrow impact",
            likelihood_reason="Rare supported input",
            checks=checks,
        )
        save(
            self.root,
            "campaign.json",
            {
                "title": "Example",
                "changes": [
                    {
                        "id": "P1",
                        "input": "SHA",
                        "prepare": self.paths["prepare"],
                        "hunt": self.paths["hunt"],
                        "candidates": [
                            {
                                "id": self.cid,
                                "candidate": self.paths["candidate"],
                                "decision": self.paths["adjudicate"],
                            }
                        ],
                    }
                ],
            },
        )


@pytest.fixture
def campaign_factory(tmp_path):
    def build(
        *,
        unknown_check=None,
        outcome="REPRODUCED_REGRESSION",
        replay_mutation=None,
        shared=(),
        unaccepted=(),
    ):
        campaign = Campaign(tmp_path, shared, unaccepted)
        campaign.prepare()
        campaign.experiment("reproduce")
        campaign.experiment("replay", replay_mutation)
        campaign.decide(unknown_check, outcome)
        return campaign

    return build


@pytest.fixture
def campaign(campaign_factory):
    return campaign_factory()


def test_unregistered_campaign_is_rejected_even_without_stage_records(tmp_path):
    save(
        tmp_path,
        "campaign.json",
        {
            "title": "Unregistered",
            "changes": [
                {"id": "P1", "input": "SHA", "prepare": None, "hunt": None, "candidates": []}
            ],
        },
    )
    with pytest.raises(ValueError, match="registry"):
        collect(tmp_path)


def test_unregistered_sealed_record_is_rejected(tmp_path):
    save(
        tmp_path,
        "prepare.json",
        {
            "stage": "prepare",
            "agent": "prepare",
            "status": "complete",
            "security_review": "SECURITY.md",
            "inputs": [],
            "artifacts": [],
        },
    )
    seal(tmp_path, "prepare.json")
    with pytest.raises(ValueError, match="attempt ID"):
        stage(tmp_path, "prepare.json", "prepare")


@pytest.mark.parametrize("missing", ["registry.json", "scope.json"])
def test_removing_campaign_control_files_cannot_bypass_validation(campaign, missing):
    (campaign.root / missing).unlink()
    with pytest.raises((OSError, ValueError)):
        collect(campaign.root)


def test_report_counts_evidence_links_and_html_escaping(campaign):
    data = collect(campaign.root)
    assert data["counts"]["REPRODUCED_REGRESSION"] == 1
    assert data["changes"][0]["status"] == "COMPLETE"
    render(campaign.root, data)
    page = (campaign.root / "report/index.html").read_text()
    assert "<script>" not in page
    assert f'href="../{campaign.paths["analysis"]}"' in page
    assert json.loads((campaign.root / "report/report.json").read_text()) == data


@pytest.mark.parametrize(
    "field", ["latent_bug", "incomplete_fix", "preexisting_bug", "reachability"]
)
def test_unknown_checks_leave_the_finding_unresolved(campaign_factory, field):
    campaign = campaign_factory(unknown_check=field)
    data = collect(campaign.root)
    row = data["findings"][0]
    assert data["counts"]["REPRODUCED_REGRESSION"] == 0
    assert row["outcome"] == "UNRESOLVED"
    assert field in row["unresolved_reason"]
    assert row["verification"] is None


@pytest.mark.parametrize("mutation", ["same-agent", "wrong-candidate"])
def test_misassigned_replay_is_rejected_at_acceptance(campaign_factory, mutation):
    def alter(root, replay):
        if mutation == "same-agent":
            replay["agent"] = "reproduce"
        else:
            replay["candidate"] = "different-candidate"

    with pytest.raises(ValueError, match="wrong assigned"):
        campaign_factory(replay_mutation=alter)


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("wrong-revision", "wrong revision"),
        ("no-failure", "differential result"),
        ("changed-poc", "poc changed"),
    ],
)
def test_invalid_replay_leaves_the_finding_unresolved(campaign_factory, mutation, reason):
    def alter(root, replay):
        if mutation == "wrong-revision":
            replay["runs"][0]["revision"] = "c" * 40
        elif mutation == "no-failure":
            replay["runs"][1]["behavior"] = "correct"
        else:
            (root / replay["poc"]).write_text("different payload")

    campaign = campaign_factory(replay_mutation=alter)
    row = collect(campaign.root)["findings"][0]
    assert row["outcome"] == "UNRESOLVED"
    assert reason in row["unresolved_reason"]


def test_confirmed_findings_report_their_verification_level(campaign):
    data = collect(campaign.root)
    row = data["findings"][0]
    assert row["outcome"] == "REPRODUCED_REGRESSION"
    assert row["verification"] == "isolated"
    assert row["unresolved_reason"] is None
    render(campaign.root, data)
    assert "REPRODUCED_REGRESSION (isolated)" in (campaign.root / "report/report.md").read_text()
    assert "REPRODUCED_REGRESSION (isolated)" in (campaign.root / "report/index.html").read_text()


def test_forged_isolated_label_in_registry_is_an_integrity_error(campaign_factory):
    campaign = campaign_factory(shared=("replay",))
    registry = campaign.root / "registry.json"
    data = json.loads(registry.read_text())
    replay = json.loads((campaign.root / campaign.paths["replay"]).read_text())
    attempt = data["attempts"][replay["attempt"]]
    attempt["verification"] = "isolated"
    del attempt["launch"]["value"]["tool"]
    attempt["launch"]["value"]["isolated"] = True
    registry.write_text(json.dumps(data))
    with pytest.raises(IntegrityError, match="stored launch data"):
        collect(campaign.root)


def test_weakest_verification_level_wins(campaign_factory):
    row = collect(campaign_factory(shared=("replay",)).root)["findings"][0]
    assert row["outcome"] == "REPRODUCED_REGRESSION"
    assert row["verification"] == "shared-host"


def test_unaccepted_replay_leaves_the_finding_unresolved_and_cli_writes_report(
    campaign_factory,
):
    campaign = campaign_factory(unaccepted=("replay",))
    row = collect(campaign.root)["findings"][0]
    assert row["outcome"] == "UNRESOLVED"
    assert "not accepted" in row["unresolved_reason"]
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(campaign.root)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads((campaign.root / "report/report.json").read_text())
    assert report["findings"][0]["outcome"] == "UNRESOLVED"


def test_tampered_evidence_exits_1_without_writing(campaign):
    (campaign.root / campaign.paths["analysis"]).write_text('{"reason": "edited"}')
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(campaign.root)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "integrity" in result.stderr
    assert not (campaign.root / "report").exists()


def test_usage_error_exits_2():
    result = subprocess.run(
        [sys.executable, str(SCRIPT)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 2


@pytest.mark.parametrize(
    "outcome", ["INCOMPLETE_FIX", "LATENT_BUG", "PREEXISTING_BUG", "REJECTED", "UNRESOLVED"]
)
def test_exclusions_and_unresolved_stay_outside_totals(campaign_factory, outcome):
    campaign = campaign_factory(outcome=outcome)
    counts = collect(campaign.root)["counts"]
    assert counts[outcome] == 1
    assert counts["REPRODUCED_REGRESSION"] == 0


def test_missing_decisions_and_dropped_candidates(campaign):
    index = read(campaign.root, "campaign.json")
    index["changes"][0]["candidates"][0]["decision"] = None
    save(campaign.root, "campaign.json", index)
    assert collect(campaign.root)["counts"]["UNRESOLVED"] == 1
    index["changes"][0]["candidates"] = []
    save(campaign.root, "campaign.json", index)
    with pytest.raises(ValueError, match="candidate mismatch"):
        collect(campaign.root)


@pytest.mark.parametrize("tamper", ["non-json", "attempt-removed"])
def test_tampered_adjudication_record_exits_1_without_writing(campaign, tamper):
    path = campaign.root / campaign.paths["adjudicate"]
    if tamper == "non-json":
        path.write_text("not json")
    else:
        value = json.loads(path.read_text())
        del value["attempt"]
        path.write_text(json.dumps(value))
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(campaign.root)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "integrity" in result.stderr
    assert not (campaign.root / "report").exists()


def test_invalid_decision_path_in_index_stops_report(campaign):
    index = read(campaign.root, "campaign.json")
    index["changes"][0]["candidates"][0]["decision"] = "../outside.json"
    save(campaign.root, "campaign.json", index)
    with pytest.raises(ValueError, match="campaign-relative"):
        collect(campaign.root)


def test_confirmation_without_verification_level_is_unresolved(campaign):
    registry = campaign.root / "registry.json"
    data = json.loads(registry.read_text())
    replay = json.loads((campaign.root / campaign.paths["replay"]).read_text())
    data["attempts"][replay["attempt"]]["verification"] = None
    registry.write_text(json.dumps(data))
    row = collect(campaign.root)["findings"][0]
    assert row["outcome"] == "UNRESOLVED"
    assert row["verification"] is None
    assert "verification level" in row["unresolved_reason"]


@pytest.mark.parametrize("tamper", ["seal-deleted-attempt-removed", "attempt-swapped-resealed"])
def test_altered_accepted_adjudication_exits_1(campaign, tamper):
    name = campaign.paths["adjudicate"]
    path = campaign.root / name
    value = json.loads(path.read_text())
    if tamper == "seal-deleted-attempt-removed":
        (campaign.root / (name + ".seal.json")).unlink()
        del value["attempt"]
        path.write_text(json.dumps(value))
    else:
        replay = json.loads((campaign.root / campaign.paths["replay"]).read_text())
        value["attempt"] = replay["attempt"]
        path.write_text(json.dumps(value))
        (campaign.root / (name + ".seal.json")).unlink()
        seal(campaign.root, name)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(campaign.root)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "integrity" in result.stderr
    assert not (campaign.root / "report").exists()


def test_changed_dependency_of_accepted_decision_exits_1(campaign_factory):
    campaign = campaign_factory(unaccepted=("replay",))
    log = (
        campaign.root
        / json.loads((campaign.root / campaign.paths["replay"]).read_text())["runs"][0]["log"]
    )
    log.write_text('{"content": "changed after sealing"}')
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(campaign.root)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "integrity" in result.stderr
    assert not (campaign.root / "report").exists()


def test_deleted_accepted_replay_exits_1(campaign):
    (campaign.root / campaign.paths["replay"]).unlink()
    (campaign.root / (campaign.paths["replay"] + ".seal.json")).unlink()
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(campaign.root)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "integrity" in result.stderr


def test_decision_naming_absent_replay_is_unresolved(campaign_factory):
    def absent(root, replay):
        replay["runs"][0]["log"] = "attempts/never/log0.json"

    campaign = campaign_factory(replay_mutation=absent)
    row = collect(campaign.root)["findings"][0]
    assert row["outcome"] == "UNRESOLVED"
    assert "unsealed" in row["unresolved_reason"]
    assert campaign.paths["adjudicate"] in row["evidence"]


def test_relabeled_shared_host_attempt_is_not_confirmed(campaign_factory):
    campaign = campaign_factory(shared=("replay",))
    registry = campaign.root / "registry.json"
    data = json.loads(registry.read_text())
    replay = json.loads((campaign.root / campaign.paths["replay"]).read_text())
    data["attempts"][replay["attempt"]]["verification"] = "isolated"
    registry.write_text(json.dumps(data))
    row = collect(campaign.root)["findings"][0]
    assert row["outcome"] == "UNRESOLVED"
    assert "verification level" in row["unresolved_reason"]
