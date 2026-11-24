"""Assignment checks use synthetic records, never model or benchmark evidence."""

import json
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from unittest.mock import patch

from evidence import IntegrityError, seal
from registry import accept, bind, candidate, check, initialize, reserve, retry, show
from report import CHECKS, collect, render, stage


def parallel_reservation(root):
    return reserve(Path(root), {"stage": "hunt", "change": "change-1", "inputs": []})


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scope = {
            "changes": [
                {"id": "change-1", "input": "original-commit"},
                {"id": "change-2", "input": "second-commit"},
            ]
        }
        (self.root / "scope.json").write_text(json.dumps(self.scope))
        initialize(self.root)

    def host_record(self, attempt_id, event="launch", **fields):
        attempt = show(self.root)["attempts"][attempt_id]
        identity = {
            "host": "synthetic-host",
            "session": "test-session",
            "agent": f"agent-{attempt_id}",
            "context": f"context-{attempt_id}",
        }
        if event == "terminal":
            identity = {key: attempt["launch"]["value"][key] for key in identity}
        name = f"runtime/{attempt_id}-{event}.json"
        raw = f"runtime/{attempt_id}-{event}.txt"
        (self.root / "runtime").mkdir(exist_ok=True)
        (self.root / raw).write_text("Synthetic host response for validation tests")
        value = {
            **identity,
            "attempt": attempt_id,
            "event": event,
            "observed_at": "2026-09-30T12:00:00+00:00",
            "evidence": [raw],
            "directory": attempt["directory"],
            "fresh_context": True,
            "isolated": True,
            "environment": f"env-{attempt_id}",
            "state": "stopped",
            "active_commands": [],
            "resources_released": True,
            **fields,
        }
        (self.root / name).write_text(json.dumps(value))
        return name

    def bind_agent(self, attempt_id, agent="agent-1"):
        handle = f"{agent}-{attempt_id}"
        return bind(self.root, attempt_id, handle, self.host_record(attempt_id, agent=handle))

    def retry_attempt(self, attempt_id, inputs=None):
        return retry(
            self.root, attempt_id, inputs, host_record=self.host_record(attempt_id, "terminal")
        )

    def reserve_candidate(self, attempt_id, key, agent="agent-1"):
        return candidate(self.root, attempt_id, key, f"{agent}-{attempt_id}")

    def start(self, stage="hunt", **fields):
        change = "campaign" if stage == "report" else "change-1"
        attempt = reserve(self.root, {"stage": stage, "change": change, "inputs": [], **fields})
        self.bind_agent(attempt["id"])
        return attempt

    def record(self, assignment, **fields):
        path = self.root / assignment["directory"] / "result.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        value = {
            "attempt": assignment["id"],
            "stage": assignment["stage"],
            "agent": show(self.root)["attempts"][assignment["id"]]["agent"],
            "change": assignment["change"],
            "candidate": assignment["candidate"],
            "status": "complete",
            "inputs": assignment["inputs"],
            "artifacts": [],
            **fields,
        }
        path.write_text(json.dumps(value))
        name = path.relative_to(self.root).as_posix()
        seal(self.root, name)
        return name

    def discover(self, inputs=()):
        attempt = self.start(inputs=list(inputs))
        cid = self.reserve_candidate(attempt["id"], "boundary-check", "agent-1")
        name = f"{attempt['directory']}/candidate.json"
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"id": cid, "key": "boundary-check", "title": "Test lead"}))
        record = self.record(
            attempt,
            candidates=[cid],
            candidate_files={cid: name},
            artifacts=[name],
            security_review="No security documents supplied",
        )
        accept(self.root, attempt["id"], record)
        return attempt, cid, name

    def test_parallel_reservations_have_distinct_ids_and_prefixes(self):
        with ProcessPoolExecutor(max_workers=3) as pool:
            attempts = list(pool.map(parallel_reservation, [str(self.root)] * 8))
        self.assertEqual(len({a["id"] for a in attempts}), 8)
        self.assertEqual(len({a["prefix"] for a in attempts}), 8)
        self.assertEqual(len(show(self.root)["attempts"]), 8)

    def test_retry_preserves_candidates_and_retires_old_attempt(self):
        first = self.start()
        cid = self.reserve_candidate(first["id"], "boundary-check", "agent-1")
        second = self.retry_attempt(first["id"])
        self.bind_agent(second["id"], "agent-2")
        self.assertNotEqual(first["id"], second["id"])
        self.assertNotEqual(first["directory"], second["directory"])
        self.assertEqual(first["prefix"], second["prefix"])
        self.assertEqual(self.reserve_candidate(second["id"], "boundary-check", "agent-2"), cid)
        self.assertNotEqual(self.reserve_candidate(second["id"], "another-check", "agent-2"), cid)
        with self.assertRaisesRegex(ValueError, "superseded"):
            self.reserve_candidate(first["id"], "late-result", "agent-1")

    def test_binding_is_idempotent_but_cannot_change_owner(self):
        attempt = self.start()
        self.bind_agent(attempt["id"], "agent-1")
        with self.assertRaisesRegex(ValueError, "agent"):
            self.bind_agent(attempt["id"], "agent-2")

    def test_wrong_agent_cannot_allocate_candidates(self):
        attempt = self.start()
        with self.assertRaisesRegex(ValueError, "agent"):
            self.reserve_candidate(attempt["id"], "lead", "other-agent")

    def test_unbound_or_wrong_stage_cannot_allocate_candidates(self):
        attempt = reserve(self.root, {"stage": "hunt", "change": "change-1", "inputs": []})
        with self.assertRaises(ValueError):
            self.reserve_candidate(attempt["id"], "lead", "agent-1")
        attempt = self.start("prepare")
        with self.assertRaisesRegex(ValueError, "hunt"):
            self.reserve_candidate(attempt["id"], "lead", "agent-1")

    def test_empty_and_unknown_assignments_fail(self):
        for assignment in ({}, {"stage": "unknown", "change": "change-1", "inputs": []}):
            with self.subTest(assignment=assignment), self.assertRaises(ValueError):
                reserve(self.root, assignment)
        with self.assertRaisesRegex(ValueError, "Unknown attempt"):
            bind(self.root, "a999", "agent", "missing.json")

    def test_attempt_rejects_wrong_change_and_unregistered_candidate(self):
        _, cid, name = self.discover()
        for fields in ({"candidate": "missing"}, {"candidate": cid, "change": "other"}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.start("reproduce", inputs=[name], **fields)

    def test_candidate_file_must_be_an_assigned_input(self):
        _, cid, _ = self.discover()
        with self.assertRaisesRegex(ValueError, "candidate file"):
            self.start("reproduce", candidate=cid)

    def test_acceptance_checks_record_bindings(self):
        _, cid, name = self.discover()
        attempt = self.start("reproduce", candidate=cid, inputs=[name])
        for fields in (
            {"candidate": "wrong"},
            {"change": "change-2"},
            {"agent": "wrong"},
            {"attempt": "wrong"},
            {"stage": "replay"},
            {"inputs": []},
            {"status": "running"},
        ):
            with self.subTest(fields=fields):
                current = self.retry_attempt(attempt["id"])
                self.bind_agent(current["id"], "agent-1")
                record = self.record(current, **fields)
                with self.assertRaises(ValueError):
                    accept(self.root, current["id"], record)
                attempt = current

    def test_blocked_results_are_accepted_without_becoming_findings(self):
        attempt = self.start("prepare")
        record = self.record(attempt, status="blocked", summary="Missing source")
        accept(self.root, attempt["id"], record)
        self.assertEqual(check(self.root, attempt["id"], record)["status"], "blocked")
        accept(self.root, attempt["id"], record)

    def test_superseded_results_cannot_be_accepted(self):
        attempt = self.start("prepare")
        record = self.record(attempt)
        self.retry_attempt(attempt["id"])
        with self.assertRaisesRegex(ValueError, "superseded"):
            accept(self.root, attempt["id"], record)

    def test_report_requires_registry_acceptance_and_rejects_superseded_results(self):
        attempt = self.start("prepare")
        record = self.record(attempt, security_review="No security documents supplied")
        with self.assertRaisesRegex(ValueError, "not accepted"):
            stage(self.root, record, "prepare")
        accept(self.root, attempt["id"], record)
        self.assertEqual(stage(self.root, record, "prepare")["attempt"], attempt["id"])
        self.retry_attempt(attempt["id"])
        with self.assertRaisesRegex(ValueError, "superseded"):
            stage(self.root, record, "prepare")

    def test_omitting_attempt_cannot_bypass_registry_checks(self):
        attempt = self.start("prepare")
        record = self.record(
            attempt, attempt=None, security_review="No security documents supplied"
        )
        with self.assertRaisesRegex(ValueError, "attempt ID"):
            stage(self.root, record, "prepare")

    def test_nested_report_outputs_have_valid_evidence_links(self):
        (self.root / "evidence.txt").write_text("test observation")
        data = {
            "title": "Test report",
            "counts": {},
            "changes": [],
            "findings": [
                {
                    "id": "c",
                    "title": "Test lead",
                    "outcome": "UNRESOLVED",
                    "input": "test change",
                    "reason": "Needs evidence",
                    "evidence": ["evidence.txt"],
                }
            ],
        }
        render(self.root, data, "attempts/a001/reports")
        markdown = (self.root / "attempts/a001/reports/report.md").read_text()
        self.assertIn("[evidence.txt](../../../evidence.txt)", markdown)
        with self.assertRaises(ValueError):
            render(self.root, data, "../outside")

    def test_reporting_attempt_accepts_its_sealed_outputs(self):
        attempt = self.start("report")
        output = f"{attempt['directory']}/reports"
        render(self.root, {"title": "Empty", "counts": {}, "changes": [], "findings": []}, output)
        record = self.record(attempt, artifacts=[output])
        accept(self.root, attempt["id"], record)
        self.assertEqual(check(self.root, attempt["id"], record)["stage"], "report")

    def test_forged_and_duplicate_hunt_ids_are_rejected(self):
        first = self.start()
        cid = self.reserve_candidate(first["id"], "lead", "agent-1")
        other = self.start()
        for ids in ([cid], [cid, cid]):
            with self.subTest(ids=ids):
                attempt = self.retry_attempt(other["id"])
                self.bind_agent(attempt["id"], "agent-1")
                record = self.record(attempt, candidates=ids, candidate_files={})
                with self.assertRaisesRegex(ValueError, "candidate IDs"):
                    accept(self.root, attempt["id"], record)
                other = attempt

    def test_failed_retry_keeps_previous_attempt_active(self):
        attempt = self.start()
        with self.assertRaises(ValueError):
            self.retry_attempt(attempt["id"], ["missing-input"])
        self.assertEqual(show(self.root)["attempts"][attempt["id"]]["state"], "running")

    def test_existing_attempt_directory_cannot_be_reused(self):
        self.start()
        (self.root / "attempts/a002").mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "directory already exists"):
            self.start("prepare")

    def test_input_changes_after_dispatch_are_rejected(self):
        (self.root / "input.txt").write_text("original")
        attempt = self.start("prepare", inputs=["input.txt"])
        (self.root / "input.txt").write_text("changed")
        record = self.record(attempt)
        with self.assertRaisesRegex(IntegrityError, "inputs changed"):
            accept(self.root, attempt["id"], record)

    def test_resealed_input_changes_are_rejected(self):
        first = self.start("prepare")
        record = self.record(first)
        attempt = self.start("hunt", inputs=[record])
        path = self.root / record
        data = json.loads(path.read_text())
        data["summary"] = "changed"
        path.write_text(json.dumps(data))
        (self.root / (record + ".seal.json")).unlink()
        seal(self.root, record)
        result = self.record(attempt, candidates=[], candidate_files={})
        with self.assertRaisesRegex(IntegrityError, "inputs changed"):
            accept(self.root, attempt["id"], result)

    def test_record_and_artifacts_must_stay_in_assigned_directory(self):
        attempt = self.start("prepare")
        (self.root / "outside.txt").write_text("outside")
        record = self.record(attempt, artifacts=["outside.txt"])
        with self.assertRaisesRegex(ValueError, "directory"):
            accept(self.root, attempt["id"], record)
        with self.assertRaisesRegex(ValueError, "directory"):
            accept(self.root, attempt["id"], "elsewhere.json")

    def test_hunt_cannot_omit_reserved_candidates(self):
        attempt = self.start()
        self.reserve_candidate(attempt["id"], "lead", "agent-1")
        record = self.record(attempt, candidates=[], candidate_files={})
        with self.assertRaisesRegex(ValueError, "candidate"):
            accept(self.root, attempt["id"], record)

    def test_hunt_cannot_reassign_a_candidate_key(self):
        attempt, cid, _ = self.discover()
        attempt = self.retry_attempt(attempt["id"])
        self.bind_agent(attempt["id"], "agent-1")
        name = f"{attempt['directory']}/candidate.json"
        path = self.root / name
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"id": cid, "key": "different-lead"}))
        record = self.record(
            attempt, candidates=[cid], candidate_files={cid: name}, artifacts=[name]
        )
        with self.assertRaisesRegex(ValueError, "key"):
            accept(self.root, attempt["id"], record)

    def test_failed_atomic_save_keeps_previous_registry(self):
        self.start()
        before = (self.root / "registry.json").read_bytes()
        with (
            patch("registry.os.replace", side_effect=OSError("interrupted")),
            self.assertRaisesRegex(OSError, "interrupted"),
        ):
            self.start("prepare")
        self.assertEqual((self.root / "registry.json").read_bytes(), before)
        self.assertEqual(len(show(self.root)["attempts"]), 1)

    def test_corrupt_registry_is_not_reset(self):
        (self.root / "registry.json").write_text("{broken")
        with self.assertRaises(ValueError):
            self.start()
        self.assertEqual((self.root / "registry.json").read_text(), "{broken")

    def test_registry_symlink_and_existing_output_directory_are_rejected(self):
        outside = self.root / "other.json"
        outside.write_text("{}")
        (self.root / "registry.json").unlink()
        (self.root / "registry.json").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "Symlink"):
            self.start()
        (self.root / "registry.json").unlink()
        (self.root / "attempts" / "a001").mkdir(parents=True)
        with self.assertRaises(ValueError):
            self.start()

    def test_cli_returns_json_and_actionable_errors(self):
        script = Path(__file__).parents[1] / "scripts" / "registry.py"
        result = subprocess.run(
            [
                sys.executable,
                str(script),
                "reserve",
                str(self.root),
                "--stage",
                "hunt",
                "--change",
                "change-1",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(json.loads(result.stdout)["id"], "a001")
        result = subprocess.run(
            [
                sys.executable,
                str(script),
                "bind",
                str(self.root),
                "missing",
                "--agent",
                "a",
                "--host-record",
                "runtime/missing.json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unknown attempt", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def index(self):
        value = {
            "title": "Test campaign",
            "changes": [
                {**change, "prepare": None, "hunt": None, "candidates": []}
                for change in self.scope["changes"]
            ],
        }
        (self.root / "campaign.json").write_text(json.dumps(value))
        return value

    def test_frozen_scope_cannot_be_replaced_or_omitted(self):
        initialize(self.root)
        (self.root / "scope.json").write_text('{"changes": []}')
        with self.assertRaisesRegex(ValueError, "Frozen scope changed"):
            initialize(self.root)
        with self.assertRaisesRegex(ValueError, "Frozen scope changed"):
            self.start()
        (self.root / "scope.json").unlink()
        with self.assertRaises(OSError):
            self.start()

    def test_uninitialized_and_out_of_scope_assignments_fail(self):
        with self.assertRaisesRegex(ValueError, "outside frozen scope"):
            self.start(change="unrequested")
        (self.root / "registry.json").unlink()
        with self.assertRaisesRegex(ValueError, "Initialize scope"):
            self.start()
        self.assertFalse((self.root / "registry.json").exists())

    def test_scope_requires_unique_nonempty_change_ids_and_inputs(self):
        (self.root / "registry.json").unlink()
        for changes in (
            [],
            [{"id": "", "input": "x"}],
            [{"id": "c"}],
            [{"id": "campaign", "input": "x"}],
            [{"id": "c", "input": "x"}, {"id": "c", "input": "y"}],
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                (self.root / "scope.json").write_text(json.dumps({"changes": changes}))
                initialize(self.root)
        self.assertFalse((self.root / "registry.json").exists())

    def test_report_rejects_dropped_added_and_changed_scope(self):
        for mutation in ("drop", "add", "input", "duplicate"):
            index = self.index()
            if mutation == "drop":
                index["changes"].pop()
            elif mutation == "add":
                index["changes"].append({"id": "unrequested", "input": "another"})
            elif mutation == "duplicate":
                index["changes"].append(index["changes"][0])
            else:
                index["changes"][0]["input"] = "replacement"
            (self.root / "campaign.json").write_text(json.dumps(index))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                collect(self.root)
        self.index()
        self.assertEqual(len(collect(self.root)["changes"]), 2)

    def test_report_rejects_another_changes_accepted_package(self):
        attempt = self.start("prepare")
        name = self.record(attempt, security_review="No security documents supplied")
        accept(self.root, attempt["id"], name)
        index = self.index()
        index["changes"][1]["prepare"] = name
        (self.root / "campaign.json").write_text(json.dumps(index))
        with self.assertRaisesRegex(ValueError, "wrong indexed change"):
            collect(self.root)

    def test_assignment_rejects_prerequisites_from_another_change(self):
        attempt = self.start("prepare")
        name = self.record(attempt)
        accept(self.root, attempt["id"], name)
        with self.assertRaisesRegex(ValueError, "prerequisite belongs to another change"):
            self.start("hunt", change="change-2", inputs=[name])

    def test_launch_requires_host_evidence_of_fresh_isolated_context(self):
        attempt = reserve(self.root, {"stage": "prepare", "change": "change-1"})
        for fields in (
            {"fresh_context": False},
            {"isolated": False},
            {"evidence": []},
            {"context": ""},
            {"environment": ""},
            {"directory": "wrong"},
            {"observed_at": "2026-09-30T12:00:00"},
            {"attempt": "a999"},
        ):
            name = self.host_record(attempt["id"], **fields)
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                bind(self.root, attempt["id"], f"agent-{attempt['id']}", name)
        self.assertEqual(show(self.root)["attempts"][attempt["id"]]["state"], "reserved")

    def test_fresh_launch_rejects_reused_agent_context_or_environment(self):
        first = self.start("prepare")
        prior = show(self.root)["attempts"][first["id"]]["launch"]["value"]
        attempt = reserve(self.root, {"stage": "prepare", "change": "change-1"})
        for field in ("agent", "context", "environment"):
            name = self.host_record(attempt["id"], **{field: prior[field]})
            agent = prior["agent"] if field == "agent" else f"agent-{attempt['id']}"
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "reused host"):
                bind(self.root, attempt["id"], agent, name)

    def test_acceptance_rechecks_launch_evidence(self):
        attempt = self.start("prepare")
        name = self.record(attempt)
        (self.root / f"runtime/{attempt['id']}-launch.txt").write_text("changed host evidence")
        with self.assertRaisesRegex(IntegrityError, "runtime evidence changed"):
            accept(self.root, attempt["id"], name)

    def test_edited_launch_data_raises_integrity_error(self):
        attempt = self.start("prepare")
        name = self.record(attempt)
        path = self.root / "registry.json"
        data = json.loads(path.read_text())
        data["attempts"][attempt["id"]]["launch"]["value"]["isolated"] = False
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(IntegrityError, "stored launch data"):
            accept(self.root, attempt["id"], name)

    def test_changed_frozen_scope_raises_integrity_error(self):
        (self.root / "scope.json").write_text('{"changes": []}')
        with self.assertRaisesRegex(IntegrityError, "Frozen scope changed"):
            show(self.root)

    def test_resealed_accepted_record_raises_integrity_error(self):
        attempt = self.start("prepare")
        name = self.record(attempt)
        accept(self.root, attempt["id"], name)
        path = self.root / name
        value = json.loads(path.read_text())
        value["status"] = "blocked"
        path.write_text(json.dumps(value))
        (self.root / (name + ".seal.json")).unlink()
        seal(self.root, name)
        with self.assertRaisesRegex(IntegrityError, "accepted record changed"):
            check(self.root, attempt["id"], name)

    def test_deleted_runtime_evidence_raises_integrity_error(self):
        attempt = self.start("prepare")
        name = self.record(attempt)
        (self.root / f"runtime/{attempt['id']}-launch.txt").unlink()
        with self.assertRaisesRegex(IntegrityError, "runtime evidence"):
            accept(self.root, attempt["id"], name)

    def test_retry_requires_matching_terminal_identity_and_quiescence(self):
        attempt = self.start("prepare")
        for fields in (
            {"state": "running"},
            {"state": "idle"},
            {"state": "timeout"},
            {"agent": "another-agent"},
            {"context": "another-context"},
            {"session": "another-session"},
            {"resources_released": False},
            {"active_commands": ["process-1"]},
            {"active_commands": None},
            {"observed_at": "2026-09-29T12:00:00+00:00"},
            {"evidence": []},
        ):
            name = self.host_record(attempt["id"], "terminal", **fields)
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                retry(self.root, attempt["id"], host_record=name)
            self.assertEqual(show(self.root)["attempts"][attempt["id"]]["state"], "running")
        self.retry_attempt(attempt["id"])
        retired = show(self.root)["attempts"][attempt["id"]]
        self.assertEqual(retired["state"], "superseded")
        self.assertEqual(retired["terminal"]["value"]["state"], "stopped")

    def test_unbound_retry_requires_launch_recovery(self):
        attempt = reserve(self.root, {"stage": "prepare", "change": "change-1"})
        with self.assertRaisesRegex(ValueError, "recover and bind"):
            retry(self.root, attempt["id"], host_record="missing.json")

    def test_worker_cannot_supply_runtime_observation_from_its_output(self):
        attempt = reserve(self.root, {"stage": "prepare", "change": "change-1"})
        path = self.root / attempt["directory"] / "worker.txt"
        path.parent.mkdir(parents=True)
        path.write_text("worker assertion")
        name = self.host_record(attempt["id"], evidence=[path.relative_to(self.root).as_posix()])
        with self.assertRaisesRegex(ValueError, "coordinator-owned"):
            bind(self.root, attempt["id"], f"agent-{attempt['id']}", name)

    def test_build_dirs_must_stay_in_attempt_directory(self):
        hunt, cid, candidate_file = self.discover()
        cases = (
            ({}, "list every build directory"),
            ({"build_dirs": []}, "list every build directory"),
            ({"build_dirs": [f"{hunt['directory']}/build"]}, "outside attempt directory"),
            ({"build_dirs": ["/tmp/build"]}, "outside attempt directory"),
            ({"build_dirs": ["../build"]}, "outside attempt directory"),
        )
        for fields, message in cases:
            attempt = self.start("reproduce", candidate=cid, inputs=[candidate_file])
            name = self.record(attempt, **fields)
            with self.subTest(fields=fields), self.assertRaisesRegex(ValueError, message):
                accept(self.root, attempt["id"], name)

    def test_build_dir_symlink_escape_is_rejected(self):
        hunt, cid, candidate_file = self.discover()
        attempt = self.start("reproduce", candidate=cid, inputs=[candidate_file])
        own = self.root / attempt["directory"]
        own.mkdir(parents=True, exist_ok=True)
        (own / "build").symlink_to(self.root / hunt["directory"])
        name = self.record(attempt, build_dirs=[f"{attempt['directory']}/build"])
        with self.assertRaisesRegex(ValueError, "outside attempt directory"):
            accept(self.root, attempt["id"], name)

    def test_build_dirs_inside_attempt_pass_and_blocked_records_skip_them(self):
        _, cid, candidate_file = self.discover()
        attempt = self.start("reproduce", candidate=cid, inputs=[candidate_file])
        name = self.record(attempt, build_dirs=[f"{attempt['directory']}/build/s0"])
        self.assertEqual(accept(self.root, attempt["id"], name)["state"], "accepted")
        blocked = self.start("replay", candidate=cid, inputs=[candidate_file])
        blocked_name = self.record(blocked, status="blocked")
        self.assertEqual(accept(self.root, blocked["id"], blocked_name)["state"], "accepted")

    def experiment_record(self, role, cid, inputs, source, reproduction=None):
        attempt = self.start(role, candidate=cid, inputs=inputs)
        directory = self.root / attempt["directory"]
        directory.mkdir(parents=True)
        artifacts = []
        for filename in ("setup.txt", "payload.txt", "input.txt", "log0.txt", "log1.txt"):
            (directory / filename).write_text("Synthetic observation, not an executed experiment")
            artifacts.append(f"{attempt['directory']}/{filename}")
        setup, poc, workload, log0, log1 = artifacts
        if reproduction:
            poc, workload = reproduction["poc"], reproduction["workload"]
        record = self.record(
            attempt,
            security_review="No security scope",
            source=source,
            setup=setup,
            poc=poc,
            workload=workload,
            artifacts=artifacts,
            build_dirs=[f"{attempt['directory']}/build"],
            runs=[
                {
                    "state": state,
                    "revision": revision,
                    "deployment": "fixture",
                    "command": "fixture",
                    "log": log,
                    "behavior": behavior,
                }
                for state, revision, log, behavior in (
                    ("S0", "before", log0, "correct"),
                    ("S1", "after", log1, "failure"),
                )
            ],
        )
        accept(self.root, attempt["id"], record)
        return record, json.loads((self.root / record).read_text())

    def test_registered_confirmation_retains_scope_and_independent_host_records(self):
        prep = self.start("prepare")
        source = f"{prep['directory']}/source.json"
        (self.root / source).parent.mkdir(parents=True)
        (self.root / source).write_text(json.dumps({"s0": "before", "s1": "after"}))
        prepared = self.record(prep, artifacts=[source], source=source, security_review="None")
        accept(self.root, prep["id"], prepared)
        hunt, cid, candidate_file = self.discover(inputs=[prepared])
        hunted = show(self.root)["attempts"][hunt["id"]]["record"]
        inputs = [prepared, hunted, candidate_file, source]
        reproduced, repro = self.experiment_record("reproduce", cid, inputs, source)
        replayed, _ = self.experiment_record(
            "replay",
            cid,
            [*inputs, reproduced, repro["poc"], repro["workload"]],
            source,
            repro,
        )
        attempt = self.start("adjudicate", candidate=cid, inputs=[*inputs, reproduced, replayed])
        checks = {
            key: {
                "conclusion": "SUPPORTED" if key in CHECKS[:3] else "REFUTED",
                "reason": "Synthetic gate test",
                "evidence": [source],
            }
            for key in CHECKS
        }
        checks["security_scope"]["conclusion"] = "NOT_APPLICABLE"
        decision = self.record(
            attempt,
            security_review="None",
            outcome="REPRODUCED_REGRESSION",
            reason="Synthetic gate test",
            evidence=[source],
            reproduction=reproduced,
            replay=replayed,
            category="FUNCTIONAL_BUG",
            severity="Low",
            likelihood="Low",
            severity_reason="Fixture",
            likelihood_reason="Fixture",
            checks=checks,
        )
        accept(self.root, attempt["id"], decision)
        index = self.index()
        index["changes"][0].update(
            prepare=prepared,
            hunt=hunted,
            candidates=[{"id": cid, "candidate": candidate_file, "decision": decision}],
        )
        (self.root / "campaign.json").write_text(json.dumps(index))
        data = collect(self.root)
        self.assertEqual(data["counts"]["REPRODUCED_REGRESSION"], 1)
        self.assertEqual(data["changes"][1]["status"], "INCOMPLETE")
        self.assertEqual(data["findings"][0]["change"], "change-1")
        self.assertEqual(data["findings"][0]["verification"], "isolated")

    def agent_record(self, attempt_id, event="launch", **fields):
        name = f"runtime/{attempt_id}-agent-{event}.json"
        raw = f"runtime/{attempt_id}-agent-{event}.txt"
        (self.root / "runtime").mkdir(exist_ok=True)
        (self.root / raw).write_text("Synthetic agent tool response for validation tests")
        if event == "launch":
            payload = {
                "tool": "codex.spawn_agent",
                "call": {"task_name": f"task-{attempt_id}", "fork_turns": "none"},
                "response": {"task_name": f"/root/task-{attempt_id}"},
            }
        else:
            payload = {
                "tool": "codex.list_agents",
                "response": {
                    "agents": [
                        {
                            "agent_name": f"/root/task-{attempt_id}",
                            "agent_status": {"completed": "done"},
                        }
                    ]
                },
            }
        value = {
            "event": event,
            "attempt": attempt_id,
            "observed_at": "2026-09-30T12:00:00+00:00",
            "evidence": [raw],
            **payload,
            **fields,
        }
        (self.root / name).write_text(json.dumps(value))
        return name

    def bind_shared(self, attempt_id):
        handle = f"/root/task-{attempt_id}"
        return bind(self.root, attempt_id, handle, agent_record=self.agent_record(attempt_id))

    def test_agent_record_binds_shared_host_level(self):
        attempt = reserve(self.root, {"stage": "prepare", "change": "change-1"})
        bound = self.bind_shared(attempt["id"])
        self.assertEqual(bound["verification"], "shared-host")
        self.assertEqual(bound["state"], "running")
        self.assertEqual(bound["agent"], f"/root/task-{attempt['id']}")

    def test_host_record_binds_isolated_level(self):
        attempt = self.start("prepare")
        self.assertEqual(show(self.root)["attempts"][attempt["id"]]["verification"], "isolated")

    def test_agent_record_rejects_unverifiable_launches(self):
        attempt = reserve(self.root, {"stage": "prepare", "change": "change-1"})
        handle = f"/root/task-{attempt['id']}"
        cases = (
            ({"call": {"task_name": "t", "fork_turns": "all"}}, "inherited conversation"),
            ({"call": {"task_name": "t"}}, "inherited conversation"),
            ({"tool": "claude.task"}, "unsupported agent tool"),
            ({"response": {}}, "agent handle"),
            ({"evidence": []}, "raw agent tool response"),
            ({"evidence": ["runtime/absent.txt"]}, "Missing evidence"),
            ({"event": "terminal"}, "expected launch"),
            ({"attempt": "a999"}, "wrong agent attempt"),
            ({"observed_at": "2026-09-30T12:00:00"}, "timezone"),
        )
        for fields, message in cases:
            name = self.agent_record(attempt["id"], **fields)
            with self.subTest(fields=fields), self.assertRaisesRegex(ValueError, message):
                bind(self.root, attempt["id"], handle, agent_record=name)
        self.assertEqual(show(self.root)["attempts"][attempt["id"]]["state"], "reserved")

    def test_agent_record_rejects_wrong_handle_and_missing_record(self):
        attempt = reserve(self.root, {"stage": "prepare", "change": "change-1"})
        with self.assertRaisesRegex(ValueError, "wrong agent handle"):
            bind(
                self.root,
                attempt["id"],
                "/root/other",
                agent_record=self.agent_record(attempt["id"]),
            )
        with self.assertRaises((OSError, ValueError)):
            bind(self.root, attempt["id"], "/root/t", agent_record="runtime/missing.json")

    def test_bind_requires_exactly_one_record(self):
        attempt = reserve(self.root, {"stage": "prepare", "change": "change-1"})
        with self.assertRaisesRegex(ValueError, "exactly one"):
            bind(self.root, attempt["id"], "handle")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            bind(
                self.root,
                attempt["id"],
                "handle",
                self.host_record(attempt["id"]),
                agent_record=self.agent_record(attempt["id"]),
            )

    def test_agent_handle_cannot_work_twice_on_one_candidate(self):
        _, cid, candidate_file = self.discover()
        shared = {"task_name": "/root/shared"}
        first = reserve(
            self.root,
            {
                "stage": "reproduce",
                "change": "change-1",
                "candidate": cid,
                "inputs": [candidate_file],
            },
        )
        bind(
            self.root,
            first["id"],
            "/root/shared",
            agent_record=self.agent_record(first["id"], response=shared),
        )
        second = reserve(
            self.root,
            {"stage": "replay", "change": "change-1", "candidate": cid, "inputs": [candidate_file]},
        )
        with self.assertRaisesRegex(ValueError, "already worked on candidate"):
            bind(
                self.root,
                second["id"],
                "/root/shared",
                agent_record=self.agent_record(second["id"], response=shared),
            )

    def test_version_2_registry_is_rejected(self):
        path = self.root / "registry.json"
        value = json.loads(path.read_text())
        value["version"] = 2
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "version 2.*requires version 3"):
            show(self.root)

    def test_cli_binds_agent_record(self):
        attempt = reserve(self.root, {"stage": "prepare", "change": "change-1"})
        script = Path(__file__).parents[1] / "scripts" / "registry.py"
        result = subprocess.run(
            [
                sys.executable,
                str(script),
                "bind",
                str(self.root),
                attempt["id"],
                "--agent",
                f"/root/task-{attempt['id']}",
                "--agent-record",
                self.agent_record(attempt["id"]),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(json.loads(result.stdout)["verification"], "shared-host")

    def test_shared_host_retry_requires_finished_agent_status(self):
        attempt = reserve(self.root, {"stage": "prepare", "change": "change-1"})
        self.bind_shared(attempt["id"])
        handle = f"/root/task-{attempt['id']}"
        cases = (
            (
                {"response": {"agents": [{"agent_name": handle, "agent_status": "running"}]}},
                "has not finished",
            ),
            (
                {"response": {"agents": [{"agent_name": handle, "agent_status": "shutdown"}]}},
                "has not finished",
            ),
            (
                {
                    "response": {
                        "agents": [
                            {
                                "agent_name": handle,
                                "agent_status": {"completed": "x", "running": "y"},
                            }
                        ]
                    }
                },
                "has not finished",
            ),
            ({"response": {"agents": []}}, "not listed exactly once"),
            ({"response": {}}, "agent list"),
            ({"tool": "codex.spawn_agent"}, "unsupported agent status tool"),
            ({"observed_at": "2026-09-29T12:00:00+00:00"}, "predates launch"),
        )
        for fields, message in cases:
            name = self.agent_record(attempt["id"], "terminal", **fields)
            with self.subTest(fields=fields), self.assertRaisesRegex(ValueError, message):
                retry(self.root, attempt["id"], agent_record=name)
            self.assertEqual(show(self.root)["attempts"][attempt["id"]]["state"], "running")
        with self.assertRaisesRegex(ValueError, "matching record type"):
            retry(self.root, attempt["id"], host_record="runtime/unused.json")
        errored = {"agents": [{"agent_name": handle, "agent_status": {"errored": "boom"}}]}
        replacement = retry(
            self.root,
            attempt["id"],
            agent_record=self.agent_record(attempt["id"], "terminal", response=errored),
        )
        self.assertEqual(show(self.root)["attempts"][attempt["id"]]["state"], "superseded")
        self.assertIsNone(replacement["verification"])

    def test_isolated_retry_rejects_agent_record(self):
        attempt = self.start("prepare")
        with self.assertRaisesRegex(ValueError, "matching record type"):
            retry(self.root, attempt["id"], agent_record="runtime/unused.json")

    def test_isolated_bind_after_shared_host_bind_succeeds(self):
        first = reserve(self.root, {"stage": "prepare", "change": "change-1"})
        self.bind_shared(first["id"])
        second = self.start("prepare")
        attempts = show(self.root)["attempts"]
        self.assertEqual(attempts[first["id"]]["verification"], "shared-host")
        self.assertEqual(attempts[second["id"]]["verification"], "isolated")

    def test_host_bind_cannot_reuse_shared_handle_on_candidate(self):
        _, cid, candidate_file = self.discover()
        first = reserve(
            self.root,
            {
                "stage": "reproduce",
                "change": "change-1",
                "candidate": cid,
                "inputs": [candidate_file],
            },
        )
        shared = {"task_name": "/root/shared"}
        bind(
            self.root,
            first["id"],
            "/root/shared",
            agent_record=self.agent_record(first["id"], response=shared),
        )
        second = reserve(
            self.root,
            {"stage": "replay", "change": "change-1", "candidate": cid, "inputs": [candidate_file]},
        )
        record = self.host_record(second["id"], agent="/root/shared")
        with self.assertRaisesRegex(ValueError, "already worked on candidate"):
            bind(self.root, second["id"], "/root/shared", record)


if __name__ == "__main__":
    unittest.main()
