"""Present validated patch records as a local audit document."""

import hashlib
import html
import json
import re
import shlex
from dataclasses import dataclass, replace
from pathlib import Path

from native_proof import assess_proof
from records import step_directories
from repair_scope import RepairScope


def safe(value: object) -> str:
    text = str(value)
    visible = "".join(
        f"\\u{ord(char):04x}"
        if (ord(char) < 32 and char not in "\n\t")
        or 0x7F <= ord(char) <= 0x9F
        or 0x202A <= ord(char) <= 0x202E
        or 0x2066 <= ord(char) <= 0x2069
        or 0x200B <= ord(char) <= 0x200F
        or ord(char) in {0x061C, 0xFEFF, 0x2028, 0x2029}
        else char
        for char in text
    )
    return html.escape(visible, quote=True)


def optional(run_dir: Path, relative: str) -> dict | None:
    path = run_dir / relative
    return json.loads(path.read_text()) if path.is_file() else None


def stage(path: str) -> str:
    if path.startswith("reproduce/"):
        return "Reproduction before patch"
    if path.startswith("validate/"):
        return "Independent validation"
    if path.startswith("patch/"):
        return "Patch and focused tests"
    if path.startswith("prove/"):
        return "Proof after patch"
    if path.startswith("regression/"):
        return "Regression and scope"
    return "Other"


def check_ids(path: str) -> tuple[str, ...]:
    root = path.split("/", 1)[0]
    return {
        "reproduce": ("check-reproduction",),
        "validate": ("check-validation",),
        "patch": ("check-patch", "check-suite"),
        "prove": ("check-arms", "check-build", "check-cases", "check-project"),
        "regression": ("check-regression-coverage", "check-regression-outcomes"),
    }.get(root, ())


@dataclass(frozen=True)
class Evidence:
    path: str
    content: str
    size: int
    digest: str
    excerpt: bool = False
    redaction_note: str = ""

    @property
    def anchor(self) -> str:
        return "evidence-" + hashlib.sha256(self.path.encode()).hexdigest()[:16]


def _poc_evidence(run_dir: Path) -> list[Evidence]:
    poc = run_dir / "reproduce/poc"
    if not poc.is_dir():
        return []
    items = []
    for path in sorted(poc.rglob("*")):
        if path.is_file() and not path.is_symlink():
            raw = path.read_bytes()
            items.append(
                Evidence(
                    str(path.relative_to(run_dir)),
                    raw.decode(errors="replace"),
                    len(raw),
                    hashlib.sha256(raw).hexdigest(),
                )
            )
    return items


def _hidden_case_sources(run_dir: Path, include_poc: bool) -> set[str]:
    if include_poc:
        return set()
    sources = set()
    for record in (run_dir / "prove").glob("attempt-*/prove.json"):
        proof = json.loads(record.read_text())
        sources.update(
            f"{record.parent.relative_to(run_dir)}/{case['source']}" for case in proof["cases"]
        )
    return sources


def _display_record(path: Path, run_dir: Path, include_poc: bool, content: str) -> str:
    if include_poc:
        return content
    if path == run_dir / "finding.json":
        finding = json.loads(content)
        finding.pop("poc", None)
        return json.dumps(finding, indent=2)
    if path.name == "prove.json":
        proof = json.loads(content)
        for case in proof["cases"]:
            case["argv"] = ["Case command omitted by disclosure choice."]
        return json.dumps(proof, indent=2)
    return content


def collect_evidence(run_dir: Path, include_poc: bool, step_file, record_paths) -> list[Evidence]:
    items = []
    hidden_sources = _hidden_case_sources(run_dir, include_poc)
    for step in step_directories(run_dir):
        manifest = json.loads((step / "manifest.json").read_text())
        for name, digest in sorted(manifest["files"].items()):
            path = step_file(step, name)
            if not name.startswith("receipts/"):
                continue
            raw = path.read_bytes()
            relative = str(path.relative_to(run_dir))
            hidden = relative in hidden_sources
            content = (
                "Case harness source omitted by disclosure choice."
                if hidden
                else raw.decode(errors="replace")
            )
            items.append(
                Evidence(
                    relative,
                    content,
                    len(raw),
                    digest,
                    False,
                    "Case harness source omitted by disclosure choice." if hidden else "",
                )
            )
    seen = {item.path for item in items}
    for path in record_paths(run_dir):
        relative = str(path.relative_to(run_dir))
        if relative in seen:
            continue
        seen.add(relative)
        raw = path.read_bytes()
        content = _display_record(path, run_dir, include_poc, raw.decode(errors="replace"))
        items.append(
            Evidence(
                str(path.relative_to(run_dir)), content, len(raw), hashlib.sha256(raw).hexdigest()
            )
        )
    if include_poc:
        items.extend(_poc_evidence(run_dir))
    return items


def evidence_label(path: str) -> str:
    parts = path.split("/")
    name = parts[-1]
    if "poc" in parts[:-1]:
        return "Proof-of-concept source"
    if name == "decision.json":
        return "Regression decision record"
    for suffix, description in (
        (".stdout", "Standard output"),
        (".stderr", "Standard error"),
        (".status.json", "Exit status"),
        (".exit", "Exit status"),
    ):
        if name.endswith(suffix):
            return f"{description} of {name.removesuffix(suffix)}"
    if "receipts" in parts[:-1] and name.endswith(".py"):
        return "Helper script used by this step"
    record_names = {
        "finding.json": "Finding record",
        "run.json": "Run record",
        "report-input.json": "Report input record",
        "reproduce.json": "Reproduction record",
        "validate.json": "Validation record",
        "patch.json": "Patch record",
        "prove.json": "Proof record",
        "regression.json": "Regression record",
    }
    return record_names.get(name, "Receipt file")


def evidence_html(items: list[Evidence], active_checks: dict[str, str]) -> tuple[str, str]:
    groups = list(dict.fromkeys(stage(item.path) for item in items))
    index = []
    blocks = []
    for group in groups:
        members = [item for item in items if stage(item.path) == group]
        index.append(f"<h3>{safe(group)}</h3><ul>")
        index.extend(f'<li><a href="#{item.anchor}">{safe(item.path)}</a></li>' for item in members)
        index.append("</ul>")
        blocks.append(f"<h3>{safe(group)}</h3>")
        for item in members:
            targets = [name for name in check_ids(item.path) if name in active_checks]
            back = " ".join(
                f'<a href="#{name}">Back to {safe(active_checks[name])}</a>' for name in targets
            )
            if not back:
                back = '<a href="#evidence-index">Back to evidence index</a>'
            label = item.redaction_note or (
                "Last 20 lines from receipt" if item.excerpt else "Raw record contents"
            )
            blocks.append(
                f'<article class="evidence-item" id="{item.anchor}">'
                f"<h4>{safe(item.path)}</h4>"
                f'<p class="evidence-label">{safe(evidence_label(item.path))}</p>'
                f"<p>{item.size} bytes · SHA-256 <code>{item.digest}</code></p>"
                f"<p>{back}</p><details><summary>{label}</summary>"
                f"<pre>{safe(item.content)}</pre></details></article>"
            )
    return "".join(index), "".join(blocks)


@dataclass(frozen=True)
class Check:
    anchor: str
    group: str
    name: str
    question: str
    command: str
    result: str
    raw_result: str
    state: str
    digest: str = ""
    evidence: str = ""


def _manifest_hash(run_dir: Path, relative: str) -> str:
    return hashlib.sha256((run_dir / relative).read_bytes()).hexdigest()


def _evidence_anchor(items: list[Evidence], prefix: str) -> str:
    for item in items:
        if item.path.startswith(prefix + "/"):
            return item.anchor
    return "evidence-index"


def _with_evidence(run_dir: Path, items: list[Evidence], directory: str, row: Check) -> Check:
    return replace(
        row,
        digest=_manifest_hash(run_dir, directory + "/manifest.json"),
        evidence=_evidence_anchor(items, directory.split("/", 1)[0]),
    )


def _reproduction_checks(run_dir: Path, items: list[Evidence]) -> list[Check]:
    reproduce = optional(run_dir, "reproduce/reproduce.json")
    validation = optional(run_dir, "validate/validate.json")
    rows = []
    command = "not run"
    if reproduce:
        raw = reproduce["outcome"]
        argv = "build_argv" if reproduce.get("failure_type") == "compile" else "poc_argv"
        command = shlex.join(reproduce[argv])
        rows.append(
            _with_evidence(
                run_dir,
                items,
                "reproduce",
                Check(
                    "check-reproduction",
                    "Reproduction before patch",
                    "Reproduction",
                    "Did the reported bug occur before the patch?",
                    command,
                    "Bug reproduced on baseline." if raw == "reproduced" else f"Baseline: {raw}.",
                    raw,
                    "pass" if raw == "reproduced" else "fail",
                ),
            )
        )
    if validation:
        raw = validation["outcome"]
        rows.append(
            _with_evidence(
                run_dir,
                items,
                "validate",
                Check(
                    "check-validation",
                    "Reproduction before patch",
                    "Independent validation",
                    "Did an independent validator confirm the reproduction?",
                    command,
                    "Independent reproduction confirmed."
                    if raw == "confirmed"
                    else f"Validation: {raw}.",
                    raw,
                    "pass" if raw == "confirmed" else "fail",
                ),
            )
        )
    return rows


def _patch_checks(run_dir: Path, attempt: int, items: list[Evidence]) -> list[Check]:
    directory = f"patch/attempt-{attempt}"
    patch = optional(run_dir, directory + "/patch.json")
    if not patch:
        return []
    committed = patch["patch_commit"] is not None
    before = patch["suite_before"]
    suite = patch["suite_after"]
    raw = f"{suite['passed']} passed, {suite['failed']} failed, {suite['skipped']} skipped"
    suite_result = (
        f"Before: {before['passed']} passed, {before['failed']} failed; "
        f"after: {suite['passed']} passed, {suite['failed']} failed, "
        f"{suite['skipped']} skipped."
    )
    return [
        _with_evidence(
            run_dir,
            items,
            directory,
            Check(
                "check-patch",
                "Build and focused tests",
                "Patch applied",
                "Was a patch commit recorded?",
                "patch.json",
                "Patch commit recorded." if committed else "No patch commit recorded.",
                str(patch["patch_commit"]),
                "pass" if committed else "fail",
            ),
        ),
        _with_evidence(
            run_dir,
            items,
            directory,
            Check(
                "check-suite",
                "Build and focused tests",
                "Focused suite",
                "Did the focused suite pass after the patch?",
                suite["command"],
                suite_result,
                raw,
                "pass" if suite["failed"] == 0 else "fail",
            ),
        ),
    ]


def _identity_result(proof: dict) -> tuple[str, str, str]:
    if proof.get("failure_type") == "compile":
        return (
            "Is runtime artifact identity applicable?",
            "Runtime artifact identity is not applicable to a compile failure.",
            "not-applicable",
        )
    state = "pass" if proof["build_identity"] == "pass" else "fail"
    if proof.get("failure_type") == "runtime":
        return (
            "Did the PoC load the intended implementation in each arm?",
            "Loaded implementation matches each arm's artifact; "
            "patched artifact differs from baseline."
            if state == "pass"
            else "Loaded implementation identity or artifact comparison failed.",
            state,
        )
    return (
        "Did the patched build differ from the baseline build?",
        "Patched artifact differs from baseline." if state == "pass" else "Build identity failed.",
        state,
    )


def _arm_checks(run_dir: Path, attempt: int, items: list[Evidence]) -> list[Check]:
    directory = f"prove/attempt-{attempt}"
    proof = optional(run_dir, directory + "/prove.json")
    if not proof:
        return []
    reproduce = optional(run_dir, "reproduce/reproduce.json")
    command = f"arms.py run --artifact {reproduce['target_artifact']}" if reproduce else "not run"
    compile_proof = proof.get("failure_type") == "compile"
    if compile_proof:
        command = "arms.py run --failure-type compile"
    reverted = proof["reverted"]
    arm_gaps = assess_proof(run_dir, attempt).arm_gaps
    identity = proof["build_identity"]
    question, identity_result, identity_state = _identity_result(proof)
    result = (
        "Compiler failed with the target diagnostic, passed after repair, and failed again "
        "on the complete baseline tree."
        if compile_proof
        else "Patched behavior did not reproduce the bug. Reverted behavior reproduced the bug."
    )
    rows = [
        _with_evidence(
            run_dir,
            items,
            directory,
            Check(
                "check-arms",
                "Proof after patch",
                "Three-arm proof",
                "Did reverting the patch reproduce the bug again?",
                command,
                (
                    "; ".join(arm_gaps)
                    if arm_gaps
                    else result
                    if reverted == "pass"
                    else f"Reverted arm: {reverted}."
                ),
                reverted,
                "inconclusive"
                if arm_gaps
                else "pass"
                if reverted == "pass"
                else "inconclusive"
                if reverted == "inconclusive"
                else "fail",
            ),
        ),
        _with_evidence(
            run_dir,
            items,
            directory,
            Check(
                "check-build",
                "Proof after patch",
                "Build identity",
                question,
                command,
                identity_result,
                identity,
                identity_state,
            ),
        ),
    ]
    if not reproduce or proof.get("failure_type", "runtime") != reproduce.get(
        "failure_type", "runtime"
    ):
        return [
            replace(
                row,
                result="Proof failure type differs from reproduction; "
                "target repair is unestablished.",
                state="inconclusive",
            )
            for row in rows
        ]
    return rows


def _regression_checks(run_dir: Path, items: list[Evidence]) -> list[Check]:
    regression = optional(run_dir, "regression/regression.json")
    if not regression:
        return []
    command = "regression/regression.json (recorded campaign and retained decisions)"
    coverage = regression["coverage"]
    outcomes = regression["outcomes"]
    found = sum(x["outcome"] == "REPRODUCED_REGRESSION" for x in outcomes)
    incomplete = sum(x["outcome"] == "INCOMPLETE_FIX" for x in outcomes)
    unresolved = sum(x["outcome"] == "UNRESOLVED" for x in outcomes)
    raw = f"{found} found, {unresolved} unresolved, {len(outcomes)} total"
    return [
        _with_evidence(
            run_dir,
            items,
            "regression",
            Check(
                "check-regression-coverage",
                "Regression and scope checks",
                "Regression coverage",
                "Was regression coverage complete for the recorded scope?",
                command,
                f"Coverage: {coverage.lower()}.",
                coverage,
                "pass" if coverage == "COMPLETE" else "caution",
            ),
        ),
        _with_evidence(
            run_dir,
            items,
            "regression",
            Check(
                "check-regression-outcomes",
                "Regression and scope checks",
                "Regression outcomes",
                "Did the regression check find a new failure or incomplete fix?",
                command,
                f"{found} reproduced; {incomplete} incomplete fix; "
                f"{unresolved} unresolved; {len(outcomes)} reviewed.",
                raw,
                "fail" if found or incomplete else "caution" if unresolved else "pass",
            ),
        ),
    ]


def _native_proof_checks(run_dir: Path, attempt: int, items: list[Evidence]) -> list[Check]:
    directory = f"prove/attempt-{attempt}"
    if not (run_dir / directory / "prove.json").is_file():
        return []
    assessment = assess_proof(run_dir, attempt)
    rows = []
    for anchor, name, findings, gaps, question in (
        (
            "check-cases",
            "Scoped case proof",
            assessment.case_findings,
            assessment.case_gaps,
            "Did the planned failures change while valid controls still passed?",
        ),
        (
            "check-project",
            "Project checks",
            assessment.project_findings,
            assessment.project_gaps,
            "Did independent project checks pass after the patch?",
        ),
    ):
        state = "fail" if findings else "inconclusive" if gaps else "pass"
        result = "; ".join((*findings, *gaps)) or "Required checks produced usable evidence."
        rows.append(
            _with_evidence(
                run_dir,
                items,
                directory,
                Check(
                    anchor,
                    "Proof after patch",
                    name,
                    question,
                    "prove.json and retained receipts",
                    result,
                    f"{len(findings)} findings, {len(gaps)} gaps",
                    state,
                ),
            )
        )
    return rows


def checks(run_dir: Path, attempt: int, items: list[Evidence]) -> list[Check]:
    return (
        _reproduction_checks(run_dir, items)
        + _arm_checks(run_dir, attempt, items)
        + _patch_checks(run_dir, attempt, items)
        + _regression_checks(run_dir, items)
        + _native_proof_checks(run_dir, attempt, items)
    )


def baseline_rows(rows: list[Check]) -> list[Check]:
    return [
        replace(
            row,
            question="Did the unchanged baseline satisfy the planned cases?",
            result="Retained baseline observations match the planned inputs and expected results.",
            state="pass",
        )
        if row.anchor in {"check-reproduction", "check-validation"}
        else row
        for row in rows
    ]


def state_label(state: str) -> str:
    return {
        "pass": "✓ Pass",
        "caution": "! Caution",
        "fail": "✗ Fail",
        "inconclusive": "! Inconclusive",
        "not-run": "\u2013 Not run",
        "none-recorded": "\u2013 None recorded",
        "not-applicable": "\u2013 Not applicable",
    }[state]


def baseline_inconclusive_rows(rows: list[Check], reason: str) -> list[Check]:
    return [
        replace(row, result=reason, state="inconclusive")
        if row.anchor in {"check-reproduction", "check-validation"}
        else row
        for row in rows
    ]


def decision_status(
    raw_status: str, reasons: list[str], rows: list[Check], scope: RepairScope, attempt: int
) -> tuple[str, str, str]:
    if attempt == 0:
        if scope.label == "No patch required":
            if scope.plan is not None and not any(
                case["role"] == "control" for case in scope.plan["cases"]
            ):
                return (
                    "NO PATCH REQUIRED",
                    "pass",
                    "The named example behaved as expected; no valid control was planned; "
                    "no patch was required.",
                )
            return (
                "CONTROL PASSED",
                "pass",
                "The scoped bug was absent; valid controls passed; no patch was required.",
            )
        return "INCONCLUSIVE", "caution", scope.detail
    proof_rows = [row for row in rows if row.anchor in {"check-cases", "check-project"}]
    decisive = [
        row
        for row in rows
        if row.state == "fail"
        and row.anchor
        in {
            "check-patch",
            "check-suite",
            "check-arms",
            "check-build",
            "check-cases",
            "check-project",
            "check-regression-outcomes",
        }
    ]
    if decisive:
        failed = decisive[0]
        return "FAILED REPAIR", "fail", f"{failed.name}: {failed.result}"
    if (
        raw_status == "READY"
        and len(proof_rows) == 2
        and all(row.state == "pass" for row in proof_rows)
        and scope.label in {"Bounded class repaired", "Exact example repaired"}
        and (
            scope.plan is None
            or scope.plan["mode"] != "bounded_class"
            or scope.label == "Bounded class repaired"
        )
    ):
        return "REPAIR SUCCEEDED", "pass", "The scoped repair and required proof passed."
    incomplete = next((row for row in proof_rows if row.state == "inconclusive"), None)
    if incomplete or len(proof_rows) != 2:
        detail = incomplete.result if incomplete else "Required native proof record is missing."
        return "INCONCLUSIVE", "caution", f"Native proof: {detail}"
    reason = "; ".join(reasons) or scope.detail
    return "INCONCLUSIVE", "caution", reason or "Required proof is missing."


def run_metadata_html(run: dict, reproduce: dict | None, metadata: dict) -> str:
    fields = (
        ("Run type", metadata.get("run_type")),
        ("Snapshot", reproduce.get("baseline_commit") if reproduce else None),
        ("Date", metadata.get("date")),
        ("Model", metadata.get("model")),
        ("Reasoning effort", metadata.get("reasoning_effort")),
        (
            "Elapsed time",
            f"{metadata['elapsed_seconds']} seconds" if "elapsed_seconds" in metadata else None,
        ),
        ("Recorded tokens", metadata.get("recorded_tokens")),
        ("Attempt count", run["attempts"]),
    )
    rows = "".join(
        f'<tr><th scope="row">{safe(name)}</th><td>{safe(value)}</td></tr>'
        for name, value in fields
        if value is not None
    )
    return f'<table class="glance"><tbody>{rows}</tbody></table>'


def baseline_links_html(
    checks: list[dict], items: list[Evidence], planned_cases: list[dict]
) -> str:
    by_path = {item.path: item.anchor for item in items}
    rows = []
    for check in checks:
        links = []
        for step in ("reproduce", "validate"):
            for kind in ("stdout", "exit"):
                path = check[step][kind]
                anchor = by_path.get(path) if path.startswith(f"{step}/receipts/") else None
                if anchor:
                    links.append(f'<a href="#{anchor}">{safe(step)} {safe(kind)}</a>')
        rows.append(
            f'<tr><th scope="row">{safe(check["check_id"])}</th>'
            f"<td>{', '.join(links) or 'Unavailable'}</td></tr>"
        )
    recorded = {check["check_id"] for check in checks}
    rows.extend(
        f'<tr><th scope="row">{safe(case["check_id"])}</th>'
        f"<td>Missing retained receipt. "
        f'<a href="#{by_path["report-input.json"]}">Report input</a></td></tr>'
        for case in planned_cases
        if case["check_id"] not in recorded
    )
    return (
        (
            '<h3>Planned baseline checks</h3><table class="glance"><thead><tr>'
            "<th>Check</th><th>Retained receipts</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
        )
        if rows
        else ""
    )


def _coverage_plan_html(assessment: RepairScope) -> str:
    plan = assessment.plan
    if plan is None:
        return ""
    rows = "".join(
        f"<tr><td>{safe(item['role'])}</td><td><code>{safe(json.dumps(item['input']))}</code></td>"
        f"<td><code>{safe(json.dumps(item['expected']))}</code></td>"
        f"<td>{safe(item['why'])}</td><td>{safe(item['check_id'])}</td></tr>"
        for item in plan["cases"]
    )
    exclusions = "".join(f"<li>{safe(value)}</li>" for value in plan["exclusions"])
    return (
        f"<p><strong>Declared boundary:</strong> {safe(plan['boundary'])}</p>"
        "<h3>Declared coverage plan</h3><table><thead><tr>"
        "<th>Role</th><th>Input</th><th>Expected</th><th>Purpose</th><th>Proof check</th>"
        f"</tr></thead><tbody>{rows}</tbody></table>"
        f"<h3>Excluded work</h3><ul>{exclusions or '<li>None recorded.</li>'}</ul>"
    )


def scope_html(run_dir: Path, assessment: RepairScope) -> tuple[str, str]:
    finding = optional(run_dir, "finding.json")
    assert finding is not None
    bug = (
        f"<h3>{safe(finding['title'])}</h3>"
        f"<p><strong>Reported claim:</strong> {safe(finding['claim'])}</p>"
        f"<p><strong>Proposed invariant:</strong> {safe(finding['invariant'])}</p>"
        '<p class="small">These recorded statements describe the requested behavior. '
        "The repair claim is limited by the retained evidence.</p>"
    )
    affected = finding["affected_code"]
    locations = ", ".join(
        f"{item['path']}:{item['start_line']}-{item['end_line']}" for item in affected
    )
    scope = (
        f"<p><strong>{safe(assessment.label)}</strong></p><p>{safe(assessment.detail)}</p>"
        f"<p><strong>Affected code:</strong> {safe(locations)}</p>"
        + _coverage_plan_html(assessment)
    )
    separate = optional(run_dir, "regression/receipts/scope.json")
    if separate is not None:
        scope += "<h3>Recorded regression scope</h3>"
        for key, label in (
            ("construction", "Construction"),
            ("operations", "Operations"),
            ("checks", "Scope checks"),
            ("excluded", "Excluded"),
        ):
            if key in separate:
                value = (
                    ", ".join(separate[key]) if isinstance(separate[key], list) else separate[key]
                )
                scope += f"<p><strong>{label}:</strong> {safe(value)}</p>"
    return bug, scope


def _diff_chunks(lines: list[str], fallback: str) -> list[tuple[str, list[str]]]:
    chunks = []
    current = []
    label = fallback
    for line in lines:
        match = re.match(r"diff --git a/(.*?) b/(.*)", line)
        if match:
            if current:
                chunks.append((label, current))
            label = match.group(2)
            current = []
        current.append(line)
    if current:
        chunks.append((label, current))
    return chunks


def patch_html(run_dir: Path, attempt: int) -> tuple[str, str]:
    patch = optional(run_dir, f"patch/attempt-{attempt}/patch.json")
    if not patch or patch["patch_commit"] is None:
        return (
            "<p>Patch verification is not applicable; no patch commit was recorded.</p>",
            "<p>No selected patch diff is available.</p>",
        )
    links = []
    panels = []
    index = 0
    for name in ("fix.patch", "tests.patch"):
        path = run_dir / "patch" / f"attempt-{attempt}" / name
        if not path.is_file():
            continue
        for label, lines in _diff_chunks(path.read_text(errors="replace").splitlines(), name):
            anchor = f"diff-file-{index}"
            index += 1
            links.append(f'<li><a href="#{anchor}">{safe(label)}</a></li>')
            rendered = []
            for line in lines:
                kind = (
                    "hunk"
                    if line.startswith("@@")
                    else "add"
                    if line.startswith("+")
                    else "del"
                    if line.startswith("-")
                    else "context"
                )
                rendered.append(f'<span class="{kind}">{safe(line)}</span>')
            panels.append(
                f'<article class="diff-panel" id="{anchor}"><h3>{safe(label)}</h3>'
                f'<p class="small">Source: {safe(name)}</p>'
                f"<pre>{chr(10).join(rendered)}</pre></article>"
            )
    summary = (
        f"<p>{patch['files_changed']} files changed, {patch['lines_added']} lines added, "
        f"{patch['lines_removed']} lines removed. "
        f"Patch commit <code>{safe(patch['patch_commit'])}</code>.</p>"
    )
    return summary, f"<ul>{''.join(links)}</ul>" + "".join(panels)
