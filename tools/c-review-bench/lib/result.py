"""Collect one arm's result: wait for it to be finished, then check its shape.

This module exists because of a specific, expensive failure. A previous measurement
read `findings.json` while the workflow was still writing it, drew two conclusions
from the partial document, and separately produced structurally different artifacts
from two runs of identical code (23 survivors with 7 fields once, 31 primaries with
8 fields the next). Three published numbers were wrong.

So collection is deliberately paranoid, in this order:

1. **A completion marker.** `meta.json` must say `"complete": true`. The driver
   writes it *after* the arm returns; there is no way to infer completion from the
   result file itself, and inferring it is what went wrong before.
2. **A settle check.** The result file's digest must be unchanged across two samples
   `settle_seconds` apart. A file still being written fails this.
3. **A schema check.** Every finding must carry the fields the grader reads, with
   the types it expects. An unexpected shape is an error, never something to infer
   meaning from.
4. **Normalisation.** c-review's own `findings.json` is converted through the
   plugin's `findings_model`, the same module that decides what `REPORT.md` shows,
   so "reported" means the same thing here as it does to a user. A generic arm
   supplies the normalised shape directly.

Cost is part of the result, not a footnote: `agents`, `tokens` and `wall_seconds`
are required, and a zero token count is refused. An arm that reports no cost cannot
be compared with one that does.

**There is no mangled-document recovery path here, deliberately.** An earlier iteration
of the plugin's last phase handed one agent the whole findings payload as JSON and asked
it to retype it into a heredoc; that agent sometimes summarised instead, once shipping
an empty `findings` array while its own `stats` said `reported: 14`. That failure mode
lived in an external driver (`recover_creview.py`, outside this repository) that clawed
the payload back out of the persist agent's transcript, and it does not apply here: the
plugin's `assemble_findings.py` builds `findings.json` in deterministic Python, never
through an agent's retyping, so the document this module reads cannot be mangled that
way. `validate_findings()` below still refuses a malformed document — schema drift is
still possible from a *generic* arm's hand-written result — but refusing is the whole
policy; there is nothing to reconstruct. One consequence worth stating plainly: `findings`
is always a **superset** of what `findings_model.reported_findings()` selects — it also
holds merged duplicates and judge-rejected (or, now, unjudged) candidates — so a check of
the form `len(findings) < stats.reported` would never fire on a document this pipeline
produced, not because such a check is unnecessary, but because the shorter list truly
cannot happen from this code path.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any


def _plugin_root() -> Path:
    """See lib/plan.plugin_root: the harness lives outside the plugin on purpose."""
    for base in Path(__file__).resolve().parents:
        cand = base / "plugins" / "c-review"
        if (cand / "scripts").is_dir():
            return cand
    raise ResultError("cannot locate the c-review plugin above " + str(Path(__file__).resolve()))


PLUGIN_SCRIPTS = _plugin_root() / "scripts"

REQUIRED_FINDING_FIELDS = ("file", "line", "title", "description")
OPTIONAL_FINDING_FIELDS = (
    "function",
    "bug_class",
    "impact",
    "code",
    "data_flow",
    "reachability",
    "recommendation",
    "confidence",
    "severity",
    "found_by",
    "fp_verdict",
    "mitigations_checked",
    "severity_rationale",
    "fp_rationale",
    # Set to "reviewer" when no judge ran and the hunter's own severity stands
    # unvalidated (assemble_findings.py's `no_judge` path). Absent when a judge did
    # validate it. Dropping it here would silently discard the one marker that says a
    # severity is a single reviewer's opinion rather than an adjudicated one.
    "severity_source",
)
REQUIRED_META_FIELDS = ("agents", "tokens", "wall_seconds", "model")
# Which token definition `tokens` carries. Recorded per cell and printed by `score`,
# because comparing an arm counted one way with an arm counted another way is not a
# comparison. See derive_cost for what each basis means.
TOKEN_BASES = ("reported_subagent_tokens", "tokens_fresh", "tokens_total")


class ResultError(Exception):
    """A result that must not be scored. Callers exit non-zero."""


def _load_findings_model() -> Any:
    """The plugin's own definition of the reported set. Not re-implemented here.

    Two definitions of "reported" would drift, and the arm that c-review is being
    measured against would be graded on a different set from the one its users see.
    """
    if str(PLUGIN_SCRIPTS) not in sys.path:
        sys.path.insert(0, str(PLUGIN_SCRIPTS))
    try:
        import findings_model  # noqa: PLC0415 - deliberately late, path-dependent
    except ImportError as exc:  # pragma: no cover - a broken checkout, not a code path
        raise ResultError(
            f"cannot import findings_model from {PLUGIN_SCRIPTS}: {exc}. The harness will not "
            f"guess what c-review counts as reported."
        ) from exc
    return findings_model


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wait_until_settled(path: Path, settle_seconds: float, timeout: float) -> str:
    """Return the digest once it has held still, or raise.

    Nothing about this is a substitute for the completion marker: a file can be
    momentarily quiescent mid-write. It is the second lock on the same door.
    """
    if settle_seconds <= 0:
        raise ResultError(
            "settle_seconds must be positive; a zero-second settle check checks nothing"
        )
    deadline = time.monotonic() + timeout
    if not path.is_file():
        raise ResultError(f"result artifact does not exist: {path}")
    previous = _digest(path)
    while True:
        time.sleep(settle_seconds)
        current = _digest(path)
        if current == previous:
            return current
        if time.monotonic() > deadline:
            raise ResultError(
                f"{path} is still changing after {timeout:.0f}s. It is being written; scoring a "
                f"partial artifact is how three wrong numbers were published last time."
            )
        previous = current


def load_meta(path: Path, settle_seconds: float, timeout: float) -> dict[str, Any]:
    wait_until_settled(path, settle_seconds, timeout)
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ResultError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(meta, dict):
        raise ResultError(f"{path}: expected a JSON object")
    if meta.get("complete") is not True:
        raise ResultError(
            f'{path} does not say "complete": true. Write the meta file only after the arm has '
            f"returned — this is the completion marker, and without it the result may be partial."
        )
    missing = [field for field in REQUIRED_META_FIELDS if field not in meta]
    if missing:
        raise ResultError(f"{path} is missing required cost field(s): {', '.join(missing)}")
    basis = meta.setdefault("token_basis", TOKEN_BASES[0])
    if basis not in TOKEN_BASES:
        raise ResultError(
            f"{path}: token_basis {basis!r} is not one of {TOKEN_BASES}. Every cell in a run "
            f"must count tokens the same way or the comparison is meaningless."
        )
    for field in ("agents", "tokens"):
        try:
            value = int(meta[field])
        except (TypeError, ValueError) as exc:
            raise ResultError(f"{path}: {field} must be an integer, got {meta[field]!r}") from exc
        if value <= 0:
            raise ResultError(
                f"{path}: {field} is {value}. An arm that reports no {field} cannot be compared "
                f"with one that does; record the real number or do not collect the arm."
            )
    return meta


def _looks_like_c_review(doc: dict[str, Any]) -> bool:
    return isinstance(doc.get("run"), dict) and isinstance(doc.get("stats"), dict)


def normalise_c_review(doc: dict[str, Any]) -> dict[str, Any]:
    model = _load_findings_model()
    reported_ids = {str(f.get("id")) for f in model.reported_findings(doc)}
    findings = []
    for finding in doc["findings"]:
        entry = {
            key: finding.get(key)
            for key in ("id", *REQUIRED_FINDING_FIELDS, *OPTIONAL_FINDING_FIELDS)
            if key in finding
        }
        entry["id"] = str(finding.get("id") or f"F-{len(findings) + 1}")
        entry["reported"] = entry["id"] in reported_ids
        entry["merged_into"] = finding.get("merged_into")
        findings.append(entry)
    externals = doc.get("run", {}).get("hunter_external_sources") or []
    consulted = any(bool(e.get("consulted")) for e in externals if isinstance(e, dict))
    detail = "; ".join(
        f"{e.get('group')}: {e.get('detail')}"
        for e in externals
        if isinstance(e, dict) and e.get("consulted")
    )
    return {
        "findings": findings,
        "external_sources_consulted": consulted,
        # How many hunters were actually ASKED. Carried through so `score` can say whether
        # the declaration check inspected zero records: an empty list and a list of sixteen
        # clean declarations both produce `consulted: false`, and only one of them is
        # evidence. A part with `declared: false` ran without `benchmarkMode`, so its
        # `consulted: false` is silence, not an answer, and counting it here would restore
        # the blindness the field was added to remove. `declared` absent (pre-c-review
        # 4.4.0) means the declaration was always on: count it.
        "declarations_seen": sum(
            1 for e in externals if isinstance(e, dict) and e.get("declared") is not False
        ),
        "external_sources_detail": detail or "none",
        "native_stats": doc.get("stats", {}),
        "groups_attempted": doc.get("run", {}).get("groups_attempted", []),
        "groups_failed": doc.get("run", {}).get("groups_failed", []),
        # Per-agent deaths, which `groups_failed` does not cover: a slice reviewer that
        # returns nothing loses lines, not bug classes. The v2.0 measurement lost 13 of 16
        # reviewers and, once `groups_failed` stopped being (mis)filled from them, nothing
        # reached the report at all. Carried so `format_report` can still raise PARTIAL RUN.
        "agent_failures": doc.get("run", {}).get("agent_failures", []),
        # `judge_ran` is false on every current run: the false-positive/severity judge was
        # removed from the plugin and severity is now the reviewer's own, unvalidated
        # assessment (`severity_source: "reviewer"` on the findings above). Carried through
        # rather than assumed, so a future run that reinstates a judge is visible here
        # instead of silently read as if the current, judge-less shape still applied.
        "judge_ran": doc.get("run", {}).get("judge_ran"),
        # The ledger gate's compact summary (`assemble_findings.run_ledger_gate`): either the
        # coverage-audit result or `{"error": ...}` when it could not run. Absent entirely on
        # a run with no unit list, which is a legitimate configuration and not a failure.
        "ledger": doc.get("run", {}).get("ledger"),
    }


def normalise_generic(doc: dict[str, Any]) -> dict[str, Any]:
    findings = []
    for index, finding in enumerate(doc["findings"], 1):
        if not isinstance(finding, dict):
            raise ResultError(
                f"findings[{index - 1}] is {type(finding).__name__}, expected an object"
            )
        entry = dict(finding)
        entry["id"] = str(finding.get("id") or f"F-{index}")
        entry["reported"] = bool(finding.get("reported", True))
        findings.append(entry)
    return {
        "findings": findings,
        "external_sources_consulted": bool(doc.get("external_sources_consulted", False)),
        # A generic arm's packet asks for the field explicitly, so its presence is the
        # declaration and its absence is silence. The two are not the same evidence.
        "declarations_seen": 1 if "external_sources_consulted" in doc else 0,
        "external_sources_detail": str(doc.get("external_sources_detail", "none")),
    }


# The subset of REQUIRED_FINDING_FIELDS that `--allow-incomplete-findings` may waive.
# `file` and `line` are never waivable: without them a finding has no site, and
# `lib/grade.py::site_match` would score it against nothing at all.
#
# `description` and `title` are waivable only ONE AT A TIME and only while some graded
# text survives, because both are members of `lib/grade.py::TEXT_FIELDS` alongside
# `impact`, `recommendation` and the rest. A finding that keeps its title and impact is
# fully visible to `mechanism_matches` with or without a description; a finding with no
# text in any TEXT_FIELD is empty, and accepting it would inflate the denominator with
# something that cannot match by construction.
WAIVABLE_FINDING_FIELDS = ("description", "title")

# Kept in step with lib/grade.py::TEXT_FIELDS. Only the fields an arm plausibly fills.
GRADED_TEXT_FIELDS = ("title", "description", "impact", "recommendation", "code", "bug_class")


def validate_findings(findings: list[dict[str, Any]], allow_incomplete: bool = False) -> list[str]:
    """Raise on anything the grader cannot read. Return the ids that were waived.

    `allow_incomplete` exists for one measured, recurring defect: c-review's sweep agent
    hand-writes its own part file and omits `description` on every finding it files (7 of 7
    on the 2026-08-07 container cell, 9 on the 2026-08-06 s2 cell). The text is not lost —
    `title`, `impact` and `recommendation` are present and all three are already in
    `TEXT_FIELDS`, so waiving the missing field changes what can be *collected* and nothing
    about what can be *graded*.

    It is opt-in, it is recorded in the collected document, and it still refuses a finding
    with no graded text at all. Use it only with the degradation stated in the write-up.
    """
    problems: list[str] = []
    waived: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        fid = str(finding.get("id"))
        if fid in seen:
            problems.append(f"duplicate finding id {fid!r}")
        seen.add(fid)
        for field in REQUIRED_FINDING_FIELDS:
            if str(finding.get(field, "")).strip():
                continue
            if allow_incomplete and field in WAIVABLE_FINDING_FIELDS:
                # Waivable, but only if the finding is still gradeable on its other text.
                if any(str(finding.get(f, "")).strip() for f in GRADED_TEXT_FIELDS):
                    waived.append(f"{fid}:{field}")
                    continue
                problems.append(
                    f"{fid}: missing {field!r} and every other graded text field, so it "
                    f"cannot match any bug — this is an empty finding, not an incomplete one"
                )
                continue
            problems.append(f"{fid}: missing required field {field!r}")
        try:
            line = int(finding.get("line", 0))
        except (TypeError, ValueError):
            problems.append(f"{fid}: line is not an integer ({finding.get('line')!r})")
            continue
        if line < 1:
            problems.append(f"{fid}: line {line} is not a source line")
    if problems:
        hint = (
            "\nFix the arm's output rather than the grader: an unexpected shape is not "
            "something to infer meaning from."
        )
        if not allow_incomplete and any("missing required field" in p for p in problems):
            hint += (
                "\nIf the arm dropped a text field it cannot be made to re-emit, "
                "`--allow-incomplete-findings` waives `description`/`title` for findings that "
                "still carry other graded text, records which ones in the collected document, "
                "and must be stated as a degradation in the write-up."
            )
        raise ResultError(
            "the result does not match the schema the grader reads:\n  "
            + "\n  ".join(problems[:20])
            + hint
        )
    return waived


def derive_cost(transcripts: list[Path]) -> dict[str, Any]:
    """Token counts read out of the transcripts, with the definition made explicit.

    There is no single "tokens" number, and pretending otherwise is how two arms end
    up compared on different scales. A transcript distinguishes:

    - `tokens_fresh` = input + output + cache **creation**: what this run had to
      produce or ingest for the first time.
    - `tokens_cache_read` = context re-read from cache. Real spend, usually the
      largest term, and it grows with how often an agent re-reads the same files.
    - `tokens_total` = the two together.

    The platform separately reports a `subagent_tokens` figure per agent, which
    matches neither exactly. Whichever basis a run uses, **every cell in that run must
    use the same one**, and `meta.token_basis` records which. The previous evaluation's
    published figures are in the same range as the platform's `subagent_tokens`, so
    that is the default basis for comparability with them.

    The driver still writes `meta.json` by hand, because the completion marker has to
    be a deliberate act. This exists so the number it writes is a measured one.
    """
    files: list[Path] = []
    for path in transcripts:
        if path.is_dir():
            files += sorted(path.rglob("*.jsonl")) + sorted(path.rglob("*.output"))
        elif path.is_file():
            files.append(path)
    if not files:
        raise ResultError(f"no transcripts found in {[str(p) for p in transcripts]}")

    totals = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
    }
    records = 0
    with_usage = 0
    agent_ids: set[str] = set()
    session_ids: set[str] = set()
    for file in files:
        for line in file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            records += 1
            if isinstance(record.get("agentId"), str):
                agent_ids.add(record["agentId"])
            for key in ("sessionId", "session_id"):
                if isinstance(record.get(key), str):
                    session_ids.add(record[key])
            usage = (record.get("message") or {}).get("usage")
            if isinstance(usage, dict):
                with_usage += 1
                for key in totals:
                    try:
                        totals[key] += int(usage.get(key) or 0)
                    except (TypeError, ValueError):
                        continue
    if with_usage == 0:
        raise ResultError(
            f"parsed {records} record(s) from {len(files)} transcript(s) and found no usage "
            f"block in any of them, so the cost was not measured. Do not fall back to an "
            f"estimate: fix the transcript path."
        )
    fresh = totals["input_tokens"] + totals["output_tokens"] + totals["cache_creation_input_tokens"]
    cache_read = totals["cache_read_input_tokens"]
    if fresh + cache_read <= 0:
        raise ResultError("the transcripts report zero tokens, which is not a measurement")
    return {
        "tokens_fresh": fresh,
        "tokens_cache_read": cache_read,
        "tokens_total": fresh + cache_read,
        "breakdown": totals,
        "distinct_ids": len(agent_ids) or len(session_ids),
        "records_with_usage": with_usage,
        "transcripts": [str(f) for f in files],
    }


def load_plan(run_dir: Path) -> dict[str, Any]:
    path = Path(run_dir) / "plan.json"
    if not path.is_file():
        raise ResultError(
            f"no plan at {path}. Run `bench.py plan` first: the plan records which corpus variant "
            f"each arm reviews and which corpora passed the integrity gate."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def collect(
    run_dir: Path,
    arm: str,
    corpus: str,
    result_path: Path,
    meta_path: Path,
    transcripts: list[Path],
    variant: str = "bench",
    settle_seconds: float = 2.0,
    timeout: float = 120.0,
    allow_incomplete: bool = False,
) -> dict[str, Any]:
    """Normalise one cell of the run matrix into `run_dir/collected/`.

    The cell is keyed on all three of arm, corpus **and variant**. Matching on the
    first two was a real defect: with a control cell in the plan, a result from the
    bug-free tree was collected as a bench result, and would have been reported as
    recall rather than as false positives.
    """
    plan = load_plan(run_dir)
    cells = [
        c
        for c in plan["cells"]
        if c["arm"] == arm and c["corpus"] == corpus and c["variant"] == variant
    ]
    if not cells:
        raise ResultError(
            f"the plan has no cell for arm {arm!r} on corpus {corpus!r} "
            f"variant {variant!r}; it has "
            + ", ".join(f"{c['arm']}/{c['corpus']}/{c['variant']}" for c in plan["cells"])
        )
    if len(cells) > 1:
        raise ResultError(
            f"the plan has {len(cells)} cells for {arm}/{corpus}/{variant}, so this result "
            f"cannot be attributed to one of them"
        )
    cell = cells[0]

    meta = load_meta(Path(meta_path), settle_seconds, timeout)
    digest = wait_until_settled(Path(result_path), settle_seconds, timeout)
    try:
        doc = json.loads(Path(result_path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ResultError(
            f"{result_path} is not valid JSON: {exc}. If an agent wrote it, it was probably "
            f"truncated; re-run the write rather than hand-repairing it."
        ) from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("findings"), list):
        raise ResultError(
            f"{result_path}: expected an object with a 'findings' list. An empty list is a valid "
            f"clean run; a missing key means this is not an arm result."
        )

    normalised = normalise_c_review(doc) if _looks_like_c_review(doc) else normalise_generic(doc)
    waived = validate_findings(normalised["findings"], allow_incomplete=allow_incomplete)

    collected = {
        "arm": arm,
        "corpus": corpus,
        "variant": cell["variant"],
        "shape": "c-review" if _looks_like_c_review(doc) else "generic",
        "source_path": str(Path(result_path).resolve()),
        "source_sha256": digest,
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "meta": meta,
        # Recorded, never silent: `score` and any human reading `collected/*.json` can see
        # exactly which findings were admitted without a required text field, and how many.
        "waived_fields": waived,
        "waived_field_count": len(waived),
        "transcripts": [str(Path(t).resolve()) for t in transcripts],
        **normalised,
    }
    out_dir = Path(run_dir) / "collected"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{arm}__{corpus}__{variant}.json").write_text(
        json.dumps(collected, indent=2) + "\n", encoding="utf-8"
    )
    return collected
