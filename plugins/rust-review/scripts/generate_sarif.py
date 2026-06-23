#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Generate rust-review SARIF from finding frontmatter.

Usage:
    python3 generate_sarif.py /path/to/output_dir
    python3 generate_sarif.py /path/to/output_dir --output /tmp/REPORT.sarif
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}
FILTER_MIN = {"all": 1, "medium": 2, "high": 3}
SURVIVOR_VERDICTS = {"TRUE_POSITIVE", "LIKELY_TP"}
# Findings with no fp_verdict (e.g. fp-judge was skipped on a partial run)
# are emitted with this synthetic verdict so the SARIF safety net still
# surfaces them. See SKILL.md Phase 8b.
UNJUDGED_FALLBACK_VERDICT = "LIKELY_TP"
CONFIDENCE_TO_SEVERITY = {"HIGH": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}

# Rust bug_class slugs from prompts/clusters/manifest.json.
RULE_DESCRIPTIONS = {
    # unsafe-boundary
    "unsafe-reaching-api": "Safe API reaches unsafe without a sound boundary proof",
    "transmute-misuse": "Incorrect mem::transmute or transmute_copy usage",
    "raw-pointer-arith": "Raw pointer arithmetic without proven bounds or validity",
    "repr-c-layout": "Unsound #[repr(C)] layout for FFI or foreign memory",
    "safety-doc": "Missing or incorrect // SAFETY: at an unsafe site",
    "debug-assert-safety": "debug_assert! is the only safety invariant in release builds",
    "pointer-cast": "Unsound cast via `as` between pointers, integers, or enums",
    "enum-discriminant": "Invalid enum discriminant or niche read/write",
    # memory-safety
    "use-after-free": "Use-after-free via dangled raw pointer",
    "double-free": "Double free via ptr::read or duplicate drop",
    "invalid-free": "Invalid free via write to uninitialized memory",
    "uninitialized-read": "Read from MaybeUninit before assume_init",
    "buffer-overflow-unsafe": "Safe index or size flows into unchecked unsafe access",
    "union-ub": "Undefined behavior from union field misuse",
    "vec-set-len-uninit": "Vec length advanced without initializing new elements",
    "panic-unwind-unsafe": "Panic during unsafe container mutation leaves stale metadata",
    # concurrency-locking
    "double-lock-deadlock": "MutexGuard double-lock from lexical scope",
    "abba-deadlock": "ABBA lock ordering deadlock",
    "condvar-misuse": "Condvar wait without a matching notifier",
    "channel-starvation": "Channel send or receive starvation or deadlock",
    "once-reentrancy": "Once::call_once reentrancy hazard",
    "reentrancy-unsafe": "Signal handler or callback reentrancy across unsafe code",
    # concurrency-data-race
    "atomic-race": "Non-atomic read-modify-write race on shared state",
    "unsafe-sync-impl": "unsafe impl Sync over interior mutability",
    "send-sync-bounds": "Missing or incorrect Send or Sync bounds",
    "shared-memory-race": "Cross-process shared memory data race",
    "static-mut-race": "Unsynchronized read or write of static mut across threads",
    # panic-dos
    "resource-exhaustion": "CPU or memory exhaustion DoS on untrusted input",
    "unwrap-on-untrusted": "unwrap or expect on attacker-controlled input",
    "arithmetic-overflow": "Integer overflow on an attacker-reachable path",
    "assertion-reachable": "Attacker-reachable assert! or unreachable! panic",
    "out-of-bounds-index": "Slice or vector index without bounds check on untrusted input",
    "str-slice-boundary": "str slice or split_at panic off a UTF-8 char boundary",
    "refcell-borrow-panic": "Attacker-reachable RefCell double-borrow panic",
    # recursion-dos
    "recursive-deserialize-stack-overflow": "Unbounded recursive Deserialize stack overflow",
    "recursive-format-stack-overflow": "Recursive Display, Debug, or Serialize stack overflow",
    "recursive-drop-stack-overflow": "Implicit recursive Drop of Box<Self> chain",
    # error-handling
    "result-discarded": "Security-relevant Result discarded without handling",
    "drop-panic": "Panic inside a Drop implementation",
    "lossy-from-into": "Lossy From, Into, or as conversion",
    "lossy-str-conversion": "Lossy UTF-8 or OS string or path conversion",
    "bufwriter-unflushed": "BufWriter dropped without flush swallows write errors",
    # logic-correctness
    "ord-eq-hash": "Ord, Eq, or Hash invariant violation",
    "adversarial-trait": "Hostile generic trait impl breaks invariants",
    "closure-panic": "Closure may panic across unsafe scaffolding",
    "float-edge": "NaN or Inf float comparison or ordering edge case",
    "string-comparison": "Partial or case-insensitive string comparison bypasses a check",
    "serialize-struct-mismatch": "serialize_struct field-count mismatch corrupts output",
    "nondeterminism": "Nondeterministic iteration or hashing in replicated state",
    "collection-key-mutation": "Mutating a key already stored in a map or set",
    # ffi-cross-language
    "cstring-dangling": "CString::as_ptr used after CString is dropped",
    "abi-mismatch": "FFI ABI signature or calling convention mismatch",
    "repr-c-padding": "#[repr(C)] padding leaks uninitialized data",
    "opaque-pointer": "Opaque pointer ownership confusion across FFI",
    "foreign-drop": "Mismatched drop of FFI-allocated memory",
    "closure-ffi": "Rust closure across extern C without catch_unwind",
    "dyn-trait-ffi": "dyn Trait fat pointer unsafely crosses FFI",
    # async-runtime
    "async-blocking": "Blocking call inside an async runtime",
    "cancel-safety": "Cancellation-unsafe .await sequence",
    "select-bias": "tokio::select! branch bias or fairness issue",
    # static-hygiene
    "cargo-lint-config": "Cargo lint config weakens safety checks",
    "msrv-mismatch": "MSRV or edition mismatch with APIs in use",
    "deprecated-api": "Deprecated unsafe API (e.g. mem::uninitialized)",
    # layout-safety
    "packed-field-ref": "Reference to field of repr(packed) struct",
    # resource-handling
    "raw-fd-lifecycle": "Raw file descriptor double-close or leak",
    "destructor-skip": "Drop skipped via process::exit or mem::forget leaks cleanup",
    # input-os-safety
    "path-traversal-join": "Path::join with attacker input escapes the intended directory",
    "toctou": "Filesystem time-of-check to time-of-use race",
    # info-disclosure
    "pointer-exposure": "Raw memory address leaked to an externally observable sink",
}


def split_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---", 4)
    if end == -1:
        return {}, text
    frontmatter = text[4:end]
    body = text[end + len("\n---") :].lstrip("\n")
    return parse_frontmatter(frontmatter), body


def parse_frontmatter(frontmatter: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    current_key: str | None = None
    for raw_line in frontmatter.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        if line.startswith("  - ") and current_key:
            result.setdefault(current_key, []).append(parse_scalar(line[4:]))
            continue
        if ":" not in line or line.startswith((" ", "\t")):
            current_key = None
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        current_key = key
        if value == "":
            result[key] = []
        else:
            result[key] = parse_scalar(value)
    return result


def _split_inline_list(inner: str) -> list[str]:
    """Split a YAML flow-list body on commas, respecting quoted strings."""
    parts: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    for ch in inner:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
            buf.append(ch)
        elif ch == ",":
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return parts


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [parse_scalar(part) for part in _split_inline_list(inner)]
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    return value


def parse_context(output_dir: Path) -> dict[str, Any]:
    path = output_dir / "context.md"
    if not path.exists():
        return {}
    frontmatter, _ = split_frontmatter(path.read_text(encoding="utf-8"))
    return frontmatter


def iter_findings(output_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Return (parsed findings, skipped records). Each skipped record is
    `{"path": ..., "reason": ...}` for a finding file that could not be read —
    the caller surfaces these in the SARIF so the loss is not stderr-only."""
    findings: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    index_path = output_dir / "findings-index.txt"
    if index_path.exists():
        paths = [
            Path(line.strip())
            for line in index_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    else:
        paths = sorted((output_dir / "findings").glob("*.md"))
    for path in paths:
        if not path.is_absolute():
            path = output_dir / path
        # A stale/missing index entry (e.g. a finding moved or deleted after the
        # Phase-7 index was written) must NOT crash the Phase-8b safety net, whose
        # whole job is to guarantee REPORT.sarif exists. Skip-and-record instead of
        # letting read_text raise FileNotFoundError.
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"warning: skipping unreadable finding file {path}: {exc}", file=sys.stderr)
            skipped.append({"path": str(path), "reason": f"unreadable ({exc.__class__.__name__})"})
            continue
        # parse_frontmatter raises on malformed YAML (e.g. a scalar then a list
        # item on one key). One bad file must not sink the Phase-8b net, so catch
        # broadly; narrowing to AttributeError would only patch this one shape.
        try:
            frontmatter, _ = split_frontmatter(text)
        except Exception as exc:
            print(f"warning: skipping unparseable finding file {path}: {exc}", file=sys.stderr)
            skipped.append({"path": str(path), "reason": f"unparseable ({exc.__class__.__name__})"})
            continue
        frontmatter["_path"] = str(path)
        findings.append(frontmatter)
    return findings, skipped


def location_parts(location: Any) -> tuple[str, int]:
    value = str(location or "")
    if "," in value or "\n" in value:
        return value, 1
    # SARIF region.startLine has a schema minimum of 1; a `:0` line (or any
    # non-positive value) would make the whole REPORT.sarif fail strict
    # validation / GitHub code-scanning ingestion, so clamp to >= 1.
    match = re.match(r"^\[([^\]]+)\]\([^)]+\):(\d+)$", value)
    if match:
        return normalize_path(match.group(1)), max(1, int(match.group(2)))
    path, sep, line = value.rpartition(":")
    if sep and line.isdecimal():
        return normalize_path(path), max(1, int(line))
    if sep and not line:
        return normalize_path(path), 1
    return normalize_path(value), 1


def normalize_path(path: str) -> str:
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    while "//" in path:
        path = path.replace("//", "/")
    return path


def severity_allowed(severity: str, severity_filter: str) -> bool:
    return SEVERITY_ORDER.get(severity.upper(), 0) >= FILTER_MIN.get(severity_filter, 1)


def sarif_level(severity: str) -> str:
    return SEVERITY_LEVEL.get(severity.upper(), "warning")


def rule_level(findings: list[dict[str, Any]], bug_class: str) -> str:
    max_severity = "LOW"
    for finding in findings:
        if finding.get("bug_class") == bug_class:
            severity = str(finding.get("severity", "LOW")).upper()
            if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(max_severity, 0):
                max_severity = severity
    return sarif_level(max_severity)


def build_sarif(output_dir: Path) -> dict[str, Any]:
    context = parse_context(output_dir)
    severity_filter = str(context.get("severity_filter", "all")).lower()
    threat_model = str(context.get("threat_model", "UNKNOWN"))
    all_findings, skipped = iter_findings(output_dir)

    # Skip a merged finding only when its merge target survives; otherwise the
    # old blind skip dropped real bugs whose target was FP-rejected or missing.
    by_id = {str(f.get("id")): f for f in all_findings if f.get("id")}

    def terminal_primary(fid: str) -> str | None:
        seen: set[str] = set()
        while fid in by_id and fid not in seen:
            seen.add(fid)
            nxt = by_id[fid].get("merged_into")
            if not nxt:
                return fid
            fid = str(nxt)
        return None

    survivor_ids: set[str] = set()
    for f in all_findings:
        if "merged_into" in f:
            continue
        if not (f.get("id") or f.get("bug_class") or f.get("title")):
            continue
        verdict = str(f.get("fp_verdict", "")).upper()
        if verdict and verdict not in SURVIVOR_VERDICTS:
            continue
        fid = f.get("id")
        if fid:
            survivor_ids.add(str(fid))

    findings = []
    for finding in all_findings:
        merged_target = finding.get("merged_into")
        if merged_target:
            if terminal_primary(str(merged_target)) in survivor_ids:
                continue
            print(
                "generate_sarif: merge target did not survive -- emitting "
                f"{finding.get('id', '?')} (merged_into: {merged_target}): "
                f"{finding.get('_path', '?')}",
                file=sys.stderr,
            )
        if not (finding.get("id") or finding.get("bug_class") or finding.get("title")):
            # No parseable frontmatter (e.g. a worker crashed mid-write before
            # emitting the `---` block). Skip rather than fabricate a phantom
            # result with ruleId "unknown" and an empty id/uri. Phase-7
            # validate_artifacts.py is the primary guard; this is defense in depth.
            path = str(finding.get("_path", "?"))
            print(
                f"generate_sarif: skipping finding with no parseable frontmatter: {path}",
                file=sys.stderr,
            )
            skipped.append({"path": path, "reason": "no parseable frontmatter"})
            continue
        verdict = str(finding.get("fp_verdict", "")).upper()
        unjudged = not verdict
        if unjudged:
            # Unjudged finding — fp-judge was skipped (partial run). Treat as
            # LIKELY_TP and infer severity from worker-assigned confidence.
            finding["fp_verdict"] = UNJUDGED_FALLBACK_VERDICT
            finding.setdefault(
                "severity",
                CONFIDENCE_TO_SEVERITY.get(str(finding.get("confidence", "")).upper(), "MEDIUM"),
            )
            finding["unjudged"] = True
        elif verdict not in SURVIVOR_VERDICTS:
            continue

        # A judged survivor whose `severity` the fp-judge never wrote (it crashed
        # or half-wrote the frontmatter) must NOT be silently dropped — this
        # generator is the safety net against exactly that. Surface it with a
        # defaulted severity, marked unvalidated, and exempt from the filter.
        sev = str(finding.get("severity", "")).upper()
        severity_unvalidated = (not unjudged) and (sev not in SEVERITY_ORDER)
        if severity_unvalidated:
            finding["severity"] = "MEDIUM"
            finding["severity_missing"] = True

        # Judged survivors are filtered by their validated severity. Unjudged
        # findings (no fp_verdict) and judged survivors missing a severity carry
        # only an *inferred* severity that no judge confirmed, so filtering them
        # on that guess would silently drop them (SKILL.md Phase 8b). Always
        # surface those — marked unvalidated below — regardless of filter.
        if not unjudged and not severity_unvalidated and not severity_allowed(sev, severity_filter):
            continue
        findings.append(finding)

    rules = []
    for bug_class in sorted({str(finding.get("bug_class", "unknown")) for finding in findings}):
        rules.append(
            {
                "id": bug_class,
                "shortDescription": {
                    "text": RULE_DESCRIPTIONS.get(bug_class, bug_class.replace("-", " ").title())
                },
                "defaultConfiguration": {"level": rule_level(findings, bug_class)},
            }
        )

    results = []
    for finding in findings:
        location, line = location_parts(finding.get("location"))
        # A finding with no recorded location yields an empty URI; surface that
        # loudly (mirroring severity_missing) instead of emitting a phantom `:1`
        # location a reviewer cannot act on.
        location_missing = not location
        severity = str(finding.get("severity", "MEDIUM")).upper()
        also_known_as = finding.get("also_known_as", [])
        if not isinstance(also_known_as, list):
            also_known_as = [str(also_known_as)]
        unjudged = bool(finding.get("unjudged", False))
        severity_missing = bool(finding.get("severity_missing", False))
        severity_validated = not (unjudged or severity_missing)
        title = str(finding.get("title") or finding.get("id") or "rust-review finding")
        markers: list[str] = []
        if not severity_validated:
            # No judge validated this severity — mark it loudly so a SARIF
            # consumer never reads the inferred/defaulted severity as confirmed.
            markers.append("UNVALIDATED SEVERITY — not judged")
        if location_missing:
            # Empty URI — flag it so it is not read as "applies to the whole tree".
            markers.append("LOCATION MISSING")
        if markers:
            title = f"[{'; '.join(markers)}] {title}"
        results.append(
            {
                "ruleId": str(finding.get("bug_class", "unknown")),
                "level": sarif_level(severity),
                "message": {"text": title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": location,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": line},
                        }
                    }
                ],
                "properties": {
                    "finding_id": str(finding.get("id", "")),
                    "bug_class": str(finding.get("bug_class", "unknown")),
                    "severity": severity,
                    "attack_vector": str(finding.get("attack_vector", "")),
                    "exploitability": str(finding.get("exploitability", "")),
                    "fp_verdict": str(finding.get("fp_verdict", "")),
                    "unjudged": unjudged,
                    "severity_validated": severity_validated,
                    "location_missing": location_missing,
                    "also_known_as": also_known_as,
                },
            }
        )

    # Surface any finding files that were dropped (unreadable / no frontmatter)
    # in the artifact itself — stderr is ephemeral, but a code-scanning consumer
    # reads only REPORT.sarif. We keep executionSuccessful=True on purpose: the
    # run DID complete and the vast majority of findings are present; flipping it
    # false can make platforms discard the entire run (losing the good findings
    # too). The skip count + per-file warning notifications are the proportionate
    # signal.
    invocation: dict[str, Any] = {
        "executionSuccessful": True,
        "properties": {
            "threat_model": threat_model,
            "severity_filter": severity_filter,
            "skipped_findings": len(skipped),
        },
    }
    if skipped:
        invocation["properties"]["skipped_paths"] = [s["path"] for s in skipped]
        invocation["toolExecutionNotifications"] = [
            {
                "level": "warning",
                "message": {
                    "text": f"Skipped finding file (excluded from results): {s['path']} — {s['reason']}"
                },
            }
            for s in skipped
        ]

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "rust-review",
                        "informationUri": "https://github.com/trailofbits/skills/tree/main/plugins/rust-review",
                        "rules": rules,
                    }
                },
                # Declares the %SRCROOT% symbol each result's artifactLocation
                # references (finding URIs are repo-relative). Optional per SARIF
                # 2.1.0 but consumers expect a matching originalUriBaseIds entry.
                "originalUriBaseIds": {
                    "%SRCROOT%": {
                        "description": {
                            "text": "Root of the audited Rust crate or workspace; "
                            "finding URIs are relative to this."
                        }
                    }
                },
                "invocations": [invocation],
                "results": results,
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate REPORT.sarif for a rust-review output dir"
    )
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    output_dir = args.output_dir.resolve()
    output_path = args.output or output_dir / "REPORT.sarif"
    sarif = build_sarif(output_dir)
    output_path.write_text(json.dumps(sarif, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {output_path}")
    skipped_count = sarif["runs"][0]["invocations"][0]["properties"]["skipped_findings"]
    if skipped_count:
        # Stdout (not just stderr) so the orchestrator's Bash capture sees it and
        # Phase 8b can note the loss in run-summary.md.
        print(
            f"WARNING: skipped {skipped_count} unreadable/frontmatterless finding "
            "file(s) — see REPORT.sarif invocations[].properties.skipped_findings"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
