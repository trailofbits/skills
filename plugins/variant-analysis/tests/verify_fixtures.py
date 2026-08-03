#!/usr/bin/env python3
"""Verify the eval fixture still matches ground truth.

Deterministic, offline once the checkout exists, and free — it does not call Claude.

Checks, in order:
  1. The checkout exists and sits at the pinned SHA. An unpinned tree means the
     recorded line numbers refer to different code.
  2. Every ground-truth line still contains its recorded anchor substring. This
     catches a patch or upstream edit that shifts lines and turns the eval into a
     measurement of nothing.
  3. The touched files still compile.

Exits non-zero on any drift, and also if it verifies zero anchors — a checker that
inspects nothing must fail rather than report success.

Skips an individual codebase that has not been fetched yet and still verifies the
rest; exits 0 with a notice only when *none* is fetched, so run_fixtures.sh stays
CI-safe on a machine that has never run setup-gradio.sh.
"""

import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent


def run(cmd, cwd=None):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=300)
        return p.returncode, (p.stdout + p.stderr)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return 1, str(exc)


def check_pinned(entry, base):
    rc, out = run(["git", "rev-parse", "HEAD"], cwd=base)
    if rc != 0:
        return [f"{entry['name']}: not a git checkout ({out.strip()})"]
    actual = out.strip()
    if actual != entry["pinned_sha"]:
        return [
            f"{entry['name']}: checkout is at {actual[:12]}, ground truth is pinned to "
            f"{entry['pinned_sha'][:12]}. Re-run ./setup-gradio.sh --force"
        ]
    return []


def check_anchors(entry, base):
    checked = 0
    failures = []
    for t in list(entry["vulnerabilities"]) + [entry["decoy"]]:
        path = base / t["file"]
        if not path.exists():
            failures.append(f"{entry['name']}: missing file {t['file']}")
            continue
        lines = path.read_text(errors="replace").splitlines()
        idx = t["line"] - 1
        if idx < 0 or idx >= len(lines):
            failures.append(
                f"{entry['name']}: {t['file']}:{t['line']} is past end of file "
                f"({len(lines)} lines) — was the patch applied?"
            )
            continue
        if t["anchor"] not in lines[idx]:
            failures.append(
                f"{entry['name']}: {t['file']}:{t['line']} drifted\n"
                f"    expected substring: {t['anchor']}\n"
                f"    actual line:        {lines[idx].strip()}"
            )
            continue
        # The grader's construct matching now depends on spans being present. Absent,
        # truth_span() silently falls back to a proximity window and the neighbouring-
        # construct conflation is back for that entry, with a green suite.
        span = t.get("span")
        if not span:
            failures.append(
                f"{entry['name']}: {t['file']}:{t['line']} has no span — the grader would "
                f"fall back to a proximity window and conflate neighbouring constructs"
            )
            continue
        if int(span[0]) < 1 or int(span[0]) > int(span[1]):
            failures.append(f"{entry['name']}: {t['file']} span {span} is not a valid range")
            continue
        # A span that no longer contains its own anchor line is a span the grader
        # would score against the wrong construct — the failure mode span exists to
        # prevent, reintroduced by a stale hand-edit.
        if not (int(span[0]) <= t["line"] <= int(span[1])):
            failures.append(
                f"{entry['name']}: {t['file']} span {span} does not contain its own "
                f"anchor line {t['line']}"
            )
            continue
        if int(span[1]) > len(lines):
            failures.append(
                f"{entry['name']}: {t['file']} span {span} runs past end of file "
                f"({len(lines)} lines)"
            )
            continue
        checked += 1
    return checked, failures


def check_compiles(entry, base):
    files = [t["file"] for t in list(entry["vulnerabilities"]) + [entry["decoy"]]]
    rc, out = run([sys.executable, "-m", "py_compile", *files], cwd=base)
    return ("patched files compile", rc == 0, out)


def main():
    truth = json.loads((HERE / "ground-truth.json").read_text())

    total_checked = 0
    all_failures = []
    results = []
    fetched = []
    skipped = []

    for entry in truth["codebases"]:
        base = HERE / entry["path"]
        if not base.exists():
            # `continue`, not `return`: with more than one codebase, returning here
            # would skip verification of every codebase after the first unfetched
            # one and report success having checked nothing.
            print(f"  - {entry['name']}: not fetched — run {entry['setup']}")
            skipped.append(entry)
            continue
        fetched.append(entry)

        print(f"→ {entry['name']} @ {entry['pinned_sha'][:12]}")
        all_failures += check_pinned(entry, base)

        checked, failures = check_anchors(entry, base)
        total_checked += checked
        all_failures += failures
        print(f"  {checked} anchors verified, {len(failures)} drifted")

        results.append(check_compiles(entry, base))

    if not fetched:
        print("\nnothing to verify yet (this is not a failure)")
        return 0

    # Only the fetched codebases are in scope. Counting the skipped ones here
    # would turn "not fetched yet" into a hard failure, which is the case the
    # skip above exists to allow.
    expected = sum(len(c["vulnerabilities"]) + 1 for c in fetched)
    if total_checked == 0:
        print("  ✗ zero anchors verified across fetched codebases — discovery is broken")
        return 1
    if total_checked != expected and not all_failures:
        print(f"  ✗ verified {total_checked} anchors but ground truth defines {expected}")
        return 1

    hard = 0
    for name, ok, out in results:
        if ok:
            print(f"  ✓ {name}")
        else:
            hard += 1
            print(f"  ✗ {name}\n{out.rstrip()}")

    for f in all_failures:
        print(f"  ✗ {f}")

    if all_failures or hard:
        return 1

    note = f", {len(skipped)} codebase(s) not fetched" if skipped else ""
    print(f"\nfixture OK ({total_checked} anchors{note})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
