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

Skips with exit 0 and a notice when the codebase has not been fetched yet, so
run_fixtures.sh stays CI-safe on a machine that has never run setup-gradio.sh.
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

    for entry in truth["codebases"]:
        base = HERE / entry["path"]
        if not base.exists():
            print(f"  - {entry['name']}: not fetched — run {entry['setup']}")
            print("\nnothing to verify yet (this is not a failure)")
            return 0

        print(f"→ {entry['name']} @ {entry['pinned_sha'][:12]}")
        all_failures += check_pinned(entry, base)

        checked, failures = check_anchors(entry, base)
        total_checked += checked
        all_failures += failures
        print(f"  {checked} anchors verified, {len(failures)} drifted")

        results.append(check_compiles(entry, base))

    expected = sum(len(c["vulnerabilities"]) + 1 for c in truth["codebases"])
    if total_checked == 0:
        print("  ✗ zero anchors verified — discovery is broken")
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

    print(f"\nfixture OK ({total_checked} anchors)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
