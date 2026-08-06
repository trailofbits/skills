"""How much of the corpus zizmor already covers, and which vectors it leaves.

zizmor is the baseline this skill has to beat rather than duplicate: it is a mature
static analyser for Actions, so any finding it already reports is not evidence that
the skill is worth loading.

    python3 measure.py            # needs corpus/ from corpus.py
    python3 measure.py --fixtures # runs against tests/fixtures instead, no network

Refuses to report anything if vectors.self_test() fails, because a signature that has
stopped matching would report a clean corpus forever.
"""

from __future__ import annotations

import collections
import json
import pathlib
import shutil
import subprocess
import sys

import vectors

HERE = pathlib.Path(__file__).parent
CORPUS = HERE / "corpus"

# Findings that describe general Actions hygiene rather than anything about an agent.
# Kept separate so "zizmor found something" is not confused with "zizmor found this".
HYGIENE = {"unpinned-uses", "artipacked", "github-app", "adhoc-packages", "cache-poisoning"}


def zizmor(path: pathlib.Path) -> list[str] | None:
    exe = shutil.which("zizmor")
    if not exe:
        return None
    r = subprocess.run(
        [exe, "--no-online-audits", "--format", "json", str(path)],
        capture_output=True,
        text=True,
    )
    try:
        return [f["ident"] for f in json.loads(r.stdout)]
    except json.JSONDecodeError:
        return []


def main(argv: list[str]) -> int:
    if vectors.self_test():
        print("signature self-test failed; counts below would be meaningless")
        return 1

    if "--fixtures" in argv:
        files = sorted(vectors.FIXTURES.glob("*.yml"))
        label = "fixtures"
    else:
        files = sorted(CORPUS.glob("*/workflow.yml"))
        label = "corpus"
    if not files:
        print(f"no {label} found; run corpus.py first")
        return 1

    # Findings and files are different numbers: zizmor reports unpinned-uses once per
    # unpinned step, so counting findings and dividing by file count produced a rate
    # over 100% under a heading that said "workflows".
    rules: collections.Counter[str] = collections.Counter()
    rule_files: collections.Counter[str] = collections.Counter()
    vec: collections.Counter[str] = collections.Counter()
    no_zizmor = 0
    have_zizmor = shutil.which("zizmor") is not None
    rows = []

    for f in files:
        text = f.read_text()
        idents = zizmor(f) or []
        if have_zizmor and not idents:
            no_zizmor += 1
        rules.update(idents)
        rule_files.update(set(idents))
        hits = [k for k, (_, fn) in vectors.VECTORS.items() if fn(text)]
        vec.update(hits)
        rows.append((idents, hits))

    n = len(files)
    print(f"{label}: {n} workflows\n")

    if have_zizmor:
        print(f"{'zizmor rule':24}{'findings':>9}{'files':>7}{'':>4}")
        for k, v in rules.most_common():
            tag = "hygiene" if k in HYGIENE else ""
            fl = rule_files[k]
            print(f"  {k:22}{v:7}{fl:7}  {100 * fl // n:3}%  {tag}")
        print(f"  {'(no finding at all)':22}{'':7}{no_zizmor:7}  {100 * no_zizmor // n:3}%")
    else:
        print("zizmor not on PATH; skipping the baseline (pip install zizmor)")

    print("\nvectors, by signature:")
    for k, (desc, _) in vectors.VECTORS.items():
        v = vec[k]
        print(f"  {k} {desc:34} {v:4}  {100 * v // n:3}%")
    for k, desc in vectors.UNDECIDABLE.items():
        print(f"  {k} {desc:34}    -  no static signature")

    if have_zizmor:
        # D is left out because pull_request_target with a head checkout is a general
        # Actions problem that zizmor owns through dangerous-triggers. B is in: an
        # expression reaching an agent's prompt is the most agent-specific thing here,
        # and leaving it out under-counted the very split this table exists to show.
        agentic = {"A", "B", "F", "H", "I"}
        rel = [r for r in rows if agentic & set(r[1])]
        print(f"\nworkflows carrying an agent-specific vector: {len(rel)}")
        by = collections.Counter()
        for idents, _ in rel:
            named = [i for i in idents if i not in HYGIENE]
            # "names a non-hygiene rule" is not "names the agent path". On this corpus
            # every template-injection finding sat on a run: step, so the label says
            # where the finding is, not that zizmor caught the vector.
            by[
                "zizmor silent"
                if not idents
                else ("non-hygiene finding elsewhere in file" if named else "hygiene only")
            ] += 1
        for k, v in by.items():
            print(f"  {k:38} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
