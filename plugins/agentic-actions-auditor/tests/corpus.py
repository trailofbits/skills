"""Collect real workflows that invoke an AI agent action, pinned by content SHA.

Writes to corpus/, which is gitignored. Nothing here is shipped as a fixture: the
corpus produces aggregate counts and the eval fixtures are written by hand, because
committing a third party's exploitable workflow would publish a list of live targets.

    python3 corpus.py [limit]
"""

from __future__ import annotations

import base64
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
OUT = HERE / "corpus"

ACTIONS = [
    "anthropics/claude-code-action",
    "google-github-actions/run-gemini-cli",
    "openai/codex-action",
    "actions/ai-inference",
]


def api(path: str):
    r = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def candidates() -> list[tuple[str, str]]:
    seen, out = set(), []
    for action in ACTIONS:
        for page in (1, 2):
            res = api(f"search/code?q={action}+path:.github/workflows&per_page=30&page={page}")
            if not isinstance(res, dict):
                continue
            for item in res.get("items", []):
                repo, path = item["repository"]["full_name"], item["path"]
                if not path.endswith((".yml", ".yaml")):
                    continue
                key = f"{repo}::{path}"
                if key not in seen:
                    seen.add(key)
                    out.append((repo, path))
    return out


def main(limit: int) -> int:
    OUT.mkdir(exist_ok=True)
    found = candidates()
    print(f"candidates: {len(found)}")
    kept = 0
    for repo, path in found:
        if kept >= limit:
            break
        meta = api(f"repos/{repo}/contents/{path}")
        if not isinstance(meta, dict) or "content" not in meta:
            continue
        text = base64.b64decode(meta["content"]).decode("utf-8", "replace")
        # search/code matches README and template files too; require the action to
        # actually be invoked or the counts describe prose rather than workflows.
        if not any(a in text for a in ACTIONS):
            continue
        kept += 1
        d = OUT / f"wf{kept:03d}"
        d.mkdir(exist_ok=True)
        (d / "workflow.yml").write_text(text)
        (d / "meta.json").write_text(
            json.dumps({"repo": repo, "path": path, "sha": meta["sha"]}, indent=1)
        )
        sys.stdout.write(".")
        sys.stdout.flush()
    print(f"\ncollected: {kept}")
    return 0 if kept else 1


if __name__ == "__main__":
    sys.exit(main(int(sys.argv[1]) if len(sys.argv) > 1 else 60))
