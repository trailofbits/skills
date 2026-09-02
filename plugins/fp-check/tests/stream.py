"""The ONLY place that knows the shape of a `claude -p --output-format stream-json` capture.

Every format assumption lives here. If the stream format or the journal layout
changes, this file breaks and nothing else does. Keep it that way: no other test
module may index into a raw event dict.

Documented surface used here:
  - stream-json emits one JSON object per line
  - assistant events carry `message.content[]` with `tool_use` blocks
  - user events carry `message.content[]` with `tool_result` blocks
  - `--forward-subagent-text` (2.1.211+) stamps subagent text with
    `parent_tool_use_id` so per-stage output can be reconstructed
  - a `result` event closes the run

Undocumented surface, deliberately quarantined to `journal_returns()`:
  - `<transcriptDir>/journal.jsonl` records each agent's actual return value
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


class StreamFormatError(AssertionError):
    """The capture does not match the shape this module knows how to read."""


@dataclass(frozen=True)
class WorkflowLaunch:
    """A Workflow tool call paired with the tool_result that answered it."""

    tool_use_id: str
    name: str
    args: dict
    status: str | None
    error: str | None
    raw_result: dict

    @property
    def started(self) -> bool:
        """A launch that reports an error never ran, whatever its status says.

        A script that fails its syntax check comes back as
        `status: "async_launched"` WITH `error` set. A harness that reads only
        the status reports green on a workflow that never executed.

        An *unanswered* tool call is one level below that trap and used to pass
        it: with no tool_result at all the payload is `{}`, so `error` is None
        and this returned True for a Workflow call that was never answered.
        No result is not the same as no error.
        """
        if not self.raw_result:
            return False
        return self.error is None


class Capture:
    def __init__(self, events: list[dict], path: Path):
        self.events = events
        self.path = path

    # ------------------------------------------------------------ loading

    @classmethod
    def load(cls, path: Path) -> Capture:
        if not path.exists():
            raise StreamFormatError(
                f"no capture at {path}. Run tests/capture-run.sh first; "
                f"the regrade path cannot report success without one."
            )
        events = []
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise StreamFormatError(f"{path}:{lineno} is not valid JSON: {exc}") from exc
        if not events:
            raise StreamFormatError(f"{path} contains zero events; refusing to report success")
        return cls(events, path)

    # ------------------------------------------------- content extraction

    def _blocks(self, event_type: str, block_type: str):
        for ev in self.events:
            if ev.get("type") != event_type:
                continue
            content = ev.get("message", {}).get("content")
            if not isinstance(content, list):
                continue
            for block in content:
                if isinstance(block, dict) and block.get("type") == block_type:
                    yield ev, block

    def _tool_results(self) -> dict[str, dict]:
        out = {}
        for _ev, block in self._blocks("user", "tool_result"):
            tid = block.get("tool_use_id")
            if tid:
                out[tid] = block
        return out

    @staticmethod
    def _result_payload(block: dict) -> dict:
        """tool_result content is either a string of JSON or a content-block list."""
        content = block.get("content")
        if isinstance(content, list):
            text = "".join(c.get("text", "") for c in content if isinstance(c, dict))
        else:
            text = content if isinstance(content, str) else ""
        text = text.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {"_text": text}
        return parsed if isinstance(parsed, dict) else {"_value": parsed}

    # -------------------------------------------------------- public API

    def workflow_launches(self) -> list[WorkflowLaunch]:
        results = self._tool_results()
        launches = []
        for _ev, block in self._blocks("assistant", "tool_use"):
            if block.get("name") != "Workflow":
                continue
            tid = block.get("id", "")
            payload = self._result_payload(results.get(tid, {}))
            launches.append(
                WorkflowLaunch(
                    tool_use_id=tid,
                    name=block.get("input", {}).get("name", ""),
                    args=block.get("input", {}).get("args", {}) or {},
                    status=payload.get("status"),
                    error=payload.get("error"),
                    raw_result=payload,
                )
            )
        return launches

    def skill_invocations(self) -> list[str]:
        """Names passed to the Skill tool, e.g. "fp-check:fp-check"."""
        out = []
        for _ev, block in self._blocks("assistant", "tool_use"):
            if block.get("name") == "Skill":
                target = block.get("input", {}).get("skill") or block.get("input", {}).get("name")
                if target:
                    out.append(target)
        return out

    def subagent_text(self) -> dict[str, list[str]]:
        """Subagent text keyed by `parent_tool_use_id`, per --forward-subagent-text.

        Currently returns `{}` for every capture taken so far, and that is not
        a bug in this method. Measured against the checked-in fixture: 29 events
        carry a `parent_tool_use_id` key and all 29 are `null`; zero text blocks
        are attributable to a subagent.

        The flag forwards text from subagents of the PARENT session. This
        plugin's agents are dispatched by the Workflow tool, which returns on
        launch and runs them in the workflow runtime — they write to
        `journal.jsonl` in the transcript dir, never into the parent stream. It
        is the same fact that put every stage result in `Capture.journal_returns`
        rather than here.

        So there is no consumer for this method, and there cannot be one until
        either the runtime forwards workflow-agent text or the capture stops
        using `-p`. Kept, with the measurement attached, so the next person does
        not pay for a capture to find out.
        """
        out: dict[str, list[str]] = {}
        for ev in self.events:
            parent = ev.get("parent_tool_use_id")
            if not parent:
                continue
            content = ev.get("message", {}).get("content")
            texts = []
            if isinstance(content, list):
                texts = [
                    c.get("text", "")
                    for c in content
                    if isinstance(c, dict) and c.get("type") == "text"
                ]
            elif isinstance(content, str):
                texts = [content]
            if texts:
                out.setdefault(parent, []).extend(t for t in texts if t)
        return out

    # ------------------------------------------- undocumented, quarantined

    @staticmethod
    def journal_returns(journal_path: Path) -> list[dict]:
        """Each agent's actual return value from journal.jsonl.

        NOT a documented interface. Isolated here so a format change breaks one
        function rather than every regrade assertion.
        """
        if not journal_path.exists():
            raise StreamFormatError(f"no journal at {journal_path}")
        rows = []
        for line in journal_path.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        if not rows:
            raise StreamFormatError(f"{journal_path} yielded zero rows")
        return rows


def load_run_meta(path: Path) -> dict:
    """Model, effort, CLI version and pass rate recorded alongside the capture."""
    if not path.exists():
        raise StreamFormatError(
            f"no run metadata at {path}; results without model/effort/CLI version "
            f"are not reproducible"
        )
    return json.loads(path.read_text())
