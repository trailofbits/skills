# File handoffs

All paths below are relative to a campaign directory outside the plugin. Agents may organize
artifacts within assigned attempt directories; the index records current paths.
Never overwrite sealed attempts.

## Index and stage records

Before dispatch, write `scope.json` as `{"changes":[{"id":"change-1","input":"PR URL or commit"}]}`
from the complete user request. Inputs may also be repository/range objects. Run registry `init`
to freeze its hash and ID/input mapping. IDs must be unique; `campaign` is reserved for reporting.
Never rewrite scope from the mutable index. A changed request starts a new campaign.

`campaign.json` has `title` and `changes`: a list of objects with unique `id`, original `input`,
`prepare` and `hunt` record paths (or null), `limitations` (text), and `candidates` (list of objects
with unique campaign-wide `id`, `candidate` file path and `decision` record path or null).
The orchestrator alone updates this index. `progress.md` records agent handles, assigned paths,
accepted outputs, blockers, owned resources and next actions. Never count a dispatch as completion.

For each change, the coordinator saves exact copies of the root-level `AGENTS.md`,
`PATCHING_GUIDELINES.md` and `THREAT_MODEL.md` found at the target commit under
`guidance/<change-id>/<target-SHA>/`. Record the full source commit ID and absent filenames in
`progress.md`. Keep copies used by prior attempts when the target changes. Pass each saved
copy as a registry `--input` for every stage of that change; campaign-wide reporting uses
the copies for every scoped change. The registry hashes these inputs so changed or missing
copies invalidate reuse on resume. The coordinator also supplies their complete contents
in each fresh-agent prompt, including preparation; paths alone are insufficient.

### Project guidance

Before target work, each stage reads every present root `AGENTS.md`,
`PATCHING_GUIDELINES.md` and `THREAT_MODEL.md` at the pinned target commit.
Preparation resolves that commit first; later stages use `source.json.s1` from the
sealed preparation. If no S1 was frozen, resolve the target from the change input or
report a blocker. Reporting covers every scoped change. Check supplied copies against
their registry input hashes; account for each filename with a copy or explicit absence.
Fetch unaccounted files by SHA or from local Git objects, and do the same for all three
files when no copies are supplied. Missing files are allowed. A complete handoff does
not require repository access; an unavailable target SHA or incomplete handoff blocks
target work. Apply relevant guidance within stage permissions and evidence rules. If
preparation freezes a different S1, refresh guidance before continuing.

### ID registry

[registry.py](../scripts/registry.py) owns `registry.json`; never edit it manually.
`progress.md` holds operational notes, not a second ID registry. Independent callers use
the same helper. It requires POSIX file locks and writes atomically under a campaign lock.

Invoke `uv run --no-project SCRIPT COMMAND CAMPAIGN ...`, resolving SCRIPT from the link:

| Command | Arguments | Result |
| --- | --- | --- |
| `init` | | Freeze `scope.json` before reserving any assignments. |
| `reserve` | `--stage STAGE --change CHANGE_ID [--candidate ID] [--input PATH ...]` | New attempt ID, directory and input hashes; new hunts also get a unique prefix. |
| `bind` | `ATTEMPT --agent HANDLE (--host-record PATH \| --agent-record PATH)` | Verify launch evidence, bind the handle and record its verification level (`isolated` for host records, `shared-host` for agent records); a different owner requires a retry. |
| `candidate` | `ATTEMPT --agent HANDLE --key HYPOTHESIS_KEY` | Reserve a candidate ID, or return the existing ID for that key. |
| `retry` | `ATTEMPT (--host-record PATH \| --agent-record PATH) [--inputs PATH ...]` | Require termination evidence of the same kind as the launch, supersede the attempt and allocate a new ID/directory with its candidate prefix. Omitted inputs reuse old paths; an empty list clears them. |
| `check` | `ATTEMPT RECORD` | Verify the sealed result against its assignment without accepting it. |
| `accept` | `ATTEMPT RECORD` | Validate and record acceptance; only then update campaign pointers. |
| `show` | | Read the registry for coordinator recovery; never pass other hunters' mappings to a worker. |

Repeat `--input` for each prerequisite. The returned assignment supplies the attempt ID,
exact input paths and output directory; new directories are created by the assigned agent.

- Reserve before dispatch, then bind the actual handle. Hunters reserve IDs before writing
  candidate files. A hypothesis key names the same suspected defect across retries; new
  defects use new keys. The helper cannot detect the same defect described under two keys.
- `registry.json` version 2 contains frozen `scope`, `prefixes` (prefix → change), `candidates` (ID → prefix,
  key, change, accepted file), and `attempts` (ID → stage, change, candidate, prefix, inputs,
  input hashes, directory, agent, state, accepted record and seal hash, launch/terminal observations).
- Attempt states are `reserved`, `running`, `accepted` and `superseded`. An accepted record
  may be blocked. Continue active attempts with the same ID; retries get new IDs/directories.
  The coordinator must stop the old agent and verify termination before recording terminal evidence.
- Acceptance checks change, stage, agent, candidate, attempt, launch evidence, exact input paths/hashes, output
  confinement and seals. Hunt results must account for all reserved candidate IDs and keys.
  Never rename sealed records. The helper verifies recorded identity, not host authentication.
- Every report requires a registry, the exact frozen scope and registry acceptance for every
  referenced stage record. Each record must belong to its indexed change.

### Verification levels

Each bound attempt records how its agent was separated:

- `isolated`: bound with a host record (below). The host confirmed a fresh context and a private
  environment.
- `shared-host`: bound with an agent record. A distinct agent started without inherited
  conversation, sharing the machine with other agents.

A finding's level is the weakest among its reproduction, replay and adjudication. Reproduction,
replay and adjudication of one candidate always need distinct agent handles.

An agent record is a JSON file in `runtime/` with retained raw evidence beside it:

```json
{"event": "launch", "attempt": "a003", "tool": "codex.spawn_agent",
 "call": {"task_name": "replay", "fork_turns": "none"},
 "response": {"task_name": "/root/replay"},
 "observed_at": "2026-09-30T21:10:00+00:00", "evidence": ["runtime/a003-spawn.txt"]}
```

A terminal agent record lists the bound handle in `response.agents`, matched on `agent_name`:

```json
{"event": "terminal", "attempt": "a003", "tool": "codex.list_agents",
 "response": {"agents": [{"agent_name": "/root/replay", "agent_status": {"completed": "..."}}]},
 "observed_at": "2026-09-30T21:20:00+00:00", "evidence": ["runtime/a003-status.txt"]}
```

Use a unique `task_name` for every attempt: a handle that worked on a candidate cannot be bound to
another reproduce, replay or adjudicate attempt for that candidate, even after a retry. An agent
whose status is neither `completed` nor `errored` (for example one stopped by force) cannot be
retried with an agent record; record a blocker.

Bind with `--agent` equal to `response.task_name`. Retry a `shared-host` attempt with a
`terminal` record from `codex.list_agents` whose `response.agents` lists that handle once with
`agent_status` `{"completed": ...}` or `{"errored": ...}`. Other tools are rejected until a
recognizer is added.

### Host verification

The coordinator captures host launch/status responses and environment checks in `runtime/`, outside
worker outputs. Workers must not write this directory, scope or registry. Enforce permissions through
the host; a shared writable checkout alone does not enforce ownership. Independent callers have the
same duties. If the host cannot verify a required fact, bind with an agent record at `shared-host` instead, or
record a blocker when no agent record is available.

Each JSON observation contains `event` (`launch` or `terminal`), `attempt`, `host`, `session`,
`agent`, `context`, `observed_at` (ISO 8601 with timezone), and `evidence` (paths to retained raw host
responses/checks). Use actual host identities, not invented labels. A host-documented fresh agent
handle may identify its context. Preserve host session identity across coordinator restarts.

- Launch also records `directory`, `environment`, `fresh_context: true` and `isolated: true`.
  Verify a new context without inherited conversation and a private workspace/runtime namespace;
  record its actual identity. Launches cannot reuse agent, context or environment identities in the
  same host session. Shared immutable sources are allowed; mutable builds, services and logs are not.
  Keep the worker waiting until binding succeeds. Stop and verify termination of a rejected launch.
- Terminal also records host-confirmed `state` (`completed`, `stopped` or `failed`),
  `active_commands: []` and `resources_released: true`. Query the host after stopping work; confirm
  no owned commands remain and release services/locks without deleting evidence. A completion
  message, timeout, idle status or stop request is insufficient. Never resume a retired handle.

Registry `bind` and `retry` require these observations, hash their raw evidence and reject missing
or inconsistent facts. Acceptance rechecks launch evidence. The helper cannot authenticate host
responses or terminate agents; the coordinator must obtain evidence directly from trusted host
tools. If dispatch occurred before a crash but binding did not, recover its handle and launch
evidence before retrying. Do not guess that an unbound assignment never started.

### Stage records

Every stage record is a JSON object with:

- `stage`: prepare, hunt, reproduce, replay, adjudicate or report; `agent`: bound host handle.
- `attempt` and `change`: reserved attempt and change IDs. Use the assignment's exact `inputs`
  and output directory.
- `status`: complete or blocked; `summary`: concise findings or exact missing prerequisites.
- `security_review`: reviewed document paths and conclusions, or search/access limitations.
- `inputs`: prerequisite record/file paths; `artifacts`: all output files/directories needed to
  inspect or repeat the work. These include source, setup scripts, sanitized configurations, tool
  versions, input, PoC, logs and analysis as applicable. No secrets or live credentials.

Use [evidence.py](../scripts/evidence.py): `uv run --no-project SCRIPT seal CAMPAIGN RECORD`, then
`verify` with the same arguments. Resolve SCRIPT from the linked installed file. Sealing records
SHA-256 hashes and recursively binds sealed prerequisite records. Verification catches changed,
missing or newly added package files. Symlink evidence is rejected: freeze its target content
safely in a separate artifact when necessary. Integrity is not proof that an agent's claim is true.

`report.py` exits 0 when it writes the report; findings may be `UNRESOLVED` with an
`unresolved_reason`, and confirmed findings carry `verification` (`isolated` or `shared-host`). It
exits 1 when evidence changed after acceptance or the campaign index is invalid, writing nothing, and
2 on usage errors.

Seal an attempt only after its work has ended, whether its status is `complete` or `blocked`.
Build/deploy outside sealed source exports. Resume verifies seals and reuses unchanged work;
invalidated work gets new paths.
Pass prerequisite records AND their complete artifact trees to agents. Copying records alone is
insufficient; remote transfers must preserve the campaign-relative layout and pass verification.

## Stage-specific fields

**prepare:** `source` is the frozen `source.json` path (or null if blocked). That file records
`s0`, `s1` full commit IDs and repository. Artifacts include pristine S0/S1 exports, diff, commit/PR
context and boundary explanation. Collect title/body/comments before sealing.

**hunt:** `inputs` includes preparation; `candidates` lists every candidate ID, matching the index.
`candidate_files` maps each ID to its sealed candidate file in the attempt directory.
Each candidate file describes `id`, stable `key`, `title`, patch intent, prior behavior,
changed code, reachable trigger, possible defect, false-positive checks and proof needed.
Include these files as artifacts.
Record coverage, including supplied leads, even if discovery is blocked.

**reproduce / replay:** `candidate` is the assigned candidate ID. `inputs` includes its accepted
candidate file, preparation and discovery; replay also includes the
reproduction record. Both set `source` to the same frozen source file. Include `setup` (repeatable
deployment instructions), `poc` (unchanged runnable entry point), `workload` (input/configuration
file without revision-specific addresses), and `runs`:

```json
[
  {"state":"S0", "revision":"FULL_SHA", "deployment":"actual interface/address",
   "command":"exact executed command", "log":"relative/log0.txt", "behavior":"correct"},
  {"state":"S1", "revision":"FULL_SHA", "deployment":"actual interface/address",
   "command":"exact executed command", "log":"relative/log1.txt", "behavior":"failure"}
]
```

Completed records also list `build_dirs`: every build or deployment directory used, as
campaign-relative paths inside the attempt directory. Never build in another attempt's directory
or a shared location; `accept` rejects paths outside the attempt directory.

Acceptance checks declared directories only; campaign
audits compare actual build locations with the declaration.

Record actual observations, not expected ones. `behavior` may be `correct`, `failure` or `unknown`.
Blocked records may omit unexecuted fields and keep `runs` empty. Both agents retain independent
setup/logs; replay references original PoC/workload unchanged. Include every PoC dependency and
immutable data file in the sealed package; do not fetch mutable scripts during execution.

**adjudicate:** `inputs` includes preparation, discovery, candidate and all available experiment
records. Set `candidate` to the candidate ID, `outcome` to a label below, and `reason` to a cited
explanation. `evidence` lists the files a human should inspect, also included in inputs/artifacts.
For confirmation also provide `reproduction`, `replay` record paths, `category`, `severity`,
`likelihood`, `severity_reason`, `likelihood_reason`, and `checks` for each:
`supported_behavior`, `reachability`, `introduced_defect`, `incomplete_fix`, `latent_bug`,
`preexisting_bug`, `intentional_change`, `unsupported_expectation`, `security_scope`.
Each check is `{"conclusion":"SUPPORTED", "reason":"explanation", "evidence":["file/path"]}`.
Confirmation requires SUPPORTED for the first three checks, REFUTED for the five exclusion
checks, and SUPPORTED for security scope (NOT_APPLICABLE for other categories). UNKNOWN prevents
confirmation. Cite files in the sealed package, explaining the relevant lines/observations.

**report:** `report-stage.json` records the reporting attempt, assigned inputs, status and
generated reports as artifacts. Render into the assigned attempt directory. A blocked report
records validation errors; it never repairs source records. Use `campaign` as the change ID
when reserving a campaign-wide reporting attempt.

## Labels

Outcomes: `REPRODUCED_REGRESSION`, `INCOMPLETE_FIX`, `LATENT_BUG`, `PREEXISTING_BUG`, `REJECTED`,
`UNRESOLVED`. Missing decisions are unresolved. Category: `VULNERABILITY`, `FUNCTIONAL_BUG`,
`PERFORMANCE`, `BUILD_TEST`. Ratings: severity Low/Medium/High/Critical; likelihood Low/Medium/High.
See [definitions](../docs/report-definitions.md) for meaning, not just accepted spellings.

Duplicate decisions may set `duplicate_of` to a canonical candidate ID; preserve their evidence
and change mappings, exclude them from unique totals, and explain the common root cause. Never
deduplicate unresolved claims into confirmation. The report validates these references.
