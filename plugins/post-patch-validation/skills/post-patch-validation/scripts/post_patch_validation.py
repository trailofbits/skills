#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Deterministic evidence runner for post-patch security validation.

The plan contains argv arrays, never shell strings. The runner pins both Git inputs,
materializes isolated worktrees, executes checks in lexical order, preserves raw evidence,
and maps observations to S1-S5 or INCONCLUSIVE.

Exploit and variant checks must print PPV_REACHED before evaluating their safety assertion.
A nonzero exit alone proves nothing: an import error, a failed build, and a failed assertion
are indistinguishable by exit code, so an unmarked run is INCONCLUSIVE rather than evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = "1.0"
ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
HEX_RE = re.compile(r"^[0-9a-f]{40,64}$")
KINDS = ("control", "exploit", "variant", "behavior", "regression", "security", "suite")
EVIDENCE_LEVELS = ("source", "build", "runtime")
FIXED_ENV = {
    "LANG": "C",
    "LC_ALL": "C",
    "TZ": "UTC",
    "NO_COLOR": "1",
    "TERM": "dumb",
    "PYTHONHASHSEED": "0",
}
BASE_ENV_KEYS = {
    "COMSPEC",
    "HOME",
    "LOGNAME",
    "PATH",
    "PATHEXT",
    "SHELL",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USER",
    "WINDIR",
    "XDG_CACHE_HOME",
}
GIT_PREFIX = ("git", "-c", f"core.hooksPath={os.devnull}")
# Kinds whose verdict depends on a *failed safety assertion* rather than a nonzero exit.
# A crashed, mis-imported, or never-built harness also exits nonzero, so those kinds must
# prove they reached the assertion by emitting REACHED_MARKER before evaluating it.
MARKER_KINDS = frozenset({"exploit", "variant"})
REACHED_MARKER = "PPV_REACHED"
WORKTREE_LOCK_REASON_PREFIX = "post-patch-validation:"
MAX_ARCHIVED_ARGV_FILE_BYTES = 16 * 1024 * 1024
MAX_PLAN_ARTIFACT_BYTES = 64 * 1024 * 1024
SHELL_NAMES = frozenset(
    {
        "ash",
        "bash",
        "cmd",
        "cmd.exe",
        "csh",
        "dash",
        "fish",
        "ksh",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "script",
        "sh",
        "tcsh",
        "zsh",
    }
)
# `-c` is rarely alone: bash accepts -xc, -lc, -ic, and any other bundling of single-letter
# flags, so match a leading-dash cluster containing "c" rather than an exact string.
SHELL_COMMAND_FLAG_RE = re.compile(r"^-[a-z]*c[a-z]*$")
SHELL_COMMAND_FLAGS = frozenset({"-command", "/c"})
# `env -S "sh -c ..."` re-splits its argument into a command line, which is the same hazard as
# a shell string reached through a different door.
ENV_SPLIT_FLAGS = frozenset({"-s", "--split-string"})
# Variables that change which code runs. Forwarding these would silently undo the isolation the
# whole tool is built on, so they are refused rather than recorded.
FORBIDDEN_ENV = frozenset(
    {
        "BASH_ENV",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "ENV",
        "GIT_SSH_COMMAND",
        "LD_AUDIT",
        "LD_PRELOAD",
        "NODE_OPTIONS",
        "PERL5OPT",
        "PYTHONSTARTUP",
        "RUBYOPT",
    }
)
# Forwarded values are recorded verbatim in result.json, so refuse the obvious secret names
# outright instead of trusting every future caller to have read the warning.
CREDENTIAL_ENV_RE = re.compile(
    r"(SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|API_KEY|ACCESS_KEY|SESSION|"
    r"COOKIE|SIGNING_KEY|(?:^|_)AUTH(?:_|$)|(?:^|_)KEY(?:_|$)|(?:^|_)PAT(?:_|$)|"
    r"(?:^|_)PASS(?:_|$))"
)
SIDES_BY_KIND = {
    "control": ("base", "patched"),
    "exploit": ("base", "patched"),
    "variant": ("base", "patched"),
    "behavior": ("base", "patched"),
    "regression": ("base", "patched"),
    "security": ("base", "patched"),
    "suite": ("patched",),
}
EXPECTED_BY_KIND = {
    "control": {"base": "zero", "patched": "zero"},
    "exploit": {"base": "nonzero", "patched": "zero"},
    "variant": {"base": "nonzero", "patched": "zero"},
    "behavior": {"base": "zero", "patched": "zero"},
    "regression": {"base": "zero", "patched": "zero"},
    "security": {"base": "zero", "patched": "zero"},
    "suite": {"patched": "zero"},
}
VERDICTS = {
    "S1": ("clean_fix", 0),
    "S2": ("fixed_with_behavior_change", 2),
    "S3": ("not_fixed", 3),
    "S4": ("fixed_with_new_vulnerability", 4),
    "S5": ("not_fixed_and_new_vulnerability", 5),
    "INCONCLUSIVE": ("inconclusive", 10),
}
VERDICT_SUMMARIES = {
    "S1": "All supplied remediation, behavior, regression, security, and suite evidence passed.",
    "S2": "Remediation evidence passed, but behavior, regression, or suite evidence failed.",
    "S3": "At least one original exploit or root-cause variant remains unfixed.",
    "S4": "Remediation evidence passed, but the patch introduced a new security failure.",
    "S5": "The patch remains incomplete and introduced a new security failure.",
    "INCONCLUSIVE": "The evidence was invalid or incomplete; do not interpret this as a pass.",
}
EVIDENCE_LEVEL_SUMMARIES = {
    "source": "source checks only; target behavior was not compiled or executed",
    "build": "target code was built or analyzed, but the reported behavior was not executed",
    "runtime": "the reported behavior and its safety assertions were executed",
}

PLAN_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Post-patch validation plan",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "case_id",
        "evidence_level",
        "finding",
        "repository",
        "base_ref",
        "expected_base_commit",
        "expected_patch_sha256",
        "changed_files",
        "submodules",
        "checks",
    ],
    "properties": {
        "schema_version": {"const": SCHEMA_VERSION},
        "case_id": {"type": "string", "pattern": ID_RE.pattern},
        "evidence_level": {"enum": list(EVIDENCE_LEVELS)},
        "finding": {
            "type": "object",
            "additionalProperties": False,
            "required": ["id", "summary"],
            "properties": {"id": {"type": "string"}, "summary": {"type": "string"}},
        },
        "repository": {"type": "string"},
        "base_ref": {"type": "string"},
        "expected_base_commit": {"type": "string", "pattern": HEX_RE.pattern},
        "patched_ref": {"type": "string"},
        "expected_patched_commit": {"type": "string", "pattern": HEX_RE.pattern},
        "patch_file": {"type": "string"},
        "expected_patch_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "changed_files": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "submodules": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
        },
        "checks": {
            "type": "array",
            "minItems": len(KINDS),
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "kind", "rationale", "covers", "argv"],
                "properties": {
                    "id": {"type": "string", "pattern": ID_RE.pattern},
                    "kind": {"enum": list(KINDS)},
                    "rationale": {"type": "string", "minLength": 1},
                    "covers": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                        "minItems": 1,
                    },
                    "argv": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 1,
                    },
                    "cwd": {"type": "string", "default": "."},
                    "env": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                    },
                    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 3600},
                    "compare_stream": {"enum": ["stdout", "stderr", "combined"]},
                },
            },
        },
    },
    "oneOf": [
        {"required": ["patched_ref", "expected_patched_commit"]},
        {"required": ["patch_file"]},
    ],
}


class PlanError(RuntimeError):
    """A fail-closed plan or execution error."""


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_bytes(canonical_json(value))


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PlanError(f"cannot read JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PlanError("plan root must be a JSON object")
    return value


def stable_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key in BASE_ENV_KEYS}
    if extra:
        env.update(extra)
    env.update(FIXED_ENV)
    return env


def run_git(repo: Path, *args: str) -> bytes:
    command = [*GIT_PREFIX, *args]
    try:
        result = subprocess.run(
            command,
            cwd=repo,
            env=stable_env(),
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise PlanError(f"failed to run git in {repo}: {exc}") from exc
    if result.returncode != 0:
        message = result.stderr.decode(errors="replace").strip()
        raise PlanError(f"git command failed ({' '.join(command[:4])} ...): {message}")
    return result.stdout


def resolve_path(value: str, relative_to: Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = relative_to / path
    return path.resolve()


def resolve_repo(value: str, relative_to: Path) -> Path:
    candidate = resolve_path(value, relative_to)
    top = run_git(candidate, "rev-parse", "--show-toplevel").decode().strip()
    repo = Path(top).resolve()
    if repo != candidate:
        raise PlanError(
            f"repository must name its Git root exactly: expected {repo}, got {candidate}"
        )
    return repo


def resolve_commit(repo: Path, ref: str) -> str:
    if not ref.strip() or ref.startswith("-"):
        raise PlanError(f"unsafe or empty Git ref: {ref!r}")
    output = run_git(repo, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")
    return output.decode().strip()


def ref_patch(repo: Path, base_commit: str, patched_commit: str) -> tuple[bytes, list[str]]:
    diff = run_git(repo, "diff", "--binary", "--full-index", base_commit, patched_commit, "--")
    names = run_git(repo, "diff", "--name-only", "-z", base_commit, patched_commit, "--")
    changed = sorted(x.decode(errors="surrogateescape") for x in names.split(b"\0") if x)
    return diff, changed


def file_patch(repo: Path, patch_file: Path) -> tuple[bytes, list[str]]:
    if not patch_file.is_file():
        raise PlanError(f"patch file does not exist: {patch_file}")
    patch = patch_file.read_bytes()
    output = run_git(repo, "apply", "--numstat", "-z", "--", str(patch_file))
    changed = []
    for record in output.split(b"\0"):
        if not record:
            continue
        fields = record.split(b"\t", 2)
        if len(fields) != 3:
            raise PlanError("could not parse changed files from patch")
        changed.append(fields[2].decode(errors="surrogateescape"))
    return patch, sorted(set(changed))


def gitlink_paths(repo: Path, commit: str) -> list[str]:
    """Return every submodule path pinned by a tree without consulting the working tree."""
    output = run_git(repo, "ls-tree", "-r", "-z", commit, "--")
    paths = []
    for record in output.split(b"\0"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        if separator and metadata.split(b" ", 1)[0] == b"160000":
            paths.append(raw_path.decode(errors="surrogateescape"))
    return sorted(paths)


def affected_submodules(changed_files: Sequence[str], submodules: Sequence[str]) -> list[str]:
    return sorted(
        path
        for path in submodules
        if any(changed == path or changed.startswith(f"{path}/") for changed in changed_files)
    )


def relative_string(path: Path, anchor: Path) -> str:
    try:
        return os.path.relpath(path, anchor)
    except ValueError:
        return str(path)


def scaffold_plan(args: argparse.Namespace) -> None:
    output = Path(args.output).expanduser().resolve()
    if output.exists():
        raise PlanError(f"refusing to overwrite existing plan: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    repo = resolve_repo(args.repo, Path.cwd())
    base_commit = resolve_commit(repo, args.base_ref)
    plan: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "case_id": args.case_id or normalize_case_id(args.finding_id),
        "evidence_level": args.evidence_level,
        "finding": {"id": args.finding_id, "summary": args.finding_summary},
        "repository": relative_string(repo, output.parent),
        "base_ref": args.base_ref,
        "expected_base_commit": base_commit,
        "checks": [],
    }
    if args.patched_ref:
        patched_commit = resolve_commit(repo, args.patched_ref)
        patch, changed = ref_patch(repo, base_commit, patched_commit)
        plan.update(
            {
                "patched_ref": args.patched_ref,
                "expected_patched_commit": patched_commit,
            }
        )
    else:
        patch_path = resolve_path(args.patch_file, Path.cwd())
        patch, changed = file_patch(repo, patch_path)
        plan["patch_file"] = relative_string(patch_path, output.parent)
    if not patch or not changed:
        raise PlanError("patch is empty; there is nothing to validate")
    plan["expected_patch_sha256"] = sha256_bytes(patch)
    plan["changed_files"] = changed
    available_submodules = set(gitlink_paths(repo, base_commit))
    if plan.get("expected_patched_commit"):
        available_submodules.update(gitlink_paths(repo, plan["expected_patched_commit"]))
    plan["submodules"] = affected_submodules(changed, sorted(available_submodules))
    write_json(output, plan)
    print(
        json.dumps(
            {
                "plan": str(output),
                "base_commit": base_commit,
                "patched_commit": plan.get("expected_patched_commit"),
                "patch_sha256": plan["expected_patch_sha256"],
                "changed_files": changed,
                "evidence_level": plan["evidence_level"],
                "submodules": plan["submodules"],
                "next": "populate checks, confirm evidence_level, then run validate-plan",
            },
            indent=2,
            sort_keys=True,
        )
    )


def normalize_case_id(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip()).strip("-._")
    if not normalized:
        normalized = "patch-validation"
    return normalized[:64]


def require_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PlanError(f"{path} must be a non-empty string")
    return value


def require_safe_cwd(value: Any, path: str) -> str:
    cwd = require_string(value, path)
    pure = PurePosixPath(cwd)
    if pure.is_absolute() or ".." in pure.parts:
        raise PlanError(f"{path} must stay inside the checkout")
    return cwd


def require_safe_relative_path(value: Any, path: str) -> str:
    relative = require_string(value, path)
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or pure.as_posix() != relative or relative == ".":
        raise PlanError(f"{path} must be a normalized relative POSIX path without ..")
    return relative


def reject_shell_string(argv: Sequence[str], path: str) -> None:
    """Reject argv that hands a command *string* to a shell.

    Inspect every argv position conservatively so an arbitrary launcher cannot hide ``sh -c``.
    This may reject a literal shell name used as data; authors can move ambiguous invocations into
    a script file. It is a determinism and argument-fidelity rule, not a sandbox, and an
    interpreter's own ``-c`` stays allowed.
    """
    for index, argument in enumerate(argv):
        name = Path(argument).name.lower()
        if name == "env":
            for candidate in argv[index + 1 :]:
                lowered = candidate.lower()
                if lowered in ENV_SPLIT_FLAGS or lowered.startswith("--split-string="):
                    raise PlanError(f"{path} may not use env --split-string; use a script file")
        if name not in SHELL_NAMES:
            continue
        for candidate in argv[index + 1 :]:
            flag = candidate.lower()
            if flag in SHELL_COMMAND_FLAGS or SHELL_COMMAND_FLAG_RE.fullmatch(flag):
                raise PlanError(f"{path} may not invoke a shell command string; use a script file")


def validate_check(raw: Any, index: int) -> dict[str, Any]:
    path = f"checks[{index}]"
    if not isinstance(raw, dict):
        raise PlanError(f"{path} must be an object")
    allowed = {
        "id",
        "kind",
        "rationale",
        "covers",
        "argv",
        "cwd",
        "env",
        "timeout_seconds",
        "compare_stream",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise PlanError(f"{path} has unknown keys: {', '.join(unknown)}")
    check_id = require_string(raw.get("id"), f"{path}.id")
    if not ID_RE.fullmatch(check_id):
        raise PlanError(f"{path}.id must match {ID_RE.pattern}")
    kind = require_string(raw.get("kind"), f"{path}.kind")
    if kind not in KINDS:
        raise PlanError(f"{path}.kind must be one of {', '.join(KINDS)}")
    rationale = require_string(raw.get("rationale"), f"{path}.rationale")
    covers = raw.get("covers")
    if not isinstance(covers, list) or not covers:
        raise PlanError(f"{path}.covers must be a non-empty string array")
    normalized_covers = [require_string(item, f"{path}.covers") for item in covers]
    argv = raw.get("argv")
    if not isinstance(argv, list) or not argv:
        raise PlanError(f"{path}.argv must be a non-empty argv array; shell strings are forbidden")
    normalized_argv = [require_string(item, f"{path}.argv") for item in argv]
    reject_shell_string(normalized_argv, f"{path}.argv")
    cwd = require_safe_cwd(raw.get("cwd", "."), f"{path}.cwd")
    timeout = raw.get("timeout_seconds", 300)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 3600:
        raise PlanError(f"{path}.timeout_seconds must be an integer from 1 to 3600")
    env = raw.get("env", {})
    if not isinstance(env, dict):
        raise PlanError(f"{path}.env must be a string map")
    normalized_env: dict[str, str] = {}
    for key, value in env.items():
        if not isinstance(key, str) or not ENV_RE.fullmatch(key):
            raise PlanError(f"{path}.env has invalid variable name: {key!r}")
        if not isinstance(value, str):
            raise PlanError(f"{path}.env.{key} must be a string")
        normalized_env[key] = value
    if kind in MARKER_KINDS:
        for value in [*normalized_argv, *(str(item) for item in env.values())]:
            if "{side}" in value or "PPV_SIDE" in value:
                raise PlanError(
                    f"{path} is a {kind} check and may not reference the revision it runs on; "
                    "it must assert the same postcondition on base and patch"
                )
    compare = raw.get("compare_stream")
    if kind == "behavior" and compare not in {"stdout", "stderr", "combined"}:
        raise PlanError(f"{path}.compare_stream is required for behavior checks")
    if kind != "behavior" and compare is not None:
        raise PlanError(f"{path}.compare_stream is only valid for behavior checks")
    result = {
        "id": check_id,
        "kind": kind,
        "rationale": rationale,
        "covers": normalized_covers,
        "argv": normalized_argv,
        "cwd": cwd,
        "env": normalized_env,
        "timeout_seconds": timeout,
    }
    if compare:
        result["compare_stream"] = compare
    return result


def validate_plan(plan: dict[str, Any], *, require_complete: bool = True) -> dict[str, Any]:
    allowed = {
        "schema_version",
        "case_id",
        "evidence_level",
        "finding",
        "repository",
        "base_ref",
        "expected_base_commit",
        "patched_ref",
        "expected_patched_commit",
        "patch_file",
        "expected_patch_sha256",
        "changed_files",
        "submodules",
        "checks",
    }
    unknown = sorted(set(plan) - allowed)
    if unknown:
        raise PlanError(f"plan has unknown keys: {', '.join(unknown)}")
    if plan.get("schema_version") != SCHEMA_VERSION:
        raise PlanError(f"schema_version must be {SCHEMA_VERSION!r}")
    case_id = require_string(plan.get("case_id"), "case_id")
    if not ID_RE.fullmatch(case_id):
        raise PlanError(f"case_id must match {ID_RE.pattern}")
    evidence_level = require_string(plan.get("evidence_level"), "evidence_level")
    if evidence_level not in EVIDENCE_LEVELS:
        raise PlanError(f"evidence_level must be one of {', '.join(EVIDENCE_LEVELS)}")
    finding = plan.get("finding")
    if not isinstance(finding, dict) or set(finding) != {"id", "summary"}:
        raise PlanError("finding must contain exactly id and summary")
    finding_id = require_string(finding.get("id"), "finding.id")
    finding_summary = require_string(finding.get("summary"), "finding.summary")
    repository = require_string(plan.get("repository"), "repository")
    base_ref = require_string(plan.get("base_ref"), "base_ref")
    base_commit = require_string(plan.get("expected_base_commit"), "expected_base_commit")
    if not HEX_RE.fullmatch(base_commit):
        raise PlanError("expected_base_commit must be a lowercase commit hash")
    has_ref = "patched_ref" in plan or "expected_patched_commit" in plan
    has_file = "patch_file" in plan
    if has_ref == has_file:
        raise PlanError(
            "provide exactly one patched_ref/expected_patched_commit pair or patch_file"
        )
    normalized: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "evidence_level": evidence_level,
        "finding": {"id": finding_id, "summary": finding_summary},
        "repository": repository,
        "base_ref": base_ref,
        "expected_base_commit": base_commit,
    }
    if has_ref:
        patched_ref = require_string(plan.get("patched_ref"), "patched_ref")
        patched_commit = require_string(
            plan.get("expected_patched_commit"), "expected_patched_commit"
        )
        if not HEX_RE.fullmatch(patched_commit):
            raise PlanError("expected_patched_commit must be a lowercase commit hash")
        normalized.update({"patched_ref": patched_ref, "expected_patched_commit": patched_commit})
    else:
        normalized["patch_file"] = require_string(plan.get("patch_file"), "patch_file")
    patch_hash = require_string(plan.get("expected_patch_sha256"), "expected_patch_sha256")
    if not re.fullmatch(r"[0-9a-f]{64}", patch_hash):
        raise PlanError("expected_patch_sha256 must be a lowercase SHA-256 digest")
    changed = plan.get("changed_files")
    if not isinstance(changed, list) or not changed:
        raise PlanError("changed_files must be a non-empty sorted string array")
    normalized_changed = [require_string(item, "changed_files") for item in changed]
    if normalized_changed != sorted(set(normalized_changed)):
        raise PlanError("changed_files must be unique and lexically sorted")
    raw_submodules = plan.get("submodules")
    if not isinstance(raw_submodules, list):
        raise PlanError("submodules must be a sorted string array; use [] when none are needed")
    submodules = [
        require_safe_relative_path(item, f"submodules[{index}]")
        for index, item in enumerate(raw_submodules)
    ]
    if submodules != sorted(set(submodules)):
        raise PlanError("submodules must be unique and lexically sorted")
    raw_checks = plan.get("checks")
    if not isinstance(raw_checks, list):
        raise PlanError("checks must be an array")
    checks = [validate_check(check, index) for index, check in enumerate(raw_checks)]
    ids = [check["id"] for check in checks]
    if len(ids) != len(set(ids)):
        raise PlanError("check ids must be unique")
    if ids != sorted(ids):
        raise PlanError("checks must be lexically sorted by id")
    if require_complete:
        present = {check["kind"] for check in checks}
        missing = [kind for kind in KINDS if kind not in present]
        if missing:
            raise PlanError(f"incomplete evidence plan; missing check kinds: {', '.join(missing)}")
    normalized.update(
        {
            "expected_patch_sha256": patch_hash,
            "changed_files": normalized_changed,
            "submodules": submodules,
            "checks": checks,
        }
    )
    return normalized


def verify_pins(plan: dict[str, Any], plan_path: Path) -> tuple[Path, str, str | None, bytes]:
    repo = resolve_repo(plan["repository"], plan_path.parent)
    base_commit = resolve_commit(repo, plan["base_ref"])
    if base_commit != plan["expected_base_commit"]:
        raise PlanError(
            f"base ref moved: expected {plan['expected_base_commit']}, resolved {base_commit}"
        )
    if "patched_ref" in plan:
        patched_commit = resolve_commit(repo, plan["patched_ref"])
        if patched_commit != plan["expected_patched_commit"]:
            raise PlanError(
                "patched ref moved: expected "
                f"{plan['expected_patched_commit']}, resolved {patched_commit}"
            )
        patch, changed = ref_patch(repo, base_commit, patched_commit)
    else:
        patched_commit = None
        patch_file = resolve_path(plan["patch_file"], plan_path.parent)
        patch, changed = file_patch(repo, patch_file)
    patch_hash = sha256_bytes(patch)
    if patch_hash != plan["expected_patch_sha256"]:
        raise PlanError(
            f"patch content changed: expected {plan['expected_patch_sha256']}, got {patch_hash}"
        )
    if changed != plan["changed_files"]:
        raise PlanError(
            f"changed-file inventory moved: expected {plan['changed_files']}, got {changed}"
        )
    available_submodules = set(gitlink_paths(repo, base_commit))
    if patched_commit:
        available_submodules.update(gitlink_paths(repo, patched_commit))
    unknown_submodules = sorted(set(plan["submodules"]) - available_submodules)
    if unknown_submodules:
        raise PlanError(
            "plan names paths that are not pinned submodules: " + ", ".join(unknown_submodules)
        )
    required_submodules = affected_submodules(changed, sorted(available_submodules))
    missing_submodules = sorted(set(required_submodules) - set(plan["submodules"]))
    if missing_submodules:
        raise PlanError(
            "changed files cross undeclared submodules: " + ", ".join(missing_submodules)
        )
    return repo, base_commit, patched_commit, patch


@dataclass(frozen=True)
class PlanArtifact:
    relative_path: str
    mode: int
    data: bytes | None


@dataclass(frozen=True)
class ExecContext:
    """Per-run paths and inputs shared by every check execution."""

    evidence: Path
    scratch_root: Path
    plan_artifacts: tuple[PlanArtifact, ...]
    case_id: str
    forwarded_env: Mapping[str, str]


def expand(
    value: str,
    *,
    checkout: Path,
    scratch: Path,
    plan_dir: Path,
    side: str | None,
) -> str:
    expanded = (
        value.replace("{checkout}", str(checkout))
        .replace("{scratch}", str(scratch))
        .replace("{plan_dir}", str(plan_dir))
    )
    return expanded if side is None else expanded.replace("{side}", side)


def resolve_forwarded_env(names: Sequence[str]) -> dict[str, str]:
    """Resolve --allow-env passthrough names, failing closed on anything unusable.

    A missing variable is an error rather than an empty string: silently forwarding "" is how
    a suite ends up testing a different toolchain than the author believed it did.
    """
    forwarded: dict[str, str] = {}
    for name in names:
        if not ENV_RE.fullmatch(name):
            raise PlanError(f"--allow-env name is not a valid variable name: {name!r}")
        upper = name.upper()
        if upper in FIXED_ENV or upper.startswith("PPV_"):
            raise PlanError(
                f"--allow-env refuses {name}: the runner reserves or fixes that variable"
            )
        if upper in FORBIDDEN_ENV:
            raise PlanError(
                f"--allow-env refuses {name}: it changes which code runs, which would defeat "
                "the isolation this validator depends on"
            )
        if CREDENTIAL_ENV_RE.search(upper):
            raise PlanError(
                f"--allow-env refuses {name}: forwarded values are recorded verbatim in "
                "result.json, so it reads as a credential"
            )
        if name in forwarded:
            continue
        if name not in os.environ:
            raise PlanError(f"--allow-env requested {name}, which is not set in this environment")
        forwarded[name] = os.environ[name]
    return forwarded


def expected_matches(expected: str, exit_code: int | None) -> bool:
    if exit_code is None:
        return False
    if expected == "zero":
        return exit_code == 0
    if expected == "nonzero":
        return exit_code != 0
    raise AssertionError(f"unknown expectation: {expected}")


def terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "posix":
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    else:
        process.kill()
    process.wait()


def marker_present(stdout_path: Path) -> bool:
    """Look for the marker as a line of its own, on stdout only.

    Both restrictions matter. Scanning stderr matched the marker inside a Python SyntaxError
    traceback, which echoes the offending source — so a harness that never executed a single
    statement satisfied the check it exists to fail. Requiring a whole line rejects the same
    token quoted inside an error message, a usage string, or an echoed argv.
    """
    token = REACHED_MARKER.encode()
    return any(line.strip() == token for line in stdout_path.read_bytes().splitlines())


def resolve_executable(argv0: str, cwd: Path, env: Mapping[str, str]) -> Path | None:
    """Resolve argv[0] the same way the child process does, for provenance hashing."""
    candidate = Path(argv0)
    separators = tuple(separator for separator in (os.sep, os.altsep) if separator)
    if candidate.is_absolute():
        return candidate
    if any(separator in argv0 for separator in separators):
        return (cwd / candidate).resolve()
    found = shutil.which(argv0, path=env.get("PATH"))
    if not found:
        return None
    found_path = Path(found)
    return found_path.resolve() if found_path.is_absolute() else (cwd / found_path).resolve()


def copy_plan_directory(
    source: Path,
    destination: Path,
    excluded_paths: Sequence[Path] = (),
) -> None:
    """Copy plan artifacts without symlinks, plan pins, or prior evidence trees."""
    excluded = {path.resolve() for path in excluded_paths}

    def ignore(directory: str, names: list[str]) -> list[str]:
        ignored: list[str] = []
        for name in names:
            child = Path(directory) / name
            try:
                if child.is_symlink():
                    raise PlanError(f"plan artifacts may not contain symlinks: {child}")
                if child.resolve() in excluded:
                    ignored.append(name)
                    continue
                if (
                    child.is_dir()
                    and (child / "result.json").is_file()
                    and (child / "artifact-manifest.json").is_file()
                ):
                    ignored.append(name)
            except OSError:
                # Let copytree report the inaccessible entry with its useful source path.
                continue
        return ignored

    try:
        shutil.copytree(source, destination, ignore=ignore)
    except (OSError, RecursionError) as exc:
        raise PlanError(
            f"could not make an isolated copy of plan artifacts: {type(exc).__name__}: {exc}"
        ) from exc


def snapshot_plan_directory(source: Path) -> tuple[PlanArtifact, ...]:
    """Load a bounded, immutable plan-artifact snapshot into runner memory."""
    artifacts: list[PlanArtifact] = []
    total = 0
    try:
        for path in sorted(source.rglob("*")):
            relative = path.relative_to(source).as_posix()
            mode = stat.S_IMODE(path.stat().st_mode)
            if path.is_dir():
                artifacts.append(PlanArtifact(relative, mode, None))
                continue
            data = path.read_bytes()
            total += len(data)
            if total > MAX_PLAN_ARTIFACT_BYTES:
                raise PlanError(
                    f"plan artifacts exceed the {MAX_PLAN_ARTIFACT_BYTES}-byte snapshot limit"
                )
            artifacts.append(PlanArtifact(relative, mode, data))
    except OSError as exc:
        raise PlanError(
            f"could not snapshot isolated plan artifacts: {type(exc).__name__}: {exc}"
        ) from exc
    return tuple(artifacts)


def materialize_plan_directory(
    artifacts: Sequence[PlanArtifact],
    destination: Path,
) -> None:
    """Materialize one private plan copy from immutable in-memory bytes."""
    try:
        destination.mkdir()
        directories: list[tuple[Path, int]] = []
        for artifact in artifacts:
            path = destination / artifact.relative_path
            if artifact.data is None:
                path.mkdir(parents=True, exist_ok=True)
                directories.append((path, artifact.mode))
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(artifact.data)
                path.chmod(artifact.mode)
        for path, mode in reversed(directories):
            path.chmod(mode)
    except OSError as exc:
        raise PlanError(
            f"could not materialize isolated plan artifacts: {type(exc).__name__}: {exc}"
        ) from exc


def resolve_argv_file(
    argument: str,
    index: int,
    cwd: Path,
    env: Mapping[str, str],
) -> Path | None:
    """Resolve an argv element that names a file as seen from the check's actual cwd."""
    if index == 0:
        return resolve_executable(argument, cwd, env)
    candidate = Path(argument)
    resolved = candidate.resolve() if candidate.is_absolute() else (cwd / candidate).resolve()
    return resolved if resolved.is_file() else None


def archive_argv_files(
    argv: Sequence[str],
    original_argv: Sequence[str],
    cwd: Path,
    env: Mapping[str, str],
    evidence: Path,
    archive_roots: Sequence[Path],
) -> list[dict[str, Any]]:
    """Hash file-valued arguments and archive bounded files from controlled roots."""
    records: list[dict[str, Any]] = []
    helpers = evidence / "helpers"
    roots = tuple(root.resolve() for root in archive_roots)
    for index, argument in enumerate(argv):
        try:
            resolved = resolve_argv_file(argument, index, cwd, env)
        except OSError as exc:
            records.append(
                {
                    "index": index,
                    "argument": original_argv[index],
                    "sha256": None,
                    "artifact": None,
                    "archive_reason": f"resolve failed: {type(exc).__name__}: {exc}",
                }
            )
            continue
        if resolved is None or not resolved.is_file():
            continue
        record: dict[str, Any] = {
            "index": index,
            "argument": original_argv[index],
            "sha256": None,
            "artifact": None,
            "archive_reason": None,
        }
        try:
            digest = sha256_file(resolved)
        except OSError as exc:
            record["archive_reason"] = f"hash failed: {type(exc).__name__}: {exc}"
            records.append(record)
            continue
        record["sha256"] = digest
        controlled = any(resolved.is_relative_to(root) for root in roots)
        if not controlled:
            record["archive_reason"] = "outside the isolated plan and checkout roots"
            records.append(record)
            continue
        try:
            size = resolved.stat().st_size
            if size > MAX_ARCHIVED_ARGV_FILE_BYTES:
                record["archive_reason"] = (
                    f"file exceeds {MAX_ARCHIVED_ARGV_FILE_BYTES}-byte archive limit"
                )
                records.append(record)
                continue
            helpers.mkdir(exist_ok=True)
            artifact = helpers / digest
            if not artifact.exists():
                shutil.copyfile(resolved, artifact)
            record["artifact"] = artifact.relative_to(evidence).as_posix()
        except OSError as exc:
            record["archive_reason"] = f"archive failed: {type(exc).__name__}: {exc}"
        records.append(record)
    return records


def execute_check(
    check: dict[str, Any],
    side: str,
    checkout: Path,
    context: ExecContext,
    sequence: int,
) -> dict[str, Any]:
    cwd = (checkout / check["cwd"]).resolve()
    try:
        cwd.relative_to(checkout.resolve())
    except ValueError as exc:
        raise PlanError(f"check {check['id']} cwd escaped its checkout") from exc
    if not cwd.is_dir():
        raise PlanError(f"check {check['id']} cwd does not exist on {side}: {check['cwd']}")
    stem = f"{sequence:03d}-{check['id']}-{side}"
    # Checks receive an opaque, per-invocation directory outside the retained evidence tree.
    # It is archived only after the process exits, so base and patched runs cannot communicate
    # through scratch state or infer ordering from retained sibling directory names.
    runtime_scratch = Path(tempfile.mkdtemp(prefix="ppv-check-"))
    archived_scratch = context.scratch_root / stem
    # The plan directory contains helper scripts and is writable by the check. Give every
    # invocation a private copy so PPV_PLAN_DIR cannot become a base/patched sentinel channel.
    runtime_plan_root = Path(tempfile.mkdtemp(prefix="ppv-plan-"))
    runtime_plan_dir = runtime_plan_root / "plan"
    try:
        materialize_plan_directory(context.plan_artifacts, runtime_plan_dir)
        # Exploit and variant checks are run side-blind: they get no {side}, no PPV_SIDE, and an
        # opaque checkout path. A check that can tell which revision it is on can assert on that
        # instead of on the code, which is the cheapest way to fake a reproduction-then-fix.
        needs_marker = check["kind"] in MARKER_KINDS
        visible_side = None if needs_marker else side
        argv = [
            expand(
                arg,
                checkout=checkout,
                scratch=runtime_scratch,
                plan_dir=runtime_plan_dir,
                side=visible_side,
            )
            for arg in check["argv"]
        ]
        check_env = dict(context.forwarded_env)
        check_env.update(
            {
                key: expand(
                    value,
                    checkout=checkout,
                    scratch=runtime_scratch,
                    plan_dir=runtime_plan_dir,
                    side=visible_side,
                )
                for key, value in check["env"].items()
            }
        )
        check_env.update(
            {
                "PPV_CHECKOUT": str(checkout),
                "PPV_SCRATCH": str(runtime_scratch),
                "PPV_PLAN_DIR": str(runtime_plan_dir),
                "PPV_CASE_ID": context.case_id,
                "PPV_REACHED_MARKER": REACHED_MARKER,
                "TEMP": str(runtime_scratch),
                "TMP": str(runtime_scratch),
                "TMPDIR": str(runtime_scratch),
            }
        )
        if visible_side is not None:
            check_env["PPV_SIDE"] = visible_side
        stdout_path = context.evidence / f"{stem}.stdout"
        stderr_path = context.evidence / f"{stem}.stderr"
        status = "completed"
        exit_code: int | None = None
        error: str | None = None
        process_env = stable_env(check_env)
        argv_files = archive_argv_files(
            argv,
            check["argv"],
            cwd,
            process_env,
            context.evidence,
            (checkout, runtime_plan_dir),
        )
        argv0_sha256 = next(
            (record["sha256"] for record in argv_files if record["index"] == 0), None
        )
        try:
            # Named evidence paths contain the logical side. Capture through anonymous/random
            # descriptors so a side-blind child cannot recover that label from fd 1 or fd 2.
            with (
                tempfile.TemporaryFile(dir=runtime_scratch) as stdout_buffer,
                tempfile.TemporaryFile(dir=runtime_scratch) as stderr_buffer,
            ):
                try:
                    process = subprocess.Popen(
                        argv,
                        cwd=cwd,
                        env=process_env,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout_buffer,
                        stderr=stderr_buffer,
                        start_new_session=os.name == "posix",
                    )
                    try:
                        exit_code = process.wait(timeout=check["timeout_seconds"])
                    except subprocess.TimeoutExpired:
                        status = "timeout"
                        error = f"exceeded {check['timeout_seconds']} seconds"
                        terminate_process(process)
                        exit_code = process.returncode
                except OSError as exc:
                    status = "execution_error"
                    error = f"{type(exc).__name__}: {exc}"
                stdout_buffer.seek(0)
                stderr_buffer.seek(0)
                with stdout_path.open("wb") as stdout:
                    shutil.copyfileobj(stdout_buffer, stdout)
                with stderr_path.open("wb") as stderr:
                    shutil.copyfileobj(stderr_buffer, stderr)
        except OSError as exc:
            raise PlanError(
                f"could not capture check {check['id']} output: {type(exc).__name__}: {exc}"
            ) from exc
        try:
            if runtime_scratch.exists():
                shutil.move(str(runtime_scratch), archived_scratch)
            else:
                archived_scratch.mkdir()
        except OSError as exc:
            status = "execution_error"
            error = f"scratch archival failed: {type(exc).__name__}: {exc}"
            shutil.rmtree(runtime_scratch, ignore_errors=True)
        expected = EXPECTED_BY_KIND[check["kind"]][side]
        return {
            "side": side,
            "argv": check["argv"],
            "argv0_sha256": argv0_sha256,
            "argv_files": argv_files,
            "cwd": check["cwd"],
            "scratch": archived_scratch.relative_to(context.evidence).as_posix(),
            "status": status,
            "exit_code": exit_code,
            "expected": expected,
            "matched": status == "completed" and expected_matches(expected, exit_code),
            "marker": marker_present(stdout_path) if needs_marker else None,
            "stdout": stdout_path.name,
            "stdout_sha256": sha256_file(stdout_path),
            "stderr": stderr_path.name,
            "stderr_sha256": sha256_file(stderr_path),
            "error": error,
        }
    finally:
        shutil.rmtree(runtime_scratch, ignore_errors=True)
        shutil.rmtree(runtime_plan_root, ignore_errors=True)


def behavior_comparison(
    check: dict[str, Any], runs: dict[str, dict[str, Any]], artifacts: Path
) -> dict[str, Any]:
    stream = check["compare_stream"]

    def content(side: str) -> bytes:
        run = runs[side]
        if stream == "stdout":
            return (artifacts / run["stdout"]).read_bytes()
        if stream == "stderr":
            return (artifacts / run["stderr"]).read_bytes()
        return (artifacts / run["stdout"]).read_bytes() + (artifacts / run["stderr"]).read_bytes()

    base = content("base")
    patched = content("patched")
    return {
        "stream": stream,
        "matched": base == patched,
        "base_sha256": sha256_bytes(base),
        "patched_sha256": sha256_bytes(patched),
    }


def classify(
    checks: Sequence[dict[str, Any]], cleanup_errors: Sequence[str] = ()
) -> dict[str, Any]:
    infrastructure = []
    baseline = []
    not_fixed = []
    behavior = []
    new_security = []
    if cleanup_errors:
        infrastructure.extend(f"cleanup: {item}" for item in cleanup_errors)
    for check in checks:
        runs = check["runs"]
        for side, run in runs.items():
            if run["status"] != "completed":
                infrastructure.append(f"{check['id']}:{side}:{run['status']}")
            # A nonzero exit alone cannot distinguish a failed safety assertion from a harness
            # that never ran. Without the marker the observation is unusable in either direction.
            elif check["kind"] in MARKER_KINDS and run.get("marker") is not True:
                infrastructure.append(f"{check['id']}:{side}:marker_missing")
        base = runs.get("base")
        patched = runs.get("patched")
        if base is not None and not base["matched"]:
            baseline.append(check["id"])
            continue
        # A control failure on the patched side means the benign harness itself stopped working
        # there, so every other patched observation is suspect. That is a validity problem, not
        # a behavior regression, and must not be reported as "fixed with behavior change".
        if check["kind"] == "control" and patched and not patched["matched"]:
            infrastructure.append(f"{check['id']}:patched:control_failed")
        elif check["kind"] in {"exploit", "variant"} and patched and not patched["matched"]:
            not_fixed.append(check["id"])
        elif check["kind"] == "security" and patched and not patched["matched"]:
            new_security.append(check["id"])
        elif (
            check["kind"] in {"behavior", "regression", "suite"}
            and patched
            and not patched["matched"]
        ):
            behavior.append(check["id"])
        if check["kind"] == "behavior" and not check.get("comparison", {}).get("matched", False):
            behavior.append(f"{check['id']}:output")
    if infrastructure or baseline:
        code = "INCONCLUSIVE"
        reasons = [
            *(
                ["execution or cleanup did not complete: " + ", ".join(infrastructure)]
                if infrastructure
                else []
            ),
            *(["baseline evidence did not match: " + ", ".join(baseline)] if baseline else []),
        ]
    elif not_fixed and new_security:
        code = "S5"
        reasons = [
            "unfixed exploit or variant: " + ", ".join(not_fixed),
            "new security failure: " + ", ".join(new_security),
        ]
    elif not_fixed:
        code = "S3"
        reasons = ["unfixed exploit or variant: " + ", ".join(not_fixed)]
    elif new_security:
        code = "S4"
        reasons = ["new security failure: " + ", ".join(new_security)]
    elif behavior:
        code = "S2"
        reasons = ["behavior or regression failure: " + ", ".join(sorted(set(behavior)))]
    else:
        code = "S1"
        reasons = [
            "all required baseline, fix, behavior, regression, security, and suite evidence passed"
        ]
    label, exit_code = VERDICTS[code]
    return {
        "code": code,
        "label": label,
        "exit_code": exit_code,
        "human_review_required": True,
        "reasons": reasons,
    }


@contextmanager
def worktree_metadata_lock(repo: Path):
    """Serialize shared worktree metadata without serializing check execution."""
    common_dir = git_common_dir(repo)
    lock_path = common_dir / "post-patch-validation.lock"
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = lock_path.open("a+b")
    except OSError as exc:
        raise PlanError(f"could not open worktree metadata lock {lock_path}: {exc}") from exc
    with handle:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            handle.write(b"\0")
            handle.flush()
            handle.seek(0)
            while True:
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.05)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            except OSError as exc:
                raise PlanError(
                    f"could not acquire worktree metadata lock {lock_path}: {exc}"
                ) from exc
            try:
                yield
            finally:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except OSError as exc:
                    raise PlanError(
                        f"could not release worktree metadata lock {lock_path}: {exc}"
                    ) from exc


def git_common_dir(repo: Path) -> Path:
    raw_common_dir = Path(run_git(repo, "rev-parse", "--git-common-dir").decode().strip())
    common_dir = raw_common_dir if raw_common_dir.is_absolute() else (repo / raw_common_dir)
    return common_dir.resolve()


@dataclass
class WorktreeOwner:
    token: str
    path: Path
    handle: Any


def acquire_worktree_owner(repo: Path) -> WorktreeOwner:
    """Hold a kernel-backed lease that cannot be confused by PID reuse."""
    owner_dir = git_common_dir(repo) / "post-patch-validation-owners"
    token = os.urandom(16).hex()
    path = owner_dir / token
    handle = None
    try:
        owner_dir.mkdir(parents=True, exist_ok=True)
        handle = path.open("x+b")
        handle.write(b"\0")
        handle.flush()
    except OSError as exc:
        if handle is not None:
            handle.close()
        with suppress(OSError):
            path.unlink()
        raise PlanError(f"could not create worktree owner lease {path}: {exc}") from exc
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    except OSError as exc:
        handle.close()
        with suppress(OSError):
            path.unlink()
        raise PlanError(f"could not acquire worktree owner lease {path}: {exc}") from exc
    return WorktreeOwner(token=token, path=path, handle=handle)


def close_worktree_owner(owner: WorktreeOwner) -> None:
    with suppress(OSError):
        if os.name == "nt":
            import msvcrt

            owner.handle.seek(0)
            msvcrt.locking(owner.handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(owner.handle.fileno(), fcntl.LOCK_UN)
    owner.handle.close()
    with suppress(OSError):
        owner.path.unlink()
    with suppress(OSError):
        owner.path.parent.rmdir()


def worktree_owner_is_active(repo: Path, token: str) -> bool:
    """Test a PPV owner lease without trusting a reusable process identifier."""
    if not re.fullmatch(r"[0-9a-f]{32}", token):
        return True
    path = git_common_dir(repo) / "post-patch-validation-owners" / token
    try:
        handle = path.open("r+b")
    except FileNotFoundError:
        return False
    except OSError:
        return True
    acquired = False
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                acquired = True
            except OSError:
                return True
        else:
            import fcntl

            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except BlockingIOError:
                return True
            except OSError:
                return True
    finally:
        if acquired:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                with suppress(OSError):
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                with suppress(OSError):
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()
    with suppress(OSError):
        path.unlink()
    return False


def process_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def stale_validator_worktrees(repo: Path) -> list[str]:
    """Return PPV-locked worktrees whose kernel-backed owner lease is inactive."""
    output = run_git(repo, "worktree", "list", "--porcelain", "-z")
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for raw_field in output.split(b"\0"):
        if not raw_field:
            if current:
                records.append(current)
                current = {}
            continue
        field = raw_field.decode(errors="surrogateescape")
        key, _, value = field.partition(" ")
        if key == "worktree" and current:
            records.append(current)
            current = {}
        current[key] = value
    if current:
        records.append(current)

    stale = []
    for record in records:
        reason = record.get("locked", "")
        if not reason.startswith(WORKTREE_LOCK_REASON_PREFIX):
            continue
        owner = reason.removeprefix(WORKTREE_LOCK_REASON_PREFIX)
        # Accept PID-only reasons from the earlier implementation so an upgrade can reclaim
        # worktrees left by a killed older runner. New locks use non-reusable lease tokens.
        legacy_stale = owner.isdigit() and not process_is_running(int(owner))
        lease_stale = bool(re.fullmatch(r"[0-9a-f]{32}", owner)) and not (
            worktree_owner_is_active(repo, owner)
        )
        if legacy_stale or lease_stale:
            stale.append(record["worktree"])
    return stale


def unlock_stale_validator_worktrees(repo: Path) -> None:
    for path in stale_validator_worktrees(repo):
        run_git(repo, "worktree", "unlock", path)
    run_git(repo, "worktree", "prune")


def add_worktree(repo: Path, path: Path, commit: str, owner_token: str) -> None:
    run_git(repo, "worktree", "add", "--detach", str(path), commit)
    try:
        run_git(
            repo,
            "worktree",
            "lock",
            "--reason",
            f"{WORKTREE_LOCK_REASON_PREFIX}{owner_token}",
            str(path),
        )
    except PlanError:
        with suppress(PlanError):
            run_git(repo, "worktree", "remove", "--force", str(path))
        raise


def initialize_submodules(checkout: Path, submodules: Sequence[str]) -> dict[str, str]:
    if not submodules:
        return {}
    common_dir_value = Path(run_git(checkout, "rev-parse", "--git-common-dir").decode().strip())
    common_dir = (
        common_dir_value if common_dir_value.is_absolute() else checkout / common_dir_value
    ).resolve()
    try:
        configured = run_git(
            checkout,
            "config",
            "-f",
            ".gitmodules",
            "--get-regexp",
            r"^submodule\..*\.path$",
        ).decode()
    except PlanError as exc:
        raise PlanError("could not read submodule paths from .gitmodules") from exc
    names_by_path: dict[str, str] = {}
    for line in configured.splitlines():
        key, separator, path = line.partition(" ")
        if not separator or not key.startswith("submodule.") or not key.endswith(".path"):
            raise PlanError(f"could not parse .gitmodules entry: {line!r}")
        names_by_path[path.strip()] = key[len("submodule.") : -len(".path")]

    modules_dir = (common_dir / "modules").resolve()
    local_urls: list[str] = []
    for path in submodules:
        name = names_by_path.get(path)
        if name is None:
            raise PlanError(f"submodule path is missing from .gitmodules: {path}")
        local_repo = (modules_dir / Path(name)).resolve()
        try:
            local_repo.relative_to(modules_dir)
        except ValueError as exc:
            raise PlanError(f"submodule name escapes the local module store: {name}") from exc
        if not local_repo.is_dir():
            raise PlanError(
                "could not initialize pinned submodules without network access; "
                f"fetch {path} in the source repository first"
            )
        local_urls.extend(("-c", f"submodule.{name}.url={local_repo}"))
    try:
        run_git(
            checkout,
            "-c",
            "protocol.file.allow=always",
            *local_urls,
            "submodule",
            "update",
            "--init",
            "--checkout",
            "--no-fetch",
            "--",
            *submodules,
        )
    except PlanError as exc:
        raise PlanError(
            "could not initialize pinned submodules without network access; "
            "fetch them in the source repository first: " + ", ".join(submodules)
        ) from exc
    return {
        path: run_git(checkout / path, "rev-parse", "HEAD").decode().strip() for path in submodules
    }


def apply_patch_file(
    checkout: Path,
    patch_file: Path,
    changed_files: Sequence[str],
    submodules: Sequence[str],
) -> list[str]:
    """Apply ordinary paths and gitlink bumps with the semantics each requires."""
    gitlink_changes = sorted(set(changed_files) & set(submodules))
    for submodule in gitlink_changes:
        if any(path.startswith(f"{submodule}/") for path in changed_files):
            raise PlanError(
                "a patch file may not combine a submodule gitlink bump with changes inside it: "
                + submodule
            )
    common = ("--binary", "--whitespace=nowarn")
    if gitlink_changes:
        run_git(
            checkout,
            "apply",
            "--index",
            *common,
            *(f"--include={path}" for path in gitlink_changes),
            "--",
            str(patch_file),
        )
    ordinary_changes = sorted(set(changed_files) - set(gitlink_changes))
    if ordinary_changes:
        run_git(
            checkout,
            "apply",
            *common,
            *(f"--exclude={path}" for path in gitlink_changes),
            "--",
            str(patch_file),
        )
    return gitlink_changes


def remove_worktree(repo: Path, path: Path) -> str | None:
    with suppress(PlanError):
        run_git(repo, "worktree", "unlock", str(path))
    try:
        result = subprocess.run(
            [*GIT_PREFIX, "worktree", "remove", "--force", str(path)],
            cwd=repo,
            env=stable_env(),
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        return f"{type(exc).__name__}: {exc}"
    if result.returncode == 0:
        return None
    return result.stderr.decode(errors="replace").strip() or f"exit {result.returncode}"


def markdown_report(result: dict[str, Any]) -> str:
    verdict = result["verdict"]
    lines = [
        "# Post-Patch Validation",
        "",
        f"**Verdict:** {verdict['code']} — {verdict['label'].replace('_', ' ')}",
        "",
        f"**Evidence level:** {result['inputs']['evidence_level']} — "
        + EVIDENCE_LEVEL_SUMMARIES[result["inputs"]["evidence_level"]],
        "",
        "**Human review required:** yes",
        "",
        f"**Finding:** {result['finding']['id']} — {result['finding']['summary']}",
        "",
        f"**Base commit:** `{result['inputs']['base_commit']}`",
        "",
        f"**Patch SHA-256:** `{result['inputs']['patch_sha256']}`",
        "",
        "**Submodules:** " + (", ".join(sorted(result["inputs"]["submodules"])) or "none"),
        "",
        "**Forwarded environment:** "
        + (", ".join(sorted(result["inputs"]["forwarded_env"])) or "none"),
        "",
        "## Reasons",
        "",
    ]
    lines.extend(f"- {reason}" for reason in verdict["reasons"])
    lines.extend(
        [
            "",
            "## Evidence",
            "",
            "| Check | Kind | Base | Patched | Comparison |",
            "|---|---|---|---|---|",
        ]
    )
    for check in result["checks"]:
        base = check["runs"].get("base")
        patched = check["runs"].get("patched")
        base_text = "—" if base is None else ("pass" if base["matched"] else "fail")
        patch_text = "—" if patched is None else ("pass" if patched["matched"] else "fail")
        comparison = check.get("comparison")
        compare_text = (
            "—" if comparison is None else ("same" if comparison["matched"] else "changed")
        )
        lines.append(
            f"| `{check['id']}` | {check['kind']} | {base_text} | {patch_text} | {compare_text} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            VERDICT_SUMMARIES[verdict["code"]],
            "The evidence level limits what this verdict establishes, and human review remains",
            "required to find omitted paths or an incorrectly specified safety assertion.",
            "",
        ]
    )
    return "\n".join(lines)


def artifact_manifest(output: Path) -> dict[str, Any]:
    files = []
    for path in sorted(p for p in output.rglob("*") if p.is_file()):
        if path == output / "artifact-manifest.json":
            continue
        files.append(
            {
                "path": path.relative_to(output).as_posix(),
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
        )
    if not files:
        raise PlanError("artifact manifest would contain zero files")
    return {"schema_version": SCHEMA_VERSION, "files": files}


def run_plan(args: argparse.Namespace) -> int:
    plan_path = Path(args.plan).expanduser().resolve()
    plan = validate_plan(load_json(plan_path))
    repo, base_commit, patched_commit, patch = verify_pins(plan, plan_path)
    output = Path(args.output).expanduser().resolve()
    if output.exists() and any(output.iterdir()):
        raise PlanError(f"refusing to mix evidence with an existing non-empty directory: {output}")
    forwarded_env = resolve_forwarded_env(args.allow_env)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "plan.snapshot.json", plan)
    (output / "patch.diff").write_bytes(patch)
    # Each invocation gets an opaque temporary scratch directory. Its contents are moved under
    # this retained root only after the process exits, preventing cross-side communication while
    # keeping every produced artifact available to reviewers.
    scratch_root = output / "scratch"
    scratch_root.mkdir()
    # Snapshot author-supplied helper artifacts once, before any check runs. Exclude the machine
    # plan (which contains revision pins), the live output, and detected prior result trees.
    plan_template_root = Path(tempfile.mkdtemp(prefix="ppv-plan-template-"))
    plan_template_dir = plan_template_root / "plan"
    try:
        copy_plan_directory(
            plan_path.parent,
            plan_template_dir,
            excluded_paths=(plan_path, output),
        )
        plan_artifacts = snapshot_plan_directory(plan_template_dir)
    finally:
        shutil.rmtree(plan_template_root, ignore_errors=True)
    context = ExecContext(
        evidence=output,
        scratch_root=scratch_root,
        plan_artifacts=plan_artifacts,
        case_id=plan["case_id"],
        forwarded_env=forwarded_env,
    )
    # Unpredictable, side-agnostic directory names. Calling them base/ and patched/ handed every
    # check a reliable oracle for which revision it was running on, via PPV_CHECKOUT or cwd —
    # exactly what side-blinding exploit and variant checks is meant to withhold. A derived name
    # would still be computable from PPV_CASE_ID, so these use generic random, separate roots.
    # Keep two unique parent levels beneath each root: the common writable host temp directory is
    # not exposed by the shallow parent walk that previously reached a shared validator root.
    worktree_roots = [
        Path(tempfile.mkdtemp(prefix="ppv-worktree-")),
        Path(tempfile.mkdtemp(prefix="ppv-worktree-")),
    ]
    if os.urandom(1)[0] & 1:
        worktree_roots.reverse()
    base_root, patched_root = worktree_roots
    temp_roots = worktree_roots
    base_checkout = base_root / "private" / "w"
    patched_checkout = patched_root / "private" / "w"
    worktrees = [
        (base_checkout, base_commit),
        (patched_checkout, patched_commit or base_commit),
    ]
    if os.urandom(1)[0] & 1:
        worktrees.reverse()
    for checkout, _commit in worktrees:
        checkout.parent.mkdir()
    try:
        owner = acquire_worktree_owner(repo)
    except PlanError:
        for temp_root in temp_roots:
            shutil.rmtree(temp_root, ignore_errors=True)
        raise
    created: list[Path] = []
    cleanup_errors: list[str] = []
    evidence: list[dict[str, Any]] = []
    submodule_pins: dict[str, dict[str, str]] = {}
    try:
        with worktree_metadata_lock(repo):
            unlock_stale_validator_worktrees(repo)
            for checkout, commit in worktrees:
                add_worktree(repo, checkout, commit, owner.token)
                created.append(checkout)
            submodules_by_checkout = {
                checkout: initialize_submodules(checkout, plan["submodules"])
                for checkout, _commit in worktrees
            }
            base_submodules = submodules_by_checkout[base_checkout]
            patched_submodules = submodules_by_checkout[patched_checkout]
        if patched_commit is None:
            patch_file = resolve_path(plan["patch_file"], plan_path.parent)
            changed_gitlinks = apply_patch_file(
                patched_checkout,
                patch_file,
                plan["changed_files"],
                plan["submodules"],
            )
            if changed_gitlinks:
                with worktree_metadata_lock(repo):
                    updated = initialize_submodules(patched_checkout, changed_gitlinks)
                patched_submodules.update(updated)
        submodule_pins = {
            path: {
                "base_commit": base_submodules[path],
                "patched_commit": patched_submodules[path],
            }
            for path in plan["submodules"]
        }
        sequence = 0
        for check in plan["checks"]:
            logical_sides = SIDES_BY_KIND[check["kind"]]
            side_sequences = {
                side: sequence + offset for offset, side in enumerate(logical_sides, start=1)
            }
            sequence += len(logical_sides)
            execution_sides = list(logical_sides)
            if check["kind"] in MARKER_KINDS and os.urandom(1)[0] & 1:
                execution_sides.reverse()
            observed: dict[str, dict[str, Any]] = {}
            for side in execution_sides:
                checkout = base_checkout if side == "base" else patched_checkout
                observed[side] = execute_check(
                    check,
                    side,
                    checkout,
                    context,
                    side_sequences[side],
                )
            runs = {side: observed[side] for side in logical_sides}
            item: dict[str, Any] = {
                "id": check["id"],
                "kind": check["kind"],
                "rationale": check["rationale"],
                "covers": check["covers"],
                "runs": runs,
            }
            if check["kind"] == "behavior":
                item["comparison"] = behavior_comparison(check, runs, output)
            evidence.append(item)
    finally:
        primary_error_active = sys.exc_info()[0] is not None
        cleanup_lock_error: PlanError | None = None
        try:
            with worktree_metadata_lock(repo):
                for checkout in reversed(created):
                    error = remove_worktree(repo, checkout)
                    if error:
                        side = "base" if checkout == base_checkout else "patched"
                        cleanup_errors.append(f"{side}: {error}")
                try:
                    run_git(repo, "worktree", "prune")
                except PlanError as exc:
                    cleanup_errors.append(f"prune: {exc}")
        except PlanError as exc:
            cleanup_lock_error = exc
        finally:
            close_worktree_owner(owner)
            for temp_root in temp_roots:
                shutil.rmtree(temp_root, ignore_errors=True)
        if cleanup_lock_error is not None and not primary_error_active:
            raise cleanup_lock_error
    verdict = classify(evidence, cleanup_errors)
    result = {
        "schema_version": SCHEMA_VERSION,
        "case_id": plan["case_id"],
        "finding": plan["finding"],
        "inputs": {
            "base_commit": base_commit,
            "patched_commit": patched_commit,
            "patch_sha256": sha256_bytes(patch),
            "changed_files": plan["changed_files"],
            "evidence_level": plan["evidence_level"],
            "submodules": submodule_pins,
            "plan_sha256": sha256_bytes(canonical_json(plan)),
            "forwarded_env": dict(forwarded_env),
        },
        "coverage": {kind: sum(check["kind"] == kind for check in evidence) for kind in KINDS},
        "checks": evidence,
        "cleanup_errors": cleanup_errors,
        "verdict": verdict,
    }
    write_json(output / "result.json", result)
    (output / "report.md").write_text(markdown_report(result), encoding="utf-8")
    write_json(output / "artifact-manifest.json", artifact_manifest(output))
    print(json.dumps({"result": str(output / "result.json"), "verdict": verdict}, indent=2))
    return int(verdict["exit_code"])


def validate_plan_command(args: argparse.Namespace) -> None:
    path = Path(args.plan).expanduser().resolve()
    plan = validate_plan(load_json(path))
    verify_pins(plan, path)
    print(
        json.dumps(
            {
                "valid": True,
                "case_id": plan["case_id"],
                "evidence_level": plan["evidence_level"],
                "submodules": plan["submodules"],
                "checks": len(plan["checks"]),
                "coverage": {
                    kind: sum(c["kind"] == kind for c in plan["checks"]) for kind in KINDS
                },
            },
            indent=2,
            sort_keys=True,
        )
    )


class PlanArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(64, f"{self.prog}: error: {message}\n")


def parser() -> argparse.ArgumentParser:
    root = PlanArgumentParser(description=__doc__)
    subparsers = root.add_subparsers(dest="command", required=True)
    scaffold = subparsers.add_parser("scaffold", help="pin a patch and write an incomplete plan")
    scaffold.add_argument("--repo", required=True)
    scaffold.add_argument("--base-ref", required=True)
    patch = scaffold.add_mutually_exclusive_group(required=True)
    patch.add_argument("--patched-ref")
    patch.add_argument("--patch-file")
    scaffold.add_argument("--finding-id", required=True)
    scaffold.add_argument("--finding-summary", required=True)
    scaffold.add_argument("--evidence-level", required=True, choices=EVIDENCE_LEVELS)
    scaffold.add_argument("--case-id")
    scaffold.add_argument("--output", required=True)
    scaffold.set_defaults(handler=scaffold_plan)
    validate = subparsers.add_parser("validate-plan", help="validate schema, coverage, and pins")
    validate.add_argument("--plan", required=True)
    validate.set_defaults(handler=validate_plan_command)
    run = subparsers.add_parser("run", help="execute a complete plan in isolated worktrees")
    run.add_argument("--plan", required=True)
    run.add_argument("--output", required=True)
    run.add_argument(
        "--allow-env",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "forward one host environment variable to every check (repeatable). The name and "
            "its resolved value are recorded in result.json, so never forward a credential."
        ),
    )
    run.set_defaults(handler=run_plan)
    schema = subparsers.add_parser("print-schema", help="print the plan's JSON Schema")
    schema.set_defaults(
        handler=lambda _args: print(json.dumps(PLAN_SCHEMA, indent=2, sort_keys=True))
    )
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = args.handler(args)
        return int(result or 0)
    except PlanError as exc:
        print(f"post-patch-validation: {exc}", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
