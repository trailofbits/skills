"""Data-source adapters. Each returns measurements; none decides risk.

Every function either returns a datum or raises `Unavailable`. Turning an `Unavailable`
into a verdict belongs to `collect.py`, which only ever turns it into
`Signal.unassessable`.

Notes earned by getting them wrong first:

- npm's full packument for popular packages is **invalid JSON** — lodash's 247KB response
  carries unescaped control characters and `jq` rejects it. Parse with
  `json.loads(..., strict=False)`.
- The packument-level `.maintainers` is the *current* publish ACL. The version-level
  `.maintainers` is a publish-time snapshot and disagrees: lodash reads 1 current against
  3 at v4.18.1.
- OSV advisories must be keyed by ecosystem+package, never by repository. Repo-keyed gives
  3 for lodash where ecosystem-keyed gives 5.
- deps.dev keys Go versions *with* a `v` prefix; OSV wants it stripped.
- deps.dev's `relatedProjects` is unordered and typed. Across 104 cached responses the
  first entry was `ISSUE_TRACKER` 51 times and `SOURCE_REPO` 53 times, so taking the
  first entry was right only because the two ids happened to coincide.
- GitHub reports primary rate-limit exhaustion as **403** with `x-ratelimit-remaining: 0`,
  not 429, so matching only 429 misses the throttle that actually happens.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from email.message import Message
from pathlib import Path
from shutil import which

from model import SCORECARD_CHECKS

UA = {"User-Agent": "trailofbits-supply-chain-risk-auditor/0.1"}
TIMEOUT = 45
OSV_BATCH_MAX = 500

# Entries older than this are refetched when online. Without a bound, a cached
# `pushed_at` ages alongside the repository and manufactures staleness flags: a repo last
# pushed 300 days before its document was cached, read from a 100-day-old entry, reports
# "no push in 400 days" about a project that may have shipped yesterday.
CACHE_MAX_AGE_SECONDS = 6 * 60 * 60


class Unavailable(Exception):
    """A source could not supply this datum. Never a risk verdict."""


class NotFound(Unavailable):
    """The resource provably does not exist (HTTP 404).

    Distinct from its parent because absence is evidence and every other failure is not:
    a 404 on SECURITY.md means there is no security policy, while a rate limit on the
    same request means nothing at all.
    """


@dataclass
class CacheEntry:
    body: dict
    age_seconds: float


@dataclass
class _Response:
    """The slice of an HTTP response the client needs, however urllib delivered it."""

    status: int
    text: str
    headers: Message = field(default_factory=Message)


class Http:
    """Caching HTTP client with a freshness bound and atomic writes.

    Built on urllib so the plugin carries no third-party dependency. The default opener
    follows redirects, and that is load-bearing: `jrburke/r.js` 301s to `requirejs/r.js`,
    and a client that stopped at the 301 would call the repository missing.
    """

    def __init__(self, cache_dir: Path, offline: bool = False, auth_marker: str = "anon"):
        self.cache_dir = cache_dir
        self.offline = offline
        # Cache keys include an auth marker: a private or SSO-gated repository 404s
        # anonymously, and without this the negative result would be served to every
        # later authenticated run — the run the user fixed their credentials for.
        self.auth_marker = auth_marker
        self.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        # None once ownership is confirmed; a caveat string when the platform cannot be
        # asked. Callers surface it — see collect.collect, which appends it to the report's
        # notes so an unenforced control appears in "Method and caveats" rather than
        # nowhere.
        self.cache_owner_caveat = self._check_cache_owner()
        self.opener = urllib.request.build_opener()
        self.stats = {"hits": 0, "fetched": 0, "offline_misses": 0, "errors": 0, "stale": 0}
        self.oldest_hit_seconds = 0.0

    def _check_cache_owner(self) -> str | None:
        """Refuse a cache owned by another user, or report why that was not checked.

        The cache holds registry and advisory responses, and the collector trusts them.
        A cache another user can write turns a compromised package into a clean
        "no advisories" verdict, so on POSIX a foreign owner aborts the run.

        `os.getuid` is POSIX-only and `st_uid` is always 0 on Windows, so the check
        cannot be evaluated there. Rather than drop it silently, this returns a caveat
        for the caller to surface: an unenforced control the report admits to is a
        smaller problem than one nobody mentions.

        Returns:
            None when ownership was verified, or the caveat text when the platform
            offers no way to verify it.

        Raises:
            SystemExit: The cache directory belongs to another user.
        """
        if not hasattr(os, "getuid"):  # Windows
            return (
                f"cache directory ownership was not verified: os.getuid is POSIX-only, so "
                f"a cache at {self.cache_dir} owned by another user would not be detected "
                f"on this platform. Keep the cache under your own user profile, or pass "
                f"--cache with a private path."
            )
        if self.cache_dir.stat().st_uid != os.getuid():
            raise SystemExit(
                f"error: cache directory {self.cache_dir} is owned by another user; "
                f"refusing to trust or write it — pass --cache with a private path"
            )
        return None

    # ------------------------------------------------------------------ cache

    def _path(self, method: str, url: str, body: str = "") -> Path:
        digest = hashlib.sha256(f"{method} {url} {body} {self.auth_marker}".encode()).hexdigest()[
            :32
        ]
        return self.cache_dir / f"{digest}.json"

    def _read_cache(self, path: Path) -> CacheEntry | None:
        if not path.exists():
            return None
        try:
            stored = json.loads(path.read_text(encoding="utf-8"), strict=False)
        except (json.JSONDecodeError, OSError):
            # A run interrupted mid-write leaves a truncated file that would otherwise
            # crash every later run. Drop it and refetch.
            self.stats["errors"] += 1
            path.unlink(missing_ok=True)
            return None
        meta = stored.get("__meta")
        if not isinstance(meta, dict):
            path.unlink(missing_ok=True)
            return None
        age = time.time() - float(meta.get("fetched_at", 0))
        if age < 0:
            # A timestamp from the future (clock skew, or a planted entry) would read
            # as age zero forever; treat it as infinitely stale instead.
            age = float("inf")
        return CacheEntry(body=stored, age_seconds=age)

    def _write_cache(self, path: Path, body: dict, status: int) -> None:
        payload = {"__meta": {"fetched_at": time.time(), "status": status}, "body": body}
        # Atomic: a partial file must never become a cache hit.
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, path)

    def _serve(self, entry: CacheEntry, url: str) -> dict:
        self.stats["hits"] += 1
        self.oldest_hit_seconds = max(self.oldest_hit_seconds, entry.age_seconds)
        if entry.body["__meta"].get("status") == 404:
            raise NotFound(f"404 from {url}")
        return entry.body["body"]

    def _usable(self, entry: CacheEntry | None) -> bool:
        if entry is None:
            return False
        return self.offline or entry.age_seconds <= CACHE_MAX_AGE_SECONDS

    # ------------------------------------------------------------------ fetch

    def _rate_limited(self, resp: _Response) -> bool:
        if resp.status == 429:
            return True
        # GitHub's primary rate limit is a 403 with the remaining count at zero.
        return resp.status == 403 and resp.headers.get("x-ratelimit-remaining") == "0"

    def _retry_delay(self, resp: _Response) -> float:
        after = resp.headers.get("Retry-After")
        if after and after.isdigit():
            return min(float(after), 30.0)
        return 3.0

    def _open(self, method: str, url: str, headers: dict, payload: dict | None) -> _Response:
        """One HTTP exchange. Error statuses are data here; only transport failures raise."""
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(url, data=data, headers={**UA, **headers}, method=method)
        if payload is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with self.opener.open(request, timeout=TIMEOUT) as resp:
                return _Response(resp.status, resp.read().decode("utf-8", "replace"), resp.headers)
        except urllib.error.HTTPError as exc:
            with exc:
                return _Response(exc.code, exc.read().decode("utf-8", "replace"), exc.headers)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self.stats["errors"] += 1
            raise Unavailable(f"request failed: {exc}") from exc

    def _send(self, method: str, url: str, headers: dict, payload: dict | None) -> dict:
        resp = self._open(method, url, headers, payload)
        if self._rate_limited(resp):
            time.sleep(self._retry_delay(resp))
            resp = self._open(method, url, headers, payload)
            if self._rate_limited(resp):
                self.stats["errors"] += 1
                raise Unavailable(f"rate limited by {url}")
        return self._decode(resp, url)

    def _decode(self, resp: _Response, url: str) -> dict:
        # 410 Gone is proxy.golang.org's "module does not exist"; treat both as provable
        # absence rather than as an outage.
        if resp.status in (404, 410):
            raise NotFound(f"{resp.status} from {url}")
        if resp.status >= 400:
            self.stats["errors"] += 1
            raise Unavailable(f"HTTP {resp.status} from {url}")
        self.stats["fetched"] += 1
        return json.loads(resp.text, strict=False)

    def _request(self, method: str, url: str, headers: dict, payload: dict | None) -> dict:
        body = json.dumps(payload, sort_keys=True) if payload else ""
        path = self._path(method, url, body)
        entry = self._read_cache(path)
        if self._usable(entry):
            return self._serve(entry, url)
        if entry is not None:
            self.stats["stale"] += 1
        if self.offline:
            self.stats["offline_misses"] += 1
            raise Unavailable(f"not in the local cache and this run is offline: {url}")
        try:
            data = self._request_and_cache(method, url, headers, payload, path)
        except NotFound:
            self._write_cache(path, {}, 404)
            raise
        return data

    def _request_and_cache(
        self, method: str, url: str, headers: dict, payload: dict | None, path: Path
    ) -> dict:
        data = self._send(method, url, headers, payload)
        self._write_cache(path, data, 200)
        return data

    def get_json(self, url: str, headers: dict | None = None) -> dict:
        return self._request("GET", url, headers or {}, None)

    def post_json(self, url: str, payload: dict) -> dict:
        return self._request("POST", url, {}, payload)


# --------------------------------------------------------------------------- OSV


def osv_advisories(http: Http, queries: list[tuple[str, str, str | None]]) -> list[list[str]]:
    """Batch-query OSV. One HTTP call per 500 packages.

    Args:
        http: Caching client.
        queries: (ecosystem, name, version) triples. A None version asks for every
            advisory recorded against the package, a historical claim rather than a
            statement about what the project installs.

    Returns:
        Advisory-ID lists, positional with `queries`. Positional rather than keyed by
        package, because a transitive tree routinely holds the same package at two
        versions and a name-keyed mapping would silently keep only one.

    Raises:
        Unavailable: If OSV returns a different number of results than queries sent.
            Results are positional, so a short response would shift every advisory onto
            the wrong package — a flagged verdict whose evidence belongs to something
            else. The mismatch is detectable, so it must not be tolerated.
    """
    out: list[list[str]] = []
    for start in range(0, len(queries), OSV_BATCH_MAX):
        chunk = queries[start : start + OSV_BATCH_MAX]
        payload: dict = {"queries": []}
        for eco, name, version in chunk:
            query: dict = {"package": {"name": name, "ecosystem": eco}}
            if version:
                query["version"] = version
            payload["queries"].append(query)
        data = http.post_json("https://api.osv.dev/v1/querybatch", payload)
        results = data.get("results", [])
        if len(results) != len(chunk):
            raise Unavailable(
                f"OSV returned {len(results)} results for {len(chunk)} queries; positional "
                f"pairing would attribute advisories to the wrong packages"
            )
        out.extend([v["id"] for v in (result or {}).get("vulns", [])] for result in results)
    return out


# --------------------------------------------------------------------------- npm

# Substring hints. Conservative on purpose: a false negative overstates the human
# publisher count, which is the safer direction, since a count of 1 is what creates a
# flag. `dependabot` and `renovate` are named explicitly because neither contains a
# hyphen next to "bot".
_AUTOMATION_HINTS = ("-bot", "bot-", "-ci", "npm-cli", "github-actions", "dependabot", "renovate")


def looks_automated(account: str) -> bool:
    """Heuristic: does this registry account look like a bot rather than a person?"""
    lowered = account.lower()
    return lowered in {"bot", "ci"} or any(hint in lowered for hint in _AUTOMATION_HINTS)


def _maintainer_names(raw: object) -> list[str]:
    """Registry maintainer lists hold dicts now and bare strings in older packuments."""
    names = []
    for entry in raw or []:
        if isinstance(entry, dict):
            name = entry.get("name")
        else:
            name = str(entry)
        if name:
            names.append(name)
    return names


def npm_metadata(http: Http, name: str) -> dict:
    """Current publish ACL, provenance, install-script flag, deprecation, repository.

    Raises:
        NotFound: If the package is not published.
        Unavailable: If `dist-tags.latest` names a version the packument does not carry,
            in which case install-script and provenance would otherwise read as
            determined negatives derived from an absent document.
    """
    quoted = urllib.parse.quote(name, safe="@").replace("/", "%2F")
    doc = http.get_json(f"https://registry.npmjs.org/{quoted}")
    latest = (doc.get("dist-tags") or {}).get("latest")
    versions = doc.get("versions") or {}
    if not latest or latest not in versions:
        raise Unavailable("npm's latest tag points at a version absent from the packument")
    version_doc = versions[latest]
    maintainers = _maintainer_names(doc.get("maintainers"))
    repository = doc.get("repository")
    repo_url = repository.get("url") if isinstance(repository, dict) else repository
    return {
        "latest": latest,
        "maintainers": maintainers,
        "human_maintainers": [m for m in maintainers if not looks_automated(m)],
        "automated_maintainers": [m for m in maintainers if looks_automated(m)],
        "has_install_script": bool(version_doc.get("hasInstallScript")),
        "provenance": bool((version_doc.get("dist") or {}).get("attestations")),
        "deprecated": version_doc.get("deprecated") or doc.get("deprecated"),
        "repository": normalize_repo(repo_url) if isinstance(repo_url, str) else None,
    }


def npm_downloads(http: Http, name: str) -> int:
    quoted = urllib.parse.quote(name, safe="@").replace("/", "%2F")
    data = http.get_json(f"https://api.npmjs.org/downloads/point/last-week/{quoted}")
    count = data.get("downloads")
    if count is None:
        raise Unavailable("npm returned no download count")
    return int(count)


# ------------------------------------------------------------------------- PyPI


def pypi_metadata(http: Http, name: str, version: str | None = None) -> dict:
    """PyPI exposes no upload ACL, and its download fields return -1 by design.

    Args:
        http: Caching client.
        name: Distribution name, PEP 503 normalised.
        version: The version to report yank status for. Yank is per-release, so checking
            the latest release's status and displaying it against a pinned version states
            something false about that version.
    """
    doc = http.get_json(f"https://pypi.org/pypi/{name}/json")
    info = doc.get("info") or {}
    releases = doc.get("releases") or {}
    latest = info.get("version")
    target = version if version in releases else None
    files = releases.get(target) if target else None
    urls = info.get("project_urls") or {}
    repo_url = None
    for label in ("Source", "Source Code", "Repository", "Code", "GitHub", "Homepage"):
        candidate = urls.get(label)
        if isinstance(candidate, str) and ("github.com" in candidate or "gitlab" in candidate):
            repo_url = candidate
            break
    return {
        "latest": latest,
        "yank_version": target,
        "yanked": any(f.get("yanked") for f in files) if files else None,
        "yanked_reason": (
            next((f.get("yanked_reason") for f in files if f.get("yanked")), None)
            if files
            else None
        ),
        "repository": normalize_repo(repo_url) if repo_url else None,
    }


# -------------------------------------------------------------------- Go module proxy


def go_module_latest(http: Http, module: str) -> dict:
    """Resolve a module against proxy.golang.org, which is the Go existence check.

    Go has no registry, so a module path that OSV has no advisories for is
    indistinguishable from a typo unless the proxy actually resolves it — and an early
    version of this collector asserted the proxy check in a comment while never making
    the request, which let nonexistent modules read as assessed-clean.

    Raises:
        NotFound: If the proxy has no such module (404, or its 410 Gone).
        Unavailable: If the proxy could not be reached.
    """
    # The proxy escapes uppercase letters as "!<lowercase>" (github.com/Azure ->
    # github.com/!azure).
    escaped = re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), module)
    return http.get_json(f"https://proxy.golang.org/{escaped}/@latest")


# ---------------------------------------------------------------------- deps.dev

_DEPSDEV_SYSTEM = {"npm": "npm", "PyPI": "pypi", "Go": "go", "crates.io": "cargo"}


def depsdev_repo(http: Http, ecosystem: str, name: str, version: str | None) -> str:
    """Resolve a package to its source repository.

    Prefers the `SOURCE_REPO` relation. `relatedProjects` is unordered and also carries
    `ISSUE_TRACKER`, which can point at a different repository entirely.
    """
    system = _DEPSDEV_SYSTEM.get(ecosystem)
    if not system or not version:
        raise Unavailable(f"no deps.dev lookup for {ecosystem} without a resolved version")
    if system == "go" and not version.startswith("v"):
        version = f"v{version}"
    quoted = name.replace("/", "%2F")
    doc = http.get_json(
        f"https://api.deps.dev/v3alpha/systems/{system}/packages/{quoted}/versions/{version}"
    )
    for project in doc.get("relatedProjects") or []:
        if project.get("relationType") != "SOURCE_REPO":
            continue
        ident = (project.get("projectKey") or {}).get("id")
        if ident:
            return normalize_repo(ident)
    for link in doc.get("links") or []:
        if link.get("label") == "SOURCE_REPO" and link.get("url"):
            return normalize_repo(link["url"])
    raise Unavailable("deps.dev lists no source repository")


# ------------------------------------------------------------- repo identifiers

_HOST_SHORTHAND = {"github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org"}
_KNOWN_FORGES = ("github.com", "gitlab.com", "bitbucket.org")


def normalize_repo(raw: str) -> str:
    """Canonicalise a repository identifier to `<host>/<owner>/<repo>`.

    deps.dev and the registries return whatever a manifest declared: npm's bare
    `owner/repo` shorthand (which means GitHub), `git+https://….git`, scp-style
    `git@host:owner/repo`, mixed-case hosts, or a deep link into a file on a branch.
    Getting any of these wrong produces a false "hosted outside GitHub" claim, which is
    this report's worst failure mode — a confident statement about a third party derived
    from a string-formatting detail.
    """
    text = (raw or "").strip().removeprefix("git+")
    for prefix, host in _HOST_SHORTHAND.items():
        if text.startswith(f"{prefix}:") and not text.startswith(f"{prefix}://"):
            text = f"{host}/{text[len(prefix) + 1 :]}"
            break
    for scheme in ("https://", "http://", "ssh://", "git://"):
        text = text.removeprefix(scheme)
    if "@" in text.split("/", 1)[0]:
        text = text.split("@", 1)[1].replace(":", "/", 1)
    text = text.removesuffix(".git").strip("/").removeprefix("www.")
    parts = text.split("/")
    if parts and "." not in parts[0] and len(parts) == 2:
        # npm's bare `owner/repo` shorthand implies GitHub.
        parts = ["github.com", *parts]
    if parts:
        parts[0] = parts[0].lower()
    # Truncate deep links: a Homepage of github.com/psf/requests/blob/main/README.md is
    # a repository identifier with noise on the end.
    if parts and parts[0] in _KNOWN_FORGES and len(parts) > 3:
        parts = parts[:3]
    return "/".join(parts)


# ------------------------------------------------------------------------ GitHub


def gh_token() -> str | None:
    """Read the gh CLI's token. Availability is not authentication.

    Unauthenticated GitHub allows 60 requests/hour against 5000 authenticated, and this
    collector makes several per dependency.
    """
    try:
        out = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None


class RepoIdentifierError(Unavailable):
    """The identifier could not be parsed or is not on a host we can query."""


def github_repo(http: Http, repo_id: str, token: str | None) -> dict:
    """Staleness, archived state, and security-policy presence.

    Raises:
        RepoIdentifierError: If the identifier is unparseable or not on GitHub. Distinct
            from a request failure so the report does not blame the GitHub API for a
            request it never made.
        Unavailable: If GitHub could not be reached.
    """
    slug = normalize_repo(repo_id)
    if not slug.startswith("github.com/"):
        raise RepoIdentifierError(f"not a GitHub repository: {slug}")
    owner_repo = slug.removeprefix("github.com/")
    if owner_repo.count("/") != 1:
        raise RepoIdentifierError(f"cannot parse owner/repo from {repo_id}")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    doc = http.get_json(f"https://api.github.com/repos/{owner_repo}", headers=headers)
    return {
        "owner_repo": owner_repo,
        "pushed_at": doc.get("pushed_at"),
        "archived": bool(doc.get("archived")),
        "security_policy": _security_policy(http, owner_repo, headers),
    }


def _security_policy(http: Http, owner_repo: str, headers: dict) -> bool | None:
    """Is a security policy published?

    Returns True, False, or None when the question could not be answered. Only a 404
    proves absence — a rate limit or a network error proves nothing, and collapsing the
    two reported "no security policy" as a measured fact about projects that have one.

    GitHub also serves the owner's `.github` repository as a default, so an in-repo-only
    check is wrong: expressjs/express 404s in-repo while expressjs/.github/SECURITY.md is
    a 200.
    """
    owner = owner_repo.split("/")[0]
    candidates = (
        f"{owner_repo}/contents/SECURITY.md",
        f"{owner_repo}/contents/.github/SECURITY.md",
        f"{owner_repo}/contents/docs/SECURITY.md",
        f"{owner}/.github/contents/SECURITY.md",
        f"{owner}/.github/contents/.github/SECURITY.md",
    )
    inconclusive = False
    for candidate in candidates:
        try:
            http.get_json(f"https://api.github.com/repos/{candidate}", headers=headers)
            return True
        except NotFound:
            continue
        except Unavailable:
            inconclusive = True
    return None if inconclusive else False


# -------------------------------------------------------------------- Scorecard

# Check names and flag thresholds live in model.SCORECARD_CHECKS, the single source of
# truth shared with the renderer. A Scorecard score of -1 means the check could not run
# — commonly for want of repository-admin access — and is a gap, not a finding.


def scorecard_checks(http: Http, repo_id: str) -> dict[str, int]:
    """Individual OpenSSF Scorecard check scores, keyed by Scorecard's own check names.

    Raises:
        NotFound: If Scorecard has no report for this repository. Coverage is incomplete —
            paulmillr/noble-curves, audited cryptography, is a 404.
    """
    slug = normalize_repo(repo_id)
    doc = http.get_json(f"https://api.scorecard.dev/projects/{slug}")
    scores = {c["name"]: c.get("score", -1) for c in doc.get("checks") or []}
    return {name: scores[name] for name in SCORECARD_CHECKS if name in scores}


# ------------------------------------------------------- optional local tooling


OPTIONAL_TOOLS = ("pip-audit", "osv-scanner", "npm", "cargo-audit", "bundler-audit")


def detect_tools() -> dict[str, bool]:
    """Which optional ecosystem tools are on PATH. Never required, only used if present."""
    return {tool: which(tool) is not None for tool in OPTIONAL_TOOLS}


def pip_audit_vulnerable(requirements: Path) -> set[str]:
    """Cross-check PyPI advisories with pip-audit, when it is installed.

    Returns the set of PEP 503 normalised names pip-audit reports as vulnerable. A
    disagreement with OSV is worth reporting in its own right — two databases differing
    tells a reader more than either alone.

    Raises:
        Unavailable: If pip-audit is missing, times out, or returns unparseable output.
    """
    try:
        out = subprocess.run(
            [
                "pip-audit",
                "--requirement",
                str(requirements),
                # Both flags are required. Without them pip-audit resolves the full
                # tree through pip, downloading distributions and running setup.py for
                # anything without a wheel — executing the untrusted code this tool
                # promises never to run. Measured: `--no-deps` alone still audited the
                # resolved transitive set, so pip was still involved; `--disable-pip`
                # (valid only with `--no-deps`) removes pip entirely and audits exactly
                # the listed pins from registry metadata.
                "--no-deps",
                "--disable-pip",
                "--format",
                "json",
                "--progress-spinner",
                "off",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise Unavailable(f"pip-audit could not run: {exc}") from exc
    if not out.stdout.strip():
        raise Unavailable(f"pip-audit produced no output (exit {out.returncode})")
    try:
        data = json.loads(out.stdout)
    except json.JSONDecodeError as exc:
        raise Unavailable(f"pip-audit output was not JSON: {exc}") from exc
    entries = data.get("dependencies") if isinstance(data, dict) else data
    vulnerable = set()
    for entry in entries or []:
        if entry.get("vulns"):
            vulnerable.add(str(entry.get("name", "")).lower())
    return vulnerable


def polite_pause(seconds: float = 0.05) -> None:
    time.sleep(seconds)
