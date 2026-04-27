#!/usr/bin/env python3
"""
Integrity audit of a single commit using a multi-agent discussion via the
GitHub Models API.

Three specialist agents review the diff in sequence — each one sees the prior
agents' findings and may agree with, challenge, or extend them.  The
discussion may run for multiple rounds (controlled by ``AUDIT_MAX_ROUNDS``,
default 1) so the agents can refine each other's findings before a
moderator synthesises the discussion into a single verdict.

Routing
-------

The commit is fetched as the structured `files[]` array (not the raw unified
diff), so per-file metadata (rename, binary, truncation) is available.  Each
file is classified against a static sensitivity manifest using
highest-classification-wins across all matching rules.  Three routing modes:

* `whole`             — total patch fits the threshold; agents see everything.
* `focused`           — total patch exceeds the threshold; only critical and
                        high-classification files (plus any low files they
                        textually reference) are sent to the panel, prefixed
                        with a Context note that lists every excluded file.
* `focused-overflow`  — even the critical+high subset exceeds the threshold;
                        the panel sees critical-only as a best effort, or is
                        skipped entirely (status `panel-skipped`) when even
                        that overflows.

Deterministic structural findings (binary changes, submodule pointer bumps,
auto-generated-file header removal) bypass the LLM and always surface.  An
issue is filed whenever the LLM verdict is suspicious, OR a structural
finding exists, OR any critical/high file was excluded from the panel by
routing.

Focus: commit *integrity* (malicious intent, backdoors, supply-chain
tampering, covert exfiltration).  Code-quality security issues (XSS, RCE,
SQLi, …) are out of scope and handled by a separate agent in the main
repository.

Required env vars:
  GITHUB_TOKEN    — for audit repo writes, issues, and GitHub Models API
  COMMIT_SHA      — SHA of the commit to audit
  AUDIT_REPO      — "owner/repo" of this audit repository
  MONITORED_REPO  — "owner/repo" being monitored

Optional env vars:
  MONITORED_REPO_TOKEN — token for reading the monitored repo (omit if public)
  COMMIT_AUTHOR        — "Name <email>" from the push event
  COMMIT_MESSAGE       — first line of the commit message
  COMMIT_TIMESTAMP     — ISO8601 commit timestamp
  AUDIT_FORCE_RERUN    — when "1" or "true" (case-insensitive), bypass the
                         preflight that skips commits already audited.
                         The preflight searches the `audit-log` branch for
                         any `logs/*/{sha}.json` and short-circuits if found,
                         eliminating duplicate-audit cost in
                         reconciler-vs-push-trigger races; see TODO #12 history.
  AUDIT_DETECT_MODE_CHANGES
                       — when "1" or "true" (case-insensitive), enable
                         file-mode-flip and symlink-target-change detection
                         via the Git Trees API.  Adds 2 API calls per audited
                         commit (one tree per side of the diff), so the check
                         is opt-in.  Default: disabled.
  AUDIT_MAX_ROUNDS     — maximum number of discussion rounds between the
                         specialist agents before the moderator runs.  A
                         round is one full pass through every specialist
                         (each agent sees the discussion so far on every
                         turn after the first).  The discussion stops
                         early when a round produces no new concerns and
                         every agent in the round agrees on the verdict.
                         Defaults to 1 (the historical single-pass
                         behaviour); values < 1 are clamped to 1.  Each
                         additional round costs roughly one model call
                         per specialist agent.

                         INTENTIONALLY NOT a workflow_dispatch input —
                         the value is set by the committed workflow YAML
                         so an attacker with dispatch permission cannot
                         inflate model-call cost by passing a huge
                         number at trigger time.

Exit codes:
  0 — success
  1 — missing required env var
  2 — diff fetch failed (404 / 403 / network error)
  4 — audit log push failed
  5 — AI discussion failed (log still written with status=ai-error)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

import agent_tools

Classification = Literal["critical", "high", "medium", "low"]
Severity = Literal["none", "low", "medium", "high", "critical"]
RoutingMode = Literal["whole", "focused", "focused-overflow", "panel-skipped"]
Status = Literal["unknown", "reviewed", "ai-error", "panel-skipped"]

# `_http` is imported lazily inside the network-touching helpers so that the
# pure-function layers (parsing, classification, routing) stay free of any
# import-time side effects when exercised by unit tests.

MODELS_ENDPOINT = "https://models.github.ai/inference"
AI_MODEL = "openai/gpt-4o-mini"
CHAR_THRESHOLD = 400_000  # ~100 K tokens at 4 chars/token
MANIFEST_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "monitored_repo_classification.json"
)
CLASSIFICATION_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]
COMMITS_API_PER_PAGE = 100
DEFAULT_MAX_ROUNDS = 1

# ---------------------------------------------------------------------------
# Agent definitions
# Each agent receives the diff plus the growing discussion transcript and
# returns a JSON object described in its system prompt.
# ---------------------------------------------------------------------------

AGENTS = [
    {
        "name": "Backdoor Hunter",
        "system_prompt": """\
You are the Backdoor Hunter, a specialist in detecting intentional malicious
modifications hidden inside otherwise legitimate-looking code changes.

Your sole focus is commit *integrity* — whether the author may have embedded
harmful functionality on purpose.  Do NOT flag code-quality issues, XSS, RCE,
or SQL injection; those are handled by a separate team.

Look specifically for:
- Hidden backdoors: secret entry points, hardcoded credentials used for covert
  access, undocumented privileged modes enabled by magic values or env vars.
- Logic bombs: code that activates only under specific conditions (date/time
  checks, hostname comparisons, counter thresholds, environment flags).
- Obfuscated or encoded payloads: base64 / hex blobs, eval of dynamic strings,
  unusually compressed or minified code inserted into a non-minified file.
- Trojan functionality: a change that appears to do one thing but also does
  something harmful (e.g. a "fix" that silently copies data elsewhere).
- Dead code that could be re-activated later: commented-out but suspicious
  blocks, feature flags that enable dangerous paths.

If a "Context note" precedes the diff, the diff has been filtered and you do
NOT see every file in the commit.  Lower your confidence on any concern that
hinges on a symbol defined in an excluded file.

Respond ONLY with a JSON object — no markdown fences, no extra text:
{
  "concerns": [
    {
      "type": "<short label, e.g. logic_bomb | hidden_backdoor | obfuscated_payload | trojan | dead_code>",
      "file": "<file path from diff, or unknown>",
      "line": <integer or null>,
      "description": "<what you found and why it is suspicious>",
      "evidence": "<short verbatim snippet from the diff that triggered this concern>"
    }
  ],
  "verdict": "<clean|suspicious|malicious>",
  "confidence": "<low|medium|high>",
  "reasoning": "<one or two sentences explaining your overall assessment>"
}
If you find nothing, return concerns=[], verdict=clean, confidence=high.""",
    },
    {
        "name": "Supply Chain Inspector",
        "system_prompt": """\
You are the Supply Chain Inspector, a specialist in detecting attempts to
compromise a project through its dependency graph, build pipeline, or external
resource fetches.

Your sole focus is commit *integrity* from a supply-chain perspective.  Do NOT
flag general code-quality issues or common web-app vulnerabilities.

Look specifically for:
- New or changed dependencies (package.json / requirements.txt / go.mod /
  Cargo.toml / pom.xml / Gemfile / composer.json / …): are they plausible?
  Do their names resemble well-known packages with a subtle typo
  (typosquatting)?  Are they pinned to an unexpectedly old or bleeding-edge
  version?
- Lockfile manipulation: hashes or resolved URLs changed without a
  corresponding manifest change; checksums removed or set to obviously wrong
  values.
- Vendored code alterations: changes to files inside vendor/ or node_modules/
  that are not a routine update (i.e. the surrounding manifest did not change).
- Package registry substitution: switching from a trusted registry to an
  unofficial mirror or a private one not previously used.
- Install-time code execution hooks: npm `preinstall` / `install` / `postinstall`
  scripts, Python `setup.py` arbitrary code, Cargo `build.rs`, Gradle init
  scripts, Makefile install targets — newly added or altered to do anything
  beyond compilation.

CI/CD pipeline tampering — give this category special attention.  Files to
scrutinise: `.github/workflows/**`, `.gitlab-ci.yml`, `.circleci/config.yml`,
`Jenkinsfile`, `azure-pipelines.yml`, `Dockerfile`, `Containerfile`,
`devcontainer.json`, shell scripts under `scripts/`, `bin/`, `ci/`, `tools/`,
`Makefile`, `justfile`, `Taskfile.yml`, pre-commit configs, husky / lefthook
hooks, and any `*.sh` / `*.ps1` referenced from the above.

Within those files, look for:

1. Remote-fetch-and-execute patterns ( "curl pipe bash" and its variants ):
   - `curl ... | bash`, `curl ... | sh`, `curl ... | python`, `curl ... | node`,
     `wget -O- ... | bash`, `wget -qO- ... | sh`, `fetch ... | sh`.
   - Process substitution variants: `bash <(curl ...)`, `sh <(wget ...)`,
     `source <(curl ...)`, `python -c "$(curl ...)"`, `eval "$(curl ...)"`.
   - Two-step download-then-exec: `curl -o /tmp/x ... && bash /tmp/x`,
     `wget ... -O installer && chmod +x installer && ./installer`.
   - PowerShell equivalents: `iex (iwr ...)`, `iex (New-Object Net.WebClient).DownloadString(...)`,
     `Invoke-Expression (Invoke-RestMethod ...)`.
   - Treat as suspicious even when the URL points at a "trusted" domain — DNS
     can be spoofed, accounts taken over, and the target file can change after
     review.  The pattern itself is the concern.
   - Especially suspicious if the URL is constructed from a variable, contains
     an IP address or non-HTTPS scheme, points at a Pastebin-style host
     (pastebin.com, gist.github.com raw, transfer.sh, 0x0.st, ngrok, requestbin,
     webhook.site, *.tunnel., a bare numeric host), or uses a URL shortener.

2. GitHub Actions / reusable-action pinning regressions:
   - Third-party `uses:` references newly added or changed.  Trusted actions
     should be pinned to a 40-character commit SHA; tags like `@v1`, `@main`,
     `@master`, or branch names are mutable and can be hijacked.
   - An existing SHA-pinned action being downgraded to a tag pin is a strong
     signal.
   - Action repositories whose owner is unfamiliar, recently created, or
     differs from upstream by a typo (e.g. `actons/checkout`, `acions/`).

3. Workflow trigger and permission escalation:
   - New or modified workflows triggered by `pull_request_target`,
     `workflow_run`, or `issue_comment` — these run with repo write
     credentials and can read secrets even from forks.
   - `permissions:` block widened to `write-all`, or specific scopes raised
     ( e.g. `contents: write`, `id-token: write`, `packages: write` ) without a
     stated reason.
   - Removal of `permissions:` blocks ( reverts to the repo default, often
     wider than the previous explicit grant ).
   - Addition of `pull_request_target` workflows that check out PR head code
     ( `actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}` )
     and then run scripts from that checkout — classic pwn-request pattern.

4. Secret handling and exfiltration channels:
   - `${{ secrets.* }}` interpolated into shell commands, log lines, HTTP
     bodies, query strings, or environment variables shipped to external
     hosts.
   - `env:` entries that mass-export secrets into a step that runs
     attacker-influenced code ( e.g. `env: GITHUB_TOKEN: ${{ secrets.PAT }}`
     just before a `run:` that fetches a remote script ).
   - Output of `printenv`, `env`, `set`, or `cat ~/.netrc` in a workflow.
   - New steps that POST to external endpoints ( `curl -d`, `gh api`,
     `slack-notify` to an unfamiliar webhook, generic webhook.site URL ).

5. Runner and execution-environment changes:
   - Switching `runs-on:` from a GitHub-hosted runner to `self-hosted`, or
     adding a self-hosted runner label, especially on a public repo.
   - Container image references changed to an unpinned tag ( `:latest`,
     `:main` ) or to an image from an untrusted registry.
   - `services:` or `container:` blocks pulling images by tag rather than by
     digest.

6. Code-signing, release, and artefact-publishing changes:
   - Signing keys / GPG keys / cosign identities being changed, removed, or
     made conditional.
   - Release upload steps that upload extra files not produced by the build,
     or that re-pack artefacts after signing.
   - Changes to OIDC trust configuration ( `id-token` claims, audience values,
     trust policies for cloud roles ).

If a "Context note" precedes the diff, the diff has been filtered and you do
NOT see every file in the commit.  Lower your confidence on any concern that
hinges on a symbol defined in an excluded file.

You will be shown the diff AND the findings of the Backdoor Hunter who reviewed
first.  You may agree with their findings, challenge them if you think they
are false positives, or add new concerns.

When reporting a CI/CD concern, prefer specific labels from this list:
`remote_fetch_execute`, `unpinned_action`, `mutable_action_ref`,
`typosquatted_action`, `workflow_permission_escalation`,
`pull_request_target_abuse`, `secret_exfiltration`, `self_hosted_runner_addition`,
`unpinned_container_image`, `signing_config_change`, `install_hook_abuse`.
Fall back to `malicious_build_step` only when none of the above fits.

Respond ONLY with a JSON object — no markdown fences, no extra text:
{
  "concerns": [
    {
      "type": "<short label from the lists above, e.g. typosquatting | lockfile_tampering | remote_fetch_execute | unpinned_action | pull_request_target_abuse | secret_exfiltration | workflow_permission_escalation | install_hook_abuse | vendored_alteration | registry_substitution | malicious_build_step>",
      "file": "<file path from diff, or unknown>",
      "line": <integer or null>,
      "description": "<what you found and why it is suspicious>",
      "evidence": "<short verbatim snippet from the diff that triggered this concern>"
    }
  ],
  "responses_to_prior": [
    "<one sentence per prior concern you want to comment on: start with the agent name and concern type>"
  ],
  "verdict": "<clean|suspicious|malicious>",
  "confidence": "<low|medium|high>",
  "reasoning": "<one or two sentences explaining your overall assessment>"
}
If you find nothing new and agree with the prior analysis, return concerns=[],
an appropriate responses_to_prior, and your verdict.""",
    },
    {
        "name": "Integrity Analyst",
        "system_prompt": """\
You are the Integrity Analyst, a specialist in detecting subtle trust-erosion
changes: modifications that do not look obviously malicious but quietly
undermine the security posture, auditability, or trustworthiness of the system.

Your sole focus is commit *integrity*.  Do NOT flag code-quality issues or
common web-app vulnerabilities (XSS, RCE, SQLi, …).

Look specifically for:
- Covert data exfiltration: new or modified network calls that send data to
  unexpected endpoints; logging or telemetry that captures sensitive fields
  (tokens, PII, secrets) without clear justification.
- Audit trail reduction: removal or disabling of logging, monitoring hooks,
  or security event recording; changes to .gitignore or similar that could
  hide sensitive files from future review.
- Cryptographic weakening: switching to weaker algorithms, reducing key sizes,
  removing signature verification, disabling certificate checks.
- Authorization / authentication silent downgrade: changes to access-control
  logic that broaden permissions without documentation, or that add bypass
  conditions for specific identities.
- Social engineering via the diff: misleading comments or commit messages that
  describe the change as a "fix" or "cleanup" while hiding its real effect.

If a "Context note" precedes the diff, the diff has been filtered and you do
NOT see every file in the commit.  Lower your confidence on any concern that
hinges on a symbol defined in an excluded file.

You will be shown the diff AND all findings from the two previous analysts.
Challenge false positives, confirm true positives, and add any new concerns
that neither analyst surfaced.

Respond ONLY with a JSON object — no markdown fences, no extra text:
{
  "concerns": [
    {
      "type": "<short label, e.g. covert_exfiltration | audit_trail_removal | crypto_weakening | auth_downgrade | social_engineering>",
      "file": "<file path from diff, or unknown>",
      "line": <integer or null>,
      "description": "<what you found and why it is suspicious>",
      "evidence": "<short verbatim snippet from the diff that triggered this concern>"
    }
  ],
  "responses_to_prior": [
    "<one sentence per prior concern you want to comment on>"
  ],
  "verdict": "<clean|suspicious|malicious>",
  "confidence": "<low|medium|high>",
  "reasoning": "<one or two sentences explaining your overall assessment>"
}
If you find nothing new, return concerns=[], respond to prior findings, and
give your verdict.""",
    },
]

MODERATOR_SYSTEM_PROMPT = """\
You are the Audit Moderator.  Three specialist analysts — Backdoor Hunter,
Supply Chain Inspector, and Integrity Analyst — have reviewed a Git diff and
discussed their findings.  Your job is to read the full discussion transcript
and produce a single authoritative verdict.

Rules:
- Weigh each concern by the confidence and supporting evidence provided.
- If two or more analysts independently flagged the same issue, treat it as
  more credible.
- If one analyst challenged another's finding and provided a convincing
  counter-argument, reduce that concern's weight accordingly.
- "suspicious" should be true whenever at least one credible, un-rebutted
  concern remains.
- "severity" should reflect the worst un-rebutted concern:
    none     — everything is clean
    low      — weak signal, no direct harm likely
    medium   — plausible concern, manual review warranted
    high     — strong evidence of malicious intent
    critical — near-certain malicious modification

If a "Context note" precedes the diff, the diff has been filtered and the
panel did NOT see every file in the commit.  When a finding's evidence is
absent from the patch text, or refers to a symbol defined in a file marked
excluded in the Context note, downgrade severity by one step and reduce
confidence — the analysts could not assess the full picture.

Respond ONLY with a JSON object — no markdown fences, no extra text:
{
  "suspicious": <bool>,
  "severity": "<none|low|medium|high|critical>",
  "summary": "<one sentence suitable for an issue title>",
  "findings": [
    {
      "type": "<concern type from the discussion>",
      "file": "<file path or unknown>",
      "line": <integer or null>,
      "description": "<consolidated description>",
      "raised_by": ["<agent name>", ...]
    }
  ]
}"""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ManifestRule:
    pattern: str
    classification: Classification
    reason: str
    audit_hint: Optional[str] = None
    _regex: Optional[re.Pattern] = None

    def matches(self, path: str) -> bool:
        if self._regex is None:
            self._regex = _glob_to_regex(self.pattern)
        return self._regex.match(path) is not None


@dataclass
class Manifest:
    schema_version: str
    default_classification: Classification
    rules: list[ManifestRule]
    fail_closed: bool = False  # True when the manifest could not be loaded


@dataclass
class FileChange:
    path: str
    previous_path: Optional[str]
    status: str
    additions: int
    deletions: int
    patch: Optional[str]  # None when binary, omitted by API, or removed
    blob_sha: Optional[str]
    # `is_binary` is set authoritatively by the patch-resolution pass
    # (`_resolve_patch_omissions`) which probes the blob for NUL bytes.  It
    # defaults to False so unit tests that construct FileChange directly do
    # not need to know about the resolution layer; tests that want to
    # exercise binary handling set it explicitly.
    is_binary: bool = False
    # True iff the API omitted the patch for a text file (size cap) or the
    # patch we have is suspected truncated.  Distinguished from `is_binary`
    # so structural-finding logic does not confuse the two.
    patch_omitted: bool = False
    # True iff `patch` was reconstructed from a blob fetch because the
    # original was missing or truncated.  Lets the composer emit an
    # explanatory header for the panel.
    patch_synthesised: bool = False
    # True iff the blob fetch itself failed (rate limit / 404) so the panel
    # has neither a real patch nor a synthesised one.  Surfaces as a
    # `text_patch_unavailable` structural finding.
    patch_unavailable: bool = False

    @property
    def patch_chars(self) -> int:
        return len(self.patch) if self.patch else 0


@dataclass
class ClassifiedFile:
    file: FileChange
    classification: Classification
    matched_rules: list[str]


@dataclass
class StructuralFinding:
    type: str
    path: str
    description: str


@dataclass
class RoutingDecision:
    mode: RoutingMode
    reason: str
    included: list[ClassifiedFile]
    excluded: list[ClassifiedFile]
    composed_patch: str
    total_chars: int


@dataclass
class CommitData:
    sha: str
    parents: list[str]
    files: list[FileChange]
    truncated: bool
    is_merge: bool


# ---------------------------------------------------------------------------
# Glob helpers
# ---------------------------------------------------------------------------

def _glob_to_regex(pattern: str) -> re.Pattern:
    """
    Convert a gitignore-style glob to a compiled regex.

    `**/`  matches zero or more leading path segments.
    `**`   (alone or trailing) matches anything including `/`.
    `*`    matches anything except `/`.
    `?`    matches a single character except `/`.
    """
    parts: list[str] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                if i + 2 < len(pattern) and pattern[i + 2] == "/":
                    parts.append("(?:.*/)?")
                    i += 3
                    continue
                parts.append(".*")
                i += 2
                continue
            parts.append("[^/]*")
            i += 1
            continue
        if c == "?":
            parts.append("[^/]")
            i += 1
            continue
        if c in r".^$+(){}[]|\\":
            parts.append(re.escape(c))
            i += 1
            continue
        parts.append(re.escape(c) if not c.isalnum() and c not in "_-/" else c)
        i += 1
    return re.compile("^" + "".join(parts) + "$")


# ---------------------------------------------------------------------------
# Config and manifest loading
# ---------------------------------------------------------------------------

def load_config():
    required = ["GITHUB_TOKEN", "COMMIT_SHA", "AUDIT_REPO", "MONITORED_REPO"]
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        print(f"ERROR: Missing required env vars: {missing}", file=sys.stderr)
        sys.exit(1)
    return {
        "github_token": os.environ["GITHUB_TOKEN"],
        "monitored_token": os.environ.get("MONITORED_REPO_TOKEN", ""),
        "commit_sha": os.environ["COMMIT_SHA"],
        "audit_repo": os.environ["AUDIT_REPO"],
        "monitored_repo": os.environ["MONITORED_REPO"],
        "commit_author": os.environ.get("COMMIT_AUTHOR", "unknown"),
        "commit_message": os.environ.get("COMMIT_MESSAGE", ""),
        "commit_timestamp": os.environ.get(
            "COMMIT_TIMESTAMP",
            datetime.now(timezone.utc).isoformat(),
        ),
    }


def load_manifest(path: Path = MANIFEST_PATH) -> Manifest:
    """
    Load the sensitivity manifest.  Fails closed: on any error every path
    will be classified as critical, so an attacker cannot defeat the audit
    by corrupting or deleting the manifest.
    """
    fail_closed = Manifest(
        schema_version="0",
        default_classification="critical",
        rules=[],
        fail_closed=True,
    )
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        print(f"WARNING: Could not read manifest at {path}: {e}", file=sys.stderr)
        print("WARNING: Failing closed — every file will be classified critical.", file=sys.stderr)
        return fail_closed
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"WARNING: Manifest at {path} is not valid JSON: {e}", file=sys.stderr)
        print("WARNING: Failing closed — every file will be classified critical.", file=sys.stderr)
        return fail_closed

    if data.get("schema_version") != "1":
        print(
            f"WARNING: Manifest schema_version {data.get('schema_version')!r} not supported.",
            file=sys.stderr,
        )
        print("WARNING: Failing closed — every file will be classified critical.", file=sys.stderr)
        return fail_closed

    default = data.get("default_classification", "medium")
    if default not in CLASSIFICATION_ORDER:
        print(f"WARNING: Manifest default_classification {default!r} invalid.", file=sys.stderr)
        return fail_closed

    rules: list[ManifestRule] = []
    for entry in data.get("rules", []):
        try:
            classification = entry["classification"]
            if classification not in CLASSIFICATION_ORDER:
                raise ValueError(f"invalid classification {classification!r}")
            rules.append(
                ManifestRule(
                    pattern=entry["pattern"],
                    classification=classification,
                    reason=entry.get("reason", ""),
                    audit_hint=entry.get("audit_hint"),
                )
            )
        except (KeyError, ValueError) as e:
            print(f"WARNING: Skipping malformed rule {entry!r}: {e}", file=sys.stderr)

    return Manifest(
        schema_version=data["schema_version"],
        default_classification=default,
        rules=rules,
    )


# ---------------------------------------------------------------------------
# GitHub commit fetch
# ---------------------------------------------------------------------------

def _api_get(url: str, headers: dict):
    import _http as http

    try:
        resp = http.get(url, headers=headers, timeout=30)
    except http.HTTPError as e:
        print(f"ERROR: Network error fetching {url}: {e}", file=sys.stderr)
        sys.exit(2)
    if resp.status_code == 404:
        print(f"ERROR: 404 for {url}.  Check SHA and token permissions.", file=sys.stderr)
        sys.exit(2)
    if resp.status_code == 403:
        print(f"ERROR: 403 for {url}.  Token may be missing or expired.", file=sys.stderr)
        sys.exit(2)
    if not resp.ok:
        print(
            f"ERROR: GitHub API returned {resp.status_code} for {url}: {resp.text[:500]}",
            file=sys.stderr,
        )
        sys.exit(2)
    return resp


def _parse_link_header(link: str) -> dict[str, str]:
    """Parse RFC 5988 Link header into a {rel: url} dict."""
    out: dict[str, str] = {}
    for part in link.split(","):
        section = part.split(";")
        if len(section) < 2:
            continue
        url = section[0].strip().lstrip("<").rstrip(">")
        for rel in section[1:]:
            rel = rel.strip()
            if rel.startswith("rel="):
                value = rel[4:].strip().strip('"')
                out[value] = url
    return out


def _files_from_payload(payload: dict) -> list[FileChange]:
    files: list[FileChange] = []
    for entry in payload.get("files", []):
        files.append(
            FileChange(
                path=entry["filename"],
                previous_path=entry.get("previous_filename"),
                status=entry.get("status", "modified"),
                additions=int(entry.get("additions", 0)),
                deletions=int(entry.get("deletions", 0)),
                patch=entry.get("patch"),
                blob_sha=entry.get("sha"),
            )
        )
    return files


def fetch_commit_files(cfg) -> CommitData:
    owner, repo = cfg["monitored_repo"].split("/", 1)
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if cfg["monitored_token"]:
        headers["Authorization"] = f"Bearer {cfg['monitored_token']}"

    sha = cfg["commit_sha"]
    print(f"Fetching commit {sha} from {cfg['monitored_repo']} (files[] API) ...")
    url = (
        f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
        f"?per_page={COMMITS_API_PER_PAGE}"
    )
    resp = _api_get(url, headers)
    payload = resp.json()
    parents = [p["sha"] for p in payload.get("parents", [])]
    files = _files_from_payload(payload)
    truncated = bool(payload.get("truncated", False))

    next_url = _parse_link_header(resp.headers.get("Link", "")).get("next")
    while next_url:
        page_resp = _api_get(next_url, headers)
        page_payload = page_resp.json()
        files.extend(_files_from_payload(page_payload))
        next_url = _parse_link_header(page_resp.headers.get("Link", "")).get("next")

    is_merge = len(parents) > 1
    if is_merge:
        print(
            f"NOTE: commit {sha[:12]} is a merge with {len(parents)} parents; "
            f"diff above is against the first parent only.",
            file=sys.stderr,
        )

    print(f"Commit fetched: {len(files)} files, truncated={truncated}, merge={is_merge}")
    return CommitData(
        sha=sha,
        parents=parents,
        files=files,
        truncated=truncated,
        is_merge=is_merge,
    )


# ---------------------------------------------------------------------------
# Blob fetch and patch synthesis
#
# The GitHub commits API omits the per-file `patch` in two unrelated cases:
# (1) genuine binary blobs, and (2) text files whose unified diff exceeded
# the per-response size cap (~3 K lines per file).  The latter must NOT be
# treated as binary.  These helpers probe the blob to disambiguate, and
# synthesise a unified-diff patch from the post-image when the API patch
# was missing or truncated.
# ---------------------------------------------------------------------------

# Extension fallback for cases where the blob fetch itself fails (rate
# limited or 404).  Only used as a last resort.
_BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".webp", ".ico",
    ".pdf", ".so", ".dylib", ".dll", ".zip", ".tar", ".gz", ".bz2",
    ".xz", ".7z", ".wasm", ".bin", ".class", ".jar", ".o", ".obj",
    ".exe", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4",
    ".mov", ".avi", ".webm", ".flac", ".ogg",
})

# Heuristic: if the patch we received is at least this many lines AND the
# file's reported additions+deletions materially exceed what the patch
# actually contains, assume the API truncated the patch and refetch.
# GitHub doc says ~3000 lines per file, so we use a slightly lower
# threshold to catch borderline cases.  Documented as a heuristic because
# the API exposes no `patch_truncated` flag (verified against
# https://docs.github.com/en/rest/commits/commits as of 2026-04).
_TRUNCATION_LINE_THRESHOLD = 2_900


def _is_binary_extension(path: str) -> bool:
    lower = path.lower()
    for ext in _BINARY_EXTENSIONS:
        if lower.endswith(ext):
            return True
    return False


def _looks_truncated(patch: str, additions: int, deletions: int) -> bool:
    """
    Heuristic: GitHub does not expose a per-file `patch_truncated` flag,
    so we infer truncation when the patch we received accounts for far
    fewer lines than the file's reported additions+deletions.  Threshold
    pairs the documented ~3000-line cap with a safety margin.
    """
    if not patch:
        return False
    lines = patch.count("\n")
    if lines < _TRUNCATION_LINE_THRESHOLD:
        return False
    expected = additions + deletions
    # Allow a generous fudge factor: the patch contains hunk headers and
    # context lines, so it is usually larger than additions+deletions, not
    # smaller.  If it is meaningfully smaller, it was truncated.
    return expected > 0 and lines < expected * 0.5


def _fetch_blob_soft(cfg: dict, sha: str) -> Optional[bytes]:
    """
    Fetch a blob's raw bytes.  Returns None on rate-limit / 404 / network
    error so the caller can fall back to extension heuristics; never
    exits the process.
    """
    if not sha:
        return None
    import _http as http
    import base64

    owner, repo = cfg["monitored_repo"].split("/", 1)
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if cfg["monitored_token"]:
        headers["Authorization"] = f"Bearer {cfg['monitored_token']}"

    url = f"https://api.github.com/repos/{owner}/{repo}/git/blobs/{sha}"
    try:
        resp = http.get(url, headers=headers, timeout=30)
    except http.HTTPError as e:
        print(f"WARNING: blob fetch network error for {sha}: {e}", file=sys.stderr)
        return None

    if resp.status_code in (403, 429):
        print(
            f"WARNING: blob fetch rate-limited (HTTP {resp.status_code}) for {sha}; "
            f"falling back to extension heuristic.",
            file=sys.stderr,
        )
        return None
    if resp.status_code == 404:
        print(f"WARNING: blob {sha} not found; falling back to extension heuristic.", file=sys.stderr)
        return None
    if not resp.ok:
        print(
            f"WARNING: blob fetch returned {resp.status_code} for {sha}: {resp.text[:200]}",
            file=sys.stderr,
        )
        return None

    payload = resp.json()
    encoding = payload.get("encoding", "base64")
    raw = payload.get("content", "")
    if encoding == "base64":
        try:
            return base64.b64decode(raw)
        except (ValueError, TypeError) as e:
            print(f"WARNING: failed to decode blob {sha}: {e}", file=sys.stderr)
            return None
    if encoding == "utf-8":
        return raw.encode("utf-8", errors="replace")
    print(f"WARNING: unknown blob encoding {encoding!r} for {sha}", file=sys.stderr)
    return None


def _is_binary_bytes(blob: bytes) -> bool:
    """Authoritative binary sniff: NUL byte in the first 8 KB => binary."""
    return b"\x00" in blob[:8192]


def _synthesise_patch_from_blob(file: FileChange, blob: bytes) -> str:
    """
    Reconstruct a unified-diff patch from the post-image of the file.

    For added files we emit every line as `+`-prefixed under a single
    `@@ -0,0 +N,N @@` hunk; for removed files we emit `-`-prefixed under
    `@@ -1,N +0,0 @@`.  For modified/renamed/copied files we have only
    the post-image (we would need the parent commit's blob to construct
    a proper diff), so we emit every line as a context line under
    `@@ -1,N +1,N @@` together with an audit note explaining the trade-off.
    """
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        text = blob.decode("utf-8", errors="replace")

    if text and not text.endswith("\n"):
        text_lines = text.split("\n")
        no_trailing = True
    else:
        text_lines = text[:-1].split("\n") if text else []
        no_trailing = False
    n = len(text_lines)

    lines: list[str] = []
    if file.status == "added":
        lines.append(f"@@ -0,0 +1,{n} @@")
        lines.extend(f"+{l}" for l in text_lines)
    elif file.status == "removed":
        lines.append(f"@@ -1,{n} +0,0 @@")
        lines.extend(f"-{l}" for l in text_lines)
    else:
        # modified / renamed / copied: we only have the post-image so we
        # cannot compute a real diff without fetching the parent blob.
        # Emit as full-file context with an audit note so the panel sees
        # the content and knows nothing has been highlighted.
        lines.append(
            "# audit-note: patch was omitted by API; rendering full post-image only"
        )
        lines.append(f"@@ -1,{n} +1,{n} @@")
        lines.extend(f" {l}" for l in text_lines)
    if no_trailing:
        lines.append("\\ No newline at end of file")
    return "\n".join(lines) + "\n"


def _resolve_patch_omissions(cfg: dict, files: list[FileChange]) -> None:
    """
    For each file with `patch is None` (and status not in
    removed/unchanged), or with a patch that looks truncated, probe the
    blob to decide whether the file is genuinely binary or just had its
    text patch omitted by the API.  Mutates `files` in place.

    For "missing patch" we always probe, regardless of classification:
    without this we cannot tell binary-vs-text and cannot avoid the
    `binary_change` false-positive cluster.

    For "truncated patch" we leave it to the caller to gate by
    classification (see `_resolve_truncated_patches_for_critical`).
    """
    for f in files:
        if f.patch is not None:
            continue
        if f.status in ("removed", "unchanged"):
            # Removals legitimately have no post-image to fetch.
            continue

        blob = _fetch_blob_soft(cfg, f.blob_sha or "")
        if blob is None:
            # Fallback to extension heuristic.  If it looks like a binary
            # extension treat it as binary (no false-positive there);
            # otherwise mark text-but-unavailable so the structural-finding
            # layer can surface it as `text_patch_unavailable`.
            if _is_binary_extension(f.path):
                f.is_binary = True
            else:
                f.patch_omitted = True
                f.patch_unavailable = True
            continue

        if _is_binary_bytes(blob):
            f.is_binary = True
            continue

        # Text file whose patch was omitted by the API: synthesise.
        f.patch = _synthesise_patch_from_blob(f, blob)
        f.patch_omitted = True
        f.patch_synthesised = True


def _resolve_truncated_patches_for_critical(
    cfg: dict,
    classified: list[ClassifiedFile],
) -> None:
    """
    For critical and high files whose patch looks truncated by the API,
    refetch the blob and replace the patch with a synthesised post-image
    rendering.  Lower-classification files keep the truncated patch (cost
    gate against the per-file blob API).

    Modified-status files lose the original `-/+` markers because we only
    fetch the post-image; that trade-off is documented in
    `_synthesise_patch_from_blob`.
    """
    for c in classified:
        if c.classification not in ("critical", "high"):
            continue
        f = c.file
        if f.patch is None:
            continue  # already handled by _resolve_patch_omissions
        if not _looks_truncated(f.patch, f.additions, f.deletions):
            continue
        blob = _fetch_blob_soft(cfg, f.blob_sha or "")
        if blob is None:
            f.patch_omitted = True
            f.patch_unavailable = True
            continue
        if _is_binary_bytes(blob):
            # Surprising — a binary file should not have produced a patch
            # at all.  Treat as binary and drop the truncated patch.
            f.patch = None
            f.is_binary = True
            continue
        f.patch = _synthesise_patch_from_blob(f, blob)
        f.patch_omitted = True
        f.patch_synthesised = True


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def _classification_rank(c: str) -> int:
    try:
        return CLASSIFICATION_ORDER.index(c)
    except ValueError:
        return len(CLASSIFICATION_ORDER)


def _classify_path(path: str, manifest: Manifest) -> tuple[str, list[str]]:
    """Return (classification, matched_rule_reasons) using highest-wins."""
    matched: list[ManifestRule] = [r for r in manifest.rules if r.matches(path)]
    if not matched:
        return manifest.default_classification, []
    best = min(matched, key=lambda r: _classification_rank(r.classification))
    matched_reasons = [r.reason or r.pattern for r in matched]
    return best.classification, matched_reasons


def classify_files(files: list[FileChange], manifest: Manifest) -> list[ClassifiedFile]:
    """Classify each file; renames are classified as the higher of old/new path."""
    out: list[ClassifiedFile] = []
    for f in files:
        new_class, new_reasons = _classify_path(f.path, manifest)
        all_reasons = list(new_reasons)
        winning_class = new_class
        if f.previous_path and f.previous_path != f.path:
            old_class, old_reasons = _classify_path(f.previous_path, manifest)
            for r in old_reasons:
                tag = f"renamed_from:{r}"
                if tag not in all_reasons:
                    all_reasons.append(tag)
            if _classification_rank(old_class) < _classification_rank(winning_class):
                winning_class = old_class
        out.append(
            ClassifiedFile(file=f, classification=winning_class, matched_rules=all_reasons)
        )
    return out


# ---------------------------------------------------------------------------
# Structural findings (deterministic, bypass the LLM)
# ---------------------------------------------------------------------------

GENERATED_HEADER = "//! Do not edit manually"


def detect_structural_findings(files: list[FileChange]) -> list[StructuralFinding]:
    findings: list[StructuralFinding] = []
    for f in files:
        if f.is_binary:
            findings.append(
                StructuralFinding(
                    type="binary_change",
                    path=f.path,
                    description=(
                        f"Binary file {f.status} (NUL bytes detected in blob); content "
                        f"is not visible to the LLM panel.  Verify the blob "
                        f"(sha={f.blob_sha or 'unknown'}) by hand."
                    ),
                )
            )
        elif f.patch_unavailable:
            findings.append(
                StructuralFinding(
                    type="text_patch_unavailable",
                    path=f.path,
                    description=(
                        f"Text file {f.status} but the unified diff was omitted by the "
                        f"GitHub API and the blob fetch failed (rate limit or 404), so "
                        f"no patch was reconstructed.  Verify the blob "
                        f"(sha={f.blob_sha or 'unknown'}) by hand."
                    ),
                )
            )
        if f.patch and "Subproject commit" in f.patch:
            findings.append(
                StructuralFinding(
                    type="submodule_pointer",
                    path=f.path,
                    description="Submodule pointer change. Verify the new commit and upstream URL.",
                )
            )
        if f.patch and _generated_header_removed(f.patch):
            findings.append(
                StructuralFinding(
                    type="generated_header_removed",
                    path=f.path,
                    description=(
                        f"The '{GENERATED_HEADER}' header was removed. An auto-generated file "
                        f"is being treated as hand-written; the audit's low-classification of "
                        f"this path no longer applies."
                    ),
                )
            )
        if f.patch:
            unicode_desc = _detect_unicode_risk(f.patch)
            if unicode_desc:
                findings.append(
                    StructuralFinding(
                        type="unicode_risk",
                        path=f.path,
                        description=(
                            f"Suspicious Unicode in added lines: {unicode_desc}.  "
                            f"These can disguise the visual reading of code from the "
                            f"patch even when the byte-level diff is correct."
                        ),
                    )
                )
        if f.patch and _is_lockfile_path(f.path):
            findings.extend(_detect_lockfile_delta(f.path, f.patch))
    return findings


# Bidi-control codepoints (Trojan Source — CVE-2021-42574).
_BIDI_CONTROLS: dict[str, str] = {
    "\u202a": "U+202A LRE",
    "\u202b": "U+202B RLE",
    "\u202c": "U+202C PDF",
    "\u202d": "U+202D LRO",
    "\u202e": "U+202E RLO",
    "\u2066": "U+2066 LRI",
    "\u2067": "U+2067 RLI",
    "\u2068": "U+2068 FSI",
    "\u2069": "U+2069 PDI",
}

# Zero-width / invisible codepoints used to disguise identifiers.
_ZERO_WIDTH: dict[str, str] = {
    "\u200b": "U+200B ZWSP",
    "\u200c": "U+200C ZWNJ",
    "\u200d": "U+200D ZWJ",
    "\ufeff": "U+FEFF BOM",
}

# Identifier-token pattern: ASCII identifier-ish characters plus any
# non-ASCII letter-ish characters and the zero-width invisibles, so we can
# reach inside the token when scanning for hazards.
_IDENT_TOKEN_RE = re.compile(
    r"[A-Za-z_\u0080-\uFFFF\u200b\u200c\u200d\ufeff]"
    r"[A-Za-z0-9_\u0080-\uFFFF\u200b\u200c\u200d\ufeff]*"
)


def _script_of(ch: str) -> Optional[str]:
    """
    Return a coarse Unicode-script label for `ch`, or None if the character
    is not a letter we care about for mixed-script detection.

    Scoped to the high-signal homoglyph attack scripts called out in the
    brief: Latin (ASCII letters) and Cyrillic / Greek.  Other scripts return
    None, which means a Latin+Han or Latin+Hebrew identifier will not be
    flagged as mixed-script — this is a deliberate scope reduction to keep
    false-positive noise low on legitimate i18n content.
    """
    cp = ord(ch)
    # Latin (ASCII letters only — Latin-1 supplement etc. is excluded so
    # umlauts / accents in legitimate identifiers do not collide).
    if (0x41 <= cp <= 0x5A) or (0x61 <= cp <= 0x7A):
        return "Latin"
    # Cyrillic + Cyrillic Supplement.
    if (0x0400 <= cp <= 0x04FF) or (0x0500 <= cp <= 0x052F):
        return "Cyrillic"
    # Greek + Coptic, Greek Extended.
    if (0x0370 <= cp <= 0x03FF) or (0x1F00 <= cp <= 0x1FFF):
        return "Greek"
    return None


def _detect_unicode_risk(patch: str) -> Optional[str]:
    """
    Inspect a unified diff and return a human-readable description of any
    Unicode-Trojan / homoglyph hazards present in *added* lines but not
    already present on the *removed* side (so removing an attack does not
    fire a finding).  Returns None if nothing suspicious is found.
    """
    is_new_file = False
    added_lines: list[str] = []
    removed_text_chars: set[str] = set()
    for raw in patch.splitlines():
        # Diff metadata.
        if raw.startswith("diff --git") or raw.startswith("index "):
            continue
        if raw.startswith("+++") or raw.startswith("---"):
            continue
        if raw.startswith("@@"):
            continue
        # `new file mode …` is part of extended header; flag it.
        if raw.startswith("new file"):
            is_new_file = True
            continue
        if raw.startswith("+"):
            added_lines.append(raw[1:])
        elif raw.startswith("-"):
            for ch in raw[1:]:
                if ch in _BIDI_CONTROLS or ch in _ZERO_WIDTH:
                    removed_text_chars.add(ch)
        # context / other lines: ignore

    if not added_lines:
        return None

    notes: list[str] = []
    seen_bidi: set[str] = set()
    seen_zw: set[tuple[str, str]] = set()  # (label, identifier)
    seen_mixed: set[tuple[str, frozenset[str]]] = set()

    for idx, line in enumerate(added_lines):
        # Bidi controls — additions only, and only those that didn't appear
        # somewhere on the `-` side (which would be removal of an attack).
        for ch, label in _BIDI_CONTROLS.items():
            if ch in line and ch not in removed_text_chars and label not in seen_bidi:
                seen_bidi.add(label)
                notes.append(f"bidi control {label}")

        # Zero-width hazards inside identifier-looking tokens.
        for m in _IDENT_TOKEN_RE.finditer(line):
            token = m.group(0)
            # BOM at the very first character of the very first added line of
            # a `new file` patch is a legitimate UTF-8 BOM, not an attack.
            for ch, label in _ZERO_WIDTH.items():
                if ch not in token:
                    continue
                if (
                    ch == "\ufeff"
                    and is_new_file
                    and idx == 0
                    and m.start() == 0
                    and token.startswith("\ufeff")
                ):
                    continue
                # Strip invisibles to recover a printable identifier handle.
                visible = token
                for invisible in _ZERO_WIDTH:
                    visible = visible.replace(invisible, "")
                key = (label, visible)
                if key in seen_zw:
                    continue
                seen_zw.add(key)
                handle = visible if visible else "(empty)"
                notes.append(f"zero-width {label} in identifier '{handle}'")

            # Mixed-script identifier detection.
            scripts = {_script_of(c) for c in token}
            scripts.discard(None)
            if len(scripts) >= 2:
                visible = token
                for invisible in _ZERO_WIDTH:
                    visible = visible.replace(invisible, "")
                script_set = frozenset(scripts)
                key2 = (visible, script_set)
                if key2 in seen_mixed:
                    continue
                seen_mixed.add(key2)
                scripts_str = "+".join(sorted(scripts))  # type: ignore[arg-type]
                notes.append(
                    f"mixed-script identifier '{visible}' ({scripts_str})"
                )

    if not notes:
        return None
    return ", ".join(notes)


def _generated_header_removed(patch: str) -> bool:
    """True iff the patch removes a GENERATED_HEADER line without re-adding one."""
    removed = False
    added = False
    for line in patch.splitlines():
        if line.startswith("-") and not line.startswith("---") and GENERATED_HEADER in line:
            removed = True
        elif line.startswith("+") and not line.startswith("+++") and GENERATED_HEADER in line:
            added = True
    return removed and not added


# ---------------------------------------------------------------------------
# Lockfile delta detection
# ---------------------------------------------------------------------------

# Canonical lockfile basenames the deterministic delta parser handles.  Match
# on basename (case-sensitive) so monorepo paths like `crates/foo/Cargo.lock`
# are picked up.
_LOCKFILE_BASENAMES: frozenset[str] = frozenset(
    {
        "Cargo.lock",
        "package-lock.json",
        "pnpm-lock.yaml",
        "uv.lock",
        "poetry.lock",
    }
)


def _is_lockfile_path(path: str) -> bool:
    return path.rsplit("/", 1)[-1] in _LOCKFILE_BASENAMES


def _reconstruct_pre_post_from_patch(
    patch: str,
) -> tuple[Optional[str], Optional[str]]:
    """
    Replay a unified diff to reconstruct the *before* and *after* text fragments
    that the patch makes visible.  Lines beginning with `-` (excluding the `---`
    file header) are pre-only; `+` (excluding `+++`) are post-only; ` ` are in
    both; `\\` (no newline at EOF) and other metadata are skipped.

    Returns `(pre_text, post_text)` if at least one usable hunk was decoded.
    Returns `(None, None)` if the patch contains no decodable hunks at all,
    so the caller can emit the unparseable-fallback finding.

    Note: this only recovers the regions visible in hunks.  Lockfile parsing
    therefore operates on partial documents — that is fine because we extract
    per-package fragments via regex, not whole-document parsing.
    """
    pre_parts: list[str] = []
    post_parts: list[str] = []
    in_hunk = False
    saw_hunk = False
    for raw in patch.splitlines():
        if raw.startswith("@@"):
            in_hunk = True
            saw_hunk = True
            # Insert a sentinel newline between hunks so adjacent regions do
            # not glue together and create false `[[package]]` matches.
            if pre_parts:
                pre_parts.append("")
            if post_parts:
                post_parts.append("")
            continue
        if not in_hunk:
            # File-level diff metadata (diff --git, index, ---, +++, mode
            # lines, etc.) — ignore.
            continue
        if raw.startswith("\\"):
            # `\ No newline at end of file` marker.
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            post_parts.append(raw[1:])
        elif raw.startswith("-") and not raw.startswith("---"):
            pre_parts.append(raw[1:])
        elif raw.startswith(" "):
            pre_parts.append(raw[1:])
            post_parts.append(raw[1:])
        elif raw == "":
            # An empty patch line is a context line on a blank source line.
            pre_parts.append("")
            post_parts.append("")
        else:
            # Unrecognised line in a hunk — diff is likely truncated.  Bail.
            return (None, None)

    if not saw_hunk:
        return (None, None)
    return ("\n".join(pre_parts), "\n".join(post_parts))


# Cargo.lock / uv.lock / poetry.lock all share the `[[package]]` array-table
# shape.  We extract per-package fragments by splitting on the table header
# and then pulling name / version / source / git-rev fields with regex.  We
# deliberately do NOT call `tomllib.loads` on the partial text reconstructed
# from a hunk — that text is almost always not a valid TOML document because
# the diff only includes the hunks, not the surrounding tables.

_TOML_PACKAGE_HEADER_RE = re.compile(r"(?m)^\[\[package\]\]\s*$")
_TOML_NAME_RE = re.compile(r'(?m)^name\s*=\s*"([^"]+)"\s*$')
_TOML_VERSION_RE = re.compile(r'(?m)^version\s*=\s*"([^"]+)"\s*$')
_TOML_SOURCE_RE = re.compile(r'(?m)^source\s*=\s*"([^"]+)"\s*$')
# Poetry `[package.source]` sub-table fields.
_TOML_SOURCE_URL_RE = re.compile(r'(?m)^url\s*=\s*"([^"]+)"\s*$')
_TOML_SOURCE_REFERENCE_RE = re.compile(r'(?m)^reference\s*=\s*"([^"]+)"\s*$')
# uv source table is inline `source = { git = "...", rev = "..." }` or sub-table.
_TOML_GIT_INLINE_RE = re.compile(
    r'source\s*=\s*\{[^}]*\bgit\s*=\s*"([^"]+)"[^}]*\}'
)
_TOML_REV_INLINE_RE = re.compile(
    r'source\s*=\s*\{[^}]*\brev\s*=\s*"([^"]+)"[^}]*\}'
)


@dataclass
class _TomlPackageFacts:
    """Per-package facts extracted from a TOML lockfile fragment."""

    version: Optional[str] = None
    source: Optional[str] = None
    git_url: Optional[str] = None
    git_rev: Optional[str] = None
    # Poetry's `[package.source]` sub-table.
    source_url: Optional[str] = None
    source_reference: Optional[str] = None


def _extract_toml_packages(text: str) -> dict[str, _TomlPackageFacts]:
    """
    Scan `text` (a partial TOML lockfile fragment recovered from a diff) and
    return `{name: _TomlPackageFacts}` for every `[[package]]` block whose
    `name` is present.  Packages without a `name` are silently dropped — they
    are typically truncated context-only fragments and have no identity.
    """
    out: dict[str, _TomlPackageFacts] = {}
    # Prepend an anchor so str split keeps text before the first header out.
    splits = _TOML_PACKAGE_HEADER_RE.split(text)
    # The first split is whatever appears before the first `[[package]]` —
    # discard it.  Remaining items are the body of each `[[package]]` block,
    # terminated by either the next `[[package]]` (already consumed by split)
    # or the next `[`-table header (which we trim out below).
    for body in splits[1:]:
        # Trim at the next non-package table header so we don't bleed into
        # `[[patch]]`, `[metadata]`, etc.  We deliberately keep `[package.*]`
        # sub-tables inside the body (poetry uses `[package.source]`,
        # `[package.dependencies]`, etc.); only `[metadata]`, `[[patch]]`,
        # and similar siblings end the package.
        next_table = re.search(
            r"(?m)^\[(?!\[package\]\]|package\.)[^\n]*$",
            body,
        )
        if next_table:
            body = body[: next_table.start()]

        name_m = _TOML_NAME_RE.search(body)
        if not name_m:
            continue
        name = name_m.group(1)

        facts = _TomlPackageFacts()
        ver_m = _TOML_VERSION_RE.search(body)
        if ver_m:
            facts.version = ver_m.group(1)
        src_m = _TOML_SOURCE_RE.search(body)
        if src_m:
            facts.source = src_m.group(1)
            # Cargo.lock encodes git deps as `git+<url>#<rev>` inside the
            # source string.
            git_m = re.match(r"git\+([^#]+)#([0-9a-f]+)", facts.source)
            if git_m:
                facts.git_url = git_m.group(1)
                facts.git_rev = git_m.group(2)

        # uv.lock-style inline source table.
        if facts.git_url is None:
            inline_git = _TOML_GIT_INLINE_RE.search(body)
            if inline_git:
                facts.git_url = inline_git.group(1)
                inline_rev = _TOML_REV_INLINE_RE.search(body)
                if inline_rev:
                    facts.git_rev = inline_rev.group(1)

        # Poetry `[package.source]` sub-table.  Look for it within the body.
        sub = re.search(
            r"(?ms)^\[package\.source\]\s*$(.*?)(?=^\[|\Z)",
            body,
        )
        if sub:
            sub_body = sub.group(1)
            url_m = _TOML_SOURCE_URL_RE.search(sub_body)
            if url_m:
                facts.source_url = url_m.group(1)
                if facts.git_url is None:
                    facts.git_url = url_m.group(1)
            ref_m = _TOML_SOURCE_REFERENCE_RE.search(sub_body)
            if ref_m:
                facts.source_reference = ref_m.group(1)
                if facts.git_rev is None:
                    facts.git_rev = ref_m.group(1)

        # Last-write-wins is acceptable: the diff fragment only contains a
        # given package once unless the whole table is being rewritten, in
        # which case the final state is what matters.
        out[name] = facts
    return out


# package-lock.json: extract per-`packages` map entries.  We treat each
# `"node_modules/<...>": { ... }` (or `"": { ... }` for the root) as one row.
# The body is balanced-brace; we find it by matching `{` to the next `}` at
# the same nesting depth.

@dataclass
class _NpmPackageFacts:
    version: Optional[str] = None
    resolved: Optional[str] = None
    integrity: Optional[str] = None


def _extract_npm_packages(text: str) -> dict[str, _NpmPackageFacts]:
    out: dict[str, _NpmPackageFacts] = {}
    # Keys we care about: any `"<key>": {` where the key starts the line of a
    # `packages` member.  We don't enforce that we are *inside* `"packages":`
    # because the diff fragment may not show that context line.  Instead we
    # accept any string-key whose immediate value is an object containing
    # `version` / `resolved` / `integrity` lockfile fields.
    key_re = re.compile(r'(?m)^\s*"([^"]*)"\s*:\s*\{')
    for m in key_re.finditer(text):
        key = m.group(1)
        # Skip well-known top-level scalar keys.
        if key in {"name", "version", "lockfileVersion", "requires", "dependencies", "packages"}:
            continue
        # Find the matching close-brace at the same nesting depth.
        depth = 1
        i = m.end()
        in_str = False
        escape = False
        end = -1
        while i < len(text):
            ch = text[i]
            if escape:
                escape = False
            elif ch == "\\" and in_str:
                escape = True
            elif ch == '"':
                in_str = not in_str
            elif not in_str:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            i += 1
        if end < 0:
            # Unbalanced — likely a hunk that cuts mid-object.  Use what we
            # have so far for field extraction.
            body = text[m.end() :]
        else:
            body = text[m.end() : end]
        facts = _NpmPackageFacts()
        ver_m = re.search(r'"version"\s*:\s*"([^"]+)"', body)
        if ver_m:
            facts.version = ver_m.group(1)
        res_m = re.search(r'"resolved"\s*:\s*"([^"]+)"', body)
        if res_m:
            facts.resolved = res_m.group(1)
        int_m = re.search(r'"integrity"\s*:\s*"([^"]+)"', body)
        if int_m:
            facts.integrity = int_m.group(1)
        # Only keep entries that look like real packages (have at least one
        # of the lockfile fields).  This filters out random nested objects
        # picked up from truncated context.
        if facts.version or facts.resolved or facts.integrity:
            out[key] = facts
    return out


# pnpm-lock.yaml: regex extractor.  pnpm-lock.yaml is whitespace-sensitive
# YAML; the repo has no PyYAML dependency and we are forbidden from adding
# one, so this minimal extractor pulls per-package keys (`/<name>@<version>:`
# in v5, or `<name>@<version>:` in v6+) plus the indented `resolution.tarball`
# / `resolution.integrity` / `resolution.commit` lines.  When the shape
# defeats this extractor, the caller falls back to the unparseable finding.

@dataclass
class _PnpmPackageFacts:
    tarball: Optional[str] = None
    integrity: Optional[str] = None
    commit: Optional[str] = None


_PNPM_PKG_KEY_RE = re.compile(
    r"(?m)^  /?(?P<key>[^\s:][^\s]*@[^\s:]+):\s*$"
)


def _extract_pnpm_packages(text: str) -> dict[str, _PnpmPackageFacts]:
    out: dict[str, _PnpmPackageFacts] = {}
    matches = list(_PNPM_PKG_KEY_RE.finditer(text))
    for idx, m in enumerate(matches):
        key = m.group("key")
        start = m.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        body = text[start:end]
        facts = _PnpmPackageFacts()
        # `resolution:` block lines: look for tarball / integrity / commit
        # under any indent level greater than 4 spaces.
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith("tarball:"):
                facts.tarball = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("integrity:"):
                facts.integrity = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("commit:"):
                facts.commit = stripped.split(":", 1)[1].strip()
        out[key] = facts
    return out


def _detect_lockfile_delta(path: str, patch: str) -> list[StructuralFinding]:
    """
    Parse a lockfile patch and emit one `lockfile_delta` finding per changed
    package.  Falls back to a single "could not be parsed deterministically"
    finding when the diff is too truncated to reconstruct usable pre/post
    fragments, so we never silently miss a change.
    """
    basename = path.rsplit("/", 1)[-1]
    pre, post = _reconstruct_pre_post_from_patch(patch)
    if pre is None or post is None:
        return [_lockfile_unparseable(path, basename)]

    try:
        if basename in {"Cargo.lock", "uv.lock", "poetry.lock"}:
            return _diff_toml_lockfile(path, basename, pre, post)
        if basename == "package-lock.json":
            return _diff_npm_lockfile(path, basename, pre, post)
        if basename == "pnpm-lock.yaml":
            return _diff_pnpm_lockfile(path, basename, pre, post)
    except Exception:
        # Any unexpected shape collapses to the unparseable fallback rather
        # than crashing the audit.
        return [_lockfile_unparseable(path, basename)]
    return []


def _lockfile_unparseable(path: str, basename: str) -> StructuralFinding:
    return StructuralFinding(
        type="lockfile_delta",
        path=path,
        description=(
            f"{basename}: lockfile changed but could not be parsed "
            f"deterministically; review by hand."
        ),
    )


def _diff_toml_lockfile(
    path: str, basename: str, pre: str, post: str
) -> list[StructuralFinding]:
    pre_pkgs = _extract_toml_packages(pre)
    post_pkgs = _extract_toml_packages(post)
    findings: list[StructuralFinding] = []
    names = sorted(set(pre_pkgs) | set(post_pkgs))
    for name in names:
        pre_f = pre_pkgs.get(name)
        post_f = post_pkgs.get(name)
        desc = _describe_toml_change(basename, name, pre_f, post_f)
        if desc is not None:
            findings.append(
                StructuralFinding(type="lockfile_delta", path=path, description=desc)
            )
    if not findings and (pre_pkgs or post_pkgs):
        # We saw packages in the diff but none of them looked changed.  This
        # happens when the hunk only touches header / metadata lines.  Stay
        # silent — the LLM panel handles non-package edits.
        return []
    if not findings and not pre_pkgs and not post_pkgs:
        # Diff did not surface a single named package — could be a tiny
        # comment-only change, or it could be a heavily truncated hunk that
        # missed every `name = "..."` line.  Emit the unparseable finding
        # so we don't silently miss a real change.
        return [_lockfile_unparseable(path, basename)]
    return findings


def _describe_toml_change(
    basename: str,
    name: str,
    pre: Optional[_TomlPackageFacts],
    post: Optional[_TomlPackageFacts],
) -> Optional[str]:
    if pre is None and post is not None:
        # Added.
        if post.git_url and post.git_rev:
            return (
                f"{basename}: {name} added at git+{post.git_url}#{post.git_rev}, "
                f"git-pinned dependency introduced."
            )
        if post.version:
            src = post.source or "registry"
            return f"{basename}: {name} {post.version} added (source {src})."
        return f"{basename}: {name} added."
    if pre is not None and post is None:
        # Removed.
        if pre.version:
            return f"{basename}: {name} {pre.version} removed."
        return f"{basename}: {name} removed."

    # Both sides present — compare.
    assert pre is not None and post is not None
    notes: list[str] = []
    if pre.version != post.version and (pre.version or post.version):
        notes.append(
            f"{pre.version or '(none)'} \u2192 {post.version or '(none)'}"
        )
    # Source flip (registry vs git etc.)
    pre_src = pre.source or pre.source_url
    post_src = post.source or post.source_url
    if pre_src != post_src and (pre_src or post_src):
        notes.append(
            f"source {pre_src or '(none)'} \u2192 {post_src or '(none)'}"
        )
    # Git-rev pin rotation — flag separately so a same-version different-rev
    # change ("pin rotate") is visible.
    pre_rev = pre.git_rev or pre.source_reference
    post_rev = post.git_rev or post.source_reference
    if pre_rev != post_rev and (pre_rev or post_rev):
        # Avoid double-reporting when the rev change is already implicit in
        # the source change.
        if not any(n.startswith("source ") for n in notes):
            notes.append(
                f"git rev {pre_rev or '(none)'} \u2192 {post_rev or '(none)'}"
            )
        elif pre.version == post.version:
            # Same version, different rev — explicit pin-rotate.
            notes.append(
                f"git rev {pre_rev or '(none)'} \u2192 {post_rev or '(none)'}"
            )
    if not notes:
        return None
    return f"{basename}: {name} " + ", ".join(notes) + "."


def _diff_npm_lockfile(
    path: str, basename: str, pre: str, post: str
) -> list[StructuralFinding]:
    pre_pkgs = _extract_npm_packages(pre)
    post_pkgs = _extract_npm_packages(post)
    findings: list[StructuralFinding] = []
    keys = sorted(set(pre_pkgs) | set(post_pkgs))
    for key in keys:
        pre_f = pre_pkgs.get(key)
        post_f = post_pkgs.get(key)
        desc = _describe_npm_change(basename, key, pre_f, post_f)
        if desc is not None:
            findings.append(
                StructuralFinding(type="lockfile_delta", path=path, description=desc)
            )
    if not findings and not pre_pkgs and not post_pkgs:
        return [_lockfile_unparseable(path, basename)]
    return findings


def _describe_npm_change(
    basename: str,
    key: str,
    pre: Optional[_NpmPackageFacts],
    post: Optional[_NpmPackageFacts],
) -> Optional[str]:
    label = key or "(root)"
    if pre is None and post is not None:
        bits: list[str] = []
        if post.version:
            bits.append(post.version)
        if post.resolved:
            bits.append(f"resolved {post.resolved}")
        if post.integrity:
            bits.append(f"integrity {post.integrity}")
        suffix = (" " + ", ".join(bits)) if bits else ""
        return f"{basename}: {label} added{suffix}."
    if pre is not None and post is None:
        return f"{basename}: {label} {pre.version or ''} removed.".replace("  ", " ")

    assert pre is not None and post is not None
    notes: list[str] = []
    version_changed = pre.version != post.version and (pre.version or post.version)
    if version_changed:
        notes.append(
            f"{pre.version or '(none)'} \u2192 {post.version or '(none)'}"
        )
    if pre.resolved != post.resolved and (pre.resolved or post.resolved):
        notes.append(
            f"resolved {pre.resolved or '(none)'} \u2192 {post.resolved or '(none)'}"
        )
    # If the version changed, the integrity must have changed too — that's
    # implied, not a separate event.  Suppress.  Only surface integrity when
    # the version did NOT change (pin-rotate / re-publish).
    if (
        not version_changed
        and pre.integrity != post.integrity
        and (pre.integrity or post.integrity)
    ):
        notes.append(
            f"integrity {pre.integrity or '(none)'} \u2192 {post.integrity or '(none)'}"
        )
    if not notes:
        return None
    return f"{basename}: {label} " + ", ".join(notes) + "."


def _diff_pnpm_lockfile(
    path: str, basename: str, pre: str, post: str
) -> list[StructuralFinding]:
    pre_pkgs = _extract_pnpm_packages(pre)
    post_pkgs = _extract_pnpm_packages(post)
    findings: list[StructuralFinding] = []
    keys = sorted(set(pre_pkgs) | set(post_pkgs))
    for key in keys:
        pre_f = pre_pkgs.get(key)
        post_f = post_pkgs.get(key)
        desc = _describe_pnpm_change(basename, key, pre_f, post_f)
        if desc is not None:
            findings.append(
                StructuralFinding(type="lockfile_delta", path=path, description=desc)
            )
    if not findings and not pre_pkgs and not post_pkgs:
        return [_lockfile_unparseable(path, basename)]
    return findings


def _describe_pnpm_change(
    basename: str,
    key: str,
    pre: Optional[_PnpmPackageFacts],
    post: Optional[_PnpmPackageFacts],
) -> Optional[str]:
    if pre is None and post is not None:
        if post.commit:
            return (
                f"{basename}: {key} added with git commit {post.commit}, "
                f"git-pinned dependency introduced."
            )
        if post.tarball:
            return f"{basename}: {key} added with tarball {post.tarball}."
        return f"{basename}: {key} added."
    if pre is not None and post is None:
        return f"{basename}: {key} removed."

    assert pre is not None and post is not None
    notes: list[str] = []
    if pre.tarball != post.tarball and (pre.tarball or post.tarball):
        notes.append(
            f"tarball {pre.tarball or '(none)'} \u2192 {post.tarball or '(none)'}"
        )
    if pre.commit != post.commit and (pre.commit or post.commit):
        notes.append(
            f"commit {pre.commit or '(none)'} \u2192 {post.commit or '(none)'}"
        )
    # Integrity is implied by tarball changes; only surface if tarball is
    # stable but integrity changed (pin-rotate).
    if (
        pre.tarball == post.tarball
        and pre.integrity != post.integrity
        and (pre.integrity or post.integrity)
    ):
        notes.append(
            f"integrity {pre.integrity or '(none)'} \u2192 {post.integrity or '(none)'}"
        )
    if not notes:
        return None
    return f"{basename}: {key} " + ", ".join(notes) + "."


# ---------------------------------------------------------------------------
# File-mode flips and symlink-target changes
#
# Both attack vectors are stored in the Git tree (the file's `mode` field)
# rather than in the file contents, so they are completely invisible in the
# unified-diff `patch`.  Detecting them requires comparing the parent's tree
# with the new commit's tree.
#
# Implementation choice: we use the Git Trees API (`recursive=1`) for both
# sides, not the per-file Contents API.  Rationale:
#   1. The Contents API does NOT expose the executable bit in its JSON
#      response.  It returns `type="file"` regardless of whether the mode is
#      `100644` or `100755`, so it cannot detect mode flips at all.
#   2. The Trees API DOES include the `mode` field on every entry, and a
#      single recursive fetch covers all files.  Two API calls (parent +
#      commit) is a flat cost regardless of how many files changed — cheaper
#      than per-file Contents calls for any non-trivial commit.
#
# When the recursive tree is `truncated` (very large repositories), we fall
# back to per-file Contents API calls for symlink-target detection, since
# that is the only thing the Contents API can still answer.  Mode-flip
# detection becomes best-effort and is silently dropped for affected files;
# we emit a single `mode_check_unavailable` finding to make the limitation
# visible.
# ---------------------------------------------------------------------------

# Git tree modes we care about.
_MODE_NON_EXECUTABLE = "100644"
_MODE_EXECUTABLE = "100755"
_MODE_SYMLINK = "120000"


def _mode_changes_enabled() -> bool:
    """Return True when ``AUDIT_DETECT_MODE_CHANGES`` env var requests the
    extra check.  Recognises ``1`` / ``true`` (case-insensitive)."""
    return os.environ.get("AUDIT_DETECT_MODE_CHANGES", "").strip().lower() in (
        "1",
        "true",
    )


def _fetch_recursive_tree(
    cfg: dict, sha: str
) -> tuple[Optional[dict[str, dict]], bool, bool]:
    """
    Fetch the recursive Git tree for ``sha`` and return
    ``(by_path, truncated, ok)``.

    ``by_path`` maps path -> raw tree entry dict (keys ``mode``, ``type``,
    ``sha``).  ``truncated`` mirrors the API's ``truncated`` flag.  ``ok`` is
    False when the call failed for any reason (network, 4xx, 5xx, malformed
    JSON), in which case ``by_path`` is None — callers must treat this as
    "we cannot tell" rather than "no changes".

    Never exits the process.  Errors are logged to stderr and reported via
    the ``ok`` return.
    """
    import _http as http

    owner, repo = cfg["monitored_repo"].split("/", 1)
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if cfg["monitored_token"]:
        headers["Authorization"] = f"Bearer {cfg['monitored_token']}"

    url = (
        f"https://api.github.com/repos/{owner}/{repo}/git/trees/{sha}?recursive=1"
    )
    try:
        resp = http.get(url, headers=headers, timeout=30)
    except http.HTTPError as e:
        print(
            f"WARNING: mode-change tree fetch network error for {sha}: {e}",
            file=sys.stderr,
        )
        return None, False, False

    if not resp.ok:
        print(
            f"WARNING: mode-change tree fetch returned {resp.status_code} "
            f"for {sha}: {resp.text[:200]}",
            file=sys.stderr,
        )
        return None, False, False

    try:
        payload = resp.json()
    except Exception as e:
        print(
            f"WARNING: mode-change tree response was not valid JSON for "
            f"{sha}: {e}",
            file=sys.stderr,
        )
        return None, False, False

    by_path: dict[str, dict] = {}
    for entry in payload.get("tree", []):
        path = entry.get("path")
        if not path:
            continue
        by_path[path] = entry
    return by_path, bool(payload.get("truncated", False)), True


def _fetch_symlink_target_via_contents(
    cfg: dict, path: str, ref: str
) -> Optional[str]:
    """
    Soft fetch a symlink's target string via the Contents API at ``ref``.

    Returns the target string when the path is a symlink at that ref, or
    None when the path doesn't exist, isn't a symlink, or the fetch failed.
    Never exits the process.
    """
    import _http as http
    import urllib.parse

    owner, repo = cfg["monitored_repo"].split("/", 1)
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if cfg["monitored_token"]:
        headers["Authorization"] = f"Bearer {cfg['monitored_token']}"

    quoted = urllib.parse.quote(path)
    url = (
        f"https://api.github.com/repos/{owner}/{repo}/contents/{quoted}"
        f"?ref={ref}"
    )
    try:
        resp = http.get(url, headers=headers, timeout=30)
    except http.HTTPError as e:
        print(
            f"WARNING: contents fetch network error for {path}@{ref}: {e}",
            file=sys.stderr,
        )
        return None
    if not resp.ok:
        return None
    try:
        payload = resp.json()
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("type") != "symlink":
        return None
    target = payload.get("target")
    return target if isinstance(target, str) else None


def _detect_mode_changes(
    cfg: dict,
    commit: CommitData,
    classified: list[ClassifiedFile],
) -> list[StructuralFinding]:
    """
    Detect file-mode flips (100644 <-> 100755) and symlink-target changes
    that are invisible in the unified-diff patch.

    See the section docstring above for the rationale on using the Trees API
    rather than per-file Contents calls.

    Errors are non-fatal: any failure to fetch a tree results in a single
    ``mode_check_unavailable`` finding and the function returns.
    """
    if not commit.parents:
        # Initial commit — nothing to diff modes against.
        return []
    parent_sha = commit.parents[0]

    new_tree, new_truncated, new_ok = _fetch_recursive_tree(cfg, commit.sha)
    parent_tree, parent_truncated, parent_ok = _fetch_recursive_tree(cfg, parent_sha)

    if not new_ok or not parent_ok:
        return [
            StructuralFinding(
                type="mode_check_unavailable",
                path="",
                description=(
                    "File-mode / symlink-target check was requested via "
                    "AUDIT_DETECT_MODE_CHANGES but the Git Trees API call "
                    "failed.  Mode flips and symlink-target changes for "
                    "this commit could not be verified."
                ),
            )
        ]

    findings: list[StructuralFinding] = []
    truncated_warning_emitted = False

    # Index commit.files by path for status lookup.  The classified list and
    # commit.files share the same FileChange instances, but we accept the
    # already-built classified argument to keep the signature aligned with
    # the brief.
    files_by_path: dict[str, FileChange] = {c.file.path: c.file for c in classified}

    for path, fc in files_by_path.items():
        status = fc.status
        # Resolve the "previous" path for renames so we can pick up the
        # parent-side entry.
        prev_path = fc.previous_path or path

        new_entry = new_tree.get(path) if new_tree is not None else None
        parent_entry = parent_tree.get(prev_path) if parent_tree is not None else None

        # Symlink target changes (modified, renamed, added).
        if status == "added":
            new_mode = (new_entry or {}).get("mode")
            if new_mode == _MODE_SYMLINK:
                # New symlink — surface so reviewer eyeballs the target.
                target = _resolve_symlink_target(
                    cfg, path, commit.sha, new_entry, new_truncated
                )
                target_str = target or "(target unavailable)"
                findings.append(
                    StructuralFinding(
                        type="symlink_added",
                        path=path,
                        description=(
                            f"New symlink {path} \u2192 {target_str}; "
                            f"verify target is intentional."
                        ),
                    )
                )
            elif new_entry is None and new_truncated:
                # Tree truncated and we can't see this path; we have no
                # reliable way to detect a newly added symlink.  The
                # mode_check_unavailable finding emitted below covers this.
                truncated_warning_emitted = truncated_warning_emitted or new_truncated
            continue

        if status == "removed":
            # Only emit symlink_removed when the parent-side entry was a
            # symlink.  A regular-file removal is uninteresting here.
            parent_mode = (parent_entry or {}).get("mode")
            if parent_mode == _MODE_SYMLINK:
                findings.append(
                    StructuralFinding(
                        type="symlink_removed",
                        path=prev_path,
                        description=(
                            f"Symlink {prev_path} was removed in this commit."
                        ),
                    )
                )
            continue

        # modified / renamed / copied / changed: compare both sides.
        new_mode = (new_entry or {}).get("mode")
        parent_mode = (parent_entry or {}).get("mode")

        # If either side is missing because of truncation, fall through to
        # symlink-only detection via Contents API.  Otherwise we may still be
        # able to rule out a mode flip.
        new_missing_due_to_trunc = new_entry is None and new_truncated
        parent_missing_due_to_trunc = parent_entry is None and parent_truncated

        if new_missing_due_to_trunc or parent_missing_due_to_trunc:
            truncated_warning_emitted = True
            # Best-effort symlink-target detection via Contents API.
            new_target = _fetch_symlink_target_via_contents(cfg, path, commit.sha)
            old_target = _fetch_symlink_target_via_contents(cfg, prev_path, parent_sha)
            if new_target is not None and old_target is not None and new_target != old_target:
                findings.append(
                    StructuralFinding(
                        type="symlink_target_changed",
                        path=path,
                        description=(
                            f"Symlink {path} target changed from "
                            f"{old_target} \u2192 {new_target}."
                        ),
                    )
                )
            elif new_target is not None and old_target is None:
                # Was not a symlink before, now is — surface as new symlink
                # for review.
                findings.append(
                    StructuralFinding(
                        type="symlink_added",
                        path=path,
                        description=(
                            f"New symlink {path} \u2192 {new_target}; "
                            f"verify target is intentional."
                        ),
                    )
                )
            continue

        # Both sides visible in the trees.
        # Mode flips (file -> exec or vice versa).
        if (
            parent_mode == _MODE_NON_EXECUTABLE
            and new_mode == _MODE_EXECUTABLE
        ):
            findings.append(
                StructuralFinding(
                    type="mode_flip_executable",
                    path=path,
                    description=(
                        f"File {path} mode changed from 100644 to 100755 "
                        f"(now executable)."
                    ),
                )
            )
        elif (
            parent_mode == _MODE_EXECUTABLE
            and new_mode == _MODE_NON_EXECUTABLE
        ):
            findings.append(
                StructuralFinding(
                    type="mode_flip_non_executable",
                    path=path,
                    description=(
                        f"File {path} mode changed from 100755 to 100644 "
                        f"(no longer executable)."
                    ),
                )
            )

        # Symlink-target change: both sides are symlinks but target differs.
        if parent_mode == _MODE_SYMLINK and new_mode == _MODE_SYMLINK:
            new_target = _resolve_symlink_target(
                cfg, path, commit.sha, new_entry, new_truncated
            )
            old_target = _resolve_symlink_target(
                cfg, prev_path, parent_sha, parent_entry, parent_truncated
            )
            if (
                new_target is not None
                and old_target is not None
                and new_target != old_target
            ):
                findings.append(
                    StructuralFinding(
                        type="symlink_target_changed",
                        path=path,
                        description=(
                            f"Symlink {path} target changed from "
                            f"{old_target} \u2192 {new_target}."
                        ),
                    )
                )

    if (new_truncated or parent_truncated) and truncated_warning_emitted:
        findings.append(
            StructuralFinding(
                type="mode_check_unavailable",
                path="",
                description=(
                    "Git Trees API returned truncated=true; mode-flip "
                    "detection is best-effort for affected files and may "
                    "have been silently skipped.  Symlink-target changes "
                    "were resolved via the Contents API where possible."
                ),
            )
        )

    return findings


def _resolve_symlink_target(
    cfg: dict,
    path: str,
    ref: str,
    tree_entry: Optional[dict],
    truncated: bool,
) -> Optional[str]:
    """
    Best-effort symlink target resolution.  Tree entries from the recursive
    Git Trees API don't carry the symlink target string (only mode + sha),
    so we always go through the Contents API to read it.  Returns None when
    the target couldn't be resolved.
    """
    # The tree_entry is currently unused but accepted for forward
    # compatibility (a future caller may pass a pre-fetched contents-API
    # blob to avoid the extra round-trip).
    del tree_entry, truncated
    return _fetch_symlink_target_via_contents(cfg, path, ref)


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

_REF_PATTERNS = [
    re.compile(r"\bmod\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*;"),
    re.compile(r"\buse\s+(?:crate|self|super)::([a-zA-Z_][a-zA-Z0-9_]*)"),
    re.compile(r'\binclude(?:_str|_bytes)?!\s*\(\s*"([^"]+)"'),
]


def _extract_refs(text: str) -> set[str]:
    refs: set[str] = set()
    for pat in _REF_PATTERNS:
        for m in pat.finditer(text):
            v = m.group(1)
            refs.add(v)
            if "/" in v or "." in v:
                base = v.rsplit("/", 1)[-1]
                refs.add(base)
                if "." in base:
                    refs.add(base.rsplit(".", 1)[0])
    return refs


def _path_stems(path: str) -> set[str]:
    out = {path}
    base = path.rsplit("/", 1)[-1]
    out.add(base)
    if "." in base:
        out.add(base.rsplit(".", 1)[0])
    return out


def _find_cross_refs(
    included: list[ClassifiedFile],
    everything: list[ClassifiedFile],
) -> list[ClassifiedFile]:
    text = "\n".join(c.file.patch for c in included if c.file.patch)
    if not text:
        return []
    refs = _extract_refs(text)
    if not refs:
        return []
    pulled: list[ClassifiedFile] = []
    included_paths = {c.file.path for c in included}
    for c in everything:
        if c.file.path in included_paths:
            continue
        if c.classification in ("critical", "high"):
            continue  # would already be included
        if _path_stems(c.file.path) & refs:
            pulled.append(c)
    return pulled


def _compose_patch(included: list[ClassifiedFile]) -> str:
    chunks: list[str] = []
    for c in included:
        f = c.file
        header = f"diff --git a/{f.previous_path or f.path} b/{f.path}\n"
        header += f"# audit: classification={c.classification} status={f.status}\n"
        if f.status == "added" and f.patch_synthesised:
            header += "new file mode 100644\n"
        elif f.status == "removed" and f.patch_synthesised:
            header += "deleted file mode 100644\n"
        if f.patch_synthesised:
            header += (
                "# audit: patch reconstructed from blob (original was omitted "
                "or truncated by the GitHub API)\n"
            )
        if f.patch:
            chunks.append(header + f.patch)
        elif f.is_binary:
            chunks.append(header + f"Binary files a/{f.path} and b/{f.path} differ\n")
        elif f.patch_unavailable:
            chunks.append(
                header
                + f"# (text patch unavailable; blob fetch failed for "
                f"sha={f.blob_sha or 'unknown'})\n"
            )
        else:
            chunks.append(header + f"# (no patch body; status={f.status})\n")
    return "\n".join(chunks)


def route_diff(
    classified: list[ClassifiedFile],
    threshold: int = CHAR_THRESHOLD,
) -> RoutingDecision:
    total = sum(c.file.patch_chars for c in classified)

    if total <= threshold:
        return RoutingDecision(
            mode="whole",
            reason=f"Total patch {total:,} chars <= threshold {threshold:,}.",
            included=list(classified),
            excluded=[],
            composed_patch=_compose_patch(classified),
            total_chars=total,
        )

    high_subset = [c for c in classified if c.classification in ("critical", "high")]
    refs = _find_cross_refs(high_subset, classified)
    if refs:
        seen = {c.file.path for c in high_subset}
        for r in refs:
            if r.file.path not in seen:
                high_subset.append(r)
                seen.add(r.file.path)
    high_subset.sort(key=lambda c: c.file.path)
    high_chars = sum(c.file.patch_chars for c in high_subset)

    if high_chars <= threshold:
        included_paths = {c.file.path for c in high_subset}
        excluded = [c for c in classified if c.file.path not in included_paths]
        return RoutingDecision(
            mode="focused",
            reason=(
                f"Total patch {total:,} > threshold {threshold:,}; "
                f"restricted to critical+high (+ cross-refs), {high_chars:,} chars."
            ),
            included=high_subset,
            excluded=excluded,
            composed_patch=_compose_patch(high_subset),
            total_chars=total,
        )

    critical_only = [c for c in classified if c.classification == "critical"]
    critical_only.sort(key=lambda c: c.file.path)
    crit_chars = sum(c.file.patch_chars for c in critical_only)
    included_paths = {c.file.path for c in critical_only}
    excluded = [c for c in classified if c.file.path not in included_paths]

    if crit_chars > threshold:
        return RoutingDecision(
            mode="panel-skipped",
            reason=(
                f"Total {total:,}, high subset {high_chars:,}, critical-only {crit_chars:,} all "
                f"> threshold {threshold:,}.  Panel skipped; manual review required."
            ),
            included=[],
            excluded=list(classified),
            composed_patch="",
            total_chars=total,
        )

    return RoutingDecision(
        mode="focused-overflow",
        reason=(
            f"Total {total:,} and high subset {high_chars:,} > threshold {threshold:,}; "
            f"restricted to critical-only, {crit_chars:,} chars."
        ),
        included=critical_only,
        excluded=excluded,
        composed_patch=_compose_patch(critical_only),
        total_chars=total,
    )


# ---------------------------------------------------------------------------
# Panel context
# ---------------------------------------------------------------------------

def _file_line(c: ClassifiedFile) -> str:
    rules = ", ".join(c.matched_rules) if c.matched_rules else "default"
    binary = " [binary]" if c.file.is_binary else ""
    return (
        f"- `{c.file.path}` — {c.classification} ({rules}); "
        f"status={c.file.status}, +{c.file.additions}/-{c.file.deletions}, "
        f"{c.file.patch_chars} chars{binary}"
    )


def build_panel_context(decision: RoutingDecision, commit: CommitData) -> str:
    if decision.mode == "whole":
        return f"## Git diff\n\n{decision.composed_patch}"

    lines = [
        "## Context note",
        "",
        f"The audit panel was given a FILTERED subset of commit {commit.sha[:12]} because "
        f"the total patch size exceeded the review budget.",
        "",
        f"Routing mode: `{decision.mode}`",
        f"Reason: {decision.reason}",
        "",
        "Files reviewed (their patches appear in the diff section below):",
    ]
    if decision.included:
        lines.extend(_file_line(c) for c in decision.included)
    else:
        lines.append("- (none)")
    lines.extend([
        "",
        "Files excluded (their content is NOT in the diff below; you cannot assess them):",
    ])
    if decision.excluded:
        lines.extend(_file_line(c) for c in decision.excluded)
    else:
        lines.append("- (none)")
    lines.extend([
        "",
        "If a finding cites a symbol or file that is not in the diff below, lower your "
        "confidence — the panel cannot see the full picture.",
        "",
        "## Git diff",
        "",
        decision.composed_patch,
    ])
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Model call
# ---------------------------------------------------------------------------

# Total chat-completion invocations a single agent turn may make,
# counting the initial call plus every follow-up triggered by the model
# emitting `tool_calls`.  Once exhausted we make one final call without
# tools and force a JSON answer so the panel still produces a verdict.
_TOOL_LOOP_HARD_CAP = 8


def _post_completion(url: str, headers: dict, payload: dict, label: str):
    """One chat-completion POST with the existing single rate-limit retry."""
    import _http as http

    try:
        resp = http.post(url, headers=headers, json=payload, timeout=120)
    except http.HTTPError as e:
        raise RuntimeError(f"Network error: {e}") from e
    if resp.status_code == 429:
        retry_after = int(resp.headers.get("retry-after", "30"))
        print(f"  [{label}] rate limited — waiting {retry_after}s ...")
        time.sleep(retry_after)
        try:
            resp = http.post(url, headers=headers, json=payload, timeout=120)
        except http.HTTPError as e:
            raise RuntimeError(f"Network error after retry: {e}") from e
    if not resp.ok:
        raise RuntimeError(f"API error {resp.status_code}: {resp.text[:500]}")
    return resp.json()


def _call_model(system_prompt, user_content, github_token, label, *, registry=None):
    """Run one agent turn, optionally with tool-calling support.

    When ``registry`` is provided the model can call any of the wands in
    ``agent_tools.WAND_SCHEMAS``; the loop dispatches each ``tool_calls``
    response, appends the wand result as a ``role=tool`` message, and
    continues until the model produces final JSON content ( or the
    per-turn budget is exhausted, in which case we re-issue the request
    without tools and with ``response_format=json_object`` to force the
    final answer ).

    The historical no-tools shape is preserved when ``registry`` is
    None: a single call, ``response_format=json_object``, JSON-decoded
    content returned.  Existing tests that monkeypatch ``_call_model``
    directly are unaffected.
    """
    url = f"{MODELS_ENDPOINT}/chat/completions"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Content-Type": "application/json",
    }
    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]

    use_tools = registry is not None
    if use_tools:
        registry.reset()
        # Splice the tool-use guidance into the system prompt so the
        # agent's own JSON-shape instructions still come last.  Done at
        # call time ( rather than baked into AGENTS ) so a registry-less
        # call ( moderator, or wands disabled ) sees the historical
        # prompt byte-for-byte.
        messages[0] = {
            "role": "system",
            "content": system_prompt + "\n\n" + agent_tools.render_tool_help(),
        }

    print(f"  [{label}] calling {AI_MODEL} ...")
    iterations = 0
    while True:
        payload = {
            "model": AI_MODEL,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": 2048,
        }
        if use_tools and iterations < _TOOL_LOOP_HARD_CAP:
            payload["tools"] = registry.schemas()
        else:
            # Either no tools requested, or we've hit the per-turn cap
            # — force a final JSON answer.
            payload["response_format"] = {"type": "json_object"}

        body = _post_completion(url, headers, payload, label)
        try:
            msg = body["choices"][0]["message"]
        except (KeyError, IndexError) as e:
            raise RuntimeError(f"Malformed completion: {e}; body={body!r}") from e

        tool_calls = msg.get("tool_calls") or []
        if use_tools and tool_calls and iterations < _TOOL_LOOP_HARD_CAP:
            messages.append({
                "role": "assistant",
                "content": msg.get("content"),
                "tool_calls": tool_calls,
            })
            for tc in tool_calls:
                fn_name = (tc.get("function") or {}).get("name", "")
                raw_args = (tc.get("function") or {}).get("arguments") or "{}"
                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                except json.JSONDecodeError as e:
                    args = {}
                    result = {"error": "bad_arguments", "detail": str(e)}
                else:
                    result = registry.dispatch(fn_name, args)
                print(
                    f"  [{label}] -> {fn_name}({json.dumps(args)[:200]}) "
                    f"source={result.get('source', '?')} "
                    f"error={result.get('error', '-')}"
                )
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id"),
                    "name": fn_name,
                    "content": json.dumps(result)[: agent_tools.MAX_OUTPUT_CHARS + 1024],
                })
            iterations += 1
            continue

        # Final answer ( or model gave up without calling tools ).
        raw = msg.get("content") or ""
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"Response was not valid JSON: {e}\nRaw: {raw[:300]}"
            ) from e


def _format_discussion_so_far(
    panel_context: str,
    prior_turns: list[dict],
    *,
    current_round: int = 1,
    max_rounds: int = 1,
) -> str:
    if not prior_turns:
        return panel_context

    if max_rounds > 1:
        intro = (
            f"\n## Discussion so far (round {current_round} of up to {max_rounds})\n\n"
            "Refine, challenge, or extend prior findings.  Raise any new "
            "concerns you uncover.  If you have nothing further to add and "
            "your verdict is unchanged, return concerns=[] and a stable "
            "verdict so the discussion can converge.\n"
        )
    else:
        intro = "\n## Discussion so far\n"

    lines = [panel_context, intro]
    show_round = max_rounds > 1
    for turn in prior_turns:
        round_label = f" (round {turn.get('round', 1)})" if show_round else ""
        lines.append(
            f"### {turn['agent']}{round_label}\n\n"
            f"```json\n{json.dumps(turn['response'], indent=2)}\n```\n"
        )
    return "\n".join(lines)


def _round_converged(round_turns: list[dict]) -> bool:
    """A round has converged when every specialist returned ``concerns=[]``
    AND the verdicts are unanimous.  When both conditions hold there is no
    new information for the next round to chew on, so further model calls
    would just burn budget.
    """
    if not round_turns:
        return False
    if any(turn["response"].get("concerns") for turn in round_turns):
        return False
    verdicts = {turn["response"].get("verdict") for turn in round_turns}
    return len(verdicts) == 1 and None not in verdicts


def run_agent_discussion(
    panel_context: str,
    github_token: str,
    *,
    max_rounds: int = DEFAULT_MAX_ROUNDS,
    registry: Optional[agent_tools.WandRegistry] = None,
):
    """
    Run the specialist agents for up to ``max_rounds`` passes.  Each pass
    walks the agents in order; every agent after the very first turn sees
    the discussion so far and may refine, challenge, or extend it.  The
    moderator synthesises a single verdict at the end.

    Stops early when a round converges (no agent in the round raised any
    concerns and they all returned the same verdict).

    Specialist agents receive ``registry`` so they can call wands ( git
    history, blame, file contents, etc. ).  The moderator never gets
    tools — its job is synthesis over the transcript, not investigation.

    Returns (verdict_dict, discussion_list).  Each discussion entry has
    keys ``agent``, ``round`` (omitted for the moderator), and
    ``response``.
    """
    if max_rounds < 1:
        max_rounds = 1

    discussion: list[dict] = []

    for round_num in range(1, max_rounds + 1):
        round_start = len(discussion)
        for i, agent in enumerate(AGENTS):
            label = agent["name"]
            if round_num == 1 and i == 0:
                user_content = panel_context
            else:
                user_content = _format_discussion_so_far(
                    panel_context,
                    discussion,
                    current_round=round_num,
                    max_rounds=max_rounds,
                )

            call_label = f"{label} r{round_num}" if max_rounds > 1 else label
            response = _call_model(
                agent["system_prompt"],
                user_content,
                github_token,
                call_label,
                registry=registry,
            )
            discussion.append({"agent": label, "round": round_num, "response": response})

            verdict = response.get("verdict", "?")
            confidence = response.get("confidence", "?")
            n_concerns = len(response.get("concerns", []))
            print(
                f"  [{call_label}] verdict={verdict} "
                f"confidence={confidence} concerns={n_concerns}"
            )

        if round_num < max_rounds and _round_converged(discussion[round_start:]):
            print(
                f"  Discussion converged after round {round_num}; "
                f"skipping remaining {max_rounds - round_num} round(s)."
            )
            break

    moderator_input = _format_discussion_so_far(
        panel_context, discussion, current_round=max_rounds, max_rounds=max_rounds
    )
    print("  [Moderator] synthesising discussion ...")
    verdict = _call_model(
        MODERATOR_SYSTEM_PROMPT, moderator_input, github_token, "Moderator"
    )
    discussion.append({"agent": "Moderator", "response": verdict})

    return verdict, discussion


# ---------------------------------------------------------------------------
# Audit log (orphaned branch)
# ---------------------------------------------------------------------------

def audit_already_exists(cfg) -> bool:
    """
    Check whether the commit at ``cfg["commit_sha"]`` has already been
    audited by walking the ``audit-log`` branch's Git tree.

    Looks for any entry of the form ``logs/<date>/<sha>.json`` regardless of
    the date directory, since the date reflects when the audit ran (not the
    commit date) and a stale reconciler may pick up a SHA already audited on
    an earlier day.

    Returns ``True`` iff such an entry is found.  On any non-determinative
    failure (404 means the audit-log branch doesn't exist yet, which is the
    normal first-run case; other errors mean we cannot tell), returns
    ``False`` so that the audit proceeds rather than spuriously skipping.
    Non-404 failures emit a stderr warning.
    """
    import _http as http

    sha = cfg["commit_sha"]
    audit_repo = cfg["audit_repo"]
    token = cfg["github_token"]
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    target_suffix = f"/{sha}.json"

    tree_url = (
        f"https://api.github.com/repos/{audit_repo}/git/trees/audit-log?recursive=1"
    )
    try:
        resp = http.get(tree_url, headers=headers, timeout=30)
    except http.HTTPError as e:
        print(
            f"WARNING: preflight tree fetch network error: {e}; assuming no prior audit.",
            file=sys.stderr,
        )
        return False

    if resp.status_code == 404:
        # audit-log branch does not exist yet (normal first-run case).
        return False
    if not resp.ok:
        print(
            f"WARNING: preflight tree fetch returned {resp.status_code}; "
            f"assuming no prior audit.",
            file=sys.stderr,
        )
        return False

    try:
        payload = resp.json()
    except Exception as e:
        print(
            f"WARNING: preflight tree response was not valid JSON: {e}; "
            f"assuming no prior audit.",
            file=sys.stderr,
        )
        return False

    for entry in payload.get("tree", []):
        path = entry.get("path", "")
        if (
            path.startswith("logs/")
            and path.endswith(target_suffix)
            and path.count("/") == 2
        ):
            return True

    if not payload.get("truncated"):
        return False

    # Tree response was truncated; fall back to the contents API which
    # paginates per-directory.
    contents_url = (
        f"https://api.github.com/repos/{audit_repo}/contents/logs?ref=audit-log"
    )
    try:
        listing = http.get(contents_url, headers=headers, timeout=30)
    except http.HTTPError as e:
        print(
            f"WARNING: preflight contents fetch network error: {e}; "
            f"assuming no prior audit.",
            file=sys.stderr,
        )
        return False

    if listing.status_code == 404:
        return False
    if not listing.ok:
        print(
            f"WARNING: preflight contents fetch returned {listing.status_code}; "
            f"assuming no prior audit.",
            file=sys.stderr,
        )
        return False

    try:
        date_entries = listing.json()
    except Exception as e:
        print(
            f"WARNING: preflight contents response was not valid JSON: {e}; "
            f"assuming no prior audit.",
            file=sys.stderr,
        )
        return False

    if not isinstance(date_entries, list):
        return False

    target_name = f"{sha}.json"
    for date_entry in date_entries:
        if not isinstance(date_entry, dict):
            continue
        if date_entry.get("type") != "dir":
            continue
        date_path = date_entry.get("path") or ""
        if not date_path.startswith("logs/"):
            continue
        date_url = (
            f"https://api.github.com/repos/{audit_repo}/contents/{date_path}"
            f"?ref=audit-log"
        )
        try:
            files_resp = http.get(date_url, headers=headers, timeout=30)
        except http.HTTPError as e:
            print(
                f"WARNING: preflight per-date fetch network error for "
                f"{date_path}: {e}; continuing.",
                file=sys.stderr,
            )
            continue
        if files_resp.status_code == 404:
            continue
        if not files_resp.ok:
            print(
                f"WARNING: preflight per-date fetch returned "
                f"{files_resp.status_code} for {date_path}; continuing.",
                file=sys.stderr,
            )
            continue
        try:
            files_listing = files_resp.json()
        except Exception:
            continue
        if not isinstance(files_listing, list):
            continue
        for f in files_listing:
            if isinstance(f, dict) and f.get("name") == target_name:
                return True

    return False


def write_audit_log(cfg, log_entry):
    sha = cfg["commit_sha"]
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    log_dir = f"logs/{date_str}"
    log_file = f"{log_dir}/{sha}.json"
    content = json.dumps(log_entry, indent=2)

    def run(cmd, check=True, capture=False):
        kwargs: dict = {"check": check, "text": True}
        if capture:
            kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return subprocess.run(cmd, **kwargs)

    run(["git", "config", "user.email", "github-actions[bot]@users.noreply.github.com"])
    run(["git", "config", "user.name", "github-actions[bot]"])

    fetch_result = run(
        ["git", "fetch", "origin", "audit-log:refs/remotes/origin/audit-log"],
        check=False,
        capture=True,
    )
    if fetch_result.returncode == 0:
        run(["git", "checkout", "audit-log"])
    else:
        run(["git", "checkout", "--orphan", "audit-log"])
        run(["git", "rm", "-rf", "--cached", "."], check=False)
        run(["git", "clean", "-fdx", "--exclude=.github"], check=False)

    os.makedirs(log_dir, exist_ok=True)
    with open(log_file, "w") as f:
        f.write(content)

    run(["git", "add", log_file])
    run(["git", "commit", "-m", f"audit: {sha[:12]} on {date_str}"])

    push_result = run(
        ["git", "push", "origin", "audit-log"],
        check=False,
        capture=True,
    )
    if push_result.returncode != 0:
        run(["git", "push", "--set-upstream", "origin", "audit-log"])

    print(f"Audit log written to {log_file} on branch audit-log.")
    return log_file


# ---------------------------------------------------------------------------
# Issue filing
# ---------------------------------------------------------------------------

def _max_severity(*levels: Severity) -> Severity:
    indices = [SEVERITY_ORDER.index(l) for l in levels if l in SEVERITY_ORDER]
    return SEVERITY_ORDER[max(indices)] if indices else "none"


def should_file_issue(
    verdict: dict,
    decision: RoutingDecision,
    structural: list[StructuralFinding],
    status: Status,
) -> tuple[bool, Severity]:
    """
    Returns (should_file, effective_severity).

    File an issue when any of the following holds:
      - LLM verdict is suspicious (status reviewed)
      - any structural finding exists
      - routing excluded any critical or high file
      - the panel was skipped entirely
    """
    reasons: list[str] = []
    severity = verdict.get("severity", "none") if verdict else "none"

    if verdict and verdict.get("suspicious") and status == "reviewed":
        reasons.append("llm_suspicious")
    if structural:
        reasons.append("structural_findings")
        severity = _max_severity(severity, "medium")
    excluded_critical_or_high = [
        c for c in decision.excluded
        if c.classification in ("critical", "high")
    ]
    if excluded_critical_or_high:
        reasons.append("critical_or_high_excluded")
        severity = _max_severity(severity, "high")
    if status == "panel-skipped":
        reasons.append("panel-skipped")
        severity = _max_severity(severity, "critical")
    return bool(reasons), severity


def file_issue(
    cfg,
    verdict,
    discussion,
    decision: RoutingDecision,
    structural: list[StructuralFinding],
    status: Status,
    effective_severity: Severity,
):
    sha = cfg["commit_sha"]
    repo = cfg["monitored_repo"]
    severity_label = effective_severity.upper()
    summary = (verdict or {}).get("summary") or "Audit raised non-LLM concerns; see tables below."
    findings = (verdict or {}).get("findings", [])

    finding_rows = "\n".join(
        "| `{type}` | `{file}` | {line} | {description} | {raised_by} |".format(
            type=f.get("type", "?"),
            file=f.get("file", "?"),
            line=f.get("line") or "N/A",
            description=f.get("description", "?"),
            raised_by=", ".join(f.get("raised_by", [])),
        )
        for f in findings
    ) or "| — | — | — | No LLM findings. | — |"

    structural_rows = "\n".join(
        "| `{type}` | `{path}` | {description} |".format(
            type=s.type, path=s.path, description=s.description,
        )
        for s in structural
    ) or "| — | — | No structural findings. |"

    routing_rows = "\n".join(
        "| `{path}` | {classification} | {rules} | {included} | {chars} |".format(
            path=c.file.path,
            classification=c.classification,
            rules=", ".join(c.matched_rules) or "default",
            included="yes" if c in decision.included else "no",
            chars=c.file.patch_chars,
        )
        for c in (decision.included + decision.excluded)
    ) or "| — | — | — | — | — |"

    transcript_sections = []
    for turn in discussion:
        agent_name = turn["agent"]
        resp = turn["response"]
        transcript_sections.append(
            f"<details>\n<summary><b>{agent_name}</b></summary>\n\n"
            f"```json\n{json.dumps(resp, indent=2)}\n```\n\n</details>"
        )
    transcript = "\n\n".join(transcript_sections) or "_(panel did not run)_"

    is_panel_skipped = status == "panel-skipped"
    heading = (
        "## Manual review required (audit panel skipped)"
        if is_panel_skipped
        else "## Integrity Audit Finding"
    )
    files_section_title = (
        "### Change summary (panel did not run; review every file directly)"
        if is_panel_skipped
        else "### Files reviewed by the panel"
    )

    body = f"""\
{heading}

| Field | Value |
|---|---|
| **Repo** | `{repo}` |
| **Commit** | [`{sha[:12]}`](https://github.com/{repo}/commit/{sha}) |
| **Author** | {cfg['commit_author']} |
| **Message** | {cfg['commit_message'][:120]} |
| **Severity** | **{severity_label}** |
| **Status** | `{status}` |
| **Routing** | `{decision.mode}` — {decision.reason} |

### Summary

{summary}

### Structural findings (deterministic, bypass the LLM)

| Type | Path | Description |
|---|---|---|
{structural_rows}

{files_section_title}

| Path | Classification | Matched rules | Included | Patch chars |
|---|---|---|---|---|
{routing_rows}

### Consolidated LLM findings

| Type | File | Line | Description | Raised by |
|---|---|---|---|---|
{finding_rows}

### Agent discussion

{transcript}

---
*Automated integrity audit by [{cfg['audit_repo']}](https://github.com/{cfg['audit_repo']}) \
using {AI_MODEL}.*
"""

    title = (
        f"[MANUAL REVIEW REQUIRED] Audit panel skipped for {repo}@{sha[:12]}"
        if is_panel_skipped
        else f"[{severity_label}] Integrity finding in {repo}@{sha[:12]}"
    )
    owner, repo_name = cfg["audit_repo"].split("/", 1)
    url = f"https://api.github.com/repos/{owner}/{repo_name}/issues"
    headers = {
        "Authorization": f"Bearer {cfg['github_token']}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    labels = [
        "integrity-audit",
        effective_severity,
        decision.mode,
    ]
    if structural:
        labels.append("structural-finding")
    payload = {"title": title, "body": body, "labels": labels}

    import _http as http

    resp = http.post(url, headers=headers, json=payload, timeout=30)
    if not resp.ok:
        raise RuntimeError(
            f"Failed to create issue: {resp.status_code} {resp.text[:500]}"
        )

    issue_url = resp.json()["html_url"]
    print(f"Issue filed: {issue_url}")
    return issue_url


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _build_log_entry(
    *,
    cfg,
    run_timestamp: str,
    commit: CommitData,
    classified: list[ClassifiedFile],
    decision: RoutingDecision,
    structural: list[StructuralFinding],
    status: Status,
    discussion: list[dict],
    verdict: dict,
    issue_url: Optional[str],
    max_rounds: int,
) -> dict:
    included_paths = {c.file.path for c in decision.included}
    files_block = []
    for c in classified:
        files_block.append({
            "path": c.file.path,
            "previous_path": c.file.previous_path,
            "status": c.file.status,
            "classification": c.classification,
            "matched_rules": c.matched_rules,
            "patch_chars": c.file.patch_chars,
            "is_binary": c.file.is_binary,
            "patch_omitted": c.file.patch_omitted,
            "patch_synthesised": c.file.patch_synthesised,
            "patch_unavailable": c.file.patch_unavailable,
            "included_in_panel": c.file.path in included_paths,
            "exclusion_reason": (
                None if c.file.path in included_paths
                else "below_focused_threshold" if decision.mode == "focused"
                else "below_critical_threshold" if decision.mode == "focused-overflow"
                else "panel-skipped" if decision.mode == "panel-skipped"
                else None
            ),
        })

    rounds_used = max(
        (turn.get("round", 1) for turn in discussion if turn.get("agent") != "Moderator"),
        default=0,
    )

    return {
        "schema_version": "5",
        "timestamp": run_timestamp,
        "commit_sha": cfg["commit_sha"],
        "commit_author": cfg["commit_author"],
        "commit_message": cfg["commit_message"],
        "commit_timestamp": cfg["commit_timestamp"],
        "monitored_repo": cfg["monitored_repo"],
        "audit_repo": cfg["audit_repo"],
        "is_merge": commit.is_merge,
        "parents": commit.parents,
        "api_truncated": commit.truncated,
        "diff_chars": decision.total_chars,
        "estimated_tokens": decision.total_chars // 4,
        "routing": {
            "mode": decision.mode,
            "reason": decision.reason,
            "total_patch_chars": decision.total_chars,
            "files": files_block,
        },
        "structural_findings": [
            {"type": s.type, "path": s.path, "description": s.description}
            for s in structural
        ],
        "status": status,
        "ai_model": AI_MODEL if status == "reviewed" else None,
        "agents": [a["name"] for a in AGENTS] + ["Moderator"] if status == "reviewed" else [],
        "discussion_rounds": {
            "max": max_rounds,
            "used": rounds_used,
            "converged_early": rounds_used < max_rounds and status == "reviewed",
        },
        "discussion": discussion,
        "verdict": verdict,
        "issue_url": issue_url,
    }


def _force_rerun_requested() -> bool:
    """Return True when ``AUDIT_FORCE_RERUN`` env var requests bypassing the
    preflight skip check.  Recognises ``1``/``true`` (case-insensitive)."""
    return os.environ.get("AUDIT_FORCE_RERUN", "").strip().lower() in ("1", "true")


def _max_rounds() -> int:
    """Return the maximum number of agent discussion rounds.

    Reads ``AUDIT_MAX_ROUNDS``.  Empty / unset / non-integer values fall
    back to ``DEFAULT_MAX_ROUNDS`` (1).  Values below 1 are clamped to 1
    so the discussion always runs at least one full pass.
    """
    raw = os.environ.get("AUDIT_MAX_ROUNDS", "").strip()
    if not raw:
        return DEFAULT_MAX_ROUNDS
    try:
        n = int(raw)
    except ValueError:
        print(
            f"WARNING: AUDIT_MAX_ROUNDS={raw!r} is not an integer; "
            f"using {DEFAULT_MAX_ROUNDS}.",
            file=sys.stderr,
        )
        return DEFAULT_MAX_ROUNDS
    return max(1, n)


def main():
    cfg = load_config()
    manifest = load_manifest()
    if manifest.fail_closed:
        print("Manifest failed to load; every file will be classified critical.", file=sys.stderr)

    # Preflight: skip if this commit already has an audit log on the
    # `audit-log` branch.  Eliminates duplicate-audit cost in the rare race
    # where the push trigger and the scheduled reconciler both dispatch an
    # audit for the same SHA.  Set AUDIT_FORCE_RERUN=1 to bypass.
    if not _force_rerun_requested() and audit_already_exists(cfg):
        print(
            f"Audit already exists for {cfg['commit_sha']}; skipping.",
            file=sys.stderr,
        )
        sys.exit(0)

    run_timestamp = datetime.now(timezone.utc).isoformat()
    issue_url: Optional[str] = None
    verdict: Optional[dict] = None
    discussion: list[dict] = []
    status: Status = "unknown"
    max_rounds = _max_rounds()

    commit = fetch_commit_files(cfg)
    # Disambiguate "no patch" cases (binary vs API-omitted text) and
    # synthesise replacement patches for text files whose diff was
    # omitted.  Mutates `commit.files` in place.
    _resolve_patch_omissions(cfg, commit.files)
    classified = classify_files(commit.files, manifest)
    # For critical / high files whose patch looks truncated by the API,
    # refetch the blob and replace the patch.  Lower-classification files
    # keep the truncated patch (per-file blob API cost gate).
    _resolve_truncated_patches_for_critical(cfg, classified)
    structural = detect_structural_findings(commit.files)
    if _mode_changes_enabled():
        structural.extend(_detect_mode_changes(cfg, commit, classified))
    decision = route_diff(classified)

    print(
        f"Routing: mode={decision.mode}, total={decision.total_chars:,} chars, "
        f"included={len(decision.included)}, excluded={len(decision.excluded)}, "
        f"structural_findings={len(structural)}"
    )

    if decision.mode == "panel-skipped":
        status = "panel-skipped"
        verdict = {
            "suspicious": False,
            "severity": "none",
            "summary": (
                "**Manual review required.** The integrity panel did not run "
                "because the diff is too large for the model context budget "
                f"({decision.reason}) "
                "A human reviewer must read the patch and the file list below "
                "directly."
            ),
            "findings": [],
        }
    elif not decision.included:
        # Edge case: a commit that touches zero files (e.g. empty merge).
        status = "reviewed"
        verdict = {
            "suspicious": False,
            "severity": "none",
            "summary": "No files in commit; nothing to review.",
            "findings": [],
        }
    else:
        panel_context = build_panel_context(decision, commit)
        registry: Optional[agent_tools.WandRegistry] = None
        if agent_tools.wands_enabled():
            registry = agent_tools.build_default_registry(
                monitored_repo=cfg["monitored_repo"],
                monitored_token=cfg["monitored_token"],
                monitored_repo_path=os.environ.get("MONITORED_REPO_PATH") or None,
                audited_sha=cfg["commit_sha"],
                max_calls=agent_tools.env_max_calls(),
            )
            print(
                f"Wands enabled: local_checkout="
                f"{registry.ctx.has_local_checkout()} "
                f"max_calls_per_turn={registry.max_calls}"
            )
        print(
            f"Starting multi-agent integrity discussion (max_rounds={max_rounds}) ..."
        )
        try:
            verdict, discussion = run_agent_discussion(
                panel_context,
                cfg["github_token"],
                max_rounds=max_rounds,
                registry=registry,
            )
            status = "reviewed"
            print(
                f"Discussion complete. "
                f"suspicious={verdict.get('suspicious')}, "
                f"severity={verdict.get('severity')}"
            )
        except Exception as e:
            print(f"ERROR during agent discussion: {e}", file=sys.stderr)
            status = "ai-error"
            verdict = {
                "suspicious": False,
                "severity": "none",
                "summary": f"AI discussion failed: {e}",
                "findings": [],
            }

    file_it, effective_severity = should_file_issue(verdict or {}, decision, structural, status)
    if file_it:
        try:
            issue_url = file_issue(
                cfg,
                verdict or {},
                discussion,
                decision,
                structural,
                status,
                effective_severity,
            )
        except Exception as e:
            print(f"ERROR filing issue (non-fatal): {e}", file=sys.stderr)

    log_entry = _build_log_entry(
        cfg=cfg,
        run_timestamp=run_timestamp,
        commit=commit,
        classified=classified,
        decision=decision,
        structural=structural,
        status=status,
        discussion=discussion,
        verdict=verdict or {},
        issue_url=issue_url,
        max_rounds=max_rounds,
    )

    try:
        write_audit_log(cfg, log_entry)
    except Exception as e:
        print(f"ERROR writing audit log: {e}", file=sys.stderr)
        sys.exit(4)

    if status == "ai-error":
        sys.exit(5)


if __name__ == "__main__":
    main()
