#!/usr/bin/env python3
"""
Integrity audit of a single commit using a multi-agent discussion via the
GitHub Models API.

Three specialist agents review the diff in sequence — each one sees the prior
agents' findings and may agree with, challenge, or extend them.  A moderator
then synthesises the discussion into a single verdict.

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
                        skipped entirely (status `panel_skipped`) when even
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

Exit codes:
  0 — success
  1 — missing required env var
  2 — diff fetch failed (404 / 403 / network error)
  4 — audit log push failed
  5 — AI discussion failed (log still written with status=ai_error)
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
from typing import Optional

# `requests` is imported lazily inside the network-touching helpers so that the
# pure-function layers (parsing, classification, routing) can be exercised by
# unit tests without the `requests` package installed.

MODELS_ENDPOINT = "https://models.inference.ai.azure.com"
AI_MODEL = "openai/gpt-4o-mini"
CHAR_THRESHOLD = 400_000  # ~100 K tokens at 4 chars/token
MANIFEST_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "monitored_repo_classification.json"
)
CLASSIFICATION_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]
COMMITS_API_PER_PAGE = 100

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
    classification: str
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
    default_classification: str
    rules: list[ManifestRule]
    fail_closed: bool = False  # True when the manifest could not be loaded


@dataclass
class FileChange:
    path: str
    previous_path: Optional[str]
    status: str
    additions: int
    deletions: int
    patch: Optional[str]  # None for binary or omitted-by-API
    blob_sha: Optional[str]

    @property
    def is_binary(self) -> bool:
        # Patch is omitted by the API for binary changes.  A removed file may
        # also have patch=None but status=removed; treat removals as not-binary
        # for routing purposes.
        return self.patch is None and self.status not in ("removed", "unchanged")

    @property
    def patch_chars(self) -> int:
        return len(self.patch) if self.patch else 0


@dataclass
class ClassifiedFile:
    file: FileChange
    classification: str
    matched_rules: list[str]


@dataclass
class StructuralFinding:
    type: str
    path: str
    description: str


@dataclass
class RoutingDecision:
    mode: str  # whole | focused | focused-overflow | panel_skipped
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
    import requests

    try:
        resp = requests.get(url, headers=headers, timeout=30)
    except requests.RequestException as e:
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
                        f"Binary file {f.status}; content is not visible to the LLM panel. "
                        f"Verify the blob (sha={f.blob_sha or 'unknown'}) by hand."
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
    return findings


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
        if f.patch:
            chunks.append(header + f.patch)
        elif f.is_binary:
            chunks.append(header + f"Binary files a/{f.path} and b/{f.path} differ\n")
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
            mode="panel_skipped",
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

def _call_model(system_prompt, user_content, github_token, label):
    """Single chat-completion call with one rate-limit retry."""
    import requests

    url = f"{MODELS_ENDPOINT}/chat/completions"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": AI_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0.1,
        "max_tokens": 2048,
        "response_format": {"type": "json_object"},
    }

    print(f"  [{label}] calling {AI_MODEL} ...")
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=120)
    except requests.RequestException as e:
        raise RuntimeError(f"Network error: {e}") from e

    if resp.status_code == 429:
        retry_after = int(resp.headers.get("retry-after", "30"))
        print(f"  [{label}] rate limited — waiting {retry_after}s ...")
        time.sleep(retry_after)
        resp = requests.post(url, headers=headers, json=payload, timeout=120)

    if not resp.ok:
        raise RuntimeError(f"API error {resp.status_code}: {resp.text[:500]}")

    raw = resp.json()["choices"][0]["message"]["content"]
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"Response was not valid JSON: {e}\nRaw: {raw[:300]}"
        ) from e


def _format_discussion_so_far(panel_context: str, prior_turns: list[dict]) -> str:
    lines = [panel_context, "\n## Discussion so far\n"]
    for turn in prior_turns:
        lines.append(
            f"### {turn['agent']}\n\n```json\n{json.dumps(turn['response'], indent=2)}\n```\n"
        )
    return "\n".join(lines)


def run_agent_discussion(panel_context: str, github_token: str):
    """
    Run the three specialist agents sequentially (each sees prior findings),
    then ask the moderator to synthesise.

    Returns (verdict_dict, discussion_list).
    """
    discussion: list[dict] = []

    for i, agent in enumerate(AGENTS):
        label = agent["name"]
        if i == 0:
            user_content = panel_context
        else:
            user_content = _format_discussion_so_far(panel_context, discussion)

        response = _call_model(
            agent["system_prompt"], user_content, github_token, label
        )
        discussion.append({"agent": label, "response": response})

        verdict = response.get("verdict", "?")
        confidence = response.get("confidence", "?")
        n_concerns = len(response.get("concerns", []))
        print(f"  [{label}] verdict={verdict} confidence={confidence} concerns={n_concerns}")

    moderator_input = _format_discussion_so_far(panel_context, discussion)
    print("  [Moderator] synthesising discussion ...")
    verdict = _call_model(
        MODERATOR_SYSTEM_PROMPT, moderator_input, github_token, "Moderator"
    )
    discussion.append({"agent": "Moderator", "response": verdict})

    return verdict, discussion


# ---------------------------------------------------------------------------
# Audit log (orphaned branch)
# ---------------------------------------------------------------------------

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

def _max_severity(*levels: str) -> str:
    indices = [SEVERITY_ORDER.index(l) for l in levels if l in SEVERITY_ORDER]
    return SEVERITY_ORDER[max(indices)] if indices else "none"


def should_file_issue(
    verdict: dict,
    decision: RoutingDecision,
    structural: list[StructuralFinding],
    status: str,
) -> tuple[bool, str]:
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
    if status == "panel_skipped":
        reasons.append("panel_skipped")
        severity = _max_severity(severity, "critical")
    return bool(reasons), severity


def file_issue(
    cfg,
    verdict,
    discussion,
    decision: RoutingDecision,
    structural: list[StructuralFinding],
    status: str,
    effective_severity: str,
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

    panel_skipped = status == "panel_skipped"
    heading = (
        "## Manual review required (audit panel skipped)"
        if panel_skipped
        else "## Integrity Audit Finding"
    )
    files_section_title = (
        "### Change summary (panel did not run; review every file directly)"
        if panel_skipped
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
        if panel_skipped
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
        f"severity:{effective_severity}",
        f"routing:{decision.mode}",
    ]
    if structural:
        labels.append("structural-finding")
    payload = {"title": title, "body": body, "labels": labels}

    import requests

    resp = requests.post(url, headers=headers, json=payload, timeout=30)
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
    status: str,
    discussion: list[dict],
    verdict: dict,
    issue_url: Optional[str],
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
            "included_in_panel": c.file.path in included_paths,
            "exclusion_reason": (
                None if c.file.path in included_paths
                else "below_focused_threshold" if decision.mode == "focused"
                else "below_critical_threshold" if decision.mode == "focused-overflow"
                else "panel_skipped" if decision.mode == "panel_skipped"
                else None
            ),
        })

    return {
        "schema_version": "3",
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
        "discussion": discussion,
        "verdict": verdict,
        "issue_url": issue_url,
    }


def main():
    cfg = load_config()
    manifest = load_manifest()
    if manifest.fail_closed:
        print("Manifest failed to load; every file will be classified critical.", file=sys.stderr)

    run_timestamp = datetime.now(timezone.utc).isoformat()
    issue_url: Optional[str] = None
    verdict: Optional[dict] = None
    discussion: list[dict] = []
    status = "unknown"

    commit = fetch_commit_files(cfg)
    classified = classify_files(commit.files, manifest)
    structural = detect_structural_findings(commit.files)
    decision = route_diff(classified)

    print(
        f"Routing: mode={decision.mode}, total={decision.total_chars:,} chars, "
        f"included={len(decision.included)}, excluded={len(decision.excluded)}, "
        f"structural_findings={len(structural)}"
    )

    if decision.mode == "panel_skipped":
        status = "panel_skipped"
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
        print("Starting multi-agent integrity discussion ...")
        try:
            verdict, discussion = run_agent_discussion(panel_context, cfg["github_token"])
            status = "reviewed"
            print(
                f"Discussion complete. "
                f"suspicious={verdict.get('suspicious')}, "
                f"severity={verdict.get('severity')}"
            )
        except Exception as e:
            print(f"ERROR during agent discussion: {e}", file=sys.stderr)
            status = "ai_error"
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
    )

    try:
        write_audit_log(cfg, log_entry)
    except Exception as e:
        print(f"ERROR writing audit log: {e}", file=sys.stderr)
        sys.exit(4)

    if status == "ai_error":
        sys.exit(5)


if __name__ == "__main__":
    main()
