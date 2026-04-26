#!/usr/bin/env python3
"""
Integrity audit of a single commit diff using a multi-agent discussion via the
GitHub Models API.

Three specialist agents review the diff in sequence — each one sees the prior
agents' findings and may agree with, challenge, or extend them.  A moderator
then synthesises the discussion into a final verdict.

Focus: commit *integrity* (malicious intent, backdoors, supply-chain tampering,
covert exfiltration).  Code-quality security issues (XSS, RCE, SQLi, …) are
out of scope and handled by a separate agent in the main repository.

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

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests

MODELS_ENDPOINT = "https://models.inference.ai.azure.com"
AI_MODEL = "openai/gpt-4o-mini"
CHAR_THRESHOLD = 400_000  # ~100 K tokens at 4 chars/token

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
# Helpers
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


def fetch_diff(cfg):
    owner, repo = cfg["monitored_repo"].split("/", 1)
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{cfg['commit_sha']}"
    headers = {
        "Accept": "application/vnd.github.diff",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if cfg["monitored_token"]:
        headers["Authorization"] = f"Bearer {cfg['monitored_token']}"

    print(f"Fetching diff for {cfg['commit_sha']} from {cfg['monitored_repo']} ...")
    try:
        resp = requests.get(url, headers=headers, timeout=30)
    except requests.RequestException as e:
        print(f"ERROR: Network error fetching diff: {e}", file=sys.stderr)
        sys.exit(2)

    if resp.status_code == 404:
        print(
            "ERROR: Commit not found (404). "
            "Check COMMIT_SHA and MONITORED_REPO_TOKEN permissions.",
            file=sys.stderr,
        )
        sys.exit(2)
    if resp.status_code == 403:
        print(
            "ERROR: Access denied (403). "
            "MONITORED_REPO_TOKEN may be missing or expired.",
            file=sys.stderr,
        )
        sys.exit(2)
    if not resp.ok:
        print(
            f"ERROR: GitHub API returned {resp.status_code}: {resp.text[:500]}",
            file=sys.stderr,
        )
        sys.exit(2)

    return resp.text


def check_token_size(diff_text):
    estimated = len(diff_text) // 4
    return estimated, len(diff_text) > CHAR_THRESHOLD


def _call_model(system_prompt, user_content, github_token, label):
    """Single chat-completion call with one rate-limit retry."""
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


def _format_discussion_so_far(diff_text, prior_turns):
    """
    Build the user message for agents after the first.
    Shows the diff followed by a clearly delimited transcript of prior turns.
    """
    lines = [f"## Git diff\n\n{diff_text}\n\n## Discussion so far\n"]
    for turn in prior_turns:
        lines.append(
            f"### {turn['agent']}\n\n```json\n{json.dumps(turn['response'], indent=2)}\n```\n"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Multi-agent discussion
# ---------------------------------------------------------------------------

def run_agent_discussion(diff_text, github_token):
    """
    Run the three specialist agents sequentially (each sees prior findings),
    then ask the moderator to synthesise.

    Returns (verdict_dict, discussion_list).
    discussion_list is a list of {"agent": name, "response": dict} entries
    including the moderator's final turn.
    """
    discussion = []

    for i, agent in enumerate(AGENTS):
        label = agent["name"]
        if i == 0:
            user_content = f"## Git diff\n\n{diff_text}"
        else:
            user_content = _format_discussion_so_far(diff_text, discussion)

        response = _call_model(
            agent["system_prompt"], user_content, github_token, label
        )
        discussion.append({"agent": label, "response": response})

        verdict = response.get("verdict", "?")
        confidence = response.get("confidence", "?")
        n_concerns = len(response.get("concerns", []))
        print(f"  [{label}] verdict={verdict} confidence={confidence} concerns={n_concerns}")

    # Moderator synthesises the full discussion
    moderator_input = _format_discussion_so_far(diff_text, discussion)
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

def file_issue(cfg, verdict, discussion):
    sha = cfg["commit_sha"]
    repo = cfg["monitored_repo"]
    severity = verdict.get("severity", "unknown").upper()
    summary = verdict.get("summary", "No summary provided.")
    findings = verdict.get("findings", [])

    finding_rows = "\n".join(
        "| `{type}` | `{file}` | {line} | {description} | {raised_by} |".format(
            type=f.get("type", "?"),
            file=f.get("file", "?"),
            line=f.get("line") or "N/A",
            description=f.get("description", "?"),
            raised_by=", ".join(f.get("raised_by", [])),
        )
        for f in findings
    ) or "| — | — | — | No findings. | — |"

    # Build a collapsible discussion transcript
    transcript_sections = []
    for turn in discussion:
        agent_name = turn["agent"]
        resp = turn["response"]
        transcript_sections.append(
            f"<details>\n<summary><b>{agent_name}</b></summary>\n\n"
            f"```json\n{json.dumps(resp, indent=2)}\n```\n\n</details>"
        )
    transcript = "\n\n".join(transcript_sections)

    body = f"""\
## Integrity Audit Finding

| Field | Value |
|---|---|
| **Repo** | `{repo}` |
| **Commit** | [`{sha[:12]}`](https://github.com/{repo}/commit/{sha}) |
| **Author** | {cfg['commit_author']} |
| **Message** | {cfg['commit_message'][:120]} |
| **Severity** | **{severity}** |

### Summary

{summary}

### Consolidated Findings

| Type | File | Line | Description | Raised by |
|---|---|---|---|---|
{finding_rows}

### Agent Discussion

{transcript}

---
*Automated integrity audit by [{cfg['audit_repo']}](https://github.com/{cfg['audit_repo']}) \
using {AI_MODEL} ({len(discussion)} agents).*
"""

    title = f"[{severity}] Integrity finding in {repo}@{sha[:12]}"
    owner, repo_name = cfg["audit_repo"].split("/", 1)
    url = f"https://api.github.com/repos/{owner}/{repo_name}/issues"
    headers = {
        "Authorization": f"Bearer {cfg['github_token']}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    payload = {
        "title": title,
        "body": body,
        "labels": ["integrity-audit", f"severity:{severity.lower()}"],
    }

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

def main():
    cfg = load_config()
    run_timestamp = datetime.now(timezone.utc).isoformat()
    issue_url = None
    verdict = None
    discussion = []
    status = "unknown"

    diff_text = fetch_diff(cfg)
    print(f"Diff fetched: {len(diff_text):,} chars")

    estimated_tokens, too_large = check_token_size(diff_text)
    print(
        f"Estimated tokens: {estimated_tokens:,} "
        f"({'TOO LARGE — skipping AI review' if too_large else 'within limit'})"
    )

    if too_large:
        status = "too_large"
        verdict = {
            "suspicious": False,
            "severity": "none",
            "summary": (
                f"Diff too large for AI review "
                f"({estimated_tokens:,} estimated tokens, "
                f"threshold is {CHAR_THRESHOLD // 4:,})."
            ),
            "findings": [],
        }
    else:
        print("Starting multi-agent integrity discussion ...")
        try:
            verdict, discussion = run_agent_discussion(diff_text, cfg["github_token"])
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

    if verdict.get("suspicious") and status == "reviewed":
        try:
            issue_url = file_issue(cfg, verdict, discussion)
        except Exception as e:
            print(f"ERROR filing issue (non-fatal): {e}", file=sys.stderr)

    log_entry = {
        "schema_version": "2",
        "timestamp": run_timestamp,
        "commit_sha": cfg["commit_sha"],
        "commit_author": cfg["commit_author"],
        "commit_message": cfg["commit_message"],
        "commit_timestamp": cfg["commit_timestamp"],
        "monitored_repo": cfg["monitored_repo"],
        "audit_repo": cfg["audit_repo"],
        "diff_chars": len(diff_text),
        "estimated_tokens": estimated_tokens,
        "status": status,
        "ai_model": AI_MODEL if status == "reviewed" else None,
        "agents": [a["name"] for a in AGENTS] + ["Moderator"] if status == "reviewed" else [],
        "discussion": discussion,
        "verdict": verdict,
        "issue_url": issue_url,
    }

    try:
        write_audit_log(cfg, log_entry)
    except Exception as e:
        print(f"ERROR writing audit log: {e}", file=sys.stderr)
        sys.exit(4)

    if status == "ai_error":
        sys.exit(5)


if __name__ == "__main__":
    main()
