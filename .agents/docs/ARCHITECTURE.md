# Architecture

## Workflow trigger

The workflow (`audit-commit.yml`) is triggered exclusively via
`workflow_dispatch` — it is never triggered by events within this repository
itself.  The caller (a workflow in `moriyoshi/winterbaume`) sends four inputs:

| Input | Required | Description |
|---|---|---|
| `commit_sha` | yes | Full SHA of the commit to audit |
| `commit_author` | no | `Name <email>` string from the push event |
| `commit_message` | no | First line of the commit message |
| `commit_timestamp` | no | ISO 8601 timestamp of the commit |

Metadata is passed as inputs rather than fetched again inside the script to
avoid a redundant API call.

## Permissions

```yaml
permissions:
  contents: write   # push to audit-log branch
  issues: write     # file findings issues
  models: read      # GitHub Models API
```

All three scopes are granted to the automatic `GITHUB_TOKEN`; no long-lived
secret is needed for the audit repo itself.

## Concurrency

```yaml
concurrency:
  group: audit-log-branch
  cancel-in-progress: false
```

Runs are serialised rather than cancelled.  Each run writes a distinct file
(`logs/{date}/{sha}.json`), so serialisation only prevents a push conflict on
the `audit-log` branch — it does not cause data loss when commits arrive
quickly.

## Script architecture (`audit_commit.py`)

### 1. Config loading

Reads and validates required environment variables.  Exits with code `1` on
any missing required variable so the workflow step fails visibly.

### 2. Diff fetch

```
GET /repos/{owner}/{repo}/commits/{sha}
Accept: application/vnd.github.diff
```

Auth uses `MONITORED_REPO_TOKEN` when set; falls back to unauthenticated for
public repositories.  Exits with code `2` on `403`/`404`.

### 3. Token-size gate

```
estimated_tokens = len(diff_text) // 4
too_large        = len(diff_text) > 400_000  (~100 K tokens)
```

If `too_large`, the entire AI discussion is skipped and the audit log entry
records `status: "too_large"`.  No issue is filed.

### 4. Multi-agent discussion

Three specialist agents run in sequence; each receives the diff and the
accumulated transcript of prior agents:

```
Backdoor Hunter
  │  concerns: logic bombs, hidden backdoors, obfuscated payloads, trojans
  ▼
Supply Chain Inspector
  │  concerns: typosquatting, lockfile tampering, malicious build steps
  │  + responses to Backdoor Hunter's findings
  ▼
Integrity Analyst
  │  concerns: covert exfiltration, audit-trail removal, crypto weakening,
  │            auth downgrade, social engineering
  │  + responses to both prior agents
  ▼
Moderator
     synthesises the full transcript into a single verdict JSON
```

Each agent is instructed to output a JSON object only (no markdown fences).
`response_format: {"type": "json_object"}` enforces this at the API level.
Temperature is set to `0.1` for determinism.

A single rate-limit retry (honouring the `retry-after` header) is attempted
per API call.

### 5. Issue filing

If `verdict.suspicious == true` and `status == "reviewed"`, an issue is
created in this repository containing:

- Commit metadata table
- Moderator summary
- Consolidated findings table (with `raised_by` column)
- Collapsible `<details>` sections showing each agent's raw JSON response

Labels `integrity-audit` and `severity:<level>` are applied.  Labels must be
pre-created; GitHub silently ignores unknown labels.

### 6. Audit log write

The log is committed to the orphaned `audit-log` branch:

```
logs/
  {YYYY-MM-DD}/
    {full-sha}.json
```

Branch management logic:

```
git fetch origin audit-log → success?
  yes → git checkout audit-log
  no  → git checkout --orphan audit-log
        git rm -rf --cached .
        git clean -fdx --exclude=.github
mkdir -p logs/{date}
write {sha}.json
git add / commit / push
```

### Log entry schema (schema_version: "2")

```json
{
  "schema_version": "2",
  "timestamp": "<ISO 8601>",
  "commit_sha": "...",
  "commit_author": "...",
  "commit_message": "...",
  "commit_timestamp": "...",
  "monitored_repo": "moriyoshi/winterbaume",
  "audit_repo": "winterbaume-automation/audit-main-repo",
  "diff_chars": 12480,
  "estimated_tokens": 3120,
  "status": "reviewed | too_large | ai_error",
  "ai_model": "openai/gpt-4o-mini | null",
  "agents": ["Backdoor Hunter", "Supply Chain Inspector", "Integrity Analyst", "Moderator"],
  "discussion": [
    { "agent": "Backdoor Hunter", "response": { ... } },
    { "agent": "Supply Chain Inspector", "response": { ... } },
    { "agent": "Integrity Analyst", "response": { ... } },
    { "agent": "Moderator", "response": { ... } }
  ],
  "verdict": {
    "suspicious": false,
    "severity": "none",
    "summary": "...",
    "findings": []
  },
  "issue_url": null
}
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Missing required env var |
| 2 | Diff fetch failed (404 / 403 / network) |
| 4 | Audit log push failed |
| 5 | AI discussion failed (log still written with `status: "ai_error"`) |

## Secrets reference

| Secret | Repo | Purpose |
|---|---|---|
| `MONITORED_REPO_TOKEN` | this repo | Read `moriyoshi/winterbaume` (omit if public) |
| `AUDIT_DISPATCH_PAT` | `moriyoshi/winterbaume` | `Actions: write` here, used to call `workflow_dispatch` |
