# Architecture

## Workflow trigger

The audit workflow (`audit-commit.yml`) has two callers:

1. **Push-driven** — a workflow in `moriyoshi/winterbaume` posts
   `workflow_dispatch` for every push to `main`.  This is the fast path,
   typically running within seconds of the push.
2. **Reconciler-driven** — `reconcile-main.yml` runs on a 30 minute cron
   inside this repo and dispatches `audit-commit.yml` for any commit on the
   monitored branch that has no log entry yet.  This is the safety net that
   covers the case where the push trigger is removed, disabled, or bypassed
   by a force push.

Both callers send the same four inputs:

| Input | Required | Description |
|---|---|---|
| `commit_sha` | yes | Full SHA of the commit to audit |
| `commit_author` | no | `Name <email>` string from the push event |
| `commit_message` | no | First line of the commit message |
| `commit_timestamp` | no | ISO 8601 timestamp of the commit |

Metadata is passed as inputs rather than fetched again inside the script to
avoid a redundant API call.

## Permissions

`audit-commit.yml`:

```yaml
permissions:
  contents: write   # push to audit-log branch
  issues: write     # file findings issues
  models: read      # GitHub Models API
```

`reconcile-main.yml`:

```yaml
permissions:
  contents: write   # push head-history.json to audit-log branch
  issues: write     # file force-push alerts
  actions: write    # dispatch audit-commit.yml for missing commits
```

All scopes are granted to the automatic `GITHUB_TOKEN`; no long-lived secret
is needed for the audit repo itself.  Note that `actions: write` only allows
dispatching workflows in this repo; the reconciler never writes to the
monitored repo.

## Concurrency

```yaml
concurrency:
  group: audit-log-branch
  cancel-in-progress: false
```

Both `audit-commit.yml` and `reconcile-main.yml` share this group so they
never race on the orphaned branch.  Runs are serialised rather than
cancelled.  Each audit run writes a distinct file (`logs/{date}/{sha}.json`)
and the reconciler only updates `head-history.json`, so serialisation only
prevents a `git push` conflict — it does not cause data loss when commits or
ticks pile up.

Workflow dispatches issued by the reconciler are asynchronous: the POST
returns immediately and the dispatched `audit-commit.yml` run waits in the
queue, then executes once the reconciler tick has finished.

## Script architecture (`audit_commit.py`)

### 1. Config loading

Reads and validates required environment variables.  Exits with code `1` on
any missing required variable so the workflow step fails visibly.

### 2. Commit fetch

```
GET /repos/{owner}/{repo}/commits/{sha}?per_page=100
Accept: application/vnd.github+json
```

Returns a structured `files[]` array per file: `filename`,
`previous_filename`, `status`, `additions`, `deletions`, `patch`, `sha`.
Pagination is followed via the `Link: rel="next"` header so commits with
more than 100 files are fully enumerated.  `truncated` from the API is
recorded in the audit log.  For merge commits the diff is against the
first parent only; this is logged via `is_merge: true`.

Auth uses `MONITORED_REPO_TOKEN` when set; falls back to unauthenticated for
public repositories.  Exits with code `2` on `403`/`404`.

### 3. Sensitivity manifest and routing

A static manifest at `.github/config/monitored_repo_classification.json`
classifies every path in the monitored repo as `critical`, `high`,
`medium`, or `low`.  Each file is matched against every glob rule and
**highest-classification-wins** — manifest order is documentation only,
not a security control.  The manifest loads fail-closed: a missing or
malformed manifest classifies every path as `critical` so the panel
cannot be silenced by corrupting the manifest.

Routing modes:

| Mode | When | Behaviour |
|---|---|---|
| `whole` | Total patch ≤ 400 KB | Panel sees the whole commit, no Context note. |
| `focused` | Total > 400 KB, critical+high subset ≤ 400 KB | Panel sees critical+high files plus any low file textually referenced from them; remaining files listed in a Context note as excluded. Issue filed because critical/high were excluded. |
| `focused-overflow` | Critical+high subset > 400 KB but critical-only ≤ 400 KB | Panel sees critical files only.  Issue filed at high severity. |
| `panel-skipped` | Even critical-only > 400 KB | Panel does not run; status `panel-skipped`; issue filed at critical severity. |

Deterministic structural findings bypass the LLM entirely and always
reach the issue:

- `binary_change` — patch is omitted by the API; blob SHA is recorded.
- `submodule_pointer` — patch contains `Subproject commit`.
- `generated_header_removed` — `//! Do not edit manually` removed from a
  file without re-adding it.

The `too_large` status from earlier schemas no longer exists; it is
replaced by `routing.mode` plus the `panel-skipped` status.

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

An issue is filed when **any** of the following holds:

- `verdict.suspicious == true` and `status == "reviewed"`
- one or more structural findings exist (binary change, submodule pointer,
  generated-header removal)
- routing excluded any critical or high file (`focused`,
  `focused-overflow`, or `panel-skipped` mode)

The issue contains:

- Commit metadata table (with routing mode and reason)
- Summary
- Structural findings table
- Files-reviewed table (path, classification, matched rules, included
  yes/no, patch chars)
- Consolidated LLM findings table
- Collapsible `<details>` sections for each agent's raw JSON

Labels: `integrity-audit`, the severity level (`none` / `low` / `medium`
/ `high` / `critical`), the routing mode (`whole` / `focused` /
`focused-overflow` / `panel-skipped`), plus `structural-finding` if any
deterministic finding exists.  Labels must be pre-created; GitHub
silently ignores unknown labels.

The effective severity is the maximum of the LLM verdict severity, a
structural-finding floor of `medium`, an excluded-critical-or-high floor
of `high`, and a `panel-skipped` floor of `critical`.

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

### Log entry schema (schema_version: "4")

```json
{
  "schema_version": "4",
  "timestamp": "<ISO 8601>",
  "commit_sha": "...",
  "commit_author": "...",
  "commit_message": "...",
  "commit_timestamp": "...",
  "monitored_repo": "moriyoshi/winterbaume",
  "audit_repo": "winterbaume-automation/audit-main-repo",
  "is_merge": false,
  "parents": ["..."],
  "api_truncated": false,
  "diff_chars": 12480,
  "estimated_tokens": 3120,
  "routing": {
    "mode": "whole | focused | focused-overflow | panel-skipped",
    "reason": "Total patch 12,480 chars <= threshold 400,000.",
    "total_patch_chars": 12480,
    "files": [
      {
        "path": "crates/foo/src/auth/lib.rs",
        "previous_path": null,
        "status": "modified",
        "classification": "high",
        "matched_rules": ["auth_module"],
        "patch_chars": 1024,
        "is_binary": false,
        "included_in_panel": true,
        "exclusion_reason": null
      }
    ]
  },
  "structural_findings": [
    {
      "type": "binary_change | submodule_pointer | generated_header_removed",
      "path": "...",
      "description": "..."
    }
  ],
  "status": "reviewed | ai-error | panel-skipped",
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

The reconciler does not parse log contents (it only enumerates SHAs from
`logs/{date}/*.json` filenames), so the schema bump is invisible to it.

## Exit codes

`audit_commit.py`:

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Missing required env var |
| 2 | Diff fetch failed (404 / 403 / network) |
| 4 | Audit log push failed |
| 5 | AI discussion failed (log still written with `status: "ai-error"`) |

`reconcile_main.py`:

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Missing required env var |
| 2 | GitHub API request failed (commits / compare) |
| 3 | git push of `head-history.json` failed |

## Reconciler script architecture (`reconcile_main.py`)

### 1. Fetch recent commits

```
GET /repos/{monitored}/commits?sha={branch}&per_page={N}
```

Returns up to `COMMITS_PER_PAGE` (default 100) commits in newest-first order.
The newest entry is taken as the current head.

### 2. Audit-log inventory

The `audit-log` branch is fetched and checked out.  `audited_shas()` walks
`logs/{date}/*.json` to build the set of SHAs already audited.

### 3. Force-push detection

`head-history.json` at the root of the `audit-log` branch is a JSON array of
entries:

```json
[
  {
    "timestamp": "<ISO 8601>",
    "head_sha": "<full sha>",
    "status": "initial | ok | force_push_detected",
    "note": "<free-form, references issue url on force_push_detected>"
  }
]
```

If the last recorded `head_sha` differs from the current head, the reconciler
calls:

```
GET /repos/{monitored}/compare/{prev}...{current}
```

The response's `status` field describes the ancestry:

| `status` | Interpretation | Action |
|---|---|---|
| `identical` | Same commit | Nothing to do |
| `ahead` | `prev` is an ancestor of `current` | Normal forward progress |
| `behind` | `current` is an ancestor of `prev` | Branch was reset back — force push |
| `diverged` | Both have unique commits | History rewrite — force push |
| `missing_base` (synthetic, on 404) | `prev` no longer findable | Aggressive history rewrite |

For any non-`ahead`/`identical` status, a critical issue is filed with labels
`integrity-audit`, `critical`, `force-push`, the entry is recorded
with `status: "force_push_detected"`, and **no audits are dispatched on this
tick**.  The next tick after the force push lands becomes the new baseline.

### 4. Dispatch missing audits

In normal (non-force-push) ticks, commits returned by the listing that have
no log entry are dispatched in oldest-first order:

```
POST /repos/{audit}/actions/workflows/audit-commit.yml/dispatches
{
  "ref": "main",
  "inputs": { commit_sha, commit_author, commit_message, commit_timestamp }
}
```

Inputs are derived from the listing payload, matching the format used by the
push-driven trigger in the monitored repo.

### 5. Persist head history

The current head is appended to `head-history.json` (capped at 500 entries),
the file is committed and pushed.  If the head SHA is unchanged from the
previous tick, no commit is created (`git diff --cached --quiet` short-circuit).

### Caveats

- GitHub Actions cron is best-effort; ticks may be delayed by 5-15 minutes
  and pause entirely after 60 days of repository inactivity.  This widens
  worst-case audit lag from "seconds after push" to "tens of minutes" in
  the safety-net path.
- The 100 commit window is wide enough to cover any plausible push-trigger
  outage at a 30 minute cadence.  If the trigger is broken for longer than
  100 commits' worth of activity, older commits will be missed; bumping
  `COMMITS_PER_PAGE` and paginating is a future enhancement.
- Race window: if a reconciler tick fires within the few seconds between a
  push-driven dispatch starting and that run pushing its log entry, the
  reconciler will dispatch a duplicate audit.  Both runs serialise on the
  shared concurrency group; the second run re-does AI work and overwrites
  the log file.  Cost is one duplicate AI discussion per race; correctness
  is preserved.

## Secrets reference

| Secret | Repo | Purpose |
|---|---|---|
| `MONITORED_REPO_TOKEN` | this repo | Read `moriyoshi/winterbaume` (omit if public) |
| `AUDIT_DISPATCH_PAT` | `moriyoshi/winterbaume` | `Actions: write` here, used to call `workflow_dispatch` |
