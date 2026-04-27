# winterbaume-audit-main-repo

Automated integrity audit of commits pushed to [moriyoshi/winterbaume](https://github.com/moriyoshi/winterbaume).

## What this repository does

Every push to the `main` branch of the main repository triggers a `workflow_dispatch` event here.  A multi-agent AI panel reviews the commit diff for signs of malicious intent and records the result.

A second, scheduled workflow (`reconcile-main.yml`) runs every 30 minutes as a safety net.  It compares the recent commit list on the monitored branch against the audit log and dispatches `audit-commit.yml` for anything missing — covering the case where the push trigger inside the main repo is removed, disabled, or bypassed by a force push.  It also detects history rewrites by tracking the head SHA in `head-history.json` on the `audit-log` branch and files a critical issue when the previous head is no longer an ancestor of the current head.

Scope is **integrity only** — backdoors, supply-chain tampering, covert exfiltration, and similar deliberate sabotage.  Code-quality security issues (XSS, RCE, SQL injection, …) are handled by a separate agent running inside the main repository.

## How results are stored

| Location | Contents |
|---|---|
| `audit-log` branch (orphaned) | One JSON file per audited commit at `logs/{YYYY-MM-DD}/{sha}.json`, plus `head-history.json` recording observed monitored-branch heads |
| Issues in this repo | Filed automatically when the panel returns `suspicious: true`, or when the reconciler detects a force push |

## Triggering a manual audit

```bash
gh workflow run audit-commit.yml \
  -f commit_sha=<SHA> \
  -f commit_author="Name <email>" \
  -f commit_message="first line of message" \
  -f commit_timestamp="2026-04-27T00:00:00Z"
```

## Triggering a manual reconciliation

```bash
gh workflow run reconcile-main.yml
```

Useful after closing a force-push issue, or to verify reconciliation after changing the trigger workflow in the monitored repo.

## Required secrets

| Secret | Where | Purpose |
|---|---|---|
| `MONITORED_REPO_TOKEN` | this repo | Read access to `moriyoshi/winterbaume` (omit if public) |
| `AUDIT_DISPATCH_PAT` | `moriyoshi/winterbaume` | `Actions: write` on this repo — used to dispatch the workflow |

## Pre-created labels

The following labels must exist in this repository before issues can be tagged correctly:

`integrity-audit`, `severity:none`, `severity:low`, `severity:medium`, `severity:high`, `severity:critical`, `force-push`

## Repository layout

```
.github/
  workflows/
    audit-commit.yml     — workflow definition (workflow_dispatch trigger)
    reconcile-main.yml   — scheduled reconciliation safety net (cron + workflow_dispatch)
  scripts/
    audit_commit.py      — multi-agent discussion orchestration
    reconcile_main.py    — list missing commits, dispatch audits, detect force pushes
AGENTS.md                — rules and protocols for coding agents
README.md                — this file
.agents/
  docs/
    OVERVIEW.md
    ARCHITECTURE.md
    JOURNAL.md
    QUALITY_GATE.md
    TODO.md
    LTM/
      INDEX.md
```
