# winterbaume-audit-main-repo

Automated integrity audit of commits pushed to [moriyoshi/winterbaume](https://github.com/moriyoshi/winterbaume).

## What this repository does

Every push to the `main` branch of the main repository triggers a `workflow_dispatch` event here.  A multi-agent AI panel reviews the commit diff for signs of malicious intent and records the result.

Scope is **integrity only** — backdoors, supply-chain tampering, covert exfiltration, and similar deliberate sabotage.  Code-quality security issues (XSS, RCE, SQL injection, …) are handled by a separate agent running inside the main repository.

## How results are stored

| Location | Contents |
|---|---|
| `audit-log` branch (orphaned) | One JSON file per audited commit at `logs/{YYYY-MM-DD}/{sha}.json` |
| Issues in this repo | Filed automatically when the panel returns `suspicious: true` |

## Triggering a manual audit

```bash
gh workflow run audit-commit.yml \
  -f commit_sha=<SHA> \
  -f commit_author="Name <email>" \
  -f commit_message="first line of message" \
  -f commit_timestamp="2026-04-27T00:00:00Z"
```

## Required secrets

| Secret | Where | Purpose |
|---|---|---|
| `MONITORED_REPO_TOKEN` | this repo | Read access to `moriyoshi/winterbaume` (omit if public) |
| `AUDIT_DISPATCH_PAT` | `moriyoshi/winterbaume` | `Actions: write` on this repo — used to dispatch the workflow |

## Pre-created labels

The following labels must exist in this repository before issues can be tagged correctly:

`integrity-audit`, `severity:none`, `severity:low`, `severity:medium`, `severity:high`, `severity:critical`

## Repository layout

```
.github/
  workflows/
    audit-commit.yml     — workflow definition (workflow_dispatch trigger)
  scripts/
    audit_commit.py      — multi-agent discussion orchestration
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
