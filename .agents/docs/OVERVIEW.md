# Overview

## Purpose

This repository provides automated integrity auditing for commits pushed to
[moriyoshi/winterbaume](https://github.com/moriyoshi/winterbaume).  It is a
satellite repository — it holds no application code, only the GitHub Actions
workflow and the orchestration script that drives the audit.

## Scope

The audit focuses exclusively on **commit integrity**: detecting whether a
change may have been made with malicious intent.  This includes:

- Intentional backdoors and logic bombs
- Supply-chain attacks (dependency tampering, typosquatting, lockfile
  manipulation, malicious build steps)
- Covert data exfiltration and unauthorised telemetry
- Subtle erosion of trust (weakened cryptography, silenced audit trails,
  auth downgrade)

Code-quality security issues (XSS, RCE, SQL injection, path traversal, …)
are explicitly out of scope here; they are handled by a separate security agent
operating inside the main repository.

## How it fits into the system

```
moriyoshi/winterbaume
  push → main
    └─ trigger-audit.yml
         POST workflow_dispatch →
              winterbaume-automation/audit-main-repo
                audit-commit.yml
                  audit_commit.py
                    ├─ fetch diff (GitHub REST API)
                    ├─ multi-agent discussion (GitHub Models API)
                    ├─ write audit-log branch
                    └─ file issue (if suspicious)

winterbaume-automation/audit-main-repo
  schedule (every 30 min)
    └─ reconcile-main.yml
         reconcile_main.py
           ├─ list recent commits on monitored main
           ├─ diff against logs/ on audit-log branch
           ├─ POST workflow_dispatch → audit-commit.yml (per missing commit)
           ├─ compare prev head ↔ current head (GitHub REST API)
           └─ file critical issue if force push detected
```

## Key components

| Component | Path | Role |
|---|---|---|
| Audit workflow | `.github/workflows/audit-commit.yml` | Entry point for per-commit audit, secrets, permissions |
| Audit script | `.github/scripts/audit_commit.py` | Orchestrates diff fetch, AI discussion, log write, issue filing |
| Reconcile workflow | `.github/workflows/reconcile-main.yml` | Scheduled (30 min) safety net, dispatches missing audits |
| Reconcile script | `.github/scripts/reconcile_main.py` | Lists commits, diffs against log, dispatches, detects force pushes |
| Audit log | `audit-log` branch (orphaned) | Permanent record of every audit run plus `head-history.json` |
| Issues | Issues tab of this repo | Human-readable findings for suspicious commits and force pushes |

## Technology choices

- **GitHub Models API** (`openai/gpt-4o-mini`, OpenAI-compatible endpoint at
  `https://models.inference.ai.azure.com`) — no external AI service required;
  auth reuses the workflow's `GITHUB_TOKEN` with `models: read` permission.
- **Python 3.12 stdlib only** — no third-party runtime dependencies. A
  small in-tree `_http` module wraps `urllib.request` to give the audit
  scripts a `requests`-shaped client without a `pip install` step.
  `pyproject.toml` declares `pytest` only as a dev dependency.
- **Orphaned branch** for the audit log — keeps history independent of the
  `main` branch so log entries can never be silently dropped by a force-push
  to `main`.
