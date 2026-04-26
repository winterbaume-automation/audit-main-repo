# Journal

## 2026-04-27 — Initial setup

**Author:** moriyoshi (via Claude Code)

### Work done

Created the repository from scratch with the following files:

- `.github/workflows/audit-commit.yml` — `workflow_dispatch` triggered workflow
  with `contents: write`, `issues: write`, and `models: read` permissions.
- `.github/scripts/audit_commit.py` — orchestration script implementing a
  multi-agent integrity review panel (Backdoor Hunter, Supply Chain Inspector,
  Integrity Analyst, Moderator) backed by the GitHub Models API
  (`openai/gpt-4o-mini`).
- `AGENTS.md` — copied verbatim from `moriyoshi/winterbaume`.
- `README.md`, `.agents/docs/OVERVIEW.md`, `.agents/docs/ARCHITECTURE.md`,
  `.agents/docs/JOURNAL.md`, `.agents/docs/QUALITY_GATE.md`,
  `.agents/docs/TODO.md`, `.agents/docs/LTM/INDEX.md` — initial documentation.

### Design decisions

- **Integrity focus only.** XSS, RCE, and similar code-quality vulnerabilities
  are explicitly out of scope; a separate security agent handles those in the
  main repo.
- **Sequential discussion pattern.** Each specialist agent sees the prior
  agents' JSON outputs so it can agree with, challenge, or extend their
  findings before the Moderator synthesises a final verdict.  This was chosen
  over parallel independent analysis because cross-agent challenge/confirmation
  reduces false positives and adds an explanation trail.
- **Orphaned `audit-log` branch.** Keeps the audit record independent of the
  `main` branch history; a force-push to `main` cannot silently erase logs.
- **Token-size gate at 400 KB** (~100 K tokens).  Diffs above this threshold
  are flagged as `too_large` and skipped rather than truncated, to avoid the
  AI reviewing an incomplete picture.
- **`schema_version: "2"`** introduced immediately (version 1 was the
  single-agent design from the first iteration).
