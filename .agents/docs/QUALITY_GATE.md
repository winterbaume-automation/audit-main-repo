# Quality Gate

Checklist to run before considering any change to this repository complete.

## Workflow YAML

- [ ] `audit-commit.yml` parses without errors:
  ```bash
  gh workflow list  # confirms the file is valid after push
  ```
- [ ] All required inputs (`commit_sha`) are marked `required: true`.
- [ ] `permissions` block includes `contents: write`, `issues: write`,
  `models: read`.
- [ ] `concurrency.cancel-in-progress` is `false` (queue, not cancel).
- [ ] `fetch-depth: 0` is present on the checkout step.

## Python script

- [ ] No bare `pip install` — the workflow pins the `pip install requests`
  step; any new dependency must be added there explicitly.
- [ ] All environment variable reads use `os.environ.get(…)` for optional
  vars and `os.environ[…]` (failing fast) only inside `load_config` where
  the missing-var check already covers them.
- [ ] Every `subprocess.run` call that must not fail silently has either
  `check=True` or an explicit returncode check.
- [ ] No string interpolation into shell commands — all subprocess calls use
  list form, never `shell=True`.
- [ ] `response_format: {"type": "json_object"}` is present on every
  `_call_model` invocation and the word "json" appears in the corresponding
  system prompt (required for JSON mode to activate).
- [ ] Rate-limit retry is present (one retry honouring `retry-after` header).
- [ ] `write_audit_log` is always called, even when `status` is `"too_large"`
  or `"ai_error"` — the log is the canonical record of every run.

## Agent prompts

- [ ] Each specialist agent prompt explicitly states that code-quality
  vulnerabilities (XSS, RCE, SQLi, …) are **out of scope**.
- [ ] Each prompt after the first mentions that prior agents' findings are
  provided and that the agent should respond to them.
- [ ] The Moderator prompt explains how to weigh corroborated vs. challenged
  concerns.

## Audit log

- [ ] Log schema version matches the current schema (`"2"` as of initial
  setup).
- [ ] A manual test run produces a valid JSON file on the `audit-log` branch
  at `logs/{date}/{sha}.json`.
- [ ] A second run with a different SHA appends a new file without touching the
  first.

## Issue filing

- [ ] Labels `integrity-audit`, `severity:none`, `severity:low`,
  `severity:medium`, `severity:high`, `severity:critical` are pre-created in
  this repository.
- [ ] A test run with a deliberately suspicious diff produces an issue with the
  correct title format `[SEVERITY] Integrity finding in {repo}@{sha[:12]}`.
- [ ] The issue body contains collapsible `<details>` sections for each agent.

## Documentation

- [ ] British English throughout all repo-authored documents.
- [ ] No full-width parentheses or colons in repo-authored documents
  (per AGENTS.md rules).
- [ ] JOURNAL.md has an entry for the change.
- [ ] TODO.md is updated to reflect any new open items or completed ones.
