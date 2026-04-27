# Quality Gate

Checklist to run before considering any change to this repository complete.

## Workflow YAML

### `audit-commit.yml`

- [ ] Parses without errors:
  ```bash
  gh workflow list  # confirms the file is valid after push
  ```
- [ ] All required inputs (`commit_sha`) are marked `required: true`.
- [ ] `permissions` block includes `contents: write`, `issues: write`,
  `models: read`.
- [ ] `concurrency.group` is `audit-log-branch` and `cancel-in-progress`
  is `false` (queue, not cancel).
- [ ] `fetch-depth: 0` is present on the checkout step.

### `reconcile-main.yml`

- [ ] Parses without errors (`gh workflow list`).
- [ ] `on:` includes both `schedule` (cron) and `workflow_dispatch` for
  manual triggering.
- [ ] `permissions` block includes `contents: write`, `issues: write`,
  `actions: write`.
- [ ] `concurrency.group` is `audit-log-branch` (shared with
  `audit-commit.yml`) and `cancel-in-progress` is `false`.
- [ ] `fetch-depth: 0` is present on the checkout step.
- [ ] `AUDIT_REPO`, `MONITORED_REPO`, `MONITORED_BRANCH` env vars are
  set on the reconciler step.

## Python script

- [ ] No new third-party runtime dependencies — the audit scripts run on
  the Python 3.12 stdlib only, via the in-tree `_http` shim. Any new
  dependency must be added to `pyproject.toml` and installed explicitly
  in the workflow ( use `uv sync` or a pinned `pip install` step ).
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
- [ ] `write_audit_log` is always called, even when `status` is `"panel-skipped"`
  or `"ai-error"` — the log is the canonical record of every run.

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

## Reconciler

- [ ] A manual `gh workflow run reconcile-main.yml` against a fully-audited
  branch produces no dispatched audits and updates `head-history.json` only
  if the head moved.
- [ ] When commits exist on the monitored branch that are not in
  `logs/`, the reconciler dispatches `audit-commit.yml` for each in
  oldest-first order.
- [ ] `head-history.json` is a JSON array; each entry has
  `timestamp`, `head_sha`, `status`, `note`; `status` is one of
  `initial`, `ok`, `force_push_detected`.
- [ ] On force push (status `behind`, `diverged`, or `missing_base`), the
  reconciler files an issue labelled `integrity-audit`, `critical`,
  `force-push` and dispatches no audits for that tick.

## Issue filing

- [ ] Labels `integrity-audit`, `none`, `low`, `medium`, `high`,
  `critical`, `whole`, `focused`, `focused-overflow`, `panel-skipped`,
  `structural-finding`, `force-push` are pre-created in this repository.
- [ ] A test run with a deliberately suspicious diff produces an issue with the
  correct title format `[SEVERITY] Integrity finding in {repo}@{sha[:12]}`.
- [ ] The issue body contains collapsible `<details>` sections for each agent.

## Routing and manifest

- [ ] `.github/config/monitored_repo_classification.json` parses as JSON
  and has `schema_version: "1"`.
- [ ] Classification logic is highest-wins across all matching rules
  (manifest order is documentation only, not a security control).
- [ ] `load_manifest()` fails closed: a missing or malformed manifest
  classifies every path as `critical`.
- [ ] Every audit log entry contains a `routing` block with `mode`,
  `reason`, `total_patch_chars`, and a per-file `files` array.
- [ ] Structural findings (binary change, submodule pointer change,
  generated-header removal) always result in an issue regardless of LLM
  verdict.
- [ ] Routing modes `focused`, `focused-overflow`, and `panel-skipped`
  always result in an issue when at least one critical or high file was
  excluded.
- [ ] `pytest .github/scripts/tests/` passes locally and in CI
  (`audit-tests.yml`).

## Documentation

- [ ] British English throughout all repo-authored documents.
- [ ] No full-width parentheses or colons in repo-authored documents
  (per AGENTS.md rules).
- [ ] JOURNAL.md has an entry for the change.
- [ ] TODO.md is updated to reflect any new open items or completed ones.
