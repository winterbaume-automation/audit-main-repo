---
name: tackle-todos
description: "Read TODO.md and scan source code for TODO/FIXME comments, build a consolidated list, then dispatch agents to address as many items as possible."
user_invocable: true
allowed-tools: Bash, Read, Write, Edit, Grep, Glob, Agent
---

# Tackle TODOs: Consolidate and Resolve Open Items

This skill scans the project for all outstanding work items — both from `.agents/docs/TODO.md` and from `# TODO` / `# FIXME` comments in source code — builds a consolidated, deduplicated, prioritised list, and then dispatches agents to resolve as many items as possible.

**Use this skill when:** you want to make a focused sweep of outstanding TODOs and fix them in bulk.

## Repo shape (read this first)

This is the audit pipeline repo, **not** the monitored `moriyoshi/winterbaume` repo.  The work surface is small and deliberately concentrated:

- `.github/scripts/audit_commit.py` — main orchestration script (panel, routing, structural findings, issue rendering)
- `.github/scripts/reconcile_main.py` — scheduled reconciler / force-push detector
- `.github/scripts/_http.py` — HTTP helpers
- `.github/scripts/tests/` — pytest suite ( `test_classify.py`, `test_glob.py`, `test_routing.py`, `test_should_file_issue.py`, `test_structural.py` )
- `.github/workflows/*.yml` — `audit-commit.yml`, `audit-tests.yml`, `reconcile-main.yml`
- `.github/config/monitored_repo_classification.json` — sensitivity manifest
- `.agents/docs/` — `TODO.md`, `JOURNAL.md`, `OVERVIEW.md`, `ARCHITECTURE.md`, `QUALITY_GATE.md`, `LTM/INDEX.md`

Because the entire pipeline lives in two Python files plus a manifest, **most TODOs land on the same handful of files**.  Parallel-agent dispatch is rarely safe here ( see Step 4 ); plan for sequential or narrowly-scoped parallel work.

## Arguments

- `[filter]` (optional): A keyword to restrict which TODOs to tackle.  Useful filters in this repo:
  - A category name from Step 2 ( `detection-bug`, `api-resilience`, ... )
  - A path / module name ( `audit_commit`, `reconcile_main`, `manifest` )
  - A free-form keyword ( `binary`, `truncation`, `force-push`, `panel` )

  If omitted, all TODOs are considered.

## Step 0: Collect TODOs from TODO.md

Read `.agents/docs/TODO.md` and extract every unchecked `- [ ]` item.  Record its description and any sub-tasks ( indented bullets / numbered lists under the item ).  TODO entries in this repo often carry significant inline context ( root-cause notes, file:line refs, evidence ) — preserve that context when forming work units.

## Step 1: Scan Source Code for TODO / FIXME Comments

Use Grep to search for `# TODO` / `# FIXME` ( and `// TODO` / `// FIXME` for completeness if any non-Python source appears later ) under:

- `.github/scripts/**/*.py`
- `.github/workflows/**/*.yml`
- `.github/config/**`

Exclude `__pycache__`, `.pytest_cache`, `.venv`.

Group and deduplicate the results.  Comments that are informational-only ( noting a known limitation that cannot be fixed without a design change ) should be flagged but deprioritised.

## Step 2: Build a Consolidated TODO List

Merge the two sources into a single list.  Deduplicate items that appear in both `TODO.md` and as code comments.

For each item, assign a category:

| Category | Description | Priority |
|----------|-------------|----------|
| **detection-bug** | False positive / negative in a structural-finding heuristic ( e.g. `binary_change` over-firing on text files ) | High — directly affects audit accuracy |
| **api-resilience** | GitHub API edge cases ( per-file patch truncation, response-size cap, missing fields, pagination, rate limits ) | High — silent data loss |
| **panel-quality** | Improvements to the LLM panel prompts, agent discussion, moderator synthesis, or model / endpoint config | Medium |
| **infrastructure** | Workflow YAML, secrets, scheduling, reconciliation, label provisioning | Medium |
| **observability** | Logging, error reporting, replayability of audit runs, scoreboard / debug surfaces | Medium |
| **test-only** | Missing pytest coverage for an existing behaviour | Low |
| **design** | Requires architectural decisions ( e.g. whether `binary_change` should escalate severity at all ) | Deferred — flag for user |

Write the consolidated list to `.agents/tmp/consolidated-todos.md` for reference.  Create the directory if it does not exist; per repo rules temporary files belong under `.agents/tmp/`, never `/tmp`.

## Step 3: Filter (if argument provided)

If the user passed a `[filter]` argument, restrict the work list to items matching that filter ( category, path / module, or keyword ).

## Step 4: Plan Work Items — sequential by default

Group the consolidated TODOs into work units.  Each work unit should:

- Be self-contained ( ideally one file, or one cross-cutting concern with a clear seam ).
- Carry the existing TODO context forward ( file:line refs, root-cause notes, evidence ) so the executing agent does not have to rediscover them.

**Parallelism caveat for this repo.**  The pipeline lives in `audit_commit.py` ( ~1500 lines ) and `reconcile_main.py`.  Two agents touching either file in parallel will conflict.  Default to **sequential** dispatch.  Parallel dispatch is only safe when work units touch disjoint files — for example, "manifest classification rule" + "reconciler force-push detection" + "workflow YAML edit".  When parallel work IS planned, use `isolation: worktree` so each agent gets its own checkout.

Present the plan to the user and get confirmation before dispatching.

## Step 5: Dispatch Agents

For each approved work unit, launch an Agent ( `subagent_type: general-purpose`; `isolation: worktree` only when running in parallel ) with a prompt that includes:

1. The specific TODO(s) to address, including the inline context already captured in `TODO.md`.
2. The files to modify, with file:line refs.
3. The expected behaviour, with reference to GitHub API docs / repo conventions where applicable.
4. The test command to run after changes, scoped tightly:
   - `uv run pytest .github/scripts/tests/test_<module>.py --maxfail=5`
   - For last-failing only: add `--lf`.
   - Avoid running the full suite in a tight loop; per repo rules, always specify `--maxfail=n` ( `n < 10` ).
5. A reminder of repo rules the agent must obey:
   - No `git checkout` / `git restore` ( other agents may share the working directory ).
   - No discretionary commits, no unsigned commits.
   - British-English spelling in repo-authored docs; no full-width parentheses or colons in `AGENTS.md` / `README.md` / `.agents/docs/**`.
   - Temporary files under `.agents/tmp/`, never `/tmp`.

## Step 6: Collect Results and Update TODO.md

After all agents complete:

1. Review each agent's results — check that the change is contained, that targeted pytest runs are green, and that no `# TODO` comment was silently moved instead of resolved.
2. For successfully resolved items, mark them `- [x]` in `.agents/docs/TODO.md` and remove the corresponding `# TODO` / `# FIXME` comment from the source.
3. For items that could not be resolved, append notes to the TODO entry explaining what was attempted and why it stalled — do **not** edit existing TODO context out of place.
4. Append a new dated entry to `.agents/docs/JOURNAL.md` documenting which items were tackled, which agents ran, and the outcomes.  Per repo convention: never edit existing JOURNAL sections, only append.

## Notes

- **Do not attempt design-category items** without user approval.  These require architectural decisions ( e.g. severity-weighting policy, schema-version bumps ).
- **High-leverage items first.**  In this repo the highest-leverage TODOs are usually `detection-bug` and `api-resilience` items, because each one shows up in every audited commit.
- The audit pipeline is itself audited by its own workflows; the repo-level `audit-tests.yml` runs the pytest suite on PRs.  Keep changes test-covered.
- This repo has no Cargo / Rust toolchain.  Anything in the parent `tackle-todos` skill that referenced `cargo`, `crates/`, or `winterbaume-{service}` does not apply here — use `uv run pytest` and the script paths above instead.
