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

## 2026-04-27 — Reconciliation safety net

**Author:** moriyoshi (via Claude Code)

### Work done

Added a scheduled reconciliation workflow to defend against the case where
the push-driven trigger inside the monitored repo is removed, disabled, or
bypassed:

- `.github/workflows/reconcile-main.yml` — `cron: '*/30 * * * *'` plus
  `workflow_dispatch`, sharing the `audit-log-branch` concurrency group with
  `audit-commit.yml`.  Permissions: `contents: write`, `issues: write`,
  `actions: write`.
- `.github/scripts/reconcile_main.py` — lists the most recent commits on
  the monitored branch, reads `audited_shas()` from the `audit-log` branch,
  and dispatches `audit-commit.yml` for every commit not yet in the log.
  Tracks the observed head SHA in `head-history.json` (root of the
  `audit-log` branch).  Files an `[CRITICAL] Force push detected` issue
  when `GET /compare/{prev}...{current}` returns `behind`, `diverged`, or
  404 on `prev`; suppresses dispatch on that tick to avoid auditing a
  rewritten history before triage.

### Design decisions

- **Cron-only safety net.** GitHub Actions cron is best-effort (5-15 min
  delays, paused after 60 days idle).  An external uptime checker firing
  `repository_dispatch` would tighten the worst-case lag but adds
  infrastructure outside the audit repo.  For a redundant safety net on
  top of the existing push trigger, cron is an acceptable trade-off.
- **Same concurrency group as `audit-commit.yml`.** Reconciler ticks and
  audit runs both touch the orphaned `audit-log` branch, so sharing the
  group eliminates `git push` conflicts at the cost of serialising work.
  Workflow dispatches are async, so the reconciler tick finishes quickly
  even when many audits get queued.
- **`compare/{prev}...{current}` for ancestry.** The compare API returns
  a categorical `status` (`ahead | behind | diverged | identical`) computed
  from merge-base reachability, which is exactly what is needed to
  distinguish forward progress from history rewrites.  A 404 on the base
  SHA is treated as a synthetic `missing_base` status — it means the prior
  head is no longer findable, which is itself a strong tampering signal.
- **Suppress dispatch on force-push tick.** The reconciler does not blindly
  audit every commit on the new branch when divergence is detected; that
  could waste AI calls on a clean rebase or burn quota on an attacker's
  freshly-rewritten history before a human can intervene.  The next tick
  treats the new head as a fresh baseline.
- **Capped history (500 entries).** `head-history.json` is append-only, but
  trimmed to the last 500 entries to keep the file small.  At the 30-minute
  cadence this is roughly 10 days of history — long enough for any
  practical incident review.
- **`actions: write` is local-only.** `GITHUB_TOKEN` with `actions: write`
  can dispatch workflows in this repo only; the reconciler never writes to
  the monitored repo.  No new secret is required.

### Known limitations

- Race window: if a reconciler tick fires within the seconds between a
  push-driven dispatch starting and that run pushing its log entry, a
  duplicate audit is dispatched.  Both runs serialise on the shared group;
  cost is one redundant AI discussion per race.  Adding a preflight check
  inside `audit_commit.py` would close this; deferred as out of scope.
- 100-commit window: if the push trigger is broken for longer than 100
  commits' worth of activity, older commits will not be picked up.
  Pagination is a future enhancement (`COMMITS_PER_PAGE` env var already
  parameterises the page size).
- The reconciler does not detect tampering with `audit-commit.yml` or
  `reconcile_main.py` themselves.  Tracking workflow-file SHAs is a
  reasonable follow-up.

## 2026-04-27 — Threat model: circumvention techniques

**Author:** moriyoshi (via Claude Code)

Catalogue of attacker techniques that defeat or degrade the current audit
facility. Recorded so subsequent mitigation work has a single reference point.
Severity is "how reliably an attacker can suppress the audit signal", not the
downstream blast radius of the malicious code itself. The reconciliation
workflow added earlier today partially mitigates items marked
**( reconciler-mitigated )**; they remain in scope because the reconciler is a
best-effort safety net, not a guarantee.

### Critical — the audit emits no signal at all

1. **`too_large` is a silent skip.** Diffs above 400 KB are logged as
   `too_large` with no AI review, no issue, and no out-of-band notification.
   An attacker can guarantee suppression by padding the commit ( vendored
   deps, regenerated `wire.rs` / `model.rs`, lockfile churn, snapshot
   fixtures, a "format the codebase" pass ) or by co-merging the malicious
   change with any legitimate large refactor.
2. **Binary blobs are invisible to the diff.** `application/vnd.github.diff`
   renders binary changes as `Binary files a/x and b/x differ`. Stego in
   image / font / video fixtures, archives unpacked at test time,
   pre-compiled `.pyc` / `.class` / `.so` / `.wasm` / `.node` / `.rlib`,
   and Git LFS pointers all bypass content review entirely. Attacker can
   also flip a text file to binary via `.gitattributes`.
3. **Trigger-side suppression** ( reconciler-mitigated ). The audit only
   sees what the monitored repo dispatches. Editing `trigger-audit.yml` to
   skip certain branch / path patterns, or to dispatch a different SHA, is
   a single commit. The new reconciler closes the gap on a 30-minute cadence
   with a 100-commit lookback, so a fast burst plus a tampered workflow
   inside the same window can still slip through.

### High — audit runs but is blind by design

4. **Per-commit blind spot.** Audit runs on a single SHA. Plant a "harmless
   utility" in commit A, weaponise it in commit Z. Pure rename in commit 1
   resets reviewer attention; modification of the renamed file in commit 2
   carries no rename signal. Squash-merge collapses this but force-push,
   tag-only payloads, and direct-to-main bursts ( with `cancel-in-progress:
   false` only serialising, not back-filling ) leave intermediate commits
   under-reviewed.
5. **GitHub diff truncation.** The diff endpoint truncates very large files
   and very large overall diffs. The script does not distinguish a complete
   diff from a truncated one, so payloads can be hidden in the truncated
   tail while still staying under the 400 KB gate.
6. **Prompt injection of the four agents.** `commit_message`,
   `commit_author`, filenames, and the diff text are concatenated into the
   prompt. Vectors include: commit messages with fake `<SYSTEM>`
   instructions, in-source comments like `// audit:safe`, README / markdown
   payloads, paths like `src/SAFE_DO_NOT_FLAG/`, author strings, and
   non-English instructions ( `gpt-4o-mini` is more susceptible than a
   frontier model ).
7. **Force-push / non-fast-forward** ( reconciler-mitigated ). Detected by
   the reconciler's `compare/{prev}...{current}` check on a 30-minute
   cadence. A push-rewrite-push sequence inside one tick still hides the
   intermediate state.

### Medium — the model is unlikely to catch it

8. **Trojan-source and Unicode tricks.** Bidi ( RLO / LRO ), zero-width
   joiners, homoglyphs ( Cyrillic `а`, Greek `ο` ) in identifiers and
   string literals. `gpt-4o-mini` is not a reliable detector for these
   from raw diffs; deterministic preprocessing would be more honest.
9. **Out-of-band execution surfaces that look declarative.** A one-line
   addition under `[build-dependencies]`, a new `proc-macro` crate, a
   custom `rustc-wrapper` in `.cargo/config.toml`, a submodule URL swap,
   a lockfile `resolved` / `source` change pointing to a private mirror,
   a `.gitattributes` filter driver, or a workflow edit. Each of these
   executes attacker code from a tiny, innocuous-looking diff.
10. **Domain-specific one-character changes.** IAM policy widening, CORS
    allowlist, CSP relaxation, regex anchor removal, crypto downgrade
    ( `Aes256Gcm` → `Aes128Gcm`, lower PBKDF2 iteration count ). Mini
    models skim these.

### Worst-case combo

A single PR that ( a ) regenerates a `wire.rs` to push the diff past
400 KB, ( b ) adds a binary fixture under `tests/`, ( c ) ships a one-line
`build.rs` change that loads the fixture at compile time, ( d ) carries a
commit message complimenting the auditor. All four top-tier weaknesses fire
at once and the only artefact is a `status: "too_large"` log line.

## 2026-04-27 — File-by-file routing with a static sensitivity manifest

**Author:** moriyoshi (via Claude Code)

### Work done

Closes threats #1 and #2 from the threat-model entry above ( silent skip on
oversized commits; binary fixtures invisible to the diff ) and partially
closes #5 ( per-file truncation flag now surfaced ).

- `.github/config/monitored_repo_classification.json` ( new ) — JSON
  manifest mapping path globs to one of `critical / high / medium / low`,
  with `reason` and optional `audit_hint` per rule.  No new runtime
  dependency ( stdlib `json` and a small home-grown glob → regex
  translator suffice ).
- `.github/scripts/audit_commit.py` rewritten:
  - Switched from `application/vnd.github.diff` to
    `application/vnd.github+json` so the script gets the structured
    `files[]` array, follows `Link: rel="next"` pagination, and surfaces
    `truncated` and `is_merge` per commit.
  - `load_manifest()` is fail-closed — a missing or malformed manifest
    classifies every path as `critical` so the panel cannot be silenced
    by corrupting the manifest itself.
  - `classify_files()` uses highest-classification-wins across all
    matching rules.  Renames classify against the higher of old and new
    paths so an attacker cannot launder a `crates/foo/auth/` file into a
    `crates/foo/misc/` folder to escape the panel.
  - `route_diff()` returns one of four modes — `whole`, `focused`,
    `focused-overflow`, `panel_skipped` — replacing the binary `too_large`
    skip with a graceful degradation that always reaches the panel for
    critical paths.
  - Cross-reference inclusion: low-classification files referenced from
    included files via `mod`, `use crate::…`, or `include!()` are pulled
    back into the panel context so the panel does not lose obvious local
    context.
  - `detect_structural_findings()` deterministically reports binary
    changes, submodule pointer changes, and removal of the auto-generated
    `//! Do not edit manually` header.  These bypass the LLM and always
    file an issue.
  - `should_file_issue()` files an issue when **any** of LLM-suspicious,
    structural finding present, critical/high excluded by routing, or
    panel skipped is true.  Effective severity is the max across all
    signals.
  - Audit log schema bumped to `"3"` with new `routing` and
    `structural_findings` blocks; reconciler is unaffected because it
    only enumerates `logs/{date}/*.json` filenames.
  - Moderator prompt now instructs the model to downgrade severity and
    confidence when a finding's evidence is absent from the filtered
    diff.
- `.github/scripts/tests/` ( new ) — 49 pytest cases covering the glob
  translator, classification ( highest-wins, renames, fail-closed manifest
  variants, real-manifest smoke ), routing across all four modes,
  cross-reference inclusion, structural finding detection, and the
  issue-filing gate.
- `.github/workflows/audit-tests.yml` ( new ) — runs `py_compile` and the
  pytest suite on PRs touching `.github/scripts/**` or
  `.github/config/**`.  Does not gate the auditor itself.
- `.agents/docs/ARCHITECTURE.md` updated: replaced the "Token-size gate"
  section with the routing table, expanded the "Issue filing" section to
  cover the new gate logic, bumped the log schema example to v3.
- `.agents/docs/QUALITY_GATE.md` gained a "Routing and manifest" section.

### Design decisions

- **JSON over YAML for the manifest.** The workflow's `pip install`
  surface is currently `requests` only.  Adding `PyYAML` for a
  configuration file that any maintainer will read once a quarter is
  poor value; JSON is verbose but cheaper.  The manifest carries a
  `_comment` key for cases where a YAML-style comment would be helpful.
- **Highest-wins ordering** rather than first-match-wins.  Manifest order
  becomes documentation, not a security control — a refactor that
  reorders the file cannot silently downgrade a path.  Cost is one
  extra pass per file, which is negligible.
- **Fail-closed manifest loading.** A missing or malformed manifest is
  the exact failure mode an attacker would arrange ( delete the file,
  introduce a typo via a separate commit ).  Failing closed makes that
  attack visible — every path becomes critical, the panel is forced into
  `panel_skipped` for any large commit, and a critical-severity issue is
  filed.
- **No per-file panel fan-out.** An earlier draft considered running the
  four-agent panel per file in `focused-overflow`.  Cost is N × 4
  calls and the agents lose cross-file context.  Better to file a
  human-review issue and let a person triage; the panel's job is to
  triage, not to substitute for review when the budget is exceeded.
- **Cross-reference inclusion is a heuristic, not a guarantee.** It
  catches the easy case where a low-classified helper is referenced
  from a high-classified file.  It is not a defence against
  adversarially-named symbols; that belongs to a separate Trojan-source
  / Unicode pre-scan ( deferred ).
- **Structural findings live alongside the LLM verdict, not inside it.**
  Binary additions and submodule swaps are deterministic; routing them
  through `gpt-4o-mini` adds latency and noise without improving
  signal.  The issue body splits them into their own table so a human
  triages on the deterministic data first.
- **`audit-commit.yml` unchanged.** No new pip dependency, no new env
  var, no new permission.  The change is entirely inside
  `audit_commit.py` plus the new manifest JSON.
- **`reconcile_main.py` untouched.** Per the script's
  `audited_shas()` ( filename-only enumeration ), it does not parse log
  contents, so the schema bump from v2 to v3 is invisible.

### Known limitations and follow-ups

- Patch truncation per file ( the API truncates `patch` above ~3 K lines
  and returns the file with `patch` set to a short marker or omitted ).
  The script currently treats omitted patches as binary; a follow-up
  should fetch via the contents API for high-value files when this
  occurs.
- Lockfile semantic delta parsing is still LLM-only; deterministic
  parsers for `Cargo.lock`, `package-lock.json`, etc. would catch
  registry / source / git-rev pin changes more reliably.
- Mode flips ( chmod +x on a checked-in script ) are not detected; the
  files[] API does not expose modes.  A separate contents-API call per
  modified file would close this; deferred for cost reasons.
- The cross-reference scanner only knows Rust idioms ( `mod`,
  `use crate::`, `include!`, `include_str!`, `include_bytes!` ).
  Generalising to other languages would be straightforward when needed.
- Trojan-source / Unicode pre-scan, lockfile delta parser, and
  workflow-file SHA tripwire for this repo's own scripts remain on the
  TODO list.

## 2026-04-27 — CI hygiene: SHA-pinned actions, manual-review framing, stdlib-only scripts

**Author:** moriyoshi (via Claude Code)

### Work done

Three loosely-related cleanups landed in this session, all driven by
operational papercuts that surfaced once the audit pipeline was running.

- **GitHub Actions pinned to commit SHAs on Node.js 24 releases.**
  ( commit `333d4eb` )  Both `actions/checkout` and `actions/setup-python`
  were on `@v4` / `@v5`, which run on Node.js 20 and would have been
  force-migrated to Node.js 24 on 2026-06-02.  Bumped to v6.0.2 / v6.2.0
  ( both verified `using: node24` in their `action.yml` ) and replaced
  the floating tags with the full 40-char commit SHAs, with the version
  as a trailing comment.  The audit panel itself enforces the same
  SHA-pin rule against the monitored repo via the `.github/workflows/**`
  rule in `monitored_repo_classification.json`; the audit repo now meets
  the same bar.
- **`panel_skipped` issues now read as manual-review requests.**
  ( commit `f29e24a` )  The previous wording filed a `[CRITICAL]
  Integrity finding` title with the explanation buried inside a
  routing-reason table cell.  No finding actually occurs in that case -
  the diff just exceeds the model context budget - so the misleading
  framing made reviewers guess what was being asked of them.  Now
  `verdict.summary` leads with `**Manual review required.**`, the issue
  title becomes `[MANUAL REVIEW REQUIRED] Audit panel skipped for
  {repo}@{sha}`, the body heading is `## Manual review required ( audit
  panel skipped )`, and the file-list section is retitled
  `### Change summary ( panel did not run; review every file directly )`
  so the table reads as the change summary the human reviewer needs.
  Other routing modes are untouched; `should_file_issue()` already
  filed an issue at severity `critical` for `panel_skipped`, only the
  presentation changed.
- **No more `requests` runtime dependency.**  Added a small in-tree
  `.github/scripts/_http.py` ( ~80 lines ) that wraps `urllib.request`
  with the subset of the `requests` API the scripts touched - `get` /
  `post` / `request`, `Response.{status_code, headers, text, ok,
  json()}`, plus an `HTTPError` raised on connection-level failure;
  4xx / 5xx are returned as `Response`, matching `requests` semantics.
  Both audit scripts now `import _http as http`; the `pip install
  requests` step is gone from `audit-commit.yml` and
  `reconcile-main.yml`; `pyproject.toml` declares an empty runtime
  dependency list.  Verified end-to-end by hitting `api.github.com`
  and `httpbin.org` for the five behaviours that mattered ( 200 path,
  JSON parsing, 4xx-as-Response, connection-error-as-HTTPError, POST
  with JSON body and custom header ).  All 49 pytest cases still pass.
- **`pyproject.toml` introduced** at repo root, declaring the project
  as a non-package ( `[tool.uv] package = false` ), Python `>=3.12`,
  no runtime dependencies, and `pytest` as a dev dependency under
  `[dependency-groups]`.  `[tool.pytest.ini_options]` sets
  `testpaths = .github/scripts/tests` and
  `pythonpath = .github/scripts`, so `uv run pytest` from the repo root
  finds and imports cleanly.  The pre-existing `tests/conftest.py`
  `sys.path` hack is now redundant but left in place as a safety net
  for callers that bypass pytest's config.
- **`OVERVIEW.md` and `QUALITY_GATE.md` updated** to reflect that the
  scripts are now stdlib-only.  The "minimal dependency surface" claim
  in `OVERVIEW.md` and the "pip install requests" gate in
  `QUALITY_GATE.md` were both factually wrong after the dependency
  removal.

### Findings and observations

- **Reading "report to the issue if the panel is skipped" as ad-hoc
  rather than as script behaviour.**  When the user wrote that line, I
  initially interpreted it as a one-off instruction to file a manual
  issue flagging the just-pushed audit-repo commit, and did so via
  `gh issue create` ( now `#1` on this repo ).  The user's intent was
  for the audit script's `panel_skipped` branch itself to produce that
  framing.  Lesson: when a sentence reads as a generic policy
  statement - "if X happens, Y" - inside a software-engineering
  session, default to interpreting it as "make the code do Y when X
  happens" rather than "do Y once now".  Issue #1 is left as a
  standing manual-review record for the audit-repo workflow change
  ( which is genuinely outside the panel's scope ); whether to keep
  it is a separate call.
- **Audit-repo changes are outside the panel's scope by design.**
  The integrity panel only reviews commits on
  `moriyoshi/winterbaume`, not on this repo.  Any change to the audit
  infrastructure itself - workflows, scripts, manifest, classification
  JSON - bypasses the panel entirely.  Worth flagging because the
  SHA-pin rule the audit enforces against the monitored repo is
  meaningful precisely because this repo's workflows themselves had
  the same hole until today.

### Known limitations and follow-ups

- **`uv.lock` is committed alongside `pyproject.toml`**, but the
  workflows do not yet `uv sync` - they still rely on the system
  Python toolchain set up by `actions/setup-python`.  An end-to-end
  switch to `uv` would pin the dev environment more tightly and
  surface dependency drift in CI; deferred per the option-A scope
  this session was framed against.
- **`tests/conftest.py` sys.path injection** is now redundant given
  the pytest `pythonpath` config in `pyproject.toml`.  A future
  cleanup could remove it; left in place for now to avoid surprising
  anyone who runs the tests outside of `pytest`.
- **Lockfile delta parser, Trojan-source / Unicode pre-scan, and a
  workflow-file SHA tripwire for this repo's own scripts** all remain
  on the TODO list from the prior entry; none addressed in this
  session.

## 2026-04-27 — GitHub Models endpoint migration

**Author:** moriyoshi (via Claude Code)

### Trigger

Workflow run
[24973890820](https://github.com/winterbaume-automation/audit-main-repo/actions/runs/24973890820/job/73121895881)
(`workflow_dispatch` against commit `f567e501`) failed with exit code 5.
The audit log was still written and issue #2 was filed; the panel
itself never ran.

### Findings

- The script logged
  `API error 400: {"error":{"code":"unknown_model","message":"Unknown model: openai/gpt-4o-mini"}}`
  before short-circuiting into the `ai-error` status.
- Exit code 5 is by design - `audit_commit.py:1497-1498` exits non-zero
  whenever `status == "ai-error"` so the failure surfaces in the Actions
  UI rather than being silently buried in the audit log. The CI failure
  itself was therefore working as intended; the underlying API
  rejection was not.
- Root cause was a mismatch between endpoint and model id, not a
  vanished model. The script targeted the legacy Azure-hosted endpoint
  `https://models.inference.ai.azure.com`, which historically expects
  bare model ids (`gpt-4o-mini`), while the configured id
  `openai/gpt-4o-mini` is the publisher-prefixed form used by the newer
  GitHub-hosted catalogue endpoint `https://models.github.ai/inference`.
  The previous run 27 minutes earlier had succeeded, suggesting the
  legacy endpoint had only just stopped accepting prefixed ids on
  GitHub's side.
- The user also confirmed that `openai/gpt-4o-mini` had not yet been
  enabled for the org in the GitHub Models settings, which is a
  separate prerequisite that needs to be in place before the next
  re-run.

### Work done

- Updated `MODELS_ENDPOINT` in `.github/scripts/audit_commit.py:81`
  from `https://models.inference.ai.azure.com` to
  `https://models.github.ai/inference`. The path suffix
  (`/chat/completions`) and the `AI_MODEL` value
  (`openai/gpt-4o-mini`) are unchanged - the new endpoint is the one
  whose catalogue uses publisher-prefixed ids natively, so flipping
  the URL is the smallest faithful fix.
- Refreshed the matching reference in `.agents/docs/OVERVIEW.md:65-66`
  so the "Technology choices" section no longer points at the legacy
  URL.
- Confirmed via Grep that no other source, test, or doc still
  references `models.inference.ai.azure.com`.
- Committed as `f82702b` on `main`; not pushed.

### Design notes

- Considered the alternative of keeping the legacy endpoint and
  stripping the `openai/` prefix from `AI_MODEL` instead. Rejected
  because the legacy endpoint is on a deprecation path; preserving the
  publisher-prefixed id and moving to the supported endpoint is the
  more durable fix and matches what the surrounding docs already
  describe.
- Did not touch the `ai-error` exit-code contract. Treating an API
  outage as a CI failure rather than a silent `ai-error` log entry is
  the right default for an audit pipeline - a green workflow with
  `status: ai-error` would be easy to overlook.

### Follow-ups

- The org needs to enable `openai/gpt-4o-mini` in the GitHub Models
  catalogue before the workflow can be re-run; the endpoint change on
  its own does not unblock the panel.
- Worth a future thought: the model id and endpoint are coupled (bare
  vs. publisher-prefixed) but live as two independent constants. A
  short comment near `MODELS_ENDPOINT` / `AI_MODEL` documenting the
  pairing would make the next migration less surprising. Not done in
  this session to keep the fix minimal.
