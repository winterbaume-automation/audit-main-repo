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

## 2026-04-27 — `binary_change` false-positive triage on issue #4

**Author:** moriyoshi (via Claude Code)

### Context

The user reviewed audit issue #4
( `[MEDIUM] Integrity finding in moriyoshi/winterbaume@f567e5018619`,
the initial commit of the monitored repo ) and was satisfied with the
overall verdict but flagged that `.agents/docs/API_COVERAGE.md` and
many other obviously-text files were emitted as `binary_change`
structural findings.  Asked whether the classification was correct and
to look for related goofs.

### Findings

- **Root cause.** `FileChange.is_binary` in
  `audit_commit.py:417-421` returns `True` whenever `patch is None`
  and `status` is not `removed` / `unchanged`.  GitHub's commits API
  omits `patch` in two unrelated cases: actual binary blobs, **and**
  text files whose patch exceeded the per-response size cap.  The
  audit cannot tell those apart from the `files[]` payload alone.

- **Evidence.** Direct fetch of
  `GET /repos/moriyoshi/winterbaume/commits/f567e5018619?per_page=300`
  shows 221 of 300 files on page 1 with `patch=None`.  Almost all are
  `.md` / `.rs` / `.toml` / `Cargo.lock` text files reporting large
  positive `additions` and `deletions=0` ( e.g.
  `.agents/docs/API_COVERAGE.md` `+12198/-0`, `Cargo.lock`
  `+14627/-0`, `crates/winterbaume-accessanalyzer/src/handlers.rs`
  `+565/-0` ).  GitHub returns 9 pages at `per_page=300` for this
  commit, so the same false-positive pattern likely repeats across
  the rest.

- **`additions == 0 && deletions == 0` is not a clean discriminator
  either.**  Direct blob fetch of `LICENSE`
  ( sha `d645695673349e3947e8e5ae42332d0ac3164cd7` ) returns 11 358
  bytes of plain Apache 2.0 text with no NUL bytes, yet GitHub
  reports `+0/-0` AND `patch=None` for it.  So the cleanest fix is
  to fetch the blob and sniff for NUL bytes ( or honour
  `.gitattributes` ) rather than trust diff metadata.

### Other goofs in the same blast radius

1. `audit_commit.py:754` — structural-finding description text says
   "Binary file added; verify the blob by hand" for files that are
   plain text.  Misleads the reviewer.

2. `audit_commit.py:858-859` — `_compose_patch` writes
   `Binary files a/X and b/X differ` into the composed patch shown to
   the LLM panel for these false binaries.  The panel sees an opaque
   placeholder where it could see real, classifiable text.

3. `audit_commit.py:832` — `_find_cross_refs` joins only
   patches that exist, so any `mod` / `use` / `include_str!` refs
   declared in the omitted-patch files are invisible to the
   cross-reference pull-in pass.  For issue #4 this means the new
   crate sources never qualified as cross-refs even though most were
   classified `medium/default`.

4. **Severity-escalation side effect.**  200+ false `binary_change`
   findings pushed the issue-#4 commit into MEDIUM
   `structural-finding` territory and effectively buried the one
   genuine LLM finding ( `remote_fetch_execute` at
   `release.yml:49`, the well-known cargo-dist installer ).

### Work done

- No code changes this session; this was a triage / diagnosis pass.
- Recorded the fix as a single prioritised TODO entry in
  `.agents/docs/TODO.md` ( four sub-tasks: replace heuristic via
  blob sniff, refetch and synthesise patches for text files, clean up
  misleading description / placeholder text, revisit severity
  escalation once the false-positive volume drops ).
- Cross-referenced the existing TODO about refetching truncated
  criticals via the contents API so the two efforts can be unified.

### Open questions for follow-up

- Per-file blob fetches add an API round-trip per "looks-binary" file.
  For an initial commit of this size that is ~hundreds of extra calls.
  Worth measuring against the rate-limit headroom before turning the
  fix on by default, or gating it on `classification in (critical,
  high)` first and broadening later.
- Whether `binary_change` should remain a structural finding at all
  once the heuristic is reliable — true binary additions to a
  predominantly text repo are still suspicious, but the description
  text and severity weighting want a second look.

## 2026-04-27 — Port `tackle-todos` skill from monitored repo

**Author:** moriyoshi (via Claude Code)

### Context

The user wanted the `tackle-todos` skill from `moriyoshi/winterbaume`
( the monitored repo ) available here as well, so future TODO sweeps
in the audit pipeline repo can reuse the same pattern: scan
`TODO.md` and source-code `TODO`/`FIXME` comments, build a
consolidated list, and dispatch agents to resolve as many items as
possible.  Direct copy was not appropriate because the upstream
skill is shaped around a Cargo workspace with many service crates,
whereas this repo is two Python files plus a manifest.

### Work done

- Created `.agents/skills/tackle-todos/SKILL.md`, adapted from
  `moriyoshi/winterbaume/.agents/skills/tackle-todos/SKILL.md`.
- Mirrored the upstream wiring by symlinking
  `.claude/skills -> ../.agents/skills` so Claude Code's skill
  picker discovers the new skill.

### Adaptations from the upstream skill

- **Repo shape preamble.**  Added an explicit list of the actual
  files the skill operates on ( `audit_commit.py`,
  `reconcile_main.py`, `_http.py`, `tests/`, `workflows/*.yml`,
  `monitored_repo_classification.json` ) and a warning that the
  small surface area concentrates almost every TODO on the same
  one or two files.

- **Comment-scan pattern.**  Switched the source-code scan from
  `// TODO` / `// FIXME` in `crates/**/*.rs` to `# TODO` / `# FIXME`
  in `.github/scripts/**/*.py`, plus workflows and config.  Excluded
  `__pycache__`, `.pytest_cache`, `.venv`.

- **Categorisation.**  Replaced the AWS-flavoured upstream
  categories ( `systematic`, `behavioural`, `serialization` ) with
  audit-pipeline categories: `detection-bug`, `api-resilience`,
  `panel-quality`, `infrastructure`, `observability`, `test-only`,
  `design`.  The `binary_change` cluster from issue #4 is the
  prototypical `detection-bug` entry.

- **Parallelism caveat.**  Upstream defaults to parallel agents in
  worktrees because per-service crates are naturally disjoint.  In
  this repo two agents touching `audit_commit.py` ( ~1500 lines )
  will conflict, so the adapted skill defaults to **sequential**
  dispatch and only recommends `isolation: worktree` when work
  units are demonstrably disjoint.

- **Test command.**  Replaced
  `cargo test -p winterbaume-{service} -- --maxfail=5` with
  `uv run pytest .github/scripts/tests/test_<module>.py --maxfail=5`
  ( plus `--lf` for last-failing ), matching the conventions in
  `CLAUDE.md` and `pyproject.toml`.

- **Repo-rule reminders.**  Added the audit-repo-specific rules the
  executing agent must obey: no `git checkout` / `git restore`, no
  discretionary or unsigned commits, British-English spelling in
  repo-authored docs, no full-width parentheses or colons in
  `AGENTS.md` / `README.md` / `.agents/docs/**`, temporary files
  under `.agents/tmp/` rather than `/tmp`.

- **Filter argument.**  Kept the optional `[filter]` argument but
  re-described useful filters for this repo ( category names like
  `detection-bug`, module names like `audit_commit` /
  `reconcile_main`, free-form keywords like `binary` / `truncation`
  / `force-push` / `panel` ) instead of AWS service names.

### Design notes

- Considered making the skill silently delegate to the upstream
  copy by reference, but rejected that — the audit repo is intended
  to be self-contained and audit-able on its own, and a future
  reader should not have to clone a second repo to understand a
  skill that ships here.
- Kept the upstream's overall step structure ( collect → scan →
  consolidate → filter → plan → dispatch → reconcile ) so anyone
  fluent in the upstream skill can use this one without re-learning
  the workflow; only the specifics inside each step changed.

### Follow-ups

- First real exercise of the skill will be the `binary_change`
  detection-bug cluster recorded in the previous TODO entry; that
  will tell us whether the categorisation and the
  sequential-by-default dispatch model are the right defaults, or
  whether the skill needs a second pass once we have field
  experience.
- The skill currently assumes `.agents/tmp/` is writable.  No
  `.gitignore` entry has been added for it yet — worth
  double-checking before the first real run so we do not
  accidentally commit `consolidated-todos.md`.

## 2026-04-27 — First `tackle-todos` sweep ( six work units )

### Context

First exercise of the newly-ported `tackle-todos` skill against the
full pending list in `.agents/docs/TODO.md`.  No `# TODO` / `# FIXME`
comments existed in `.github/scripts/`, `.github/workflows/`, or
`.github/config/`, so all work units came from the TODO.md list.  The
sweep was dispatched strictly sequentially per the skill's repo-shape
note that almost every TODO lands on `audit_commit.py`.

Seven items in TODO.md were operational ( secrets, multi-repo config,
manual `workflow_dispatch` runs, post-month manifest tuning, scheduled
reconciler verification, force-push validation ); these need user
action and were not candidates for agent dispatch.  The remaining
items were grouped into six work units.

### Work done

- **WU-1: `binary_change` false-positive fix + truncated-patch
  refetch.**  TODO #14 sub-tasks 1-3 bundled with TODO #8 ( the
  refetch path ) since TODO #14 sub-task 2 explicitly flagged the
  overlap.  `FileChange.is_binary` is now a stored field, set during
  a new `_resolve_patch_omissions` pass that fetches the blob via
  `GET /repos/{owner}/{repo}/git/blobs/{sha}` and sniffs the first
  8 KB for NUL bytes ( authoritative ); extension fallback for
  rate-limited blob fetches.  Text files with `patch=None` get a
  synthesised unified diff so the LLM panel sees the content.  The
  same refetch path runs for critical / high files when the patch
  looks API-truncated ( per-file blob cost gate keeps it off the
  long tail ).  New `text_patch_unavailable` finding type fires only
  when reconstruction failed.  TODO #14 sub-task 4 ( whether
  `binary_change` should still escalate severity at all ) is a design
  decision and was deliberately left open, with a note that the
  false-positive volume motivating it has now been eliminated.

- **WU-2: Trojan-source / Unicode pre-scan.**  TODO #6.  New
  `unicode_risk` structural finding fires on bidi controls
  ( U+202A-U+202E and U+2066-U+2069 ) introduced on `+` lines,
  zero-width characters in identifier-looking tokens of added code,
  and mixed-script identifiers.  Mixed-script detection scoped to
  Latin / Cyrillic / Greek to keep i18n false-positive risk low; CJK,
  Hebrew, and Arabic mixed with Latin is not flagged.  BOM at the
  very start of a `new file` is exempted.  Bidi controls on `-` lines
  that vanish on the `+` side ( i.e. an attack being removed ) do not
  fire.

- **WU-3: Lockfile delta parser.**  TODO #7.  New `lockfile_delta`
  structural finding emits one entry per changed package across
  `Cargo.lock`, `package-lock.json`, `pnpm-lock.yaml`, `uv.lock`,
  `poetry.lock` ( basename match so monorepos like
  `crates/foo/Cargo.lock` work ).  Detects version bumps, source /
  registry changes, git-rev pin rotations, integrity-only churn for
  packages whose version did not move.  Stdlib-only ( regex
  extractors over the patch-reconstructed pre / post text; `tomllib`
  was rejected because partial fragments from a unified diff are
  rarely valid TOML ).  Unparseable patches collapse to a single
  "could not be parsed deterministically" finding rather than crash.

- **WU-4: Preflight skip when log already exists.**  TODO #12.  New
  `audit_already_exists(cfg)` walks the `audit-log` branch via the
  Git Trees API and short-circuits `main()` when
  `logs/*/{commit_sha}.json` is present anywhere ( the date directory
  may differ from today ).  Falls back to the Contents API when the
  tree response is itself `truncated`.  `AUDIT_FORCE_RERUN=1`
  bypasses the check for the explicit re-audit case.  Eliminates the
  duplicate-audit cost in the rare reconciler-vs-push-trigger race.

- **WU-5: File-mode flip / symlink change detection.**  TODO #9.
  Gated behind `AUDIT_DETECT_MODE_CHANGES` ( default off ) because of
  the per-tick API cost.  When enabled, two recursive Trees-API
  fetches ( one per side of the diff ) catch `100644 → 100755`
  flips; a per-symlink Contents-API call resolves the `target`
  field, since the recursive Trees response does not include it.
  New finding types: `mode_flip_executable`,
  `mode_flip_non_executable`, `symlink_added`,
  `symlink_target_changed`, `symlink_removed`.
  `mode_check_unavailable` fires once per audit when trees are
  unfetchable or `truncated=True` left a path uncovered.

- **WU-6: Reconciler tracks workflow-file SHAs.**  TODO #13.  New
  `workflow_history.json` on the `audit-log` branch records the SHAs
  of `audit-commit.yml` ( in the audit repo ) and `trigger-audit.yml`
  ( in the monitored repo ) on every tick.  Tampering files a
  `[CRITICAL] Audit-pipeline workflow {modified|removed}` issue with
  the new `workflow-tamper` label.  Detection runs alongside
  force-push detection, never blocks the audit-dispatch loop.  404
  on `trigger-audit.yml` is treated as "not yet installed" ( per
  TODO #2's still-pending status ) — silent, no issue.

### Test surface

Test count rose from 50 ( pre-sweep baseline ) to **129 passed**
across the same `uv run pytest .github/scripts/tests/` run.

| Work unit | Tests added | Cumulative |
|---|---|---|
| WU-1 | +19 ( new `test_patch_resolution.py` + 1 in `test_structural.py` ) | 69 |
| WU-2 | +7 in `test_structural.py` | 76 |
| WU-3 | +12 ( new `test_lockfile_delta.py` ) | 88 |
| WU-4 | +10 ( new `test_preflight.py` ) | 98 |
| WU-5 | +16 ( new `test_mode_changes.py` ) | 114 |
| WU-6 | +15 ( new `test_workflow_tamper.py` ) | 129 |

Every WU mocked the HTTP layer via `monkeypatch` against `_http.get`
or `_http.request`; no real network calls were made in any test.

### Decisions worth recording

- **Strict sequential dispatch** rather than the parallel-with-worktrees
  variant the skill's `Step 4` allows.  The reasoning recorded for
  this sweep: every WU except WU-6 touches `audit_commit.py`, and the
  one disjoint WU-6 was small enough that the worktree-and-merge-back
  coordination would have cost more than the wall-clock saving.  This
  is field experience for the skill's "parallel only when files are
  disjoint" guidance.
- **Sub-task 4 of TODO #14 ( binary_change severity escalation )
  intentionally left open.**  The false-positive volume that
  motivated re-evaluating the policy has been eliminated by sub-tasks
  1-3, so the urgency is reduced and a real audit run on the
  issue-#4 commit will give us actual data to decide on rather than
  hypotheticals.
- **No `tomllib` for the lockfile parser.**  Partial diff
  reconstruction rarely produces valid TOML ( hunks omit surrounding
  tables ), so `tomllib.loads` would crash on most realistic patches.
  Per-`[[package]]` regex extraction is robust to truncation and
  produces the same end result.
- **`AUDIT_DETECT_MODE_CHANGES` defaults to off.**  Two extra
  Trees-API calls per audited commit is a real cost on a high-traffic
  monitored repo; the gate keeps the feature opt-in until we have
  evidence it earns its keep.

### Follow-ups

- **TODO #14 sub-task 4** ( binary_change severity escalation policy )
  remains open as a design decision.  Recommend: trigger a
  re-audit of `moriyoshi/winterbaume@f567e5018619` ( the original
  issue-#4 commit ) once WU-1 is deployed, count the resulting
  `binary_change` findings, and decide on policy from real numbers.
- **Operational TODO items #1-#5, #10, #11** remain open.  None of
  them are agent-actionable; they are user-side tasks ( secrets,
  multi-repo workflow installation, live test runs, post-month
  manifest tuning ).
- **Reconciler `main()` orchestration is still untested.**  WU-6
  added focused unit tests for the new helpers but did not extend
  test coverage to the subprocess / git layer; matches the brief but
  worth keeping on a separate "reconciler test infrastructure" item
  for a later sweep.
- **`.agents/tmp/` `.gitignore`.**  Carried forward from the prior
  journal entry — `.agents/tmp/consolidated-todos.md` was created
  during this sweep.  Verify it stays untracked before any commit
  involving these changes.

## 2026-04-27 — Multi-round agent discussion ( `AUDIT_MAX_ROUNDS` )

### Context

The integrity panel previously ran a single sequential pass over the
three specialist agents ( Backdoor Hunter -> Supply Chain Inspector
-> Integrity Analyst ) before the Moderator synthesised a verdict.
Each agent saw the prior agents' findings on its first ( and only )
turn and could not refine its own position once the next agent
weighed in.  The user asked for an enhancement allowing at most N
conversation rounds between the agents so the panel could converge
on a shared view rather than just stack one-shot insights.

### Work done

- **`run_agent_discussion(panel_context, github_token, *, max_rounds)`**
  in `audit_commit.py` now loops the specialists for up to
  `max_rounds` passes.  Every turn after the very first sees the full
  transcript so far, including the agent's own previous response, so
  agents can refine, challenge, or extend prior findings.  The
  Moderator still runs exactly once at the end.
- **Convergence-based early stop.**  A new `_round_converged()`
  predicate returns true when every specialist in a round returned
  `concerns=[]` AND all verdicts in the round are unanimous.  When
  that holds after round k < max_rounds, the loop breaks and the
  Moderator is called immediately, saving roughly
  `len(AGENTS) * (max_rounds - k)` model calls.
- **`_format_discussion_so_far(...)`** gained `current_round` /
  `max_rounds` keyword arguments.  When `max_rounds > 1` it prefixes
  the transcript with `## Discussion so far ( round X of up to Y )`
  and tags each rendered turn with its round number, giving agents
  enough context to know whether they are revisiting their own work.
  For `max_rounds == 1` the rendering is byte-identical to the
  pre-change output, so audit-log diffs over historical runs are
  unaffected.
- **`_max_rounds()` env-var helper** parses `AUDIT_MAX_ROUNDS`,
  falling back to `DEFAULT_MAX_ROUNDS` ( 1 ) on empty / unset /
  non-integer values, and clamps anything < 1 up to 1.  Garbage
  values emit a stderr warning rather than raising.
- **Per-turn `round` tag in the discussion list.**  Every entry
  appended by the specialist loop now carries `{"agent", "round",
  "response"}`; the Moderator turn omits `round` ( a single
  synthesis turn does not belong to any round ).  Existing consumers
  that read `agent` and `response` are unchanged.
- **Audit-log schema bumped 4 -> 5.**  `_build_log_entry` now
  emits a `discussion_rounds` block ( `max`, `used`,
  `converged_early` ) so a downstream analyst can see at a glance
  whether the panel hit the budget or terminated early.
  `converged_early` only goes true on `status == "reviewed"` so
  ai-error / panel-skipped runs do not falsely advertise
  convergence.
- **`AUDIT_MAX_ROUNDS` is intentionally NOT a workflow_dispatch
  input.**  Initial draft surfaced it as a dispatch input; user
  pushed back ( "should not be able to be injected externally" ) and
  the YAML was reworked so the value is hard-coded in
  `audit-commit.yml`'s `env:` block as `"1"`.  An attacker with
  dispatch permission therefore cannot inflate model-call cost by
  passing a huge number at trigger time — bumping the budget
  requires a reviewable commit to the workflow file.  The module
  docstring now explicitly calls this out.

### Findings and observations

- **The first specialist ( Backdoor Hunter ) on round 2+ does see a
  transcript even though its system prompt does not mention "prior
  agents".**  Pre-change, round 1 turn 1 received only the panel
  context — no `## Discussion so far` block — and the prompt was
  written accordingly.  The new code path branches on
  `round_num == 1 and i == 0` to keep that exact behaviour for the
  very first turn, then falls through to the transcript-aware path
  for every subsequent turn.  No prompt edits were needed: the
  transcript header explicitly tells the agent it is in a follow-up
  round and may refine prior findings.
- **`schema_version` was a no-op marker until now.**  No code path
  reads it back, but the ARCHITECTURE doc tracks it, so bumping
  rather than silently extending the v4 shape is the conservative
  call.  If a future analyst wires up a version check, they will see
  v5 and know `discussion[*].round` and `discussion_rounds` are
  available.
- **Convergence predicate intentionally requires unanimity, not a
  majority.**  Two agents agreeing while the third still flags a
  concern is exactly the case where another round of debate is most
  valuable.  Treating "2 of 3 clean" as converged would silence the
  dissenting analyst, which defeats the point of the multi-agent
  setup.

### Test surface

| File | Tests added | Notes |
|---|---|---|
| `tests/test_discussion_rounds.py` ( new ) | +13 | Stubs `_call_model` via `monkeypatch.setattr` so no network calls fire.  Covers default-1-pass, multi-round looping, transcript propagation into round 2, convergence early-stop, the unanimity / concerns predicates in `_round_converged`, the `max_rounds=0` clamp, and the env-var parser ( default / int / clamp / garbage / whitespace ). |

Total test count rose 129 -> **142 passed** in
`uv run pytest .github/scripts/tests/`.

### Decisions worth recording

- **Default left at 1 ( single pass ).**  The committed workflow
  YAML sets `AUDIT_MAX_ROUNDS: "1"`, preserving the historical
  single-pass behaviour byte-for-byte.  Switching to 2 or 3 is now
  a one-line YAML edit reviewable in source rather than an
  argument-passing gymnastics through the dispatch API.
- **Naming**: the user explicitly preferred "round" over
  "roundtrip" mid-implementation; all identifiers, env vars, and
  log fields use "round" consistently.
- **`max_rounds < 1` is silently clamped, not rejected.**  Both
  `_max_rounds()` and `run_agent_discussion()` clamp.  Defence in
  depth: the workflow YAML is the trusted setter, but should it
  ever ship a `"0"` or `"-1"` by accident, the script still runs
  one pass rather than degrading to a Moderator-only verdict on no
  evidence.

### Follow-ups

- **Tune the unanimity predicate against real data.**  Once the
  workflow flips `AUDIT_MAX_ROUNDS` above 1 in production, the
  `discussion_rounds.converged_early` field in the audit log lets
  an analyst measure how often round 1 already converged ( in
  which case spend on round 2+ would be wasted ) versus how often
  the extra round changed the verdict.  That data should drive any
  future change to the convergence predicate.
- **Consider per-agent stable-verdict tracking.**  The current
  predicate triggers on a round of zero concerns + unanimity.  An
  alternative is "agents' verdicts unchanged from the prior round
  for two rounds in a row".  Defer until we have audit-log data
  showing the simpler predicate is too eager or too lazy.
- **Prompt updates for explicit round-awareness** — the system
  prompts of the three specialists were not edited.  They behave
  reasonably under multi-round play because the transcript header
  tells them it is round X of Y, but a tighter pass over the
  prompts ( "in follow-up rounds, prefer to refine rather than
  duplicate" ) might reduce token spend.  Defer until we have
  real multi-round transcripts to inspect.

## 2026-04-27 — Agent wands ( history / blame / file inspection tools )

### Context

The integrity panel ran one chat-completion turn per agent against the
routed diff and could not look beyond it.  Findings whose confidence
hinged on context outside the patch — a symbol defined in an excluded
file, a suspicious commit referenced from the message, the recent log
of the path under review — had to be surfaced as low-confidence
guesses or skipped.  The user asked for an MCP-style tool layer that
gives the specialist agents access to git history with a local-first /
GitHub-API-fallback shim so older commits ( missing from a shallow
checkout ) still resolve.

### Work done

- **`.github/scripts/agent_tools.py`** ( new, ~700 lines, stdlib-only ).
  Six wands wired into the OpenAI tool-calling protocol:
    - `git_log( ref?, path?, max_count? )` — recent commits
    - `git_show_commit( sha )` — single-commit metadata + diff
    - `git_blame( path, ref?, line_start?, line_end? )` — per-line authorship
    - `git_show_file( path, ref? )` — file contents at a ref
    - `git_diff_refs( base, head, path? )` — diff between two refs
    - `git_search_log( query, ref?, max_count? )` — search commit messages
  Each wand attempts a local subprocess against the shallow checkout
  at `MONITORED_REPO_PATH` first, falling back to the REST or GraphQL
  API on a miss.  `git_blame` uses GraphQL ( `repository.object.blame.ranges` )
  for the remote path because REST has no blame endpoint; per-line
  content is omitted from the GraphQL fallback to save context, with
  a note instructing the model to follow up with `git_show_file` if
  it needs the actual lines.  Output text is capped at 16 KB per call
  and list-shaped wands are clamped at 100 items / 200 blame ranges.

- **`WandRegistry`** is the dispatch table the chat-completion loop
  hands tool calls to.  It enforces a per-turn budget
  ( `AUDIT_WAND_MAX_CALLS`, default 5 ) and wraps every wand error
  in a structured `{error, detail}` JSON so the model can recover
  rather than crashing the panel.

- **`audit_commit._call_model`** rewritten as a tool-calling loop.
  When a registry is provided ( specialists ) the call advertises
  `tools`, drops `response_format=json_object`, and loops on
  `tool_calls`: each call is dispatched, the result is appended as
  a `role=tool` message, and the loop continues until the model
  produces final JSON content.  A loop hard-cap ( `_TOOL_LOOP_HARD_CAP`
  = 8 ) re-issues the request without tools and with
  `response_format=json_object` to force a final answer if the model
  keeps asking for more context.  The historical no-registry path
  ( moderator, or wands disabled ) is byte-identical to before.

- **System prompts unchanged on disk.**  Tool guidance is spliced
  into the system prompt at call time via `agent_tools.render_tool_help()`,
  so a wands-disabled run renders the historical prompt verbatim.

- **`audit-commit.yml`** now includes a second `actions/checkout`
  step that shallow-clones the monitored repo to
  `${{ github.workspace }}/monitored-repo` ( `fetch-depth: 50` ) and
  exports `MONITORED_REPO_PATH` so wands hit local git first.

- **Tests** ( +34 across two new files ): `test_agent_tools.py`
  covers ref / path validation, registry budget and error wrapping,
  every wand's local-first and API-fallback paths via monkeypatched
  subprocess + `_http` stubs, output truncation, GraphQL blame
  parsing, and the env-var helpers.  `test_tool_loop.py` covers
  `_call_model`'s tool-call dispatch, multi-step loops, malformed
  arguments, unknown tool names, hard-cap recovery, and that
  `run_agent_discussion` passes the registry to specialists but
  not the moderator.  Total `uv run pytest` count: 142 -> 176.

### Design decisions

- **Local-first shim, not local-only.**  A 50-commit shallow clone
  covers the typical "recent log" question for free; older commits
  ( history searches, year-old blames ) still resolve via the API.
  The wand returns `source: "local" | "github"` so the model and
  the audit log know which backend answered.

- **Default-on, opt-out via `AUDIT_DISABLE_WANDS=1`.**  The user's
  brief framed the wands as core capability, not an experiment.  The
  per-turn budget and hard cap give cost controls; an env switch is
  there for debugging the model layer when a regression appears.

- **Moderator stays tool-less.**  Its job is synthesis over the
  transcript, not investigation.  Giving the moderator tools would
  let it second-guess specialists with private context they did not
  see, defeating the audit-trail value of the discussion-then-verdict
  shape.

- **Per-turn budget is a registry property, not a global counter.**
  Each agent turn calls `registry.reset()`; the budget then acts as
  a per-turn governor.  This matches how `_TOOL_LOOP_HARD_CAP` is
  scoped: the model gets to investigate freely within one turn but
  cannot starve the next agent's budget.

- **GraphQL only for blame.**  Every other wand has a clean REST
  equivalent.  Blame is the one operation REST does not expose, so
  we accept the second auth surface only where it earns its keep.

- **All schemas use `additionalProperties: false`.**  Forces the
  model to fill exactly the fields we documented; reduces the
  surface for argument-injection mistakes.

- **No new pip dependency.**  Subprocess + `_http` ( the existing
  stdlib-only HTTP wrapper ) cover everything.  Stays consistent
  with the deliberate "no requests, no PyYAML" stance recorded in
  earlier journal entries.

### Known limitations

- **GraphQL blame requires `MONITORED_REPO_TOKEN`.**  The unauth
  GraphQL endpoint refuses to return repo data.  When the monitored
  repo is public AND the wands have to fall back to remote blame
  AND no token is set, the wand returns a structured `wand_error`
  result.  Documented; not a blocker because the typical wand call
  is local-first.

- **Path validation accepts `..` segments.**  Git itself rejects
  paths that escape the worktree, so the wand layer leans on that.
  The only paths we hard-block are absolute paths and embedded NUL
  bytes.

- **Budget defends cost, not adversarial tool spam.**  An agent that
  tries to dump megabytes of file contents into context can be
  slowed by the per-turn budget but not stopped — a future
  enhancement could record a running output-byte count and short-
  circuit when it exceeds a threshold.

### Follow-ups

- Once the workflow has run for a few weeks with wands enabled,
  inspect a sample of audit-log discussions for tool-use patterns:
  which wands the agents actually reach for, whether the local
  hit rate matches expectations ( a `fetch-depth: 50` shallow
  clone should serve >90% of `git_log` / `git_blame` requests
  on recent paths ), and whether the per-turn budget needs tuning.

- Consider exposing a seventh wand for `git_grep` ( regex search
  across the working tree at a ref ).  Deferred because the
  current six already cover the use cases the panel has asked
  about in the threat-model entries; add only when audit-log data
  shows a real gap.

- The wand result format does not currently distinguish a
  `local: stale` from `local: fresh` answer — if the shallow
  clone misses a force-push update between fetch and read, an
  agent could be served outdated content.  In practice the
  audit-commit workflow checks out the latest `main` before the
  panel runs, so this is a theoretical concern.  Worth revisiting
  if the failure mode ever materialises.


## 2026-04-27 — Security self-review of the wand layer ( injection hardening )

### Context

After landing the wand framework in the previous entry, the user
asked for a self-review of the hand-built GraphQL payload and the
surrounding REST URL construction.  The framing was correct — building
JSON / URLs from model-supplied values is the obvious place an
adversary who has prompt-injected the panel ( e.g. via a crafted
commit message or filename ) would try to break out.  Recorded here
both as the audit trail for the fix and so the next reader can see
which boundaries we have already cleared.

### Findings

| Boundary | Risk | Status |
|---|---|---|
| GraphQL query `_BLAME_GRAPHQL` | Query injection | **Safe.**  Query is a static template constant; variables flow via the `variables` dict, which `json.dumps` escapes when the request body is serialised, and the GitHub GraphQL server parses the query into an AST and binds variables as typed values rather than string-substituting them.  No injection vector. |
| Refs in REST URL paths ( `/commits/{sha}`, `/compare/{base}...{head}`, blame's `/commits/{ref}` resolver ) | Path traversal via `..` | **Was vulnerable.**  `_REF_RE` permitted `..` ( `feature/..`, `foo/../bar`, etc. ) so a prompt-injected `ref` argument could rewrite the URL path to a different API endpoint.  Git itself rejects `..` in valid refs, so the local backend was already safe; the gap was on the REST fallback. |
| Path in `urllib.parse.quote( path )` | Path traversal via `..` segments | **Was vulnerable.**  `urllib.parse.quote` does not encode dots, so a path like `../../etc/passwd` would pass through the contents-API URL unchanged.  GitHub would 404 most attempts, but it still leaks ( and could become a real escape if the URL routing ever widens ). |
| Ref interpolated into `_git_show_file_remote` query string ( `?ref={ref}` ) | Query-string injection | **Hygiene gap.**  Already constrained by `_REF_RE` to URL-safe characters, but interpolated unencoded.  A future widening of the ref grammar would silently reopen the gap. |
| HTTP headers ( `Accept`, `Authorization`, `Content-Type` ) | Header injection | **Safe.**  All values come from constants or `ctx.monitored_token` ( workflow secret ); no model-controlled header values. |
| Local subprocess invocations ( `git -C <path> ...` ) | Shell injection | **Safe.**  Every `subprocess.run` call uses list-form argv; no `shell=True` anywhere. |
| Search query in `_git_search_log_remote` | GitHub-search modifier injection ( e.g. `repo:other/repo` ) | **Not a security boundary.**  The worst case is the panel reading commit messages from a different public repo.  Query is `urlencode`-escaped so HTTP-level injection is impossible.  Documented in the journal; no code change. |

### Work done

- **`_validate_ref`** now rejects any ref containing the substring
  `..`.  Git's own `check-ref-format` rules already forbid `..` in
  valid refs, so this never blocks legitimate input.  Closes the URL
  path-traversal vector for every wand whose REST fallback puts a ref
  in the URL path.

- **`_validate_path`** now rejects any path containing a `..` segment
  ( split on `/` ).  `..foo` and `foo..bar` remain valid filename
  fragments — only a standalone `..` segment is blocked.  Closes the
  REST contents-API traversal vector for `git_show_file`.

- **`_git_show_file_remote` ref query parameter** now goes through
  `urllib.parse.quote( ref, safe="" )`.  Belt-and-braces on top of the
  character-whitelist validation; ensures any future widening of the
  ref grammar cannot silently reopen a query-string injection.

- **`_api_graphql` docstring** explicitly states the parameterised-
  binding invariant and forbids f-string substitution of user input
  into the `query` argument.  A future reader who refactors the
  variable-binding into string interpolation now has a written
  warning.

- **Tests** ( +2 ): `test_validate_ref_rejects_path_traversal` and
  `test_validate_path_rejects_dotdot_segments` cover the new
  rejection rules.  The pre-existing
  `test_validate_path_rejects_absolute_and_nul` was extended to
  assert that `..foo` / `strange..name.txt` still pass — i.e. only
  the path-segment form is blocked.  Total `uv run pytest` count
  rises 176 -> 178.

### Decisions worth recording

- **Reject `..` at validation, not at URL-construction.**  A
  per-call URL-canonicalisation pass would also work, but every
  caller would have to remember to invoke it.  Rejecting at
  `_validate_ref` / `_validate_path` makes the safety property a
  property of the validators, which is where every wand already
  routes its inputs.

- **Search query left unrestricted.**  GitHub's search syntax is rich
  enough that lock-down would be invasive, and the security boundary
  here is on the wrong side — the search runs against a public
  ( or repo-scoped ) endpoint and the worst case is reading a
  different repo's commit messages.  Recorded in the table above so
  a future reviewer does not flag this as an oversight.

- **GraphQL query stays as a constant.**  The framework deliberately
  keeps every wand's GraphQL payload as a hardcoded module-level
  string with all dynamic values flowing through `variables`.  The
  docstring on `_api_graphql` now spells this out as a hard rule
  for future contributors.

### Follow-ups

- The seventh wand idea ( `git_grep` ) deferred in the previous
  entry will reuse `_validate_path` for its target paths, so the
  hardening here transfers to it for free when added.

- Worth a once-over of the AGENT discussion transcripts after the
  first multi-round real run to see whether the model ever passes
  pathological inputs that hit the rejection branches.  If it does,
  we have field evidence either of a buggy prompt-injection attack
  or of legitimate-looking inputs the model misformatted, both of
  which are useful telemetry.

- Consider adding an `AUDIT_WAND_OUTPUT_BUDGET` env var that caps
  total tool-result bytes per agent turn ( separate from the
  per-call `MAX_OUTPUT_CHARS` ).  Defends against a model that
  spams many small calls to fill context, which the per-turn call
  budget alone does not bound.  Not urgent; covered for now by the
  `AUDIT_WAND_MAX_CALLS` limit ( default 5 ) and the
  `_TOOL_LOOP_HARD_CAP` ( 8 ).


## 2026-04-27 — Workflow fix: anonymous monitored-repo clone

### Trigger

The first run of `audit-commit.yml` after the wand layer landed
( [run 24981108738](https://github.com/winterbaume-automation/audit-main-repo/actions/runs/24981108738/job/73143285863) )
failed at the new `Shallow clone monitored repo` step.

### Findings

- The freshly added step used `actions/checkout@v6.0.2` with
  `token: ${{ secrets.MONITORED_REPO_TOKEN }}`.  That secret has
  never been provisioned ( and per the standing TODO it's only
  needed if `moriyoshi/winterbaume` goes private ), so the
  expression evaluated to an empty string.
- `actions/checkout` does not treat an empty token as "unauthenticated";
  it still configures the local git config with an
  `AUTHORIZATION: basic <empty:>` extra-header, which GitHub's
  HTTPS endpoint rejects as malformed Basic auth.  The clone fails
  with `fatal: could not read Username` rather than gracefully
  falling back to an anonymous fetch.
- The monitored repo is public, so no auth is required for read
  access.  We were paying the auth cost for nothing on the happy
  path and breaking entirely on the missing-secret path.

### Work done

- Replaced the second `actions/checkout` invocation in
  `.github/workflows/audit-commit.yml` with a plain
  `git clone --depth 50 https://github.com/moriyoshi/winterbaume.git monitored-repo`
  `run:` step.  Keeps `MONITORED_REPO_PATH` pointed at the same
  workspace path as before so the wand shim's local-first lookup
  is unaffected.
- Left the comment block above the step explaining that the switch
  back to `actions/checkout` with a `token:` is the correct fix if
  the monitored repo ever goes private; future readers should not
  need to re-derive this.
- Left the `MONITORED_REPO_TOKEN` env passthrough on the
  `Run audit script` step intact.  The audit script and the wand
  layer still honour it for the GraphQL blame fallback and for
  raised-rate-limit REST reads when it is set; if a token gets
  added later, no further workflow edit is needed.

### Decisions worth recording

- **Unauthenticated clone over conditional auth.**  An earlier draft
  considered branching on whether `MONITORED_REPO_TOKEN` is set and
  selecting between the two checkout strategies via `if:`.  Rejected
  because the conditional makes the workflow harder to read for a
  one-line gain when the secret eventually does land, and an
  authenticated clone of a public repo is no faster — both go through
  the same HTTPS endpoint with the same per-tree fetch.
- **Stayed at `--depth 50`.**  Same reasoning as the original wand
  entry: 50 commits cover the typical recent-history question for
  free, and any older reference falls through to the GitHub API
  shim.  No change.
- **Did not swap to `gh repo clone` or the `git` HTTPS-with-PAT
  workaround.**  Both add a moving part for no improvement on a
  public repo.

### Follow-ups

- Once the workflow run lands successfully on the next push, sample
  the resulting audit-log entry to confirm `source: "local"` shows
  up in the wand call traces ( i.e. the local clone is actually
  being preferred over the API ).  If every wand call still falls
  through to `source: "github"`, the local checkout path is wrong
  or the repo isn't being cloned to where `MONITORED_REPO_PATH`
  expects.
- If the monitored repo ever goes private, restore the
  `actions/checkout` step with `repository:`, `token: ${{ secrets.MONITORED_REPO_TOKEN }}`,
  and `path: monitored-repo`.  The comment in the workflow file
  flags this as the migration path so it doesn't have to be
  re-discovered.

