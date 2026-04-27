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
