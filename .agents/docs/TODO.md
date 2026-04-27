# TODO

Open items carried forward from JOURNAL.md consolidation.

## Pending

- [x] Pre-create issue labels in the GitHub repository UI:
  `integrity-audit`, `none`, `low`, `medium`, `high`, `critical`,
  `force-push`, `whole`, `focused`, `focused-overflow`, `panel-skipped`,
  `structural-finding`.

- [ ] Add `MONITORED_REPO_TOKEN` as a repository secret if `moriyoshi/winterbaume`
  is private or rate-limit headroom is needed.

- [ ] Add `trigger-audit.yml` to `moriyoshi/winterbaume` and store
  `AUDIT_DISPATCH_PAT` (Fine-Grained PAT: `Actions: write` on this repo) as
  a secret there.

- [ ] Perform a first live test run via manual `workflow_dispatch` with a
  known-clean commit SHA from `moriyoshi/winterbaume`.

- [ ] Verify that a second run with a different SHA appends to the `audit-log`
  branch without conflict.

- [ ] Review and tune the initial sensitivity manifest at
  `.github/config/monitored_repo_classification.json` after the first
  month of real audit data; in particular, look at `routing.mode`
  distribution across audited commits and adjust globs that produce too
  many false-positive `focused` modes.

- [x] Implement a deterministic Trojan-source / Unicode pre-scan
  ( bidi controls U+202A-U+202E and U+2066-U+2069, zero-width characters
  in identifiers, mixed-script identifiers ) and surface as structural
  findings.  Landed via WU-2 of the 2026-04-27 sweep; mixed-script
  detection scoped to Latin / Cyrillic / Greek to keep i18n
  false-positive risk low.

- [x] Implement a deterministic lockfile delta parser ( `Cargo.lock`,
  `package-lock.json`, `pnpm-lock.yaml`, `uv.lock`, `poetry.lock` ) that
  reports registry / source / git-rev pin changes as structural findings
  rather than relying on the LLM to spot them in noisy diffs.  Landed
  via WU-3 of the 2026-04-27 sweep; stdlib-only ( regex extractors with
  an unparseable fallback ).

- [x] When a per-file `patch` is truncated by the GitHub API ( ~3 K
  lines ) for a critical or high file, refetch via the contents API and
  reconstruct.  Landed bundled with WU-1 of the 2026-04-27 sweep;
  unified with the `binary_change` blob-refetch path.

- [x] Detect file-mode flips ( chmod +x on a checked-in file ) and
  symlink target changes by issuing a contents-API call per modified
  file; gate behind a flag because of the per-file API cost.  Landed
  via WU-5 of the 2026-04-27 sweep; gate is `AUDIT_DETECT_MODE_CHANGES`
  ( default off ).  Implementation uses two recursive Trees-API fetches
  ( cheaper and more reliable than per-file Contents-API for the
  executable-bit case ) with a Contents-API fallback for symlink
  targets.

- [ ] Verify the first scheduled run of `reconcile-main.yml` lands within
  ~30 min of merge: confirm `head-history.json` appears on the `audit-log`
  branch with a single `initial` entry and that no spurious audits get
  dispatched when the log is already complete.

- [ ] Manually validate force-push detection by force-pushing a no-op
  history rewrite to a throwaway branch in the monitored repo and pointing
  `MONITORED_BRANCH` at it for one tick.  Confirm a `[CRITICAL] Force push
  detected` issue is filed and dispatch is suppressed for that tick.

- [x] Consider preflight check inside `audit_commit.py` to skip work when
  `logs/{date}/{sha}.json` already exists, eliminating duplicate-audit cost
  in the rare reconciler-vs-push-trigger race.  Landed via WU-4 of the
  2026-04-27 sweep.  Walks the `audit-log` branch via the Git Trees API
  ( with a Contents-API fallback when the tree is `truncated` ); bypass
  via `AUDIT_FORCE_RERUN=1`.

- [x] Consider tracking workflow-file SHAs of `audit-commit.yml` and
  `trigger-audit.yml` so the reconciler can detect tampering with the audit
  pipeline itself, not just the monitored branch history.  Landed via
  WU-6 of the 2026-04-27 sweep.  New `workflow_history.json` on the
  `audit-log` branch records the SHAs each tick; tampering files a
  `[CRITICAL] Audit-pipeline workflow {modified|removed}` issue with the
  `workflow-tamper` label.  Detection runs alongside force-push
  detection, never blocks audit dispatch.

- [ ] Fix the `binary_change` false-positive cluster surfaced by issue #4
  ( audit of `moriyoshi/winterbaume@f567e5018619`, the initial commit ).
  Root cause: `FileChange.is_binary` in `audit_commit.py:417-421` infers
  "binary" purely from `patch is None` ( with status not `removed`/
  `unchanged` ).  GitHub's commits API omits `patch` in two unrelated
  cases: actual binary blobs, **and** text files whose patch exceeded the
  per-response size cap.  In the issue #4 commit, 221 of 300 files on
  page 1 had `patch=None`; almost all were `.md` / `.rs` / `.toml` /
  `Cargo.lock` text files with thousands of additions.  Sub-tasks, in
  priority order:
    1. [x] Replace the heuristic so that "no patch" alone does not imply
       binary.  Candidate signals: fetch the blob via
       `GET /repos/{owner}/{repo}/git/blobs/{sha}` and sniff for NUL
       bytes ( authoritative ); fall back to extension /
       `.gitattributes` heuristics if blob fetch is rate-limited.  Note
       that `additions == 0 && deletions == 0` is **not** a reliable
       discriminator on its own — `LICENSE` ( 11 KB plain Apache text )
       reports `+0/-0` in this commit.  Landed via WU-1 of the
       2026-04-27 sweep.  `is_binary` is now a stored field on
       `FileChange`, set during the new `_resolve_patch_omissions` pass
       which fetches the blob and sniffs the first 8 KB for NUL bytes;
       extension fallback covers the rate-limited case.
    2. [x] When `patch is None` for a file that turns out to be text,
       refetch the blob and synthesise a unified-diff patch ( all lines
       prefixed with `+` for an `added` file ) so the LLM panel and the
       cross-reference scan ( `audit_commit.py:832` ) can see the
       content.  This overlaps with the existing TODO above for "refetch
       via the contents API" on truncated criticals; consider unifying.
       Landed via WU-1 of the 2026-04-27 sweep; unified with the
       truncated-patch refetch ( applied for critical / high files only
       as a per-file API cost gate ).  Modified files render as
       full-file post-image context with a `# audit-note:` header,
       since the parent blob is not fetched ( trade-off documented in
       `_synthesise_patch_from_blob` ).
    3. [x] Update the structural-finding description text at
       `audit_commit.py:754` and the composed-patch placeholder at
       `audit_commit.py:858-859` so they distinguish "true binary" from
       "API-omitted text" once detection is reliable.  Landed via WU-1
       of the 2026-04-27 sweep.  `binary_change` text now says "( NUL
       bytes detected in blob )"; a new `text_patch_unavailable`
       finding type fires only when the blob fetch failed and the path
       is not in the binary-extension set.
    4. [ ] Severity-escalation side effect: 200+ false `binary_change`
       findings pushed the issue-#4 commit into MEDIUM
       `structural-finding` territory and buried the one genuine LLM
       finding ( `remote_fetch_execute` at `release.yml:49`, the
       well-known cargo-dist installer ).  After the detection fix lands,
       re-evaluate whether `binary_change` should still escalate severity
       at all, or only for paths that look executable / opaque.
       **Open — design decision, requires user input.**  Sub-tasks 1-3
       have eliminated the false-positive volume that motivated this
       review, so the urgency is reduced.  Re-evaluate after the next
       audit run on the issue-#4 commit confirms the count drops to
       single digits.

## Completed

- [x] File-by-file routing with a static sensitivity manifest replaces
  the silent `too_large` skip.  See JOURNAL.md entry of 2026-04-27.
