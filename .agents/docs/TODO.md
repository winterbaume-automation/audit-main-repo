# TODO

Open items carried forward from JOURNAL.md consolidation.

## Pending

- [ ] Pre-create issue labels in the GitHub repository UI:
  `integrity-audit`, `severity:none`, `severity:low`, `severity:medium`,
  `severity:high`, `severity:critical`, `force-push`,
  `routing:whole`, `routing:focused`, `routing:focused-overflow`,
  `routing:panel_skipped`, `structural-finding`.

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

- [ ] Implement a deterministic Trojan-source / Unicode pre-scan
  ( bidi controls U+202A-U+202E and U+2066-U+2069, zero-width characters
  in identifiers, mixed-script identifiers ) and surface as structural
  findings.

- [ ] Implement a deterministic lockfile delta parser ( `Cargo.lock`,
  `package-lock.json`, `pnpm-lock.yaml`, `uv.lock`, `poetry.lock` ) that
  reports registry / source / git-rev pin changes as structural findings
  rather than relying on the LLM to spot them in noisy diffs.

- [ ] When a per-file `patch` is truncated by the GitHub API ( ~3 K
  lines ) for a critical or high file, refetch via the contents API and
  reconstruct.

- [ ] Detect file-mode flips ( chmod +x on a checked-in file ) and
  symlink target changes by issuing a contents-API call per modified
  file; gate behind a flag because of the per-file API cost.

- [ ] Verify the first scheduled run of `reconcile-main.yml` lands within
  ~30 min of merge: confirm `head-history.json` appears on the `audit-log`
  branch with a single `initial` entry and that no spurious audits get
  dispatched when the log is already complete.

- [ ] Manually validate force-push detection by force-pushing a no-op
  history rewrite to a throwaway branch in the monitored repo and pointing
  `MONITORED_BRANCH` at it for one tick.  Confirm a `[CRITICAL] Force push
  detected` issue is filed and dispatch is suppressed for that tick.

- [ ] Consider preflight check inside `audit_commit.py` to skip work when
  `logs/{date}/{sha}.json` already exists, eliminating duplicate-audit cost
  in the rare reconciler-vs-push-trigger race.

- [ ] Consider tracking workflow-file SHAs of `audit-commit.yml` and
  `trigger-audit.yml` so the reconciler can detect tampering with the audit
  pipeline itself, not just the monitored branch history.

## Completed

- [x] File-by-file routing with a static sensitivity manifest replaces
  the silent `too_large` skip.  See JOURNAL.md entry of 2026-04-27.
