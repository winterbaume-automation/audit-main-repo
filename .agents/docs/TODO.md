# TODO

Open items carried forward from JOURNAL.md consolidation.

## Pending

- [ ] Pre-create issue labels in the GitHub repository UI:
  `integrity-audit`, `severity:none`, `severity:low`, `severity:medium`,
  `severity:high`, `severity:critical`, `force-push`.

- [ ] Add `MONITORED_REPO_TOKEN` as a repository secret if `moriyoshi/winterbaume`
  is private or rate-limit headroom is needed.

- [ ] Add `trigger-audit.yml` to `moriyoshi/winterbaume` and store
  `AUDIT_DISPATCH_PAT` (Fine-Grained PAT: `Actions: write` on this repo) as
  a secret there.

- [ ] Perform a first live test run via manual `workflow_dispatch` with a
  known-clean commit SHA from `moriyoshi/winterbaume`.

- [ ] Verify that a second run with a different SHA appends to the `audit-log`
  branch without conflict.

- [ ] Consider adding a `too_large` issue (or a workflow summary annotation)
  so oversized commits surface visibly rather than silently passing.

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

_(none yet)_
