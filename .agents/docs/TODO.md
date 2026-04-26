# TODO

Open items carried forward from JOURNAL.md consolidation.

## Pending

- [ ] Pre-create issue labels in the GitHub repository UI:
  `integrity-audit`, `severity:none`, `severity:low`, `severity:medium`,
  `severity:high`, `severity:critical`.

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

## Completed

_(none yet)_
