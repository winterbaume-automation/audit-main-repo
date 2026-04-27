#!/usr/bin/env python3
"""
Periodic reconciliation safety net for the integrity-audit pipeline.

The push-driven `audit-commit.yml` workflow only fires when the trigger
workflow inside the monitored repo dispatches it.  If that workflow is
removed, disabled, or bypassed by a force push, audit coverage silently
breaks.  This reconciler closes that gap.

On every tick it:

  1. Lists the most recent commits on `MONITORED_REPO@MONITORED_BRANCH`.
  2. Reads the `audit-log` branch and builds the set of already-audited
     SHAs from `logs/**/*.json`.
  3. Dispatches `audit-commit.yml` for each commit on the branch that has
     no log entry yet.
  4. Tracks the observed head SHA in `head-history.json` on the
     `audit-log` branch.  If the previously-recorded head is no longer an
     ancestor of the current head ( compare API status of `behind`,
     `diverged`, or the base 404s ), a critical issue is filed and no
     audits are dispatched for that tick - manual triage is required.

Required env vars:
  GITHUB_TOKEN    - audit repo writes, issue creation, workflow dispatch
  AUDIT_REPO      - "owner/repo" of this audit repository
  MONITORED_REPO  - "owner/repo" being monitored

Optional env vars:
  MONITORED_REPO_TOKEN - read access to monitored repo ( omit if public )
  MONITORED_BRANCH     - branch to track ( default: main )
  COMMITS_PER_PAGE     - how many recent commits to scan ( default: 100 )

Exit codes:
  0 - success
  1 - missing required env var
  2 - GitHub API request failed
  3 - git push of head-history failed
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests

API = "https://api.github.com"
HEAD_HISTORY_FILE = "head-history.json"
HISTORY_MAX_ENTRIES = 500


def load_config():
    required = ["GITHUB_TOKEN", "AUDIT_REPO", "MONITORED_REPO"]
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        print(f"ERROR: Missing required env vars: {missing}", file=sys.stderr)
        sys.exit(1)
    return {
        "github_token": os.environ["GITHUB_TOKEN"],
        "monitored_token": os.environ.get("MONITORED_REPO_TOKEN", ""),
        "audit_repo": os.environ["AUDIT_REPO"],
        "monitored_repo": os.environ["MONITORED_REPO"],
        "monitored_branch": os.environ.get("MONITORED_BRANCH", "main"),
        "commits_per_page": int(os.environ.get("COMMITS_PER_PAGE", "100")),
    }


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _monitored_headers(cfg):
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if cfg["monitored_token"]:
        headers["Authorization"] = f"Bearer {cfg['monitored_token']}"
    return headers


def _audit_headers(cfg):
    return {
        "Authorization": f"Bearer {cfg['github_token']}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _request(method, url, headers, **kwargs):
    try:
        resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)
    except requests.RequestException as e:
        print(f"ERROR: Network error {method} {url}: {e}", file=sys.stderr)
        sys.exit(2)
    if resp.status_code == 429:
        retry_after = int(resp.headers.get("retry-after", "30"))
        print(f"  rate limited - waiting {retry_after}s ...")
        time.sleep(retry_after)
        try:
            resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)
        except requests.RequestException as e:
            print(f"ERROR: Network error on retry {method} {url}: {e}", file=sys.stderr)
            sys.exit(2)
    return resp


def _get(url, headers):
    resp = _request("GET", url, headers)
    if not resp.ok:
        print(f"ERROR: {resp.status_code} GET {url} - {resp.text[:500]}", file=sys.stderr)
        sys.exit(2)
    return resp


# ---------------------------------------------------------------------------
# Monitored repo queries
# ---------------------------------------------------------------------------

def fetch_recent_commits(cfg):
    owner, repo = cfg["monitored_repo"].split("/", 1)
    url = (
        f"{API}/repos/{owner}/{repo}/commits"
        f"?sha={cfg['monitored_branch']}&per_page={cfg['commits_per_page']}"
    )
    return _get(url, _monitored_headers(cfg)).json()


def compare_commits(cfg, base, head):
    """
    Return GitHub compare result for base...head.  Synthesises
    `{"status": "missing_base"}` when the base SHA is no longer findable
    ( orphaned by a force push that has already been GC-collected on the
    server side ).
    """
    owner, repo = cfg["monitored_repo"].split("/", 1)
    url = f"{API}/repos/{owner}/{repo}/compare/{base}...{head}"
    resp = _request("GET", url, _monitored_headers(cfg))
    if resp.status_code == 404:
        return {"status": "missing_base"}
    if not resp.ok:
        print(f"ERROR: Compare failed {resp.status_code}: {resp.text[:500]}", file=sys.stderr)
        sys.exit(2)
    return resp.json()


# ---------------------------------------------------------------------------
# Git helpers ( operating on the audit-log branch )
# ---------------------------------------------------------------------------

def run_git(args, check=True, capture=False):
    kwargs: dict = {"check": check, "text": True}
    if capture:
        kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return subprocess.run(["git", *args], **kwargs)


def checkout_audit_log_branch():
    """
    Fetch and check out the `audit-log` branch.  Returns True if the
    branch already existed on origin, False if a fresh orphan branch was
    created locally ( first ever reconciler run ).
    """
    run_git(["config", "user.email", "github-actions[bot]@users.noreply.github.com"])
    run_git(["config", "user.name", "github-actions[bot]"])
    fetch = run_git(
        ["fetch", "origin", "audit-log:refs/remotes/origin/audit-log"],
        check=False,
        capture=True,
    )
    if fetch.returncode == 0:
        run_git(["checkout", "audit-log"])
        return True
    run_git(["checkout", "--orphan", "audit-log"])
    run_git(["rm", "-rf", "--cached", "."], check=False)
    run_git(["clean", "-fdx", "--exclude=.github"], check=False)
    return False


def audited_shas():
    """SHAs already recorded under `logs/{date}/{sha}.json` on this branch."""
    shas = set()
    if not os.path.isdir("logs"):
        return shas
    for date_dir in os.listdir("logs"):
        date_path = os.path.join("logs", date_dir)
        if not os.path.isdir(date_path):
            continue
        for fname in os.listdir(date_path):
            if fname.endswith(".json"):
                shas.add(fname[:-5])
    return shas


def load_head_history():
    if not os.path.exists(HEAD_HISTORY_FILE):
        return []
    try:
        with open(HEAD_HISTORY_FILE) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"WARN: head-history.json unreadable ({e}) - starting fresh", file=sys.stderr)
        return []
    return data if isinstance(data, list) else []


def save_head_history(history):
    with open(HEAD_HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)
        f.write("\n")


def append_history_entry(history, head_sha, status, note=""):
    history.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "head_sha": head_sha,
        "status": status,
        "note": note,
    })
    if len(history) > HISTORY_MAX_ENTRIES:
        history = history[-HISTORY_MAX_ENTRIES:]
    return history


def commit_and_push_history(message):
    run_git(["add", HEAD_HISTORY_FILE])
    diff = run_git(["diff", "--cached", "--quiet"], check=False)
    if diff.returncode == 0:
        print("head-history.json unchanged - no commit needed")
        return
    run_git(["commit", "-m", message])
    push = run_git(["push", "origin", "audit-log"], check=False, capture=True)
    if push.returncode != 0:
        run_git(["push", "--set-upstream", "origin", "audit-log"])


# ---------------------------------------------------------------------------
# Workflow dispatch
# ---------------------------------------------------------------------------

def dispatch_audit(cfg, commit):
    sha = commit["sha"]
    commit_obj = commit.get("commit") or {}
    author = commit_obj.get("author") or {}
    author_str = f"{author.get('name', 'unknown')} <{author.get('email', '')}>"
    raw_message = commit_obj.get("message") or ""
    first_line = raw_message.splitlines()[0][:200] if raw_message else ""
    timestamp = author.get("date", "")

    owner, repo = cfg["audit_repo"].split("/", 1)
    url = f"{API}/repos/{owner}/{repo}/actions/workflows/audit-commit.yml/dispatches"
    payload = {
        "ref": "main",
        "inputs": {
            "commit_sha": sha,
            "commit_author": author_str,
            "commit_message": first_line,
            "commit_timestamp": timestamp,
        },
    }
    resp = _request("POST", url, _audit_headers(cfg), json=payload)
    if not resp.ok:
        print(
            f"ERROR: Failed to dispatch audit for {sha[:12]}: "
            f"{resp.status_code} {resp.text[:300]}",
            file=sys.stderr,
        )
        return False
    print(f"  dispatched audit for {sha[:12]} - {first_line[:60]}")
    return True


# ---------------------------------------------------------------------------
# Force-push alert
# ---------------------------------------------------------------------------

def file_force_push_issue(cfg, prev, current, compare_status):
    title = (
        f"[CRITICAL] Force push detected on "
        f"{cfg['monitored_repo']}@{cfg['monitored_branch']}"
    )
    body = f"""\
## Force push detected

The reconciliation safety net observed that the previously-recorded head of
`{cfg['monitored_repo']}@{cfg['monitored_branch']}` is no longer an ancestor
of the current head.  This is consistent with a force push, history rewrite,
or branch reset.

| Field | Value |
|---|---|
| Monitored repo | `{cfg['monitored_repo']}` |
| Branch | `{cfg['monitored_branch']}` |
| Previous head | [`{prev[:12]}`](https://github.com/{cfg['monitored_repo']}/commit/{prev}) |
| Current head | [`{current[:12]}`](https://github.com/{cfg['monitored_repo']}/commit/{current}) |
| Compare status | `{compare_status}` |
| Compare URL | https://github.com/{cfg['monitored_repo']}/compare/{prev}...{current} |
| Detected at | {datetime.now(timezone.utc).isoformat()} |

### What this means

A `compare_status` of `behind`, `diverged`, or `missing_base` means the
previous head is **not** reachable from the current head.  Commits that were
on the branch may have been dropped or rewritten without going through the
normal push trigger, so they would not have been audited.

### What to do

1. Investigate why the force push happened - intentional history cleanup or
   unauthorised tampering?
2. If unauthorised, treat the previous head as a known-good baseline and
   audit every reachable commit between the new head and the divergence
   point manually via `gh workflow run audit-commit.yml`.
3. Once acknowledged, close this issue.  The reconciler resumes normal
   operation on the next tick regardless - this issue is informational.

### Reconciler state

History tracking file: `{HEAD_HISTORY_FILE}` on the `audit-log` branch.
"""
    owner, repo = cfg["audit_repo"].split("/", 1)
    url = f"{API}/repos/{owner}/{repo}/issues"
    payload = {
        "title": title,
        "body": body,
        "labels": ["integrity-audit", "severity:critical", "force-push"],
    }
    resp = _request("POST", url, _audit_headers(cfg), json=payload)
    if not resp.ok:
        print(
            f"ERROR: Failed to create force-push issue: "
            f"{resp.status_code} {resp.text[:500]}",
            file=sys.stderr,
        )
        return None
    issue_url = resp.json()["html_url"]
    print(f"Force-push issue filed: {issue_url}")
    return issue_url


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    cfg = load_config()
    print(f"Reconciling {cfg['monitored_repo']}@{cfg['monitored_branch']} ...")

    commits = fetch_recent_commits(cfg)
    if not commits:
        print("ERROR: monitored branch returned zero commits", file=sys.stderr)
        sys.exit(2)
    current_head = commits[0]["sha"]
    print(f"Current head: {current_head[:12]} ({len(commits)} commits returned)")

    branch_existed = checkout_audit_log_branch()
    if not branch_existed:
        print("audit-log branch did not exist - created orphan locally")

    history = load_head_history()
    audited = audited_shas()
    print(f"Audit log contains {len(audited)} commit entries; "
          f"head history has {len(history)} entries")

    prev = history[-1]["head_sha"] if history else None
    force_push = False
    if prev and prev != current_head:
        compare = compare_commits(cfg, prev, current_head)
        status = compare.get("status", "unknown")
        print(f"Compare {prev[:12]}...{current_head[:12]}: status={status}")
        if status not in ("ahead", "identical"):
            issue_url = file_force_push_issue(cfg, prev, current_head, status)
            history = append_history_entry(
                history, current_head, "force_push_detected",
                note=f"prev={prev}, status={status}, issue={issue_url}",
            )
            force_push = True

    if not force_push:
        missing = [c for c in reversed(commits) if c["sha"] not in audited]
        if missing:
            print(f"Dispatching audits for {len(missing)} unaudited commit(s) ...")
            for c in missing:
                dispatch_audit(cfg, c)
        else:
            print("All recent commits already audited.")

        if not history or history[-1]["head_sha"] != current_head:
            history = append_history_entry(
                history, current_head,
                "initial" if not prev else "ok",
            )

    save_head_history(history)
    try:
        commit_and_push_history(
            f"reconcile: head={current_head[:12]} "
            f"({'force_push' if force_push else 'ok'})"
        )
    except subprocess.CalledProcessError as e:
        print(f"ERROR pushing head-history: {e}", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
