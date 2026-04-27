"""Agent wands: history-inspection tools the specialist panel can call.

The integrity panel runs against a single commit's diff, but the agents
sometimes need broader context to triage a finding ( "is this `mod foo`
declared elsewhere", "who last touched this line", "did the same author
land a similar payload last week" ).  Each wand below answers one of
those questions through a unified shim that:

1. Tries a local shallow checkout of the monitored repo at
   ``MONITORED_REPO_PATH`` first.  Cheap and offline.
2. Falls back to the GitHub REST or GraphQL API when the requested
   commit / ref / blob is not present locally ( the typical case for an
   older history reference in a shallow clone ).
3. Returns a structured ``dict`` that includes ``source`` so the model
   knows whether it is reading local or remote data.

The wands are exposed to the model through the OpenAI tool-calling
protocol; ``WAND_SCHEMAS`` carries the JSON-schema list that gets
attached to the chat-completion payload.  ``WandRegistry.dispatch``
runs the named wand with the model's argument dict and returns a
``dict`` ready to be JSON-serialised back into the conversation.

Stdlib only ( consistent with the rest of ``.github/scripts`` ).
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


# Per-wand result text is capped so a runaway tool call cannot blow the
# model context window.  The cap is conservative: 16 KB ~= 4 K tokens at
# 4 chars/token, well below the per-message budget the panel runs under.
MAX_OUTPUT_CHARS = 16_384

# How many sequential tool calls a single agent turn may issue before we
# force the model to produce its final JSON answer.  Defends against a
# model that loops forever asking for more context.
DEFAULT_MAX_TOOL_CALLS_PER_TURN = 5

# Cap on rows / lines returned by list-shaped wands.  The model can ask
# for fewer; it cannot ask for more.
HARD_MAX_LIST_ITEMS = 100

# Cap on blame range count returned to the model.  Per-line blame on a
# 10 K-line file would otherwise dominate context.
HARD_MAX_BLAME_RANGES = 200

# Subprocess timeout for any single git invocation.  Local operations on
# a shallow checkout should be sub-second; this exists purely as a
# safety net against an unhealthy filesystem.
GIT_TIMEOUT_SECS = 30

# HTTP timeout for any single API call.
API_TIMEOUT_SECS = 30

# A "ref" can be a 4-40 character hex SHA, a branch / tag name, or
# HEAD ( or `HEAD~N`, `HEAD^`, etc. ).  We enforce a conservative
# character set so an attacker who somehow controls the model's
# arguments ( e.g. via prompt injection in the audited commit ) cannot
# smuggle shell metacharacters or URL-routing characters ( `?`, `&`,
# `#`, space ) into the URL path the REST fallback builds.  The
# matching ``..`` substring check below additionally blocks the
# only path-traversal pattern this character set still permits;
# `git check-ref-format` rejects `..` in ref names anyway, so the
# local backend was already safe.
_REF_RE = re.compile(r"^[A-Za-z0-9_./~^@-]{1,200}$")

# Path component validation: forbid the empty string and absolute paths.
# We additionally reject any `..` path segment in ``_validate_path`` so
# a path like ``../etc/passwd`` cannot escape the repo on the REST
# fallback ( ``urllib.parse.quote`` does not encode `..` since the dot
# is in its default safe set ).  Local git already rejects escapes via
# the worktree boundary; this matters for the API path.
_PATH_RE = re.compile(r"^(?!/)[^\x00]{1,1024}$")


class WandError(RuntimeError):
    """Raised by a wand when both local and API backends fail.

    The audit pipeline catches this in ``WandRegistry.dispatch`` and
    returns a structured error to the model so it can adapt rather than
    crashing the whole panel turn.
    """


# ---------------------------------------------------------------------------
# Wand context
# ---------------------------------------------------------------------------

@dataclass
class WandContext:
    """Everything a wand needs to talk to either backend.

    ``monitored_repo_path`` is the working directory of a local clone of
    the monitored repo.  It is allowed to be a shallow clone — wands
    detect missing objects and fall back to the API.  When unset, every
    wand goes straight to the API.

    ``audited_sha`` is the commit currently under review.  Wands use it
    as the default ``ref`` when the model omits one.
    """

    monitored_repo: str  # "owner/repo"
    monitored_token: str = ""
    monitored_repo_path: Optional[str] = None
    audited_sha: Optional[str] = None

    @property
    def owner_repo(self) -> tuple[str, str]:
        owner, _, repo = self.monitored_repo.partition("/")
        return owner, repo

    def has_local_checkout(self) -> bool:
        if not self.monitored_repo_path:
            return False
        git_dir = os.path.join(self.monitored_repo_path, ".git")
        return os.path.isdir(git_dir) or os.path.isfile(git_dir)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _validate_ref(ref: str) -> str:
    if not isinstance(ref, str) or not _REF_RE.match(ref):
        raise WandError(f"Invalid ref: {ref!r}")
    if ".." in ref:
        # `..` would let a ref like ``feature/..`` traverse the URL path
        # in the REST fallback ( ``/repos/o/r/commits/feature/..`` ->
        # ``/repos/o/r``, a different endpoint ).  Git itself rejects
        # `..` in valid refs, so this never blocks legitimate input.
        raise WandError(f"Invalid ref ( contains '..' ): {ref!r}")
    return ref


def _validate_path(path: str) -> str:
    if not isinstance(path, str) or not _PATH_RE.match(path):
        raise WandError(f"Invalid path: {path!r}")
    # Reject any `..` segment: this is the only escape pattern the
    # permissive ``_PATH_RE`` still allows, and ``urllib.parse.quote``
    # does not encode dots.  ``..foo`` and ``foo..bar`` are legal
    # filename fragments and are NOT rejected.
    for segment in path.split("/"):
        if segment == "..":
            raise WandError(f"Invalid path ( '..' segment ): {path!r}")
    return path


def _truncate(text: str, *, cap: int = MAX_OUTPUT_CHARS) -> tuple[str, bool]:
    if len(text) <= cap:
        return text, False
    return text[:cap], True


def _clamp_int(n: Any, *, default: int, lo: int, hi: int) -> int:
    if n is None:
        return default
    try:
        v = int(n)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


# ---------------------------------------------------------------------------
# Local-git shim
# ---------------------------------------------------------------------------

def _run_git(
    ctx: WandContext, args: list[str], *, capture_stderr: bool = False
) -> tuple[int, str, str]:
    """Run ``git -C <repo> <args...>`` and return ``(rc, stdout, stderr)``.

    Never raises CalledProcessError; the caller decides what a non-zero
    exit code means.  Subprocess timeouts surface as ``rc=124`` with the
    timeout message in stderr, matching the GNU coreutils convention so
    callers can write a single "non-zero means fall back" predicate.
    """
    if not ctx.monitored_repo_path:
        return 127, "", "no MONITORED_REPO_PATH"
    cmd = ["git", "-C", ctx.monitored_repo_path] + args
    try:
        res = subprocess.run(
            cmd,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE if capture_stderr else subprocess.DEVNULL,
            timeout=GIT_TIMEOUT_SECS,
        )
    except subprocess.TimeoutExpired as e:
        return 124, "", f"git timeout: {e}"
    except FileNotFoundError as e:
        # `git` itself missing — treat as "no local backend" so we fall
        # back to the API rather than crashing.
        return 127, "", f"git not found: {e}"
    return res.returncode, res.stdout, res.stderr or ""


def _has_commit_locally(ctx: WandContext, sha: str) -> bool:
    if not ctx.has_local_checkout():
        return False
    rc, _, _ = _run_git(ctx, ["cat-file", "-e", f"{sha}^{{commit}}"])
    return rc == 0


def _has_ref_locally(ctx: WandContext, ref: str) -> bool:
    """A ref resolves locally if `git rev-parse --verify` succeeds."""
    if not ctx.has_local_checkout():
        return False
    rc, _, _ = _run_git(ctx, ["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"])
    return rc == 0


# ---------------------------------------------------------------------------
# HTTP helper ( import _http lazily so unit tests can monkeypatch the
# module-level reference without forcing an import order )
# ---------------------------------------------------------------------------

def _api_get(url: str, ctx: WandContext, *, accept: str = "application/vnd.github+json") -> dict:
    import _http as http

    headers = {
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if ctx.monitored_token:
        headers["Authorization"] = f"Bearer {ctx.monitored_token}"
    try:
        resp = http.get(url, headers=headers, timeout=API_TIMEOUT_SECS)
    except http.HTTPError as e:
        raise WandError(f"network error: {e}") from e
    if resp.status_code == 404:
        raise WandError(f"not found: {url}")
    if not resp.ok:
        raise WandError(f"GitHub API {resp.status_code}: {resp.text[:200]}")
    try:
        return resp.json()
    except Exception as e:
        raise WandError(f"non-JSON GitHub response: {e}") from e


def _api_graphql(query: str, variables: dict, ctx: WandContext) -> dict:
    """POST a GraphQL request to the GitHub API.

    Injection safety: callers MUST pass the query as a static template
    constant ( see ``_BLAME_GRAPHQL`` ) and put every model-supplied
    value in ``variables``.  ``json.dumps`` escapes the variables dict
    when building the request body, and the GraphQL server parses the
    query into an AST and binds variables as typed values — it never
    string-substitutes them.  Do NOT introduce f-string formatting of
    user input into the ``query`` argument; that would break this
    invariant and reopen GraphQL injection as an attack vector.
    """
    import _http as http

    headers = {
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
    }
    if ctx.monitored_token:
        headers["Authorization"] = f"Bearer {ctx.monitored_token}"
    try:
        resp = http.post(
            "https://api.github.com/graphql",
            headers=headers,
            json={"query": query, "variables": variables},
            timeout=API_TIMEOUT_SECS,
        )
    except http.HTTPError as e:
        raise WandError(f"network error ( graphql ): {e}") from e
    if not resp.ok:
        raise WandError(f"GitHub GraphQL {resp.status_code}: {resp.text[:200]}")
    try:
        body = resp.json()
    except Exception as e:
        raise WandError(f"non-JSON GraphQL response: {e}") from e
    if body.get("errors"):
        raise WandError(f"GraphQL errors: {body['errors'][:2]}")
    return body.get("data") or {}


# ---------------------------------------------------------------------------
# Wand: git_log
# ---------------------------------------------------------------------------

def _wand_git_log(ctx: WandContext, args: dict) -> dict:
    ref = args.get("ref")
    if ref is None:
        ref = ctx.audited_sha or "HEAD"
    _validate_ref(ref)
    path = args.get("path")
    if path is not None:
        _validate_path(path)
    max_count = _clamp_int(
        args.get("max_count"), default=20, lo=1, hi=HARD_MAX_LIST_ITEMS
    )

    if _has_ref_locally(ctx, ref):
        out = _git_log_local(ctx, ref, path, max_count)
        if out is not None:
            return {"source": "local", **out}

    return {"source": "github", **_git_log_remote(ctx, ref, path, max_count)}


def _git_log_local(
    ctx: WandContext, ref: str, path: Optional[str], max_count: int
) -> Optional[dict]:
    fmt = "%H%x09%an%x09%ae%x09%aI%x09%s"
    cmd = ["log", f"--pretty=format:{fmt}", f"-n{max_count}", ref]
    if path is not None:
        cmd += ["--", path]
    rc, stdout, stderr = _run_git(ctx, cmd, capture_stderr=True)
    if rc != 0:
        return None
    commits: list[dict] = []
    for line in stdout.splitlines():
        parts = line.split("\t", 4)
        if len(parts) < 5:
            continue
        commits.append({
            "sha": parts[0],
            "author_name": parts[1],
            "author_email": parts[2],
            "date": parts[3],
            "message_first_line": parts[4],
        })
    return {"ref": ref, "path": path, "commits": commits}


def _git_log_remote(
    ctx: WandContext, ref: str, path: Optional[str], max_count: int
) -> dict:
    owner, repo = ctx.owner_repo
    qs: list[tuple[str, str]] = [("sha", ref), ("per_page", str(max_count))]
    if path is not None:
        qs.append(("path", path))
    url = (
        f"https://api.github.com/repos/{owner}/{repo}/commits?"
        + urllib.parse.urlencode(qs)
    )
    payload = _api_get(url, ctx)
    if not isinstance(payload, list):
        raise WandError(f"GitHub commits API returned non-list: {type(payload).__name__}")
    commits: list[dict] = []
    for entry in payload[:max_count]:
        c = entry.get("commit") or {}
        a = c.get("author") or {}
        msg_lines = (c.get("message") or "").splitlines()
        commits.append({
            "sha": entry.get("sha"),
            "author_name": a.get("name"),
            "author_email": a.get("email"),
            "date": a.get("date"),
            "message_first_line": msg_lines[0] if msg_lines else "",
        })
    return {"ref": ref, "path": path, "commits": commits}


# ---------------------------------------------------------------------------
# Wand: git_show_commit
# ---------------------------------------------------------------------------

def _wand_git_show_commit(ctx: WandContext, args: dict) -> dict:
    sha = args.get("sha")
    if not isinstance(sha, str):
        raise WandError("git_show_commit requires `sha`")
    _validate_ref(sha)

    if _has_commit_locally(ctx, sha):
        out = _git_show_commit_local(ctx, sha)
        if out is not None:
            return {"source": "local", **out}

    return {"source": "github", **_git_show_commit_remote(ctx, sha)}


def _git_show_commit_local(ctx: WandContext, sha: str) -> Optional[dict]:
    # Metadata.
    rc, meta_out, _ = _run_git(
        ctx,
        [
            "show",
            "--no-patch",
            f"--pretty=format:%H%x1f%P%x1f%an%x1f%ae%x1f%aI%x1f%B",
            sha,
        ],
    )
    if rc != 0:
        return None
    parts = meta_out.split("\x1f", 5)
    if len(parts) < 6:
        return None
    sha_full, parents_str, author_name, author_email, date, message = parts
    parents = parents_str.split() if parents_str.strip() else []

    # Diff.
    rc, diff_out, _ = _run_git(
        ctx, ["show", "--no-color", "--format=", sha]
    )
    if rc != 0:
        diff_out = ""
    diff_text, truncated = _truncate(diff_out)

    return {
        "sha": sha_full,
        "parents": parents,
        "author_name": author_name,
        "author_email": author_email,
        "date": date,
        "message": message.strip(),
        "diff": diff_text,
        "diff_truncated": truncated,
    }


def _git_show_commit_remote(ctx: WandContext, sha: str) -> dict:
    owner, repo = ctx.owner_repo
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}?per_page=100"
    payload = _api_get(url, ctx)
    c = payload.get("commit") or {}
    a = c.get("author") or {}
    parents = [p.get("sha") for p in (payload.get("parents") or []) if p.get("sha")]

    files = payload.get("files") or []
    chunks: list[str] = []
    for f in files:
        header = f"diff --git a/{f.get('previous_filename', f.get('filename'))} b/{f.get('filename')}\n"
        header += (
            f"# status={f.get('status')} +{f.get('additions', 0)}/-{f.get('deletions', 0)}\n"
        )
        patch = f.get("patch") or "# (patch omitted by API)\n"
        chunks.append(header + patch)
    diff_text = "\n".join(chunks)
    diff_text, truncated = _truncate(diff_text)

    return {
        "sha": payload.get("sha", sha),
        "parents": parents,
        "author_name": a.get("name"),
        "author_email": a.get("email"),
        "date": a.get("date"),
        "message": c.get("message") or "",
        "diff": diff_text,
        "diff_truncated": truncated,
    }


# ---------------------------------------------------------------------------
# Wand: git_blame
# ---------------------------------------------------------------------------

def _wand_git_blame(ctx: WandContext, args: dict) -> dict:
    path = args.get("path")
    if not isinstance(path, str):
        raise WandError("git_blame requires `path`")
    _validate_path(path)
    ref = args.get("ref") or ctx.audited_sha or "HEAD"
    _validate_ref(ref)
    line_start = args.get("line_start")
    line_end = args.get("line_end")
    if line_start is not None:
        line_start = _clamp_int(line_start, default=1, lo=1, hi=10**8)
    if line_end is not None:
        line_end = _clamp_int(line_end, default=line_start or 1, lo=1, hi=10**8)
    if line_start and line_end and line_end < line_start:
        line_start, line_end = line_end, line_start

    if _has_ref_locally(ctx, ref):
        out = _git_blame_local(ctx, ref, path, line_start, line_end)
        if out is not None:
            return {"source": "local", **out}

    return {"source": "github", **_git_blame_remote(ctx, ref, path, line_start, line_end)}


def _git_blame_local(
    ctx: WandContext,
    ref: str,
    path: str,
    line_start: Optional[int],
    line_end: Optional[int],
) -> Optional[dict]:
    cmd = ["blame", "--line-porcelain"]
    if line_start is not None:
        end = line_end or line_start
        cmd += ["-L", f"{line_start},{end}"]
    cmd += [ref, "--", path]
    rc, stdout, _ = _run_git(ctx, cmd)
    if rc != 0:
        return None
    lines: list[dict] = []
    cur_sha: Optional[str] = None
    cur_author: Optional[str] = None
    cur_date: Optional[str] = None
    cur_lineno: Optional[int] = None
    for raw in stdout.splitlines():
        if re.match(r"^[0-9a-f]{40} ", raw):
            tok = raw.split()
            cur_sha = tok[0]
            cur_lineno = int(tok[2]) if len(tok) >= 3 else None
            cur_author = None
            cur_date = None
            continue
        if raw.startswith("author "):
            cur_author = raw[len("author ") :]
            continue
        if raw.startswith("author-time "):
            cur_date = raw[len("author-time ") :]
            continue
        if raw.startswith("\t"):
            lines.append({
                "sha": cur_sha,
                "lineno": cur_lineno,
                "author": cur_author,
                "author_time": cur_date,
                "content": raw[1:],
            })
            if len(lines) >= HARD_MAX_BLAME_RANGES:
                break
    truncated = len(lines) >= HARD_MAX_BLAME_RANGES
    return {
        "path": path,
        "ref": ref,
        "line_start": line_start,
        "line_end": line_end,
        "lines": lines,
        "truncated": truncated,
    }


_BLAME_GRAPHQL = """
query Blame($owner: String!, $repo: String!, $oid: GitObjectID!, $path: String!) {
  repository(owner: $owner, name: $repo) {
    object(oid: $oid) {
      ... on Commit {
        blame(path: $path) {
          ranges {
            startingLine
            endingLine
            commit {
              oid
              messageHeadline
              author {
                name
                email
                date
              }
            }
          }
        }
      }
    }
  }
}
"""


def _git_blame_remote(
    ctx: WandContext,
    ref: str,
    path: str,
    line_start: Optional[int],
    line_end: Optional[int],
) -> dict:
    owner, repo = ctx.owner_repo
    # GraphQL needs an OID ( commit SHA ); resolve symbolic refs first
    # via the REST commits API.
    oid = ref
    if not re.match(r"^[0-9a-f]{40}$", ref):
        info = _api_get(
            f"https://api.github.com/repos/{owner}/{repo}/commits/{ref}",
            ctx,
        )
        oid = info.get("sha") or ref

    data = _api_graphql(
        _BLAME_GRAPHQL,
        {"owner": owner, "repo": repo, "oid": oid, "path": path},
        ctx,
    )
    obj = (((data.get("repository") or {}).get("object")) or {})
    blame = (obj.get("blame") or {}).get("ranges") or []

    ranges_out: list[dict] = []
    for r in blame:
        s = r.get("startingLine") or 0
        e = r.get("endingLine") or 0
        if line_start is not None and e < line_start:
            continue
        if line_end is not None and s > line_end:
            continue
        c = r.get("commit") or {}
        a = c.get("author") or {}
        ranges_out.append({
            "starting_line": s,
            "ending_line": e,
            "sha": c.get("oid"),
            "message_first_line": c.get("messageHeadline"),
            "author_name": a.get("name"),
            "author_email": a.get("email"),
            "author_time": a.get("date"),
        })
        if len(ranges_out) >= HARD_MAX_BLAME_RANGES:
            break
    truncated = len(ranges_out) >= HARD_MAX_BLAME_RANGES

    return {
        "path": path,
        "ref": oid,
        "line_start": line_start,
        "line_end": line_end,
        "ranges": ranges_out,
        "truncated": truncated,
        "note": (
            "Remote blame returns ranges only ( per-line content omitted to "
            "save context ); fetch the file via git_show_file to inspect "
            "specific lines."
        ),
    }


# ---------------------------------------------------------------------------
# Wand: git_show_file
# ---------------------------------------------------------------------------

def _wand_git_show_file(ctx: WandContext, args: dict) -> dict:
    path = args.get("path")
    if not isinstance(path, str):
        raise WandError("git_show_file requires `path`")
    _validate_path(path)
    ref = args.get("ref") or ctx.audited_sha or "HEAD"
    _validate_ref(ref)

    if _has_ref_locally(ctx, ref):
        out = _git_show_file_local(ctx, ref, path)
        if out is not None:
            return {"source": "local", **out}

    return {"source": "github", **_git_show_file_remote(ctx, ref, path)}


def _git_show_file_local(ctx: WandContext, ref: str, path: str) -> Optional[dict]:
    rc, stdout, _ = _run_git(ctx, ["show", f"{ref}:{path}"])
    if rc != 0:
        return None
    content, truncated = _truncate(stdout)
    return {"path": path, "ref": ref, "content": content, "truncated": truncated}


def _git_show_file_remote(ctx: WandContext, ref: str, path: str) -> dict:
    owner, repo = ctx.owner_repo
    # `_validate_ref` already restricts ``ref`` to URL-safe characters
    # ( and forbids `..` ), but URL-encode it anyway so a future
    # widening of the ref grammar cannot reopen a query-string injection.
    quoted_path = urllib.parse.quote(path)
    quoted_ref = urllib.parse.quote(ref, safe="")
    url = (
        f"https://api.github.com/repos/{owner}/{repo}/contents/{quoted_path}"
        f"?ref={quoted_ref}"
    )
    payload = _api_get(url, ctx)
    if isinstance(payload, list):
        raise WandError(f"{path}@{ref} is a directory, not a file")
    if payload.get("type") == "symlink":
        return {
            "path": path,
            "ref": ref,
            "content": f"<symlink -> {payload.get('target')}>",
            "truncated": False,
        }
    encoding = payload.get("encoding", "base64")
    raw = payload.get("content", "") or ""
    if encoding == "base64":
        try:
            text_bytes = base64.b64decode(raw)
        except Exception as e:
            raise WandError(f"could not decode contents API blob: {e}") from e
        try:
            text = text_bytes.decode("utf-8")
        except UnicodeDecodeError:
            text = text_bytes.decode("utf-8", errors="replace")
    else:
        text = raw
    text, truncated = _truncate(text)
    return {"path": path, "ref": ref, "content": text, "truncated": truncated}


# ---------------------------------------------------------------------------
# Wand: git_diff_refs
# ---------------------------------------------------------------------------

def _wand_git_diff_refs(ctx: WandContext, args: dict) -> dict:
    base = args.get("base")
    head = args.get("head")
    if not isinstance(base, str) or not isinstance(head, str):
        raise WandError("git_diff_refs requires `base` and `head`")
    _validate_ref(base)
    _validate_ref(head)
    path = args.get("path")
    if path is not None:
        _validate_path(path)

    if _has_ref_locally(ctx, base) and _has_ref_locally(ctx, head):
        out = _git_diff_refs_local(ctx, base, head, path)
        if out is not None:
            return {"source": "local", **out}

    return {"source": "github", **_git_diff_refs_remote(ctx, base, head, path)}


def _git_diff_refs_local(
    ctx: WandContext, base: str, head: str, path: Optional[str]
) -> Optional[dict]:
    cmd = ["diff", "--no-color", base, head]
    if path is not None:
        cmd += ["--", path]
    rc, stdout, _ = _run_git(ctx, cmd)
    if rc != 0:
        return None
    diff_text, truncated = _truncate(stdout)
    return {"base": base, "head": head, "path": path, "diff": diff_text, "truncated": truncated}


def _git_diff_refs_remote(
    ctx: WandContext, base: str, head: str, path: Optional[str]
) -> dict:
    owner, repo = ctx.owner_repo
    url = f"https://api.github.com/repos/{owner}/{repo}/compare/{base}...{head}"
    payload = _api_get(url, ctx)
    files = payload.get("files") or []
    chunks: list[str] = []
    for f in files:
        if path is not None and f.get("filename") != path:
            continue
        prev = f.get("previous_filename") or f.get("filename")
        header = f"diff --git a/{prev} b/{f.get('filename')}\n"
        header += (
            f"# status={f.get('status')} "
            f"+{f.get('additions', 0)}/-{f.get('deletions', 0)}\n"
        )
        patch = f.get("patch") or "# (patch omitted by API)\n"
        chunks.append(header + patch)
    diff_text, truncated = _truncate("\n".join(chunks))
    return {"base": base, "head": head, "path": path, "diff": diff_text, "truncated": truncated}


# ---------------------------------------------------------------------------
# Wand: git_search_log
# ---------------------------------------------------------------------------

def _wand_git_search_log(ctx: WandContext, args: dict) -> dict:
    query = args.get("query")
    if not isinstance(query, str) or not query.strip():
        raise WandError("git_search_log requires non-empty `query`")
    if len(query) > 256:
        raise WandError("git_search_log `query` too long ( max 256 chars )")
    max_count = _clamp_int(
        args.get("max_count"), default=20, lo=1, hi=HARD_MAX_LIST_ITEMS
    )
    ref = args.get("ref") or ctx.audited_sha or "HEAD"
    _validate_ref(ref)

    # Local search only works when the ref is local and the shallow
    # depth covers the area we'd care about; otherwise the API search is
    # more authoritative.
    if _has_ref_locally(ctx, ref):
        out = _git_search_log_local(ctx, ref, query, max_count)
        if out is not None and out.get("commits"):
            return {"source": "local", **out}

    return {"source": "github", **_git_search_log_remote(ctx, query, max_count)}


def _git_search_log_local(
    ctx: WandContext, ref: str, query: str, max_count: int
) -> Optional[dict]:
    fmt = "%H%x09%an%x09%ae%x09%aI%x09%s"
    rc, stdout, _ = _run_git(
        ctx,
        [
            "log",
            f"--pretty=format:{fmt}",
            f"-n{max_count}",
            f"--grep={query}",
            "-i",
            ref,
        ],
    )
    if rc != 0:
        return None
    commits: list[dict] = []
    for line in stdout.splitlines():
        parts = line.split("\t", 4)
        if len(parts) < 5:
            continue
        commits.append({
            "sha": parts[0],
            "author_name": parts[1],
            "author_email": parts[2],
            "date": parts[3],
            "message_first_line": parts[4],
        })
    return {"query": query, "ref": ref, "commits": commits}


def _git_search_log_remote(
    ctx: WandContext, query: str, max_count: int
) -> dict:
    owner, repo = ctx.owner_repo
    q = f"{query} repo:{owner}/{repo}"
    url = (
        "https://api.github.com/search/commits?"
        + urllib.parse.urlencode({"q": q, "per_page": str(max_count)})
    )
    payload = _api_get(url, ctx)
    items = payload.get("items") or []
    commits: list[dict] = []
    for entry in items[:max_count]:
        c = entry.get("commit") or {}
        a = c.get("author") or {}
        msg_lines = (c.get("message") or "").splitlines()
        commits.append({
            "sha": entry.get("sha"),
            "author_name": a.get("name"),
            "author_email": a.get("email"),
            "date": a.get("date"),
            "message_first_line": msg_lines[0] if msg_lines else "",
        })
    return {"query": query, "commits": commits}


# ---------------------------------------------------------------------------
# Tool schemas ( OpenAI function-calling )
# ---------------------------------------------------------------------------

WAND_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "git_log",
            "description": (
                "List recent commits on the monitored repo, optionally filtered "
                "by a path.  Useful when triaging whether the file under review "
                "has a suspicious recent history ( e.g. another touch by the "
                "same author shortly before this one )."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ref": {
                        "type": "string",
                        "description": "Branch, tag, or SHA to start from.  Defaults to the audited commit.",
                    },
                    "path": {
                        "type": "string",
                        "description": "Optional path filter ( file or directory ).",
                    },
                    "max_count": {
                        "type": "integer",
                        "description": "Maximum number of commits to return ( 1 - 100, default 20 ).",
                        "minimum": 1,
                        "maximum": HARD_MAX_LIST_ITEMS,
                    },
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "git_show_commit",
            "description": (
                "Fetch a specific commit's metadata and unified diff.  Use "
                "this to inspect a commit referenced from the audited diff "
                "( e.g. a parent of a merge, or a commit named in a comment )."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "sha": {
                        "type": "string",
                        "description": "Commit SHA ( 7 - 40 hex chars ).",
                    },
                },
                "required": ["sha"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "git_blame",
            "description": (
                "Per-line authorship for a path at a ref.  Optionally limit "
                "to a line range.  Use this to check whether a suspicious "
                "line is new in this commit or has been there for a while."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "ref": {
                        "type": "string",
                        "description": "Defaults to the audited commit.",
                    },
                    "line_start": {"type": "integer", "minimum": 1},
                    "line_end": {"type": "integer", "minimum": 1},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "git_show_file",
            "description": (
                "Read a file's contents at a specific ref.  Use this when a "
                "finding hinges on a symbol defined in a file the panel did "
                "NOT receive in the routed diff."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "ref": {
                        "type": "string",
                        "description": "Defaults to the audited commit.",
                    },
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "git_diff_refs",
            "description": (
                "Diff between two refs ( SHA / branch / tag ), optionally "
                "limited to a path.  Useful for spanning multiple commits "
                "( e.g. compare audited commit with its grandparent )."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "base": {"type": "string"},
                    "head": {"type": "string"},
                    "path": {"type": "string"},
                },
                "required": ["base", "head"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "git_search_log",
            "description": (
                "Search commit messages on the monitored repo.  Use to look "
                "for prior commits with similar wording, or to find a "
                "commit referenced by message."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "ref": {
                        "type": "string",
                        "description": "Branch / SHA to search from ( default: audited commit ).",
                    },
                    "max_count": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": HARD_MAX_LIST_ITEMS,
                    },
                },
                "required": ["query"],
                "additionalProperties": False,
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

WandFn = Callable[[WandContext, dict], dict]

_DEFAULT_WANDS: dict[str, WandFn] = {
    "git_log": _wand_git_log,
    "git_show_commit": _wand_git_show_commit,
    "git_blame": _wand_git_blame,
    "git_show_file": _wand_git_show_file,
    "git_diff_refs": _wand_git_diff_refs,
    "git_search_log": _wand_git_search_log,
}


@dataclass
class WandRegistry:
    """Dispatch table the chat-completion loop hands tool calls to.

    ``call_count`` and ``max_calls`` are the per-turn budget.  Once a
    single agent turn exhausts the budget, ``dispatch`` returns a
    structured error ( rather than raising ) so the model can wrap up
    and return its final JSON.
    """

    ctx: WandContext
    wands: dict[str, WandFn] = field(default_factory=lambda: dict(_DEFAULT_WANDS))
    max_calls: int = DEFAULT_MAX_TOOL_CALLS_PER_TURN
    call_count: int = 0

    def reset(self) -> None:
        self.call_count = 0

    def schemas(self) -> list[dict]:
        return WAND_SCHEMAS

    def dispatch(self, name: str, args: dict) -> dict:
        self.call_count += 1
        if self.call_count > self.max_calls:
            return {
                "error": "tool_budget_exhausted",
                "detail": (
                    f"Agent exceeded the per-turn tool budget "
                    f"( {self.max_calls} calls ).  Produce your final JSON now."
                ),
            }
        fn = self.wands.get(name)
        if fn is None:
            return {"error": "unknown_tool", "detail": f"no wand named {name!r}"}
        try:
            return fn(self.ctx, args or {})
        except WandError as e:
            return {"error": "wand_error", "detail": str(e)}
        except Exception as e:  # pragma: no cover - belt and braces
            print(
                f"WARNING: wand {name} raised unexpected {type(e).__name__}: {e}",
                file=sys.stderr,
            )
            return {"error": "wand_internal_error", "detail": f"{type(e).__name__}: {e}"}


def build_default_registry(
    monitored_repo: str,
    monitored_token: str,
    monitored_repo_path: Optional[str],
    audited_sha: Optional[str],
    *,
    max_calls: int = DEFAULT_MAX_TOOL_CALLS_PER_TURN,
) -> WandRegistry:
    return WandRegistry(
        ctx=WandContext(
            monitored_repo=monitored_repo,
            monitored_token=monitored_token,
            monitored_repo_path=monitored_repo_path,
            audited_sha=audited_sha,
        ),
        max_calls=max_calls,
    )


# ---------------------------------------------------------------------------
# Helper: short, model-friendly description of available tools.  Used in
# the prompt to remind agents what they can call without ballooning the
# system prompt.
# ---------------------------------------------------------------------------

def render_tool_help() -> str:
    lines = [
        "## Available tools ( call when extra context would change your verdict )",
        "",
    ]
    for schema in WAND_SCHEMAS:
        fn = schema["function"]
        lines.append(f"- `{fn['name']}` — {fn['description'].splitlines()[0]}")
    lines.extend([
        "",
        "Tools are optional.  Prefer to answer from the diff alone when the "
        "diff is sufficient; reach for a tool only when a finding's confidence "
        "depends on information outside the routed patch.  Each tool returns "
        "JSON; large outputs are truncated.",
    ])
    return "\n".join(lines)


def env_max_calls() -> int:
    raw = os.environ.get("AUDIT_WAND_MAX_CALLS", "").strip()
    if not raw:
        return DEFAULT_MAX_TOOL_CALLS_PER_TURN
    try:
        n = int(raw)
    except ValueError:
        return DEFAULT_MAX_TOOL_CALLS_PER_TURN
    return max(0, min(20, n))


def wands_enabled() -> bool:
    """Master switch for the wand layer.

    Default-on.  Set ``AUDIT_DISABLE_WANDS=1`` to fall back to the
    historical no-tools panel ( useful when debugging the model layer ).
    """
    return os.environ.get("AUDIT_DISABLE_WANDS", "").strip().lower() not in ("1", "true")
