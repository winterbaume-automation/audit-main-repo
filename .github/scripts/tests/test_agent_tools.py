"""Wand tests: shim local-vs-API selection, registry dispatch, validation.

The shim is exercised by monkeypatching both the subprocess invocation
( for the local backend ) and ``_http`` ( for the GitHub API backend )
so no real git or HTTP traffic is generated.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

import agent_tools
from agent_tools import (
    DEFAULT_MAX_TOOL_CALLS_PER_TURN,
    HARD_MAX_BLAME_RANGES,
    MAX_OUTPUT_CHARS,
    WandContext,
    WandError,
    WandRegistry,
    _validate_crate_name,
    _validate_path,
    _validate_ref,
    build_default_registry,
    env_max_calls,
    render_tool_help,
    wands_enabled,
)


# ---------------------------------------------------------------------------
# Helpers: stub subprocess and _http
# ---------------------------------------------------------------------------

class FakeCompletedProcess:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _stub_run_git(monkeypatch, scripts):
    """Replace ``subprocess.run`` for git invocations.

    ``scripts`` is a list of ``(predicate, FakeCompletedProcess)`` pairs.
    The first matching predicate wins; predicates are called with the
    full argv list ( so tests can match on ``"cat-file"`` etc. ).
    Calls beyond the scripted set return rc=128.
    """
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        for predicate, result in scripts:
            if predicate(cmd):
                return result
        return FakeCompletedProcess(128, "", "no scripted match")

    monkeypatch.setattr(agent_tools.subprocess, "run", fake_run)
    return calls


class FakeResponse:
    def __init__(self, status_code=200, text="{}", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self):
        return json.loads(self.text)


def _stub_http(monkeypatch, get_handler=None, post_handler=None):
    """Inject a fake `_http` module so wand calls can be replayed."""
    import _http as real_http

    class StubHttp:
        HTTPError = real_http.HTTPError

        @staticmethod
        def get(url, headers=None, timeout=30):
            if get_handler is None:
                raise AssertionError(f"unexpected GET {url}")
            return get_handler(url, headers, timeout)

        @staticmethod
        def post(url, headers=None, json=None, timeout=30):
            if post_handler is None:
                raise AssertionError(f"unexpected POST {url}")
            return post_handler(url, headers, json, timeout)

    monkeypatch.setitem(__import__("sys").modules, "_http", StubHttp)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_validate_ref_accepts_sha_and_branch():
    assert _validate_ref("abc1234") == "abc1234"
    assert _validate_ref("main") == "main"
    assert _validate_ref("HEAD~3") == "HEAD~3"
    assert _validate_ref("v1.2.3") == "v1.2.3"


def test_validate_ref_rejects_shell_metacharacters():
    for bad in ("foo;rm", "foo bar", "foo|cat", "$(whoami)", "", "a" * 300):
        with pytest.raises(WandError):
            _validate_ref(bad)


def test_validate_ref_rejects_path_traversal():
    """A ref containing `..` would let the REST fallback URL traverse
    out of the ``/repos/o/r/commits/{ref}`` path; git itself also
    rejects `..` in valid ref names so this never blocks legitimate
    input."""
    for bad in ("..", "feature/..", "../../../etc", "foo/../bar"):
        with pytest.raises(WandError):
            _validate_ref(bad)


def test_validate_path_rejects_absolute_and_nul():
    with pytest.raises(WandError):
        _validate_path("/etc/passwd")
    with pytest.raises(WandError):
        _validate_path("foo\x00bar")
    with pytest.raises(WandError):
        _validate_path("")
    # `..foo` and `foo..bar` are legal filename fragments — only a
    # standalone `..` segment is rejected.
    assert _validate_path("crates/foo/src/lib.rs") == "crates/foo/src/lib.rs"
    assert _validate_path(".github/workflows/release.yml") == ".github/workflows/release.yml"
    assert _validate_path("strange..name.txt") == "strange..name.txt"


def test_validate_path_rejects_dotdot_segments():
    """``..`` as a path segment would escape the repo on the REST
    contents-API fallback ( ``urllib.parse.quote`` does not encode
    dots ), so reject it at the boundary."""
    for bad in ("..", "../etc/passwd", "foo/../bar", "a/b/..", "../../x"):
        with pytest.raises(WandError):
            _validate_path(bad)


# ---------------------------------------------------------------------------
# Registry: budget, unknown tool, error wrapping
# ---------------------------------------------------------------------------

def test_registry_dispatches_known_wand(monkeypatch):
    ctx = WandContext(monitored_repo="o/r")
    registry = WandRegistry(ctx=ctx, wands={"echo": lambda c, a: {"got": a}})
    out = registry.dispatch("echo", {"x": 1})
    assert out == {"got": {"x": 1}}


def test_registry_unknown_tool_returns_error():
    ctx = WandContext(monitored_repo="o/r")
    registry = WandRegistry(ctx=ctx, wands={})
    out = registry.dispatch("nope", {})
    assert out["error"] == "unknown_tool"


def test_registry_wraps_wand_error():
    def boom(_c, _a):
        raise WandError("kaboom")

    registry = WandRegistry(ctx=WandContext(monitored_repo="o/r"), wands={"x": boom})
    out = registry.dispatch("x", {})
    assert out == {"error": "wand_error", "detail": "kaboom"}


def test_registry_enforces_per_turn_budget():
    registry = WandRegistry(
        ctx=WandContext(monitored_repo="o/r"),
        wands={"x": lambda c, a: {"ok": True}},
        max_calls=2,
    )
    assert registry.dispatch("x", {})["ok"] is True
    assert registry.dispatch("x", {})["ok"] is True
    out = registry.dispatch("x", {})
    assert out["error"] == "tool_budget_exhausted"


def test_registry_reset_clears_call_count():
    registry = WandRegistry(
        ctx=WandContext(monitored_repo="o/r"),
        wands={"x": lambda c, a: {"ok": True}},
        max_calls=1,
    )
    registry.dispatch("x", {})
    assert registry.dispatch("x", {})["error"] == "tool_budget_exhausted"
    registry.reset()
    assert registry.dispatch("x", {})["ok"] is True


# ---------------------------------------------------------------------------
# git_log: local path
# ---------------------------------------------------------------------------

def test_git_log_local_when_ref_is_present(monkeypatch, tmp_path):
    (tmp_path / ".git").mkdir()
    ctx = WandContext(monitored_repo="o/r", monitored_repo_path=str(tmp_path))
    log_out = (
        "abc123\tAlice\talice@example.com\t2026-04-20T10:00:00Z\tinitial commit\n"
        "def456\tBob\tbob@example.com\t2026-04-21T10:00:00Z\tfollow-up\n"
    )
    _stub_run_git(
        monkeypatch,
        [
            (lambda cmd: "rev-parse" in cmd, FakeCompletedProcess(0, "abc123\n", "")),
            (lambda cmd: "log" in cmd, FakeCompletedProcess(0, log_out, "")),
        ],
    )
    out = agent_tools._wand_git_log(ctx, {"ref": "main", "max_count": 5})
    assert out["source"] == "local"
    assert len(out["commits"]) == 2
    assert out["commits"][0]["sha"] == "abc123"
    assert out["commits"][1]["author_name"] == "Bob"


# ---------------------------------------------------------------------------
# git_log: API fallback when ref not local
# ---------------------------------------------------------------------------

def test_git_log_falls_back_to_api(monkeypatch, tmp_path):
    (tmp_path / ".git").mkdir()
    ctx = WandContext(monitored_repo="o/r", monitored_repo_path=str(tmp_path))
    _stub_run_git(
        monkeypatch,
        [(lambda cmd: True, FakeCompletedProcess(128, "", "fatal"))],
    )

    def get_handler(url, headers, timeout):
        assert "/repos/o/r/commits" in url
        return FakeResponse(
            200,
            json.dumps([
                {
                    "sha": "ff00",
                    "commit": {
                        "message": "API commit",
                        "author": {
                            "name": "Cara",
                            "email": "cara@example.com",
                            "date": "2026-04-25T10:00:00Z",
                        },
                    },
                }
            ]),
        )

    _stub_http(monkeypatch, get_handler=get_handler)
    out = agent_tools._wand_git_log(ctx, {"ref": "deadbeef", "max_count": 1})
    assert out["source"] == "github"
    assert out["commits"][0]["sha"] == "ff00"
    assert out["commits"][0]["author_name"] == "Cara"


def test_git_log_uses_audited_sha_when_ref_omitted(monkeypatch):
    ctx = WandContext(monitored_repo="o/r", audited_sha="cafe1234")
    seen: list[str] = []

    def get_handler(url, headers, timeout):
        seen.append(url)
        return FakeResponse(200, "[]")

    _stub_http(monkeypatch, get_handler=get_handler)
    agent_tools._wand_git_log(ctx, {})
    assert any("sha=cafe1234" in u for u in seen)


# ---------------------------------------------------------------------------
# git_show_commit
# ---------------------------------------------------------------------------

def test_git_show_commit_local_path(monkeypatch, tmp_path):
    (tmp_path / ".git").mkdir()
    ctx = WandContext(monitored_repo="o/r", monitored_repo_path=str(tmp_path))
    meta = (
        "abc123\x1f"
        "parent1 parent2\x1f"
        "Alice\x1f"
        "a@x.y\x1f"
        "2026-04-01T00:00:00Z\x1f"
        "commit message\nbody\n"
    )
    diff = "diff --git a/x b/x\n@@ -1 +1 @@\n-old\n+new\n"
    _stub_run_git(
        monkeypatch,
        [
            (lambda cmd: "cat-file" in cmd, FakeCompletedProcess(0, "", "")),
            (lambda cmd: "show" in cmd and "--no-patch" in cmd, FakeCompletedProcess(0, meta, "")),
            (lambda cmd: "show" in cmd, FakeCompletedProcess(0, diff, "")),
        ],
    )
    out = agent_tools._wand_git_show_commit(ctx, {"sha": "abc123"})
    assert out["source"] == "local"
    assert out["sha"] == "abc123"
    assert out["parents"] == ["parent1", "parent2"]
    assert out["author_name"] == "Alice"
    assert "old" in out["diff"] and "new" in out["diff"]


def test_git_show_commit_falls_back_when_sha_missing(monkeypatch):
    ctx = WandContext(monitored_repo="o/r")  # no local checkout

    def get_handler(url, headers, timeout):
        assert "/repos/o/r/commits/abc123" in url
        return FakeResponse(200, json.dumps({
            "sha": "abc123",
            "parents": [{"sha": "p1"}],
            "commit": {
                "message": "API path",
                "author": {"name": "A", "email": "a@x", "date": "2026-04-01"},
            },
            "files": [{
                "filename": "src/main.rs",
                "previous_filename": "src/main.rs",
                "status": "modified",
                "additions": 1,
                "deletions": 0,
                "patch": "@@\n+let _ = 1;\n",
            }],
        }))

    _stub_http(monkeypatch, get_handler=get_handler)
    out = agent_tools._wand_git_show_commit(ctx, {"sha": "abc123"})
    assert out["source"] == "github"
    assert "let _ = 1;" in out["diff"]
    assert out["parents"] == ["p1"]


def test_git_show_commit_requires_sha():
    ctx = WandContext(monitored_repo="o/r")
    with pytest.raises(WandError):
        agent_tools._wand_git_show_commit(ctx, {})


# ---------------------------------------------------------------------------
# git_blame
# ---------------------------------------------------------------------------

def test_git_blame_local_porcelain(monkeypatch, tmp_path):
    (tmp_path / ".git").mkdir()
    ctx = WandContext(monitored_repo="o/r", monitored_repo_path=str(tmp_path))
    porcelain = (
        "abc1234567890abcdef1234567890abcdef12345 1 1 1\n"
        "author Alice\n"
        "author-time 1714003200\n"
        "filename foo.rs\n"
        "\tfn main() {}\n"
        "def4567890abcdef1234567890abcdef12345678 2 2 1\n"
        "author Bob\n"
        "author-time 1714089600\n"
        "filename foo.rs\n"
        "\t    println!(\"hi\");\n"
    )
    _stub_run_git(
        monkeypatch,
        [
            (lambda cmd: "rev-parse" in cmd, FakeCompletedProcess(0, "abc\n", "")),
            (lambda cmd: "blame" in cmd, FakeCompletedProcess(0, porcelain, "")),
        ],
    )
    out = agent_tools._wand_git_blame(
        ctx, {"path": "foo.rs", "line_start": 1, "line_end": 2}
    )
    assert out["source"] == "local"
    assert len(out["lines"]) == 2
    assert out["lines"][0]["author"] == "Alice"
    assert out["lines"][1]["content"].strip() == 'println!("hi");'


def test_git_blame_remote_returns_ranges(monkeypatch):
    ctx = WandContext(monitored_repo="o/r")

    def post_handler(url, headers, payload, timeout):
        assert url.endswith("/graphql")
        return FakeResponse(200, json.dumps({
            "data": {
                "repository": {
                    "object": {
                        "blame": {
                            "ranges": [
                                {
                                    "startingLine": 1,
                                    "endingLine": 5,
                                    "commit": {
                                        "oid": "abc",
                                        "messageHeadline": "first",
                                        "author": {
                                            "name": "Alice",
                                            "email": "a@x",
                                            "date": "2026-04-01",
                                        },
                                    },
                                },
                            ],
                        },
                    },
                },
            },
        }))

    _stub_http(monkeypatch, post_handler=post_handler)
    out = agent_tools._wand_git_blame(
        ctx, {"path": "foo.rs", "ref": "abcdef0123456789abcdef0123456789abcdef01"}
    )
    assert out["source"] == "github"
    assert out["ranges"][0]["author_name"] == "Alice"
    assert out["ranges"][0]["starting_line"] == 1


# ---------------------------------------------------------------------------
# git_show_file
# ---------------------------------------------------------------------------

def test_git_show_file_local(monkeypatch, tmp_path):
    (tmp_path / ".git").mkdir()
    ctx = WandContext(monitored_repo="o/r", monitored_repo_path=str(tmp_path))
    _stub_run_git(
        monkeypatch,
        [
            (lambda cmd: "rev-parse" in cmd, FakeCompletedProcess(0, "abc\n", "")),
            (lambda cmd: "show" in cmd, FakeCompletedProcess(0, "hello world\n", "")),
        ],
    )
    out = agent_tools._wand_git_show_file(ctx, {"path": "README.md", "ref": "main"})
    assert out["source"] == "local"
    assert out["content"] == "hello world\n"
    assert out["truncated"] is False


def test_git_show_file_remote_decodes_base64(monkeypatch):
    import base64

    ctx = WandContext(monitored_repo="o/r")
    enc = base64.b64encode(b"contents").decode()

    def get_handler(url, headers, timeout):
        return FakeResponse(200, json.dumps({
            "type": "file",
            "encoding": "base64",
            "content": enc,
        }))

    _stub_http(monkeypatch, get_handler=get_handler)
    out = agent_tools._wand_git_show_file(ctx, {"path": "x", "ref": "abc"})
    assert out["source"] == "github"
    assert out["content"] == "contents"


def test_git_show_file_truncates_large_local(monkeypatch, tmp_path):
    (tmp_path / ".git").mkdir()
    ctx = WandContext(monitored_repo="o/r", monitored_repo_path=str(tmp_path))
    big = "x" * (MAX_OUTPUT_CHARS + 100)
    _stub_run_git(
        monkeypatch,
        [
            (lambda cmd: "rev-parse" in cmd, FakeCompletedProcess(0, "abc\n", "")),
            (lambda cmd: "show" in cmd, FakeCompletedProcess(0, big, "")),
        ],
    )
    out = agent_tools._wand_git_show_file(ctx, {"path": "p", "ref": "main"})
    assert out["truncated"] is True
    assert len(out["content"]) == MAX_OUTPUT_CHARS


# ---------------------------------------------------------------------------
# git_diff_refs
# ---------------------------------------------------------------------------

def test_git_diff_refs_falls_back_when_one_side_missing(monkeypatch, tmp_path):
    (tmp_path / ".git").mkdir()
    ctx = WandContext(monitored_repo="o/r", monitored_repo_path=str(tmp_path))
    rev_calls = {"count": 0}

    def rev_parse_response(cmd):
        # Only the second rev-parse fails ( head is missing locally ).
        rev_calls["count"] += 1
        return FakeCompletedProcess(0 if rev_calls["count"] == 1 else 128, "abc\n", "")

    def fake_run(cmd, **kwargs):
        if "rev-parse" in cmd:
            return rev_parse_response(cmd)
        if "diff" in cmd:
            return FakeCompletedProcess(0, "diff text", "")
        return FakeCompletedProcess(128, "", "")

    monkeypatch.setattr(agent_tools.subprocess, "run", fake_run)

    def get_handler(url, headers, timeout):
        assert "/compare/" in url
        return FakeResponse(200, json.dumps({
            "files": [{
                "filename": "x",
                "status": "modified",
                "additions": 1,
                "deletions": 0,
                "patch": "@@\n+a\n",
            }],
        }))

    _stub_http(monkeypatch, get_handler=get_handler)
    out = agent_tools._wand_git_diff_refs(
        ctx, {"base": "main", "head": "feature"}
    )
    assert out["source"] == "github"
    assert "+a" in out["diff"]


# ---------------------------------------------------------------------------
# git_search_log
# ---------------------------------------------------------------------------

def test_git_search_log_remote_path(monkeypatch):
    ctx = WandContext(monitored_repo="o/r")

    def get_handler(url, headers, timeout):
        assert "/search/commits" in url
        return FakeResponse(200, json.dumps({
            "items": [{
                "sha": "abc",
                "commit": {
                    "message": "fix typo\n\nlonger\n",
                    "author": {"name": "X", "email": "x@y", "date": "2026-04-25"},
                },
            }],
        }))

    _stub_http(monkeypatch, get_handler=get_handler)
    out = agent_tools._wand_git_search_log(ctx, {"query": "typo", "max_count": 5})
    assert out["source"] == "github"
    assert out["commits"][0]["message_first_line"] == "fix typo"


def test_git_search_log_rejects_empty_query():
    ctx = WandContext(monitored_repo="o/r")
    with pytest.raises(WandError):
        agent_tools._wand_git_search_log(ctx, {"query": ""})


# ---------------------------------------------------------------------------
# crates_io_lookup
# ---------------------------------------------------------------------------

def test_validate_crate_name_accepts_real_names():
    assert _validate_crate_name("serde") == "serde"
    assert _validate_crate_name("httpdate") == "httpdate"
    assert _validate_crate_name("tokio-util") == "tokio-util"
    assert _validate_crate_name("rust_decimal") == "rust_decimal"


def test_validate_crate_name_rejects_garbage():
    for bad in ("", " ", "1bad", "../etc", "foo bar", "name?", "a" * 65):
        with pytest.raises(WandError):
            _validate_crate_name(bad)


def test_crates_io_lookup_returns_metadata_on_exact_match(monkeypatch):
    """Exact lookup ( e.g. ``httpdate`` ) returns the established crate's
    full metadata so the panel can see the download count, repository,
    and creation date — the data needed to clear a false typosquatting
    flag."""
    ctx = WandContext(monitored_repo="o/r")

    seen: list[str] = []

    def get_handler(url, headers, timeout):
        seen.append(url)
        assert "/api/v1/crates/httpdate" in url
        # crates.io requires a non-default UA; the wand sets one.
        assert "User-Agent" in headers
        return FakeResponse(200, json.dumps({
            "crate": {
                "name": "httpdate",
                "description": "HTTP date parsing and formatting",
                "downloads": 123_456_789,
                "recent_downloads": 5_000_000,
                "max_version": "1.0.3",
                "max_stable_version": "1.0.3",
                "created_at": "2016-04-08T00:00:00Z",
                "updated_at": "2024-09-01T00:00:00Z",
                "repository": "https://github.com/pyfisch/httpdate",
                "homepage": None,
                "documentation": "https://docs.rs/httpdate",
                "keywords": ["http", "date"],
                "categories": ["date-and-time"],
            },
            "versions": [
                {
                    "num": "1.0.3",
                    "created_at": "2024-09-01T00:00:00Z",
                    "yanked": False,
                    "downloads": 100_000,
                    "license": "MIT OR Apache-2.0",
                },
            ],
        }))

    _stub_http(monkeypatch, get_handler=get_handler)
    out = agent_tools._wand_crates_io_lookup(ctx, {"name": "httpdate"})
    assert out["found"] is True
    assert out["source"] == "crates_io"
    assert out["crate"]["downloads"] == 123_456_789
    assert out["crate"]["repository"] == "https://github.com/pyfisch/httpdate"
    assert out["recent_versions"][0]["num"] == "1.0.3"
    # Only the exact endpoint should have been hit — no fuzzy fallback.
    assert len(seen) == 1


def test_crates_io_lookup_falls_back_to_fuzzy_search_on_404(monkeypatch):
    """A genuine typosquat: the named crate does not exist, so the wand
    fans out to the search endpoint and surfaces lexically similar
    crates ( the *real* crate the typosquat is imitating )."""
    ctx = WandContext(monitored_repo="o/r")

    def get_handler(url, headers, timeout):
        if "/api/v1/crates/htttp-date" in url:
            return FakeResponse(404, "{}")
        assert "q=htttp-date" in url and "per_page=10" in url
        return FakeResponse(200, json.dumps({
            "crates": [
                {
                    "name": "http-date",
                    "downloads": 50_000,
                    "max_version": "0.5.0",
                    "created_at": "2020-01-01T00:00:00Z",
                    "repository": "https://github.com/example/http-date",
                },
                {
                    "name": "httpdate",
                    "downloads": 123_456_789,
                    "max_version": "1.0.3",
                    "created_at": "2016-04-08T00:00:00Z",
                    "repository": "https://github.com/pyfisch/httpdate",
                },
            ],
        }))

    _stub_http(monkeypatch, get_handler=get_handler)
    out = agent_tools._wand_crates_io_lookup(ctx, {"name": "htttp-date"})
    assert out["found"] is False
    assert out["source"] == "crates_io"
    assert len(out["similar"]) == 2
    assert out["similar"][1]["name"] == "httpdate"
    assert out["similar"][1]["downloads"] == 123_456_789


def test_crates_io_lookup_validates_name(monkeypatch):
    """Invalid crate names ( shell metacharacters, traversal, empty ) are
    rejected before any HTTP traffic is generated.  The stubbed http
    raises if it is called at all, so a regression that drops the
    validator would fail this test loudly."""
    ctx = WandContext(monitored_repo="o/r")
    _stub_http(monkeypatch)  # both handlers None — any call asserts
    for bad in ("", " ", "../etc", "foo bar", "name?", "a" * 100):
        with pytest.raises(WandError):
            agent_tools._wand_crates_io_lookup(ctx, {"name": bad})


def test_crates_io_lookup_requires_name():
    ctx = WandContext(monitored_repo="o/r")
    with pytest.raises(WandError):
        agent_tools._wand_crates_io_lookup(ctx, {})


def test_crates_io_lookup_wired_into_default_registry(monkeypatch):
    """The new wand is exposed through the default registry — agents
    can call it by name without any further wiring."""
    monkeypatch.delenv("AUDIT_DISABLE_WANDS", raising=False)
    reg = build_default_registry(
        monitored_repo="o/r",
        monitored_token="",
        monitored_repo_path=None,
        audited_sha=None,
    )
    assert "crates_io_lookup" in reg.wands
    assert any(
        s["function"]["name"] == "crates_io_lookup" for s in reg.schemas()
    )


# ---------------------------------------------------------------------------
# Helpers and env vars
# ---------------------------------------------------------------------------

def test_render_tool_help_lists_every_wand():
    text = render_tool_help()
    for schema in agent_tools.WAND_SCHEMAS:
        assert schema["function"]["name"] in text


def test_env_max_calls_default(monkeypatch):
    monkeypatch.delenv("AUDIT_WAND_MAX_CALLS", raising=False)
    assert env_max_calls() == DEFAULT_MAX_TOOL_CALLS_PER_TURN


def test_env_max_calls_clamps(monkeypatch):
    monkeypatch.setenv("AUDIT_WAND_MAX_CALLS", "999")
    assert env_max_calls() == 20
    monkeypatch.setenv("AUDIT_WAND_MAX_CALLS", "-3")
    assert env_max_calls() == 0
    monkeypatch.setenv("AUDIT_WAND_MAX_CALLS", "garbage")
    assert env_max_calls() == DEFAULT_MAX_TOOL_CALLS_PER_TURN


def test_wands_enabled_default_on(monkeypatch):
    monkeypatch.delenv("AUDIT_DISABLE_WANDS", raising=False)
    assert wands_enabled() is True
    monkeypatch.setenv("AUDIT_DISABLE_WANDS", "1")
    assert wands_enabled() is False


def test_build_default_registry_wires_context():
    reg = build_default_registry(
        monitored_repo="o/r",
        monitored_token="t",
        monitored_repo_path=None,
        audited_sha="abc",
        max_calls=4,
    )
    assert reg.ctx.monitored_repo == "o/r"
    assert reg.ctx.audited_sha == "abc"
    assert reg.max_calls == 4
    assert reg.ctx.has_local_checkout() is False
