"""Preflight skip when an audit log already exists for the commit SHA.

Covers the public surface of ``audit_already_exists`` and the
``AUDIT_FORCE_RERUN`` bypass via ``_force_rerun_requested``.  The HTTP layer
is mocked at the ``_http`` module level so no real network calls are made.
"""

from __future__ import annotations

import json
from typing import Any

import _http
import audit_commit


SHA = "abc123"
OTHER_SHA = "def456"

CFG = {
    "github_token": "ghs_test",
    "commit_sha": SHA,
    "audit_repo": "owner/audit-repo",
    "monitored_repo": "owner/monitored",
}


def _resp(status_code: int, body: Any = None, *, text: str | None = None) -> _http.Response:
    if text is None:
        text = "" if body is None else json.dumps(body)
    return _http.Response(status_code=status_code, headers={}, text=text)


def _make_get(handler):
    """Wrap a handler(url) -> Response into the _http.get(url, headers, *, timeout) signature."""

    def fake_get(url, headers=None, *, timeout=30):
        return handler(url)

    return fake_get


# ---------------------------------------------------------------------------
# Tree API hits
# ---------------------------------------------------------------------------

def test_tree_contains_target_sha_returns_true(monkeypatch):
    payload = {
        "tree": [
            {"path": "logs", "type": "tree"},
            {"path": "logs/2026-04-26", "type": "tree"},
            {"path": f"logs/2026-04-26/{SHA}.json", "type": "blob"},
        ],
        "truncated": False,
    }

    def handler(url):
        assert "git/trees/audit-log" in url
        assert "recursive=1" in url
        return _resp(200, payload)

    monkeypatch.setattr(_http, "get", _make_get(handler))

    assert audit_commit.audit_already_exists(CFG) is True


def test_tree_contains_other_sha_returns_false(monkeypatch):
    payload = {
        "tree": [
            {"path": f"logs/2026-04-26/{OTHER_SHA}.json", "type": "blob"},
        ],
        "truncated": False,
    }

    monkeypatch.setattr(_http, "get", _make_get(lambda url: _resp(200, payload)))

    assert audit_commit.audit_already_exists(CFG) is False


def test_tree_404_returns_false(monkeypatch):
    """branch doesn't exist yet (first-run case) is not an error."""
    monkeypatch.setattr(_http, "get", _make_get(lambda url: _resp(404, {"message": "Not Found"})))

    assert audit_commit.audit_already_exists(CFG) is False


def test_tree_403_returns_false_with_warning(monkeypatch, capsys):
    monkeypatch.setattr(_http, "get", _make_get(lambda url: _resp(403, {"message": "rate"})))

    assert audit_commit.audit_already_exists(CFG) is False
    captured = capsys.readouterr()
    assert "WARNING" in captured.err
    assert "403" in captured.err


def test_tree_empty_returns_false(monkeypatch):
    monkeypatch.setattr(
        _http,
        "get",
        _make_get(lambda url: _resp(200, {"tree": [], "truncated": False})),
    )

    assert audit_commit.audit_already_exists(CFG) is False


def test_tree_network_error_returns_false_with_warning(monkeypatch, capsys):
    def handler(url):
        raise _http.HTTPError("connection refused")

    monkeypatch.setattr(_http, "get", _make_get(handler))

    assert audit_commit.audit_already_exists(CFG) is False
    captured = capsys.readouterr()
    assert "WARNING" in captured.err
    assert "network error" in captured.err.lower()


# ---------------------------------------------------------------------------
# Truncated tree -> contents API fallback
# ---------------------------------------------------------------------------

def test_truncated_tree_falls_back_to_contents_and_finds_sha(monkeypatch):
    """When the tree is truncated, walk per-date directories via contents API."""
    truncated_tree = {"tree": [], "truncated": True}
    date_listing = [
        {"path": "logs/2026-04-25", "name": "2026-04-25", "type": "dir"},
        {"path": "logs/2026-04-26", "name": "2026-04-26", "type": "dir"},
    ]
    files_in_25 = [
        {"name": f"{OTHER_SHA}.json", "type": "file"},
    ]
    files_in_26 = [
        {"name": f"{SHA}.json", "type": "file"},
    ]

    def handler(url):
        if "git/trees/audit-log" in url:
            return _resp(200, truncated_tree)
        if url.endswith("/contents/logs?ref=audit-log"):
            return _resp(200, date_listing)
        if "/contents/logs/2026-04-25" in url:
            return _resp(200, files_in_25)
        if "/contents/logs/2026-04-26" in url:
            return _resp(200, files_in_26)
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(_http, "get", _make_get(handler))

    assert audit_commit.audit_already_exists(CFG) is True


def test_truncated_tree_fallback_misses_returns_false(monkeypatch):
    truncated_tree = {"tree": [], "truncated": True}
    date_listing = [
        {"path": "logs/2026-04-25", "name": "2026-04-25", "type": "dir"},
    ]
    files_in_25 = [
        {"name": f"{OTHER_SHA}.json", "type": "file"},
    ]

    def handler(url):
        if "git/trees/audit-log" in url:
            return _resp(200, truncated_tree)
        if url.endswith("/contents/logs?ref=audit-log"):
            return _resp(200, date_listing)
        if "/contents/logs/2026-04-25" in url:
            return _resp(200, files_in_25)
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(_http, "get", _make_get(handler))

    assert audit_commit.audit_already_exists(CFG) is False


# ---------------------------------------------------------------------------
# Force re-run bypass
# ---------------------------------------------------------------------------

def test_force_rerun_env_var_recognised(monkeypatch):
    monkeypatch.setenv("AUDIT_FORCE_RERUN", "1")
    assert audit_commit._force_rerun_requested() is True

    monkeypatch.setenv("AUDIT_FORCE_RERUN", "true")
    assert audit_commit._force_rerun_requested() is True

    monkeypatch.setenv("AUDIT_FORCE_RERUN", "TRUE")
    assert audit_commit._force_rerun_requested() is True

    monkeypatch.setenv("AUDIT_FORCE_RERUN", "0")
    assert audit_commit._force_rerun_requested() is False

    monkeypatch.setenv("AUDIT_FORCE_RERUN", "")
    assert audit_commit._force_rerun_requested() is False

    monkeypatch.delenv("AUDIT_FORCE_RERUN", raising=False)
    assert audit_commit._force_rerun_requested() is False


def test_force_rerun_does_not_short_circuit_audit_already_exists(monkeypatch):
    """audit_already_exists itself is independent of the env var; the
    AUDIT_FORCE_RERUN gate lives in main().  Even with the env var set,
    audit_already_exists returns True when a matching log is present — it is
    main()'s job to decide whether to honour the True answer."""
    payload = {
        "tree": [
            {"path": f"logs/2026-04-26/{SHA}.json", "type": "blob"},
        ],
        "truncated": False,
    }
    monkeypatch.setattr(_http, "get", _make_get(lambda url: _resp(200, payload)))
    monkeypatch.setenv("AUDIT_FORCE_RERUN", "1")

    assert audit_commit.audit_already_exists(CFG) is True
    assert audit_commit._force_rerun_requested() is True
