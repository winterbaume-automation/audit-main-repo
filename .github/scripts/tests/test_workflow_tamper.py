"""Workflow-tamper detection in the reconciler.

Covers ``fetch_workflow_sha`` (HTTP layer mocked at ``_http.request``) and
the pure ``decide_workflow_action`` decision function.  The reconciler's
git/subprocess plumbing and ``main()`` orchestration are out of scope for
this focused suite.
"""

from __future__ import annotations

import json
from typing import Any

import _http
import reconcile_main


CFG: dict[str, Any] = {
    "github_token": "ghs_test_audit",
    "monitored_token": "ghs_test_monitored",
    "audit_repo": "owner/audit-repo",
    "monitored_repo": "owner/monitored",
    "monitored_branch": "main",
    "commits_per_page": 100,
}

AUDIT_PATH = reconcile_main.AUDIT_COMMIT_WORKFLOW_PATH
TRIGGER_PATH = reconcile_main.TRIGGER_AUDIT_WORKFLOW_PATH


def _resp(status_code: int, body: Any = None, *, text: str | None = None) -> _http.Response:
    if text is None:
        text = "" if body is None else json.dumps(body)
    return _http.Response(status_code=status_code, headers={}, text=text)


def _make_request(handler):
    """Wrap a handler(method, url, headers) -> Response into the
    _http.request signature."""

    def fake_request(method, url, *, headers=None, json=None, timeout=30):
        return handler(method, url, headers)

    return fake_request


# ---------------------------------------------------------------------------
# fetch_workflow_sha — happy path
# ---------------------------------------------------------------------------

def test_fetch_workflow_sha_audit_repo_returns_sha(monkeypatch):
    captured: dict[str, Any] = {}

    def handler(method, url, headers):
        captured["method"] = method
        captured["url"] = url
        captured["headers"] = headers
        assert method == "GET"
        assert f"/repos/owner/audit-repo/contents/{AUDIT_PATH}" in url
        assert headers["Authorization"] == "Bearer ghs_test_audit"
        assert headers["Accept"] == "application/vnd.github+json"
        return _resp(200, {"sha": "abc1234567890def", "type": "file"})

    monkeypatch.setattr(_http, "request", _make_request(handler))

    sha = reconcile_main.fetch_workflow_sha(CFG, CFG["audit_repo"], AUDIT_PATH)
    assert sha == "abc1234567890def"
    # Sanity: we hit GET, not POST.
    assert captured["method"] == "GET"


def test_fetch_workflow_sha_monitored_repo_uses_monitored_headers(monkeypatch):
    """When fetching from the monitored repo, the monitored-repo token (if any)
    must be used — not the audit-repo token."""
    captured: dict[str, Any] = {}

    def handler(method, url, headers):
        captured["url"] = url
        captured["headers"] = headers
        assert f"/repos/owner/monitored/contents/{TRIGGER_PATH}" in url
        # Monitored-repo headers carry the monitored token (if set) and
        # never the audit token.
        assert headers.get("Authorization") == "Bearer ghs_test_monitored"
        return _resp(200, {"sha": "deadbeefcafef00d", "type": "file"})

    monkeypatch.setattr(_http, "request", _make_request(handler))

    sha = reconcile_main.fetch_workflow_sha(
        CFG, CFG["monitored_repo"], TRIGGER_PATH
    )
    assert sha == "deadbeefcafef00d"


def test_fetch_workflow_sha_monitored_repo_public_no_auth_header(monkeypatch):
    """If MONITORED_REPO_TOKEN is empty ( public repo ), no Authorization
    header should be sent for the monitored fetch."""
    cfg = dict(CFG)
    cfg["monitored_token"] = ""

    def handler(method, url, headers):
        assert "Authorization" not in headers
        return _resp(200, {"sha": "f00d", "type": "file"})

    monkeypatch.setattr(_http, "request", _make_request(handler))

    sha = reconcile_main.fetch_workflow_sha(cfg, cfg["monitored_repo"], TRIGGER_PATH)
    assert sha == "f00d"


# ---------------------------------------------------------------------------
# fetch_workflow_sha — non-2xx responses
# ---------------------------------------------------------------------------

def test_fetch_workflow_sha_404_returns_none_no_warning(monkeypatch, capsys):
    """File doesn't exist yet ( first install path ) is not an error."""
    monkeypatch.setattr(
        _http,
        "request",
        _make_request(lambda m, u, h: _resp(404, {"message": "Not Found"})),
    )

    sha = reconcile_main.fetch_workflow_sha(
        CFG, CFG["monitored_repo"], TRIGGER_PATH
    )
    assert sha is None
    captured = capsys.readouterr()
    # 404 should be silent — no WARNING / ERROR on stderr.
    assert "WARNING" not in captured.err
    assert "ERROR" not in captured.err


def test_fetch_workflow_sha_403_returns_none_with_warning(monkeypatch, capsys):
    monkeypatch.setattr(
        _http,
        "request",
        _make_request(lambda m, u, h: _resp(403, {"message": "rate limited"})),
    )

    sha = reconcile_main.fetch_workflow_sha(CFG, CFG["audit_repo"], AUDIT_PATH)
    assert sha is None
    captured = capsys.readouterr()
    assert "WARNING" in captured.err
    assert "403" in captured.err
    assert AUDIT_PATH in captured.err


def test_fetch_workflow_sha_500_returns_none_with_warning(monkeypatch, capsys):
    monkeypatch.setattr(
        _http,
        "request",
        _make_request(lambda m, u, h: _resp(500, {"message": "server error"})),
    )

    sha = reconcile_main.fetch_workflow_sha(CFG, CFG["audit_repo"], AUDIT_PATH)
    assert sha is None
    captured = capsys.readouterr()
    assert "WARNING" in captured.err
    assert "500" in captured.err


def test_fetch_workflow_sha_network_error_returns_none_with_warning(monkeypatch, capsys):
    def handler(method, url, headers):
        raise _http.HTTPError("connection refused")

    monkeypatch.setattr(_http, "request", _make_request(handler))

    sha = reconcile_main.fetch_workflow_sha(CFG, CFG["audit_repo"], AUDIT_PATH)
    assert sha is None
    captured = capsys.readouterr()
    assert "WARNING" in captured.err
    assert "network error" in captured.err.lower()


def test_fetch_workflow_sha_missing_sha_field_returns_none_with_warning(monkeypatch, capsys):
    """Defensive: a malformed Contents response with no `sha` field must
    not crash the reconciler."""
    monkeypatch.setattr(
        _http,
        "request",
        _make_request(lambda m, u, h: _resp(200, {"type": "file"})),
    )

    sha = reconcile_main.fetch_workflow_sha(CFG, CFG["audit_repo"], AUDIT_PATH)
    assert sha is None
    captured = capsys.readouterr()
    assert "WARNING" in captured.err


def test_fetch_workflow_sha_invalid_json_returns_none_with_warning(monkeypatch, capsys):
    monkeypatch.setattr(
        _http,
        "request",
        _make_request(lambda m, u, h: _resp(200, text="<not json>")),
    )

    sha = reconcile_main.fetch_workflow_sha(CFG, CFG["audit_repo"], AUDIT_PATH)
    assert sha is None
    captured = capsys.readouterr()
    assert "WARNING" in captured.err


# ---------------------------------------------------------------------------
# decide_workflow_action — pure decision logic (step 4 cases)
# ---------------------------------------------------------------------------

def test_decide_action_both_null_is_none():
    action, _ = reconcile_main.decide_workflow_action(None, None)
    assert action == "none"


def test_decide_action_unchanged_is_none():
    action, _ = reconcile_main.decide_workflow_action("abc1234", "abc1234")
    assert action == "none"


def test_decide_action_first_observed_is_added():
    action, reason = reconcile_main.decide_workflow_action(None, "abc1234")
    assert action == "added"
    assert "abc1234"[:12] in reason


def test_decide_action_disappeared_is_removed():
    action, reason = reconcile_main.decide_workflow_action("abc1234", None)
    assert action == "removed"
    assert "abc1234"[:12] in reason


def test_decide_action_sha_changed_is_modified():
    action, reason = reconcile_main.decide_workflow_action("abc1234", "def5678")
    assert action == "modified"
    assert "abc1234"[:12] in reason
    assert "def5678"[:12] in reason


# ---------------------------------------------------------------------------
# decide_workflow_action — exhaustive truth table for the 4 cases in step 4
# ---------------------------------------------------------------------------

def test_decide_action_truth_table_matches_spec():
    """Step 4 in the brief enumerates four cases.  Pin them all down here
    so a future refactor can't silently regress the contract."""
    # Case A: prev null, curr null -> no action.
    assert reconcile_main.decide_workflow_action(None, None)[0] == "none"

    # Case B: prev null, curr non-null -> added (no issue, just a note).
    assert reconcile_main.decide_workflow_action(None, "x")[0] == "added"

    # Case C: prev non-null, curr null -> removed (file an issue).
    assert reconcile_main.decide_workflow_action("x", None)[0] == "removed"

    # Case D1: prev non-null, curr non-null, equal -> no action.
    assert reconcile_main.decide_workflow_action("x", "x")[0] == "none"

    # Case D2: prev non-null, curr non-null, differ -> modified.
    assert reconcile_main.decide_workflow_action("x", "y")[0] == "modified"
