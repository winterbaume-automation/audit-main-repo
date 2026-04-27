"""File-mode flip and symlink-target change detection (WU-5).

Both attack vectors are stored in the Git tree (mode field), not the file
contents, so they are invisible in the unified-diff `patch`.  These tests
exercise ``_detect_mode_changes`` in isolation by mocking the ``_http``
layer — no real network calls.

Mocking pattern mirrors ``test_preflight.py`` and ``test_patch_resolution.py``.
"""

from __future__ import annotations

import json
from typing import Any, Callable

import _http
import audit_commit
from audit_commit import (
    ClassifiedFile,
    CommitData,
    FileChange,
)


CFG = {
    "github_token": "ghs_test",
    "monitored_token": "ghs_test_mon",
    "commit_sha": "newsha",
    "audit_repo": "owner/audit-repo",
    "monitored_repo": "owner/mon",
}

NEW_SHA = "newsha"
PARENT_SHA = "parentsha"


def _resp(status_code: int, body: Any = None, *, text: str | None = None) -> _http.Response:
    if text is None:
        text = "" if body is None else json.dumps(body)
    return _http.Response(status_code=status_code, headers={}, text=text)


def _make_get(handler: Callable[[str], _http.Response]):
    def fake_get(url, headers=None, *, timeout=30):
        return handler(url)

    return fake_get


def _file(path: str, status: str, *, previous_path: str | None = None) -> FileChange:
    return FileChange(
        path=path,
        previous_path=previous_path,
        status=status,
        additions=1,
        deletions=0,
        patch="@@ stub @@",
        blob_sha="blob_" + path,
    )


def _classify(files: list[FileChange]) -> list[ClassifiedFile]:
    return [
        ClassifiedFile(file=f, classification="medium", matched_rules=[])
        for f in files
    ]


def _commit(
    sha: str = NEW_SHA,
    parents: list[str] | None = None,
    files: list[FileChange] | None = None,
) -> CommitData:
    return CommitData(
        sha=sha,
        parents=parents if parents is not None else [PARENT_SHA],
        files=files or [],
        truncated=False,
        is_merge=False,
    )


def _tree_payload(entries: list[dict], truncated: bool = False) -> dict:
    return {"sha": "tree_sha", "tree": entries, "truncated": truncated}


# ---------------------------------------------------------------------------
# Gate helper
# ---------------------------------------------------------------------------

def test_mode_changes_enabled_recognises_truthy_values(monkeypatch):
    monkeypatch.setenv("AUDIT_DETECT_MODE_CHANGES", "1")
    assert audit_commit._mode_changes_enabled() is True

    monkeypatch.setenv("AUDIT_DETECT_MODE_CHANGES", "true")
    assert audit_commit._mode_changes_enabled() is True

    monkeypatch.setenv("AUDIT_DETECT_MODE_CHANGES", "TRUE")
    assert audit_commit._mode_changes_enabled() is True


def test_mode_changes_disabled_when_unset(monkeypatch):
    monkeypatch.delenv("AUDIT_DETECT_MODE_CHANGES", raising=False)
    assert audit_commit._mode_changes_enabled() is False


def test_mode_changes_disabled_when_falsy(monkeypatch):
    monkeypatch.setenv("AUDIT_DETECT_MODE_CHANGES", "0")
    assert audit_commit._mode_changes_enabled() is False

    monkeypatch.setenv("AUDIT_DETECT_MODE_CHANGES", "")
    assert audit_commit._mode_changes_enabled() is False

    monkeypatch.setenv("AUDIT_DETECT_MODE_CHANGES", "no")
    assert audit_commit._mode_changes_enabled() is False


# ---------------------------------------------------------------------------
# Mode-flip detection
# ---------------------------------------------------------------------------

def test_mode_flip_to_executable_emits_finding(monkeypatch):
    """Path bin/run.sh flipped 100644 -> 100755 and is in commit.files."""
    new_tree = _tree_payload([
        {"path": "bin/run.sh", "type": "blob", "mode": "100755", "sha": "n1"},
        {"path": "README.md", "type": "blob", "mode": "100644", "sha": "n2"},
    ])
    parent_tree = _tree_payload([
        {"path": "bin/run.sh", "type": "blob", "mode": "100644", "sha": "p1"},
        {"path": "README.md", "type": "blob", "mode": "100644", "sha": "p2"},
    ])

    def handler(url):
        if f"git/trees/{NEW_SHA}" in url:
            return _resp(200, new_tree)
        if f"git/trees/{PARENT_SHA}" in url:
            return _resp(200, parent_tree)
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(_http, "get", _make_get(handler))

    files = [_file("bin/run.sh", "modified")]
    findings = audit_commit._detect_mode_changes(CFG, _commit(files=files), _classify(files))
    assert len(findings) == 1
    assert findings[0].type == "mode_flip_executable"
    assert findings[0].path == "bin/run.sh"
    assert "100644" in findings[0].description
    assert "100755" in findings[0].description


def test_mode_unchanged_no_finding(monkeypatch):
    """bin/run.sh is 100755 in both trees -> no finding."""
    new_tree = _tree_payload([
        {"path": "bin/run.sh", "type": "blob", "mode": "100755", "sha": "n1"},
    ])
    parent_tree = _tree_payload([
        {"path": "bin/run.sh", "type": "blob", "mode": "100755", "sha": "p1"},
    ])

    def handler(url):
        if f"git/trees/{NEW_SHA}" in url:
            return _resp(200, new_tree)
        if f"git/trees/{PARENT_SHA}" in url:
            return _resp(200, parent_tree)
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(_http, "get", _make_get(handler))

    files = [_file("bin/run.sh", "modified")]
    findings = audit_commit._detect_mode_changes(CFG, _commit(files=files), _classify(files))
    assert findings == []


def test_mode_flip_to_non_executable_emits_finding(monkeypatch):
    new_tree = _tree_payload([
        {"path": "scripts/lib.sh", "type": "blob", "mode": "100644", "sha": "n1"},
    ])
    parent_tree = _tree_payload([
        {"path": "scripts/lib.sh", "type": "blob", "mode": "100755", "sha": "p1"},
    ])

    def handler(url):
        if f"git/trees/{NEW_SHA}" in url:
            return _resp(200, new_tree)
        if f"git/trees/{PARENT_SHA}" in url:
            return _resp(200, parent_tree)
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(_http, "get", _make_get(handler))

    files = [_file("scripts/lib.sh", "modified")]
    findings = audit_commit._detect_mode_changes(CFG, _commit(files=files), _classify(files))
    assert len(findings) == 1
    assert findings[0].type == "mode_flip_non_executable"
    assert findings[0].path == "scripts/lib.sh"


def test_mode_change_for_untouched_file_ignored(monkeypatch):
    """A tree entry that flipped modes but isn't in commit.files -> no finding."""
    new_tree = _tree_payload([
        {"path": "untouched.sh", "type": "blob", "mode": "100755", "sha": "n1"},
        {"path": "actually_modified.txt", "type": "blob", "mode": "100644", "sha": "n2"},
    ])
    parent_tree = _tree_payload([
        {"path": "untouched.sh", "type": "blob", "mode": "100644", "sha": "p1"},
        {"path": "actually_modified.txt", "type": "blob", "mode": "100644", "sha": "p2"},
    ])

    def handler(url):
        if f"git/trees/{NEW_SHA}" in url:
            return _resp(200, new_tree)
        if f"git/trees/{PARENT_SHA}" in url:
            return _resp(200, parent_tree)
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(_http, "get", _make_get(handler))

    # Only actually_modified.txt is in commit.files; untouched.sh is not.
    files = [_file("actually_modified.txt", "modified")]
    findings = audit_commit._detect_mode_changes(CFG, _commit(files=files), _classify(files))
    assert findings == []


# ---------------------------------------------------------------------------
# Symlink detection
# ---------------------------------------------------------------------------

def test_symlink_target_changed_emits_finding(monkeypatch):
    new_tree = _tree_payload([
        {"path": "links/lib.so", "type": "blob", "mode": "120000", "sha": "n1"},
    ])
    parent_tree = _tree_payload([
        {"path": "links/lib.so", "type": "blob", "mode": "120000", "sha": "p1"},
    ])

    def handler(url):
        if f"git/trees/{NEW_SHA}" in url:
            return _resp(200, new_tree)
        if f"git/trees/{PARENT_SHA}" in url:
            return _resp(200, parent_tree)
        # Contents API for the symlink target.
        if "/contents/links/lib.so" in url and f"ref={NEW_SHA}" in url:
            return _resp(200, {"type": "symlink", "target": "/usr/lib/libnew.so"})
        if "/contents/links/lib.so" in url and f"ref={PARENT_SHA}" in url:
            return _resp(200, {"type": "symlink", "target": "/usr/lib/libold.so"})
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(_http, "get", _make_get(handler))

    files = [_file("links/lib.so", "modified")]
    findings = audit_commit._detect_mode_changes(CFG, _commit(files=files), _classify(files))
    assert len(findings) == 1
    assert findings[0].type == "symlink_target_changed"
    assert findings[0].path == "links/lib.so"
    assert "/usr/lib/libold.so" in findings[0].description
    assert "/usr/lib/libnew.so" in findings[0].description


def test_new_symlink_added_emits_finding(monkeypatch):
    """120000 entry only in new tree, status=added -> symlink_added finding."""
    new_tree = _tree_payload([
        {"path": "etc/shortcut", "type": "blob", "mode": "120000", "sha": "n1"},
    ])
    parent_tree = _tree_payload([])

    def handler(url):
        if f"git/trees/{NEW_SHA}" in url:
            return _resp(200, new_tree)
        if f"git/trees/{PARENT_SHA}" in url:
            return _resp(200, parent_tree)
        if "/contents/etc/shortcut" in url and f"ref={NEW_SHA}" in url:
            return _resp(200, {"type": "symlink", "target": "/etc/passwd"})
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(_http, "get", _make_get(handler))

    files = [_file("etc/shortcut", "added")]
    findings = audit_commit._detect_mode_changes(CFG, _commit(files=files), _classify(files))
    assert len(findings) == 1
    assert findings[0].type == "symlink_added"
    assert findings[0].path == "etc/shortcut"
    assert "/etc/passwd" in findings[0].description


def test_added_regular_file_does_not_emit_symlink_finding(monkeypatch):
    """A new normal file (mode 100644) should not be a symlink_added finding."""
    new_tree = _tree_payload([
        {"path": "newfile.txt", "type": "blob", "mode": "100644", "sha": "n1"},
    ])
    parent_tree = _tree_payload([])

    def handler(url):
        if f"git/trees/{NEW_SHA}" in url:
            return _resp(200, new_tree)
        if f"git/trees/{PARENT_SHA}" in url:
            return _resp(200, parent_tree)
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(_http, "get", _make_get(handler))

    files = [_file("newfile.txt", "added")]
    findings = audit_commit._detect_mode_changes(CFG, _commit(files=files), _classify(files))
    assert findings == []


def test_symlink_with_same_target_no_finding(monkeypatch):
    new_tree = _tree_payload([
        {"path": "links/lib.so", "type": "blob", "mode": "120000", "sha": "n1"},
    ])
    parent_tree = _tree_payload([
        {"path": "links/lib.so", "type": "blob", "mode": "120000", "sha": "p1"},
    ])

    def handler(url):
        if f"git/trees/{NEW_SHA}" in url:
            return _resp(200, new_tree)
        if f"git/trees/{PARENT_SHA}" in url:
            return _resp(200, parent_tree)
        if "/contents/links/lib.so" in url:
            return _resp(200, {"type": "symlink", "target": "/usr/lib/libsame.so"})
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(_http, "get", _make_get(handler))

    files = [_file("links/lib.so", "modified")]
    findings = audit_commit._detect_mode_changes(CFG, _commit(files=files), _classify(files))
    assert findings == []


# ---------------------------------------------------------------------------
# Errors and truncation
# ---------------------------------------------------------------------------

def test_tree_403_emits_mode_check_unavailable(monkeypatch):
    def handler(url):
        return _resp(403, {"message": "rate limited"})

    monkeypatch.setattr(_http, "get", _make_get(handler))

    files = [_file("anything", "modified")]
    findings = audit_commit._detect_mode_changes(CFG, _commit(files=files), _classify(files))
    assert len(findings) == 1
    assert findings[0].type == "mode_check_unavailable"


def test_tree_network_error_emits_mode_check_unavailable(monkeypatch):
    def handler(url):
        raise _http.HTTPError("connection refused")

    monkeypatch.setattr(_http, "get", _make_get(handler))

    files = [_file("anything", "modified")]
    findings = audit_commit._detect_mode_changes(CFG, _commit(files=files), _classify(files))
    assert len(findings) == 1
    assert findings[0].type == "mode_check_unavailable"


def test_truncated_tree_falls_back_to_contents_api_for_symlink_target(monkeypatch):
    """When tree is truncated, symlink-target detection still works via Contents API.

    Mode-flip detection silently drops for the truncated paths, but
    mode_check_unavailable surfaces to flag the limitation.
    """
    # Both trees claim truncated=True and don't list the file at all.
    new_tree = _tree_payload([], truncated=True)
    parent_tree = _tree_payload([], truncated=True)

    def handler(url):
        if f"git/trees/{NEW_SHA}" in url:
            return _resp(200, new_tree)
        if f"git/trees/{PARENT_SHA}" in url:
            return _resp(200, parent_tree)
        if "/contents/links/lib.so" in url and f"ref={NEW_SHA}" in url:
            return _resp(200, {"type": "symlink", "target": "/usr/lib/libnew.so"})
        if "/contents/links/lib.so" in url and f"ref={PARENT_SHA}" in url:
            return _resp(200, {"type": "symlink", "target": "/usr/lib/libold.so"})
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(_http, "get", _make_get(handler))

    files = [_file("links/lib.so", "modified")]
    findings = audit_commit._detect_mode_changes(CFG, _commit(files=files), _classify(files))

    types = [f.type for f in findings]
    assert "symlink_target_changed" in types
    assert "mode_check_unavailable" in types


def test_initial_commit_no_parent_no_findings(monkeypatch):
    """Commit with no parents is the root commit; nothing to diff against."""

    def handler(url):
        raise AssertionError("no API calls expected for root commit")

    monkeypatch.setattr(_http, "get", _make_get(handler))

    files = [_file("foo.txt", "added")]
    findings = audit_commit._detect_mode_changes(
        CFG, _commit(parents=[], files=files), _classify(files)
    )
    assert findings == []


def test_renamed_file_uses_previous_path_on_parent_side(monkeypatch):
    """A rename: previous_path on parent side, new path on new side."""
    new_tree = _tree_payload([
        {"path": "bin/run.sh", "type": "blob", "mode": "100755", "sha": "n1"},
    ])
    parent_tree = _tree_payload([
        {"path": "scripts/run.sh", "type": "blob", "mode": "100644", "sha": "p1"},
    ])

    def handler(url):
        if f"git/trees/{NEW_SHA}" in url:
            return _resp(200, new_tree)
        if f"git/trees/{PARENT_SHA}" in url:
            return _resp(200, parent_tree)
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(_http, "get", _make_get(handler))

    files = [_file("bin/run.sh", "renamed", previous_path="scripts/run.sh")]
    findings = audit_commit._detect_mode_changes(CFG, _commit(files=files), _classify(files))
    assert len(findings) == 1
    assert findings[0].type == "mode_flip_executable"
    assert findings[0].path == "bin/run.sh"
