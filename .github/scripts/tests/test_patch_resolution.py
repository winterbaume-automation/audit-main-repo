"""
Tests for the patch-resolution pass that disambiguates binary blobs from
API-omitted text patches and refetches truncated patches on critical /
high files.

The HTTP layer is mocked via monkeypatch against `audit_commit._http` —
no real network calls.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Optional

import pytest

import audit_commit
from audit_commit import (
    ClassifiedFile,
    FileChange,
    _is_binary_bytes,
    _looks_truncated,
    _resolve_patch_omissions,
    _resolve_truncated_patches_for_critical,
    _synthesise_patch_from_blob,
    detect_structural_findings,
)


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

@dataclass
class _FakeResponse:
    status_code: int
    _payload: Optional[dict] = None
    headers: dict = None  # type: ignore[assignment]
    text: str = ""

    def __post_init__(self) -> None:
        if self.headers is None:
            self.headers = {}

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self) -> dict:
        return self._payload or {}


class _FakeHTTP:
    """
    Replaces the `_http` module imported lazily inside `_fetch_blob_soft`.
    Stores a sha -> (status_code, content_bytes) map.
    """

    class HTTPError(Exception):
        pass

    def __init__(self, blobs: dict[str, tuple[int, bytes]]):
        self.blobs = blobs
        self.calls: list[str] = []

    def get(self, url, headers=None, *, timeout=30):
        self.calls.append(url)
        sha = url.rsplit("/", 1)[-1]
        if sha not in self.blobs:
            return _FakeResponse(status_code=404, text="not found")
        status, content = self.blobs[sha]
        if status != 200:
            return _FakeResponse(status_code=status, text="rate limited")
        return _FakeResponse(
            status_code=200,
            _payload={
                "sha": sha,
                "encoding": "base64",
                "content": base64.b64encode(content).decode("ascii"),
                "size": len(content),
            },
        )


@pytest.fixture
def cfg() -> dict:
    return {
        "monitored_repo": "owner/repo",
        "monitored_token": "fake-token",
    }


def _install_fake_http(monkeypatch: pytest.MonkeyPatch, fake: _FakeHTTP) -> None:
    """`_fetch_blob_soft` does `import _http as http` lazily."""
    import sys
    monkeypatch.setitem(sys.modules, "_http", fake)


# ---------------------------------------------------------------------------
# _is_binary_bytes
# ---------------------------------------------------------------------------

def test_is_binary_bytes_detects_nul():
    assert _is_binary_bytes(b"hello\x00world") is True


def test_is_binary_bytes_treats_text_as_text():
    assert _is_binary_bytes(b"hello world\nthis is plain text\n") is False


def test_is_binary_bytes_only_sniffs_first_8k():
    """A NUL after the first 8 KB does NOT trigger the binary signal."""
    blob = (b"a" * 8192) + b"\x00" + (b"b" * 100)
    assert _is_binary_bytes(blob) is False


# ---------------------------------------------------------------------------
# _looks_truncated
# ---------------------------------------------------------------------------

def test_looks_truncated_with_short_patch_is_false():
    """Small patches are never considered truncated even if expected > actual."""
    assert _looks_truncated("@@ -1 +1 @@\n+a\n", additions=10, deletions=0) is False


def test_looks_truncated_when_lines_far_below_expected():
    big_patch = "@@ -1,3000 +1,3000 @@\n" + ("+x\n" * 2950)
    # Reported additions+deletions of 10 000 vs 2 950 lines => looks truncated
    assert _looks_truncated(big_patch, additions=10_000, deletions=0) is True


def test_looks_truncated_when_lines_match_expected():
    big_patch = "@@ -1,3000 +1,3000 @@\n" + ("+x\n" * 2950)
    assert _looks_truncated(big_patch, additions=2_950, deletions=0) is False


# ---------------------------------------------------------------------------
# _synthesise_patch_from_blob
# ---------------------------------------------------------------------------

def test_synthesise_added_file_emits_plus_prefixed_lines():
    f = FileChange(
        path="docs/x.md", previous_path=None, status="added",
        additions=3, deletions=0, patch=None, blob_sha="abc",
    )
    patch = _synthesise_patch_from_blob(f, b"line one\nline two\nline three\n")
    assert "@@ -0,0 +1,3 @@" in patch
    assert "+line one" in patch
    assert "+line two" in patch
    assert "+line three" in patch


def test_synthesise_removed_file_emits_minus_prefixed_lines():
    f = FileChange(
        path="docs/old.md", previous_path=None, status="removed",
        additions=0, deletions=2, patch=None, blob_sha="abc",
    )
    patch = _synthesise_patch_from_blob(f, b"goodbye\ncruel world\n")
    assert "@@ -1,2 +0,0 @@" in patch
    assert "-goodbye" in patch
    assert "-cruel world" in patch


def test_synthesise_modified_file_emits_context_with_audit_note():
    f = FileChange(
        path="src/lib.rs", previous_path=None, status="modified",
        additions=10, deletions=10, patch=None, blob_sha="abc",
    )
    patch = _synthesise_patch_from_blob(f, b"first\nsecond\n")
    assert "audit-note: patch was omitted by API" in patch
    assert "@@ -1,2 +1,2 @@" in patch
    assert " first" in patch
    assert " second" in patch
    # No +/- markers on a context-only synthesis.
    assert "+first" not in patch
    assert "-first" not in patch


# ---------------------------------------------------------------------------
# _resolve_patch_omissions
# ---------------------------------------------------------------------------

def test_resolve_patch_none_text_blob_synthesises_patch(
    cfg: dict, monkeypatch: pytest.MonkeyPatch,
) -> None:
    f = FileChange(
        path="docs/README.md", previous_path=None, status="added",
        additions=2, deletions=0, patch=None, blob_sha="sha-text",
    )
    blob = b"line a\nline b\n"
    fake = _FakeHTTP({"sha-text": (200, blob)})
    _install_fake_http(monkeypatch, fake)

    _resolve_patch_omissions(cfg, [f])

    assert f.is_binary is False
    assert f.patch_omitted is True
    assert f.patch_synthesised is True
    assert f.patch is not None
    assert "+line a" in f.patch
    # And the structural-finding layer treats this as a non-event.
    assert detect_structural_findings([f]) == []


def test_resolve_patch_none_binary_blob_marks_binary(
    cfg: dict, monkeypatch: pytest.MonkeyPatch,
) -> None:
    f = FileChange(
        path="assets/logo.png", previous_path=None, status="added",
        additions=0, deletions=0, patch=None, blob_sha="sha-bin",
    )
    blob = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 100
    fake = _FakeHTTP({"sha-bin": (200, blob)})
    _install_fake_http(monkeypatch, fake)

    _resolve_patch_omissions(cfg, [f])

    assert f.is_binary is True
    assert f.patch is None
    assert f.patch_synthesised is False
    findings = detect_structural_findings([f])
    assert any(s.type == "binary_change" for s in findings)


def test_resolve_patch_none_rate_limited_falls_back_to_extension(
    cfg: dict, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """403 on the blob fetch => use extension heuristic."""
    png = FileChange(
        path="assets/logo.png", previous_path=None, status="added",
        additions=0, deletions=0, patch=None, blob_sha="sha-png",
    )
    md = FileChange(
        path="docs/README.md", previous_path=None, status="added",
        additions=100, deletions=0, patch=None, blob_sha="sha-md",
    )
    fake = _FakeHTTP({
        "sha-png": (403, b""),
        "sha-md": (403, b""),
    })
    _install_fake_http(monkeypatch, fake)

    _resolve_patch_omissions(cfg, [png, md])

    # .png falls through to the binary-extension table.
    assert png.is_binary is True
    assert png.patch_unavailable is False
    # .md is text-shaped — surface as text_patch_unavailable so it does
    # not silently get treated as binary.
    assert md.is_binary is False
    assert md.patch_unavailable is True
    findings = detect_structural_findings([png, md])
    assert any(s.type == "binary_change" and s.path == "assets/logo.png" for s in findings)
    assert any(
        s.type == "text_patch_unavailable" and s.path == "docs/README.md" for s in findings
    )


def test_resolve_patch_none_429_also_falls_back(
    cfg: dict, monkeypatch: pytest.MonkeyPatch,
) -> None:
    md = FileChange(
        path="docs/README.md", previous_path=None, status="added",
        additions=100, deletions=0, patch=None, blob_sha="sha-md",
    )
    fake = _FakeHTTP({"sha-md": (429, b"")})
    _install_fake_http(monkeypatch, fake)

    _resolve_patch_omissions(cfg, [md])
    assert md.patch_unavailable is True


def test_resolve_patch_none_for_removed_file_is_skipped(
    cfg: dict, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Removals legitimately have patch=None; the resolution layer must not
    issue a blob fetch for them."""
    f = FileChange(
        path="old.bin", previous_path=None, status="removed",
        additions=0, deletions=0, patch=None, blob_sha="sha-x",
    )
    fake = _FakeHTTP({})
    _install_fake_http(monkeypatch, fake)

    _resolve_patch_omissions(cfg, [f])
    assert fake.calls == []
    assert f.is_binary is False
    assert f.patch_omitted is False


# ---------------------------------------------------------------------------
# _resolve_truncated_patches_for_critical
# ---------------------------------------------------------------------------

_classified_seq = 0


def _classified(path: str, classification: str, *, patch: str, additions: int, deletions: int):
    global _classified_seq
    _classified_seq += 1
    f = FileChange(
        path=path, previous_path=None, status="modified",
        additions=additions, deletions=deletions,
        patch=patch, blob_sha=f"sha-{_classified_seq}",
    )
    return ClassifiedFile(file=f, classification=classification, matched_rules=[])


def test_truncated_critical_patch_is_refetched(
    cfg: dict, monkeypatch: pytest.MonkeyPatch,
) -> None:
    big_patch = "@@ -1,3000 +1,3000 @@\n" + ("+x\n" * 2950)
    c = _classified(
        ".github/workflows/release.yml",
        "critical",
        patch=big_patch,
        additions=10_000,
        deletions=0,
    )
    blob = b"refreshed line one\nrefreshed line two\n"
    fake = _FakeHTTP({c.file.blob_sha: (200, blob)})
    _install_fake_http(monkeypatch, fake)

    _resolve_truncated_patches_for_critical(cfg, [c])

    assert c.file.patch_synthesised is True
    assert c.file.patch is not None
    assert "refreshed line one" in c.file.patch
    assert len(fake.calls) == 1


def test_truncated_low_patch_is_NOT_refetched(
    cfg: dict, monkeypatch: pytest.MonkeyPatch,
) -> None:
    big_patch = "@@ -1,3000 +1,3000 @@\n" + ("+x\n" * 2950)
    c = _classified(
        "docs/giant.md",
        "low",
        patch=big_patch,
        additions=10_000,
        deletions=0,
    )
    fake = _FakeHTTP({c.file.blob_sha: (200, b"will not be fetched\n")})
    _install_fake_http(monkeypatch, fake)

    _resolve_truncated_patches_for_critical(cfg, [c])

    # No fetch issued; original patch left intact (per cost gate).
    assert fake.calls == []
    assert c.file.patch_synthesised is False
    assert c.file.patch == big_patch


def test_non_truncated_critical_patch_is_left_alone(
    cfg: dict, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A small patch on a critical file should NOT trigger a refetch."""
    small_patch = "@@ -1 +1 @@\n-foo\n+bar\n"
    c = _classified(
        ".github/workflows/x.yml",
        "critical",
        patch=small_patch,
        additions=1,
        deletions=1,
    )
    fake = _FakeHTTP({c.file.blob_sha: (200, b"would not be fetched\n")})
    _install_fake_http(monkeypatch, fake)

    _resolve_truncated_patches_for_critical(cfg, [c])
    assert fake.calls == []
    assert c.file.patch_synthesised is False


def test_truncated_critical_refetch_failure_marks_unavailable(
    cfg: dict, monkeypatch: pytest.MonkeyPatch,
) -> None:
    big_patch = "@@ -1,3000 +1,3000 @@\n" + ("+x\n" * 2950)
    c = _classified(
        ".github/workflows/release.yml",
        "critical",
        patch=big_patch,
        additions=10_000,
        deletions=0,
    )
    fake = _FakeHTTP({c.file.blob_sha: (403, b"")})
    _install_fake_http(monkeypatch, fake)

    _resolve_truncated_patches_for_critical(cfg, [c])
    assert c.file.patch_unavailable is True
    assert c.file.patch_omitted is True
