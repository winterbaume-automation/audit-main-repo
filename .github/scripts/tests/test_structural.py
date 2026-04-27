"""Deterministic structural findings — these bypass the LLM."""

from audit_commit import (
    FileChange,
    detect_structural_findings,
)


def test_binary_addition_produces_finding():
    f = FileChange(
        path="tests/fixtures/blob.bin",
        previous_path=None,
        status="added",
        additions=0,
        deletions=0,
        patch=None,
        blob_sha="cafe1234",
    )
    findings = detect_structural_findings([f])
    assert len(findings) == 1
    assert findings[0].type == "binary_change"
    assert findings[0].path == "tests/fixtures/blob.bin"
    assert "cafe1234" in findings[0].description


def test_binary_modification_produces_finding():
    f = FileChange(
        path="assets/icon.png",
        previous_path=None,
        status="modified",
        additions=0,
        deletions=0,
        patch=None,
        blob_sha="abc",
    )
    findings = detect_structural_findings([f])
    assert any(s.type == "binary_change" for s in findings)


def test_removed_binary_does_not_produce_finding():
    """Removals legitimately have patch=None; do not count as suspicious binary."""
    f = FileChange(
        path="old.bin",
        previous_path=None,
        status="removed",
        additions=0,
        deletions=0,
        patch=None,
        blob_sha="abc",
    )
    findings = detect_structural_findings([f])
    assert findings == []


def test_submodule_pointer_change_produces_finding():
    patch = (
        "@@ -1 +1 @@\n"
        "-Subproject commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "+Subproject commit bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
    )
    f = FileChange(
        path="vendor/dep",
        previous_path=None,
        status="modified",
        additions=1,
        deletions=1,
        patch=patch,
        blob_sha="abc",
    )
    findings = detect_structural_findings([f])
    assert any(s.type == "submodule_pointer" for s in findings)


def test_generated_header_removal_produces_finding():
    patch = (
        "@@ -1,3 +1,2 @@\n"
        "-//! Do not edit manually. Regenerate with: smithy-codegen.\n"
        " use crate::wire;\n"
        " pub fn x() {}\n"
    )
    f = FileChange(
        path="crates/foo/src/wire.rs",
        previous_path=None,
        status="modified",
        additions=0,
        deletions=1,
        patch=patch,
        blob_sha="abc",
    )
    findings = detect_structural_findings([f])
    assert any(s.type == "generated_header_removed" for s in findings)


def test_generated_header_replacement_does_not_produce_finding():
    """If the header is removed AND re-added (e.g. wording tweak), do not flag."""
    patch = (
        "@@ -1,3 +1,3 @@\n"
        "-//! Do not edit manually. Old wording.\n"
        "+//! Do not edit manually. New wording.\n"
        " use crate::wire;\n"
    )
    f = FileChange(
        path="crates/foo/src/wire.rs",
        previous_path=None,
        status="modified",
        additions=1,
        deletions=1,
        patch=patch,
        blob_sha="abc",
    )
    findings = detect_structural_findings([f])
    assert not any(s.type == "generated_header_removed" for s in findings)


def test_clean_text_change_produces_no_findings():
    patch = "@@ -1 +1 @@\n-foo\n+bar\n"
    f = FileChange(
        path="src/lib.rs",
        previous_path=None,
        status="modified",
        additions=1,
        deletions=1,
        patch=patch,
        blob_sha="abc",
    )
    assert detect_structural_findings([f]) == []
