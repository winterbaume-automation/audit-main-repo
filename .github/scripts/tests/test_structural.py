"""Deterministic structural findings — these bypass the LLM."""

from audit_commit import (
    FileChange,
    detect_structural_findings,
)


def test_binary_addition_produces_finding():
    """A genuine binary file (resolution layer set is_binary=True) flags."""
    f = FileChange(
        path="tests/fixtures/blob.bin",
        previous_path=None,
        status="added",
        additions=0,
        deletions=0,
        patch=None,
        blob_sha="cafe1234",
        is_binary=True,
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
        is_binary=True,
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


def test_text_file_with_synthesised_patch_produces_no_binary_finding():
    """
    The pre-fix bug: a text file whose patch was omitted by the API was
    reported as `binary_change`.  Under the new model, the resolution
    layer fetches the blob, finds no NUL bytes, synthesises a patch, and
    leaves `is_binary=False`.  Therefore no `binary_change` finding fires.
    """
    f = FileChange(
        path="docs/README.md",
        previous_path=None,
        status="added",
        additions=1500,
        deletions=0,
        patch="@@ -0,0 +1,1500 @@\n" + "\n".join(f"+line {i}" for i in range(1500)),
        blob_sha="abc",
        is_binary=False,
        patch_omitted=True,
        patch_synthesised=True,
    )
    findings = detect_structural_findings([f])
    assert findings == []


def test_text_patch_unavailable_produces_finding():
    """
    Blob fetch failed (rate-limited) on a text-shaped path: surface a
    `text_patch_unavailable` finding so the audit cannot silently miss
    the file.
    """
    f = FileChange(
        path="docs/README.md",
        previous_path=None,
        status="added",
        additions=1500,
        deletions=0,
        patch=None,
        blob_sha="abc",
        is_binary=False,
        patch_omitted=True,
        patch_unavailable=True,
    )
    findings = detect_structural_findings([f])
    assert any(s.type == "text_patch_unavailable" for s in findings)
    assert not any(s.type == "binary_change" for s in findings)


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


# ---------------------------------------------------------------------------
# Unicode-risk / Trojan-source pre-scan
# ---------------------------------------------------------------------------


def test_unicode_risk_bidi_control_added_produces_finding():
    """U+202E (RLO) appearing on a `+` line is the classic Trojan Source
    payload from CVE-2021-42574 / Boucher & Anderson 2021."""
    patch = (
        "@@ -1,2 +1,3 @@\n"
        " unchanged\n"
        '+let access_level = "user\u202e \u2066// Check if admin\u2069 \u2066";\n'
        " trailing\n"
    )
    f = FileChange(
        path="src/lib.rs",
        previous_path=None,
        status="modified",
        additions=1,
        deletions=0,
        patch=patch,
        blob_sha="abc",
    )
    findings = detect_structural_findings([f])
    risk = [s for s in findings if s.type == "unicode_risk"]
    assert len(risk) == 1
    assert "U+202E" in risk[0].description


def test_unicode_risk_bidi_control_removed_produces_no_finding():
    """A bidi control on the `-` side that vanishes on the `+` side is the
    attack being *removed* — not a finding."""
    patch = (
        "@@ -1,2 +1,2 @@\n"
        '-let access_level = "user\u202e \u2066admin\u2069";\n'
        '+let access_level = "user";\n'
    )
    f = FileChange(
        path="src/lib.rs",
        previous_path=None,
        status="modified",
        additions=1,
        deletions=1,
        patch=patch,
        blob_sha="abc",
    )
    findings = detect_structural_findings([f])
    assert not any(s.type == "unicode_risk" for s in findings)


def test_unicode_risk_zero_width_in_identifier_produces_finding():
    """A zero-width space hidden inside an identifier is a homoglyph attack
    — `admi​n` looks the same as `admin` but is a different symbol."""
    patch = (
        "@@ -0,0 +1,2 @@\n"
        "+def admi\u200bn():\n"
        "+    pass\n"
    )
    f = FileChange(
        path="src/lib.py",
        previous_path=None,
        status="added",
        additions=2,
        deletions=0,
        patch=patch,
        blob_sha="abc",
    )
    findings = detect_structural_findings([f])
    risk = [s for s in findings if s.type == "unicode_risk"]
    assert len(risk) == 1
    assert "zero-width" in risk[0].description.lower()
    assert "U+200B" in risk[0].description


def test_unicode_risk_mixed_script_identifier_produces_finding():
    """`аdmin` with a Cyrillic `а` (U+0430) is the classic homoglyph attack."""
    patch = (
        "@@ -0,0 +1,1 @@\n"
        "+def \u0430dmin():  # Cyrillic a\n"
    )
    f = FileChange(
        path="src/lib.py",
        previous_path=None,
        status="added",
        additions=1,
        deletions=0,
        patch=patch,
        blob_sha="abc",
    )
    findings = detect_structural_findings([f])
    risk = [s for s in findings if s.type == "unicode_risk"]
    assert len(risk) == 1
    assert "mixed-script" in risk[0].description.lower()
    assert "Cyrillic" in risk[0].description
    assert "Latin" in risk[0].description


def test_unicode_risk_clean_ascii_patch_produces_no_finding():
    patch = (
        "@@ -1,2 +1,2 @@\n"
        "-def admin():\n"
        "+def admin_user():\n"
    )
    f = FileChange(
        path="src/lib.py",
        previous_path=None,
        status="modified",
        additions=1,
        deletions=1,
        patch=patch,
        blob_sha="abc",
    )
    findings = detect_structural_findings([f])
    assert not any(s.type == "unicode_risk" for s in findings)


def test_unicode_risk_bom_at_start_of_new_file_produces_no_finding():
    """A UTF-8 BOM as the very first character of a freshly-added file is
    legitimate file framing, not a Trojan-source attack."""
    patch = (
        "diff --git a/src/lib.py b/src/lib.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/src/lib.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+\ufeff# encoding helper\n"
        "+x = 1\n"
    )
    f = FileChange(
        path="src/lib.py",
        previous_path=None,
        status="added",
        additions=2,
        deletions=0,
        patch=patch,
        blob_sha="abc",
    )
    findings = detect_structural_findings([f])
    assert not any(s.type == "unicode_risk" for s in findings)


def test_unicode_risk_bom_in_middle_of_existing_file_produces_finding():
    """A BOM appearing anywhere other than the start of a brand-new file is
    suspicious — usually a smuggling vector, not file framing."""
    patch = (
        "@@ -1,3 +1,4 @@\n"
        " import os\n"
        " import sys\n"
        "+def \ufeffhandler():\n"
        "     pass\n"
    )
    f = FileChange(
        path="src/lib.py",
        previous_path=None,
        status="modified",
        additions=1,
        deletions=0,
        patch=patch,
        blob_sha="abc",
    )
    findings = detect_structural_findings([f])
    risk = [s for s in findings if s.type == "unicode_risk"]
    assert len(risk) == 1
    assert "U+FEFF" in risk[0].description
