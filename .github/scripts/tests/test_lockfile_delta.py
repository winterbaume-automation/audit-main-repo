"""Lockfile delta detection — deterministic supply-chain pin-change findings."""

from audit_commit import (
    FileChange,
    detect_structural_findings,
)


def _file(path: str, patch: str) -> FileChange:
    return FileChange(
        path=path,
        previous_path=None,
        status="modified",
        additions=1,
        deletions=1,
        patch=patch,
        blob_sha="abc",
    )


def _delta_findings(f: FileChange):
    return [s for s in detect_structural_findings([f]) if s.type == "lockfile_delta"]


# ---------------------------------------------------------------------------
# Cargo.lock
# ---------------------------------------------------------------------------


def test_cargo_lock_version_bump_produces_one_finding():
    """A `serde` version bump should surface as one finding mentioning both
    versions."""
    patch = (
        "@@ -120,7 +120,7 @@\n"
        " [[package]]\n"
        ' name = "serde"\n'
        '-version = "1.0.197"\n'
        '+version = "1.0.198"\n'
        ' source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        ' checksum = "abc"\n'
        ' \n'
    )
    f = _file("Cargo.lock", patch)
    findings = _delta_findings(f)
    assert len(findings) == 1, [s.description for s in findings]
    desc = findings[0].description
    assert "Cargo.lock" in desc
    assert "serde" in desc
    assert "1.0.197" in desc
    assert "1.0.198" in desc


def test_cargo_lock_source_flip_to_git_produces_finding_with_url_and_rev():
    """A registry -> git flip should mention the git URL and rev."""
    patch = (
        "@@ -50,7 +50,7 @@\n"
        " [[package]]\n"
        ' name = "tokio"\n'
        ' version = "1.36.0"\n'
        '-source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        '+source = "git+https://github.com/example/fork#beefcafe1234"\n'
        ' \n'
    )
    f = _file("Cargo.lock", patch)
    findings = _delta_findings(f)
    assert len(findings) == 1, [s.description for s in findings]
    desc = findings[0].description
    assert "tokio" in desc
    assert "git+https://github.com/example/fork" in desc or "github.com/example/fork" in desc
    assert "beefcafe1234" in desc


def test_cargo_lock_in_subcrate_path_is_recognised():
    """Monorepo paths with `crates/foo/Cargo.lock` should be picked up."""
    patch = (
        "@@ -1,5 +1,5 @@\n"
        " [[package]]\n"
        ' name = "demo"\n'
        '-version = "0.1.0"\n'
        '+version = "0.2.0"\n'
        ' source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    f = _file("crates/foo/Cargo.lock", patch)
    findings = _delta_findings(f)
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# package-lock.json
# ---------------------------------------------------------------------------


def test_npm_lock_integrity_only_change_produces_finding():
    """When `integrity` changes but `version` does not, surface a pin-rotate
    finding — even though the version is identical."""
    patch = (
        "@@ -10,7 +10,7 @@\n"
        '     "node_modules/lodash": {\n'
        '       "version": "4.17.20",\n'
        '       "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",\n'
        '-      "integrity": "sha512-old=="\n'
        '+      "integrity": "sha512-new=="\n'
        "     },\n"
    )
    f = _file("package-lock.json", patch)
    findings = _delta_findings(f)
    assert len(findings) == 1, [s.description for s in findings]
    desc = findings[0].description
    assert "lodash" in desc
    assert "integrity" in desc
    assert "sha512-old==" in desc
    assert "sha512-new==" in desc


def test_npm_lock_version_and_integrity_change_produces_one_finding():
    """When both version AND integrity change, do not double-report; integrity
    is implied by version."""
    patch = (
        "@@ -10,8 +10,8 @@\n"
        '     "node_modules/lodash": {\n'
        '-      "version": "4.17.20",\n'
        '-      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",\n'
        '-      "integrity": "sha512-old=="\n'
        '+      "version": "4.17.21",\n'
        '+      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",\n'
        '+      "integrity": "sha512-new=="\n'
        "     },\n"
    )
    f = _file("package-lock.json", patch)
    findings = _delta_findings(f)
    assert len(findings) == 1, [s.description for s in findings]
    desc = findings[0].description
    assert "lodash" in desc
    assert "4.17.20" in desc
    assert "4.17.21" in desc
    # The integrity change is implied; we should NOT surface it as a separate
    # event in the same finding when the version moved.
    assert "integrity" not in desc.lower()


# ---------------------------------------------------------------------------
# pnpm-lock.yaml
# ---------------------------------------------------------------------------


def test_pnpm_lock_new_packages_entry_produces_finding():
    """A newly added `packages:` entry should produce a finding mentioning
    the tarball URL."""
    patch = (
        "@@ -100,6 +100,12 @@\n"
        " packages:\n"
        " \n"
        "+  /react@18.2.0:\n"
        "+    resolution:\n"
        "+      tarball: https://registry.npmjs.org/react/-/react-18.2.0.tgz\n"
        "+      integrity: sha512-newpkg==\n"
        "+    dev: false\n"
        "+\n"
        "   /vue@3.4.0:\n"
        "     resolution:\n"
        "       tarball: https://registry.npmjs.org/vue/-/vue-3.4.0.tgz\n"
    )
    f = _file("pnpm-lock.yaml", patch)
    findings = _delta_findings(f)
    assert len(findings) >= 1
    react = [s for s in findings if "react@18.2.0" in s.description]
    assert react, [s.description for s in findings]
    assert "tarball" in react[0].description.lower() or "registry.npmjs.org" in react[0].description


# ---------------------------------------------------------------------------
# uv.lock
# ---------------------------------------------------------------------------


def test_uv_lock_git_rev_change_produces_finding():
    """A git-rev change in uv.lock should produce a finding."""
    patch = (
        "@@ -30,7 +30,7 @@\n"
        " [[package]]\n"
        ' name = "requests"\n'
        ' version = "2.31.0"\n'
        '-source = { git = "https://github.com/psf/requests", rev = "aaaaaaa" }\n'
        '+source = { git = "https://github.com/psf/requests", rev = "bbbbbbb" }\n'
        ' \n'
    )
    f = _file("uv.lock", patch)
    findings = _delta_findings(f)
    assert len(findings) == 1, [s.description for s in findings]
    desc = findings[0].description
    assert "requests" in desc
    assert "aaaaaaa" in desc
    assert "bbbbbbb" in desc


def test_uv_lock_version_bump_produces_finding():
    patch = (
        "@@ -30,7 +30,7 @@\n"
        " [[package]]\n"
        ' name = "requests"\n'
        '-version = "2.31.0"\n'
        '+version = "2.32.0"\n'
        ' source = { registry = "https://pypi.org/simple" }\n'
    )
    f = _file("uv.lock", patch)
    findings = _delta_findings(f)
    assert len(findings) == 1
    desc = findings[0].description
    assert "requests" in desc
    assert "2.31.0" in desc
    assert "2.32.0" in desc


# ---------------------------------------------------------------------------
# poetry.lock
# ---------------------------------------------------------------------------


def test_poetry_lock_reference_change_produces_finding():
    """Poetry's `[package.source].reference` is the git rev; a change there
    with a static version is a pin-rotate."""
    patch = (
        "@@ -40,8 +40,8 @@\n"
        " [[package]]\n"
        ' name = "pydantic"\n'
        ' version = "2.5.0"\n'
        ' \n'
        " [package.source]\n"
        ' type = "git"\n'
        ' url = "https://github.com/pydantic/pydantic"\n'
        '-reference = "a1b2c3d"\n'
        '+reference = "deadbee"\n'
        " \n"
    )
    f = _file("poetry.lock", patch)
    findings = _delta_findings(f)
    assert len(findings) == 1, [s.description for s in findings]
    desc = findings[0].description
    assert "pydantic" in desc
    assert "a1b2c3d" in desc
    assert "deadbee" in desc


# ---------------------------------------------------------------------------
# Negative & fallback cases
# ---------------------------------------------------------------------------


def test_non_lockfile_path_produces_no_lockfile_delta_finding():
    """A `.rs` source file should never produce a `lockfile_delta` finding,
    no matter what its patch contains."""
    patch = (
        "@@ -1,3 +1,3 @@\n"
        ' [[package]]\n'
        '-version = "1.0.0"\n'
        '+version = "2.0.0"\n'
    )
    f = _file("src/foo.rs", patch)
    findings = _delta_findings(f)
    assert findings == []


def test_truncated_cargo_lock_diff_produces_unparseable_finding():
    """A patch with no recoverable hunks should fall back to one
    'could not be parsed deterministically' finding per file."""
    # No `@@` hunk header at all — purely malformed input.
    patch = (
        "diff --git a/Cargo.lock b/Cargo.lock\n"
        "index abc..def 100644\n"
        "--- a/Cargo.lock\n"
        "+++ b/Cargo.lock\n"
        "(diff body lost in transit)\n"
    )
    f = _file("Cargo.lock", patch)
    findings = _delta_findings(f)
    assert len(findings) == 1
    desc = findings[0].description
    assert "could not be parsed" in desc.lower()


def test_cargo_lock_hunk_with_no_named_packages_produces_unparseable_finding():
    """When the diff has hunks but they don't surface any `name = ...` line,
    we cannot identify the changed package — fall back."""
    patch = (
        "@@ -5,3 +5,3 @@\n"
        '-some_metadata = "old"\n'
        '+some_metadata = "new"\n'
        " unrelated = 1\n"
    )
    f = _file("Cargo.lock", patch)
    findings = _delta_findings(f)
    assert len(findings) == 1
    assert "could not be parsed" in findings[0].description.lower()
