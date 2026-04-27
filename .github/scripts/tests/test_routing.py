"""Routing layer: never silently exclude critical/high files."""

from audit_commit import (
    ClassifiedFile,
    FileChange,
    route_diff,
)


def _classified(path, classification, *, patch_size=100, matched_rules=None):
    patch = "@@ -1 +1 @@\n" + ("a" * patch_size)
    f = FileChange(
        path=path,
        previous_path=None,
        status="modified",
        additions=1,
        deletions=1,
        patch=patch,
        blob_sha="abc",
    )
    return ClassifiedFile(
        file=f,
        classification=classification,
        matched_rules=matched_rules or [],
    )


def test_whole_mode_when_below_threshold():
    files = [
        _classified("a.rs", "medium", patch_size=100),
        _classified("b.rs", "low", patch_size=100),
    ]
    decision = route_diff(files, threshold=10_000)
    assert decision.mode == "whole"
    assert len(decision.included) == 2
    assert decision.excluded == []


def test_focused_mode_excludes_low_classification():
    files = [
        _classified(".github/workflows/x.yml", "critical", patch_size=200),
        _classified("crates/foo/src/auth/lib.rs", "high", patch_size=200),
        _classified("crates/foo/src/wire.rs", "low", patch_size=2_000),
        _classified("docs/x.md", "low", patch_size=2_000),
    ]
    decision = route_diff(files, threshold=1_000)
    assert decision.mode == "focused"
    included_paths = {c.file.path for c in decision.included}
    assert ".github/workflows/x.yml" in included_paths
    assert "crates/foo/src/auth/lib.rs" in included_paths
    excluded_paths = {c.file.path for c in decision.excluded}
    assert "crates/foo/src/wire.rs" in excluded_paths
    assert "docs/x.md" in excluded_paths


def test_focused_overflow_when_high_subset_too_big():
    files = [
        _classified(".github/workflows/x.yml", "critical", patch_size=300),
        _classified("crates/foo/src/auth/lib.rs", "high", patch_size=2_000),
        _classified("docs/x.md", "low", patch_size=100),
    ]
    decision = route_diff(files, threshold=1_000)
    assert decision.mode == "focused-overflow"
    included_paths = {c.file.path for c in decision.included}
    assert ".github/workflows/x.yml" in included_paths
    assert "crates/foo/src/auth/lib.rs" not in included_paths
    excluded_paths = {c.file.path for c in decision.excluded}
    assert "crates/foo/src/auth/lib.rs" in excluded_paths


def test_panel_skipped_when_critical_only_too_big():
    files = [
        _classified(".github/workflows/x.yml", "critical", patch_size=10_000),
        _classified("docs/x.md", "low", patch_size=100),
    ]
    decision = route_diff(files, threshold=1_000)
    assert decision.mode == "panel_skipped"
    assert decision.included == []
    assert len(decision.excluded) == 2


def test_critical_or_high_never_silently_excluded_by_routing():
    """
    Sanity: across the focused / focused-overflow modes, every critical or
    high file that ends up excluded must be reflected in the excluded list
    so an issue can be raised.
    """
    files = [
        _classified("c1", "critical", patch_size=300),
        _classified("c2", "critical", patch_size=300),
        _classified("h1", "high", patch_size=600),
        _classified("l1", "low", patch_size=10_000),
    ]
    decision = route_diff(files, threshold=1_000)
    # critical-only ~624 chars fits the budget; high subset exceeds it.
    assert decision.mode == "focused-overflow"
    # h1 was excluded because the high subset would exceed threshold.
    excluded_classes = {c.classification for c in decision.excluded}
    assert "high" in excluded_classes


def test_cross_reference_pulls_in_low_referenced_by_high():
    """High file `mod helper;` triggers inclusion of helper.rs even if low."""
    high_patch = (
        "@@ -1,3 +1,4 @@\n"
        " // existing\n"
        "+mod helper;\n"
        " other\n"
    )
    high = ClassifiedFile(
        file=FileChange(
            path="crates/foo/src/auth/lib.rs",
            previous_path=None,
            status="modified",
            additions=1,
            deletions=0,
            patch=high_patch,
            blob_sha="x",
        ),
        classification="high",
        matched_rules=["auth"],
    )
    helper = _classified("crates/foo/src/auth/helper.rs", "low", patch_size=100)
    big_low = _classified("docs/x.md", "low", patch_size=10_000)

    decision = route_diff([high, helper, big_low], threshold=500)
    assert decision.mode == "focused"
    included_paths = {c.file.path for c in decision.included}
    assert "crates/foo/src/auth/lib.rs" in included_paths
    assert "crates/foo/src/auth/helper.rs" in included_paths, (
        "cross-reference inclusion should pull helper.rs back in"
    )
    assert "docs/x.md" not in included_paths
