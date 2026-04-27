"""Classification layer: highest-wins, rename handling, manifest fail-closed."""

import json
from pathlib import Path

from audit_commit import (
    FileChange,
    Manifest,
    ManifestRule,
    classify_files,
    load_manifest,
)


def _manifest(rules, default="medium"):
    return Manifest(
        schema_version="1",
        default_classification=default,
        rules=[ManifestRule(**r) for r in rules],
    )


def _file(path, *, previous_path=None, status="modified", patch="@@ -1 +1 @@\n-x\n+y\n"):
    return FileChange(
        path=path,
        previous_path=previous_path,
        status=status,
        additions=1,
        deletions=1,
        patch=patch,
        blob_sha="deadbeef",
    )


def test_highest_classification_wins():
    """A path matching multiple rules takes the highest classification."""
    manifest = _manifest([
        {"pattern": "**/*.md", "classification": "low", "reason": "docs"},
        {"pattern": ".agents/**", "classification": "critical", "reason": "agents"},
    ])
    classified = classify_files([_file(".agents/docs/README.md")], manifest)
    assert classified[0].classification == "critical"
    # Both rules recorded so a reviewer can see why.
    assert "agents" in classified[0].matched_rules
    assert "docs" in classified[0].matched_rules


def test_default_when_no_rule_matches():
    manifest = _manifest([
        {"pattern": ".github/workflows/**", "classification": "critical", "reason": "ci"},
    ], default="medium")
    classified = classify_files([_file("crates/foo/src/lib.rs")], manifest)
    assert classified[0].classification == "medium"
    assert classified[0].matched_rules == []


def test_rename_takes_higher_classification():
    """Renaming auth/x.rs to misc/x.rs must keep auth's high classification."""
    manifest = _manifest([
        {"pattern": "**/auth/**", "classification": "high", "reason": "auth"},
    ], default="medium")
    classified = classify_files(
        [_file("misc/x.rs", previous_path="auth/x.rs", status="renamed")],
        manifest,
    )
    assert classified[0].classification == "high"
    assert any("renamed_from:auth" in r for r in classified[0].matched_rules)


def test_rename_does_not_downgrade():
    """Renaming README.md to crates/foo/Cargo.toml takes the higher (critical)."""
    manifest = _manifest([
        {"pattern": "**/*.md", "classification": "low", "reason": "docs"},
        {"pattern": "**/Cargo.toml", "classification": "critical", "reason": "cargo"},
    ], default="medium")
    classified = classify_files(
        [_file("crates/foo/Cargo.toml", previous_path="README.md", status="renamed")],
        manifest,
    )
    assert classified[0].classification == "critical"


def test_load_manifest_fail_closed_on_missing_file(tmp_path):
    m = load_manifest(tmp_path / "does_not_exist.json")
    assert m.fail_closed
    assert m.default_classification == "critical"


def test_load_manifest_fail_closed_on_bad_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{ not json")
    m = load_manifest(p)
    assert m.fail_closed
    assert m.default_classification == "critical"


def test_load_manifest_fail_closed_on_unknown_schema(tmp_path):
    p = tmp_path / "future.json"
    p.write_text(json.dumps({"schema_version": "99", "rules": []}))
    m = load_manifest(p)
    assert m.fail_closed


def test_load_manifest_skips_malformed_rules(tmp_path):
    p = tmp_path / "manifest.json"
    p.write_text(json.dumps({
        "schema_version": "1",
        "default_classification": "low",
        "rules": [
            {"pattern": "good/**", "classification": "high", "reason": "ok"},
            {"pattern": "no_class/**"},  # missing classification
            {"pattern": "bad/**", "classification": "made_up", "reason": "nope"},
        ],
    }))
    m = load_manifest(p)
    assert not m.fail_closed
    assert len(m.rules) == 1
    assert m.rules[0].pattern == "good/**"


def test_real_manifest_loads():
    """Smoke-check: the committed production manifest must parse cleanly."""
    repo_root = Path(__file__).resolve().parents[3]
    manifest = load_manifest(repo_root / ".github/config/monitored_repo_classification.json")
    assert not manifest.fail_closed
    assert manifest.schema_version == "1"
    assert manifest.default_classification == "medium"
    assert len(manifest.rules) > 5
    # Sanity: the workflow rule must classify .github/workflows/x.yml as critical.
    classified = classify_files(
        [_file(".github/workflows/audit-commit.yml")],
        manifest,
    )
    assert classified[0].classification == "critical"
