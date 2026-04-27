"""Issue-filing gate logic: file when LLM, structural, routing, or skip says so."""

from audit_commit import (
    ClassifiedFile,
    FileChange,
    RoutingDecision,
    StructuralFinding,
    should_file_issue,
)


def _classified(path, classification):
    return ClassifiedFile(
        file=FileChange(
            path=path, previous_path=None, status="modified",
            additions=0, deletions=0, patch="@@\n", blob_sha=None,
        ),
        classification=classification,
        matched_rules=[],
    )


def _decision(mode, included=None, excluded=None):
    return RoutingDecision(
        mode=mode,
        reason="test",
        included=included or [],
        excluded=excluded or [],
        composed_patch="",
        total_chars=0,
    )


def test_clean_review_does_not_file_issue():
    verdict = {"suspicious": False, "severity": "none"}
    decision = _decision("whole", included=[_classified("a", "medium")])
    file_it, sev = should_file_issue(verdict, decision, [], "reviewed")
    assert not file_it
    assert sev == "none"


def test_suspicious_llm_files_issue():
    verdict = {"suspicious": True, "severity": "high"}
    decision = _decision("whole", included=[_classified("a", "medium")])
    file_it, sev = should_file_issue(verdict, decision, [], "reviewed")
    assert file_it
    assert sev == "high"


def test_structural_finding_alone_files_issue_at_medium():
    verdict = {"suspicious": False, "severity": "none"}
    decision = _decision("whole", included=[_classified("a", "medium")])
    structural = [StructuralFinding(type="binary_change", path="x.bin", description="y")]
    file_it, sev = should_file_issue(verdict, decision, structural, "reviewed")
    assert file_it
    assert sev == "medium"


def test_excluded_critical_file_files_issue_at_high():
    verdict = {"suspicious": False, "severity": "none"}
    decision = _decision(
        "focused",
        included=[_classified("a", "high")],
        excluded=[_classified("b", "critical")],
    )
    file_it, sev = should_file_issue(verdict, decision, [], "reviewed")
    assert file_it
    assert sev == "high"


def test_panel_skipped_files_issue_at_critical():
    verdict = {"suspicious": False, "severity": "none"}
    decision = _decision("panel_skipped", excluded=[_classified("a", "critical")])
    file_it, sev = should_file_issue(verdict, decision, [], "panel_skipped")
    assert file_it
    assert sev == "critical"


def test_severity_climbs_to_max_across_signals():
    """LLM low + structural (medium) + excluded high (high) => high."""
    verdict = {"suspicious": True, "severity": "low"}
    decision = _decision(
        "focused",
        included=[_classified("a", "medium")],
        excluded=[_classified("b", "critical")],
    )
    structural = [StructuralFinding(type="binary_change", path="x.bin", description="y")]
    file_it, sev = should_file_issue(verdict, decision, structural, "reviewed")
    assert file_it
    assert sev == "high"
