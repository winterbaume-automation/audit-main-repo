"""Multi-round agent discussion: loop count, convergence early-stop, env parsing.

The model layer (`_call_model`) is monkeypatched with a deterministic stub so
no network calls are made; the stub returns scripted responses keyed by
(round, agent label) so each test can exercise a precise scenario.
"""

from __future__ import annotations

from typing import Any

import audit_commit
from audit_commit import AGENTS, _round_converged, run_agent_discussion


SPECIALIST_NAMES = [a["name"] for a in AGENTS]
PER_ROUND_CALLS = len(AGENTS)


def _stub_model(monkeypatch, scripted: list[dict]):
    """Replace ``_call_model`` with a stub that returns the next scripted
    response and records every call.

    Each scripted entry is the response dict to return.  Calls beyond the
    scripted length raise so a misconfigured test fails loudly instead of
    looping forever.
    """
    calls: list[dict[str, Any]] = []

    def fake_call_model(system_prompt, user_content, github_token, label, **kwargs):
        if len(calls) >= len(scripted):
            raise AssertionError(
                f"unexpected extra call #{len(calls) + 1} (label={label!r})"
            )
        calls.append({"label": label, "user_content": user_content, "kwargs": kwargs})
        return scripted[len(calls) - 1]

    monkeypatch.setattr(audit_commit, "_call_model", fake_call_model)
    return calls


CLEAN_RESPONSE = {"concerns": [], "verdict": "clean", "confidence": "high",
                  "reasoning": "nothing suspicious"}
SUSPICIOUS_RESPONSE = {
    "concerns": [{"type": "logic_bomb", "file": "x", "line": 1,
                  "description": "d", "evidence": "e"}],
    "verdict": "suspicious",
    "confidence": "medium",
    "reasoning": "saw a thing",
}
MOD_VERDICT = {"suspicious": False, "severity": "none", "summary": "ok",
               "findings": []}


# ---------------------------------------------------------------------------
# Loop count
# ---------------------------------------------------------------------------

def test_default_max_rounds_runs_one_pass(monkeypatch):
    """``max_rounds=1`` (the default) preserves the historical single-pass
    behaviour: 3 specialist calls + 1 moderator = 4 calls total."""
    scripted = [CLEAN_RESPONSE] * PER_ROUND_CALLS + [MOD_VERDICT]
    calls = _stub_model(monkeypatch, scripted)

    verdict, discussion = run_agent_discussion("ctx", "tok")

    assert len(calls) == PER_ROUND_CALLS + 1
    assert verdict == MOD_VERDICT
    # Specialist turns + moderator turn.
    assert len(discussion) == PER_ROUND_CALLS + 1
    assert [t["agent"] for t in discussion[:PER_ROUND_CALLS]] == SPECIALIST_NAMES
    assert discussion[-1]["agent"] == "Moderator"
    # Every specialist turn carries a round tag.
    assert all(t["round"] == 1 for t in discussion[:PER_ROUND_CALLS])


def test_two_rounds_when_concerns_persist(monkeypatch):
    """When agents keep raising concerns the discussion runs the full
    ``max_rounds`` passes before the moderator synthesises."""
    rounds = 2
    scripted = [SUSPICIOUS_RESPONSE] * (PER_ROUND_CALLS * rounds) + [MOD_VERDICT]
    calls = _stub_model(monkeypatch, scripted)

    verdict, discussion = run_agent_discussion("ctx", "tok", max_rounds=rounds)

    assert len(calls) == PER_ROUND_CALLS * rounds + 1
    # Specialist labels include round tags only when max_rounds > 1.
    specialist_labels = [c["label"] for c in calls[:-1]]
    assert specialist_labels[0].endswith(" r1")
    assert specialist_labels[PER_ROUND_CALLS].endswith(" r2")
    # Discussion entries carry the right round numbers.
    rounds_seen = [t["round"] for t in discussion if t["agent"] != "Moderator"]
    assert rounds_seen == [1] * PER_ROUND_CALLS + [2] * PER_ROUND_CALLS
    assert verdict == MOD_VERDICT


def test_round_two_sees_round_one_transcript(monkeypatch):
    """Every agent on rounds >= 2 — including the first specialist — must
    receive the full transcript so it can refine prior findings."""
    scripted = [SUSPICIOUS_RESPONSE] * (PER_ROUND_CALLS * 2) + [MOD_VERDICT]
    calls = _stub_model(monkeypatch, scripted)

    run_agent_discussion("ctx", "tok", max_rounds=2)

    # The first call of round 2 is at index PER_ROUND_CALLS (after round 1's
    # specialists).
    round2_first_call = calls[PER_ROUND_CALLS]
    assert "Discussion so far" in round2_first_call["user_content"]
    # Round-1 evidence must be visible.
    assert "logic_bomb" in round2_first_call["user_content"]
    assert "round 2 of up to 2" in round2_first_call["user_content"]


# ---------------------------------------------------------------------------
# Convergence early-stop
# ---------------------------------------------------------------------------

def test_round_converges_when_clean_and_unanimous():
    round_turns = [
        {"agent": name, "round": 1, "response": CLEAN_RESPONSE}
        for name in SPECIALIST_NAMES
    ]
    assert _round_converged(round_turns) is True


def test_round_does_not_converge_when_concerns_remain():
    round_turns = [
        {"agent": SPECIALIST_NAMES[0], "round": 1, "response": SUSPICIOUS_RESPONSE},
        {"agent": SPECIALIST_NAMES[1], "round": 1, "response": CLEAN_RESPONSE},
        {"agent": SPECIALIST_NAMES[2], "round": 1, "response": CLEAN_RESPONSE},
    ]
    assert _round_converged(round_turns) is False


def test_round_does_not_converge_when_verdicts_disagree():
    disagreeing = {**CLEAN_RESPONSE, "verdict": "suspicious"}
    round_turns = [
        {"agent": SPECIALIST_NAMES[0], "round": 1, "response": CLEAN_RESPONSE},
        {"agent": SPECIALIST_NAMES[1], "round": 1, "response": disagreeing},
        {"agent": SPECIALIST_NAMES[2], "round": 1, "response": CLEAN_RESPONSE},
    ]
    assert _round_converged(round_turns) is False


def test_discussion_short_circuits_on_convergence(monkeypatch):
    """When round 1 ends with no concerns and unanimous verdicts the loop
    must skip the remaining rounds and jump straight to the moderator."""
    # Round 1: 3 clean specialists.  Then moderator.  No round 2 calls.
    scripted = [CLEAN_RESPONSE] * PER_ROUND_CALLS + [MOD_VERDICT]
    calls = _stub_model(monkeypatch, scripted)

    verdict, discussion = run_agent_discussion("ctx", "tok", max_rounds=3)

    assert len(calls) == PER_ROUND_CALLS + 1
    assert calls[-1]["label"] == "Moderator"
    assert verdict == MOD_VERDICT
    rounds_seen = {t["round"] for t in discussion if t["agent"] != "Moderator"}
    assert rounds_seen == {1}


def test_clamps_below_one_to_one(monkeypatch):
    """A pathological ``max_rounds=0`` is clamped to 1 so the panel still
    runs."""
    scripted = [CLEAN_RESPONSE] * PER_ROUND_CALLS + [MOD_VERDICT]
    calls = _stub_model(monkeypatch, scripted)

    run_agent_discussion("ctx", "tok", max_rounds=0)

    assert len(calls) == PER_ROUND_CALLS + 1


# ---------------------------------------------------------------------------
# Env-var helper
# ---------------------------------------------------------------------------

def test_max_rounds_default(monkeypatch):
    monkeypatch.delenv("AUDIT_MAX_ROUNDS", raising=False)
    assert audit_commit._max_rounds() == 1


def test_max_rounds_parses_int(monkeypatch):
    monkeypatch.setenv("AUDIT_MAX_ROUNDS", "4")
    assert audit_commit._max_rounds() == 4


def test_max_rounds_clamps_below_one(monkeypatch):
    monkeypatch.setenv("AUDIT_MAX_ROUNDS", "0")
    assert audit_commit._max_rounds() == 1
    monkeypatch.setenv("AUDIT_MAX_ROUNDS", "-3")
    assert audit_commit._max_rounds() == 1


def test_max_rounds_falls_back_on_garbage(monkeypatch):
    monkeypatch.setenv("AUDIT_MAX_ROUNDS", "two")
    assert audit_commit._max_rounds() == 1


def test_max_rounds_handles_whitespace(monkeypatch):
    monkeypatch.setenv("AUDIT_MAX_ROUNDS", "  3  ")
    assert audit_commit._max_rounds() == 3
