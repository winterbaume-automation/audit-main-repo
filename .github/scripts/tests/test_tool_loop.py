"""Tool-calling loop tests for ``_call_model``.

The HTTP layer is monkeypatched with a queue of canned chat-completion
responses; the registry is replaced with a stub so we can observe the
arguments dispatched and the tool results that flow back into the
conversation.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

import audit_commit
from agent_tools import WandContext, WandRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, body: dict, status_code: int = 200):
        self._body = body
        self.status_code = status_code
        self.text = json.dumps(body)
        self.headers = {}

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self) -> dict:
        return self._body


def _stub_completion_queue(monkeypatch, responses: list[dict]):
    """Replace `_http.post` with a queue that yields canned completions."""
    import _http as real_http

    queue = list(responses)
    posts: list[dict] = []

    class StubHttp:
        HTTPError = real_http.HTTPError

        @staticmethod
        def post(url, headers=None, json=None, timeout=30):
            posts.append({"url": url, "payload": json})
            if not queue:
                raise AssertionError("ran out of canned completions")
            return FakeResponse(queue.pop(0))

        @staticmethod
        def get(url, headers=None, timeout=30):
            raise AssertionError("unexpected GET")

    import sys

    monkeypatch.setitem(sys.modules, "_http", StubHttp)
    return posts


def _completion(content=None, tool_calls=None):
    msg: dict[str, Any] = {}
    if content is not None:
        msg["content"] = content
    else:
        msg["content"] = None
    if tool_calls is not None:
        msg["tool_calls"] = tool_calls
    return {"choices": [{"message": msg}]}


def _build_registry(handler):
    """A registry with a single ``demo`` wand that delegates to ``handler``."""
    return WandRegistry(
        ctx=WandContext(monitored_repo="o/r"),
        wands={"demo": handler},
        max_calls=5,
    )


# ---------------------------------------------------------------------------
# No registry -> historical single-call shape
# ---------------------------------------------------------------------------

def test_call_model_without_registry_uses_response_format(monkeypatch):
    posts = _stub_completion_queue(
        monkeypatch,
        [_completion(content=json.dumps({"verdict": "clean", "concerns": []}))],
    )
    out = audit_commit._call_model("sys", "user", "tok", "L1")
    assert out == {"verdict": "clean", "concerns": []}
    assert len(posts) == 1
    payload = posts[0]["payload"]
    assert payload["response_format"] == {"type": "json_object"}
    assert "tools" not in payload


# ---------------------------------------------------------------------------
# Registry: tool call gets dispatched, result flows back, final JSON returned
# ---------------------------------------------------------------------------

def test_call_model_dispatches_tool_call_and_returns_final_json(monkeypatch):
    seen_args: list[dict] = []

    def demo(ctx, args):
        seen_args.append(args)
        return {"hello": args.get("who")}

    registry = _build_registry(demo)

    tool_calls = [{
        "id": "tc_1",
        "type": "function",
        "function": {"name": "demo", "arguments": json.dumps({"who": "world"})},
    }]
    final = json.dumps({"verdict": "clean", "concerns": []})
    posts = _stub_completion_queue(
        monkeypatch,
        [
            _completion(tool_calls=tool_calls),
            _completion(content=final),
        ],
    )

    out = audit_commit._call_model(
        "sys", "user", "tok", "L1", registry=registry
    )
    assert out == {"verdict": "clean", "concerns": []}
    assert seen_args == [{"who": "world"}]

    # First request advertises tools; second request inherits the
    # tool result message in the conversation.
    assert "tools" in posts[0]["payload"]
    second_msgs = posts[1]["payload"]["messages"]
    roles = [m["role"] for m in second_msgs]
    assert "tool" in roles
    tool_msg = next(m for m in second_msgs if m["role"] == "tool")
    assert json.loads(tool_msg["content"]) == {"hello": "world"}
    # System prompt has been augmented with the tool-help section.
    sys_msg = second_msgs[0]
    assert sys_msg["role"] == "system"
    assert "Available tools" in sys_msg["content"]


# ---------------------------------------------------------------------------
# Registry: multiple sequential tool calls
# ---------------------------------------------------------------------------

def test_call_model_loops_on_repeated_tool_calls(monkeypatch):
    calls: list[str] = []

    def demo(ctx, args):
        calls.append(args.get("step"))
        return {"step": args.get("step")}

    registry = _build_registry(demo)
    tc = lambda i: [{
        "id": f"tc_{i}",
        "type": "function",
        "function": {"name": "demo", "arguments": json.dumps({"step": i})},
    }]
    final = json.dumps({"verdict": "clean"})
    posts = _stub_completion_queue(
        monkeypatch,
        [
            _completion(tool_calls=tc(1)),
            _completion(tool_calls=tc(2)),
            _completion(content=final),
        ],
    )
    out = audit_commit._call_model("sys", "user", "tok", "L", registry=registry)
    assert out == {"verdict": "clean"}
    assert calls == [1, 2]
    assert len(posts) == 3


# ---------------------------------------------------------------------------
# Registry: per-turn budget caps tool calls; loop forces final answer
# ---------------------------------------------------------------------------

def test_call_model_forces_final_answer_when_budget_exhausted(monkeypatch):
    """When the registry's budget runs out, the dispatch returns a
    structured ``tool_budget_exhausted`` error.  The model can still
    keep asking for tools, but eventually the loop's hard cap kicks in:
    the next request omits ``tools`` and forces ``response_format``,
    so the model must produce JSON.
    """
    def demo(ctx, args):
        return {"ok": True}

    registry = WandRegistry(
        ctx=WandContext(monitored_repo="o/r"),
        wands={"demo": demo},
        max_calls=1,
    )

    tc = lambda i: [{
        "id": f"tc_{i}",
        "type": "function",
        "function": {"name": "demo", "arguments": "{}"},
    }]
    # 8 tool-calling responses ( hard cap is 8 ) then we force final.
    canned = [_completion(tool_calls=tc(i)) for i in range(audit_commit._TOOL_LOOP_HARD_CAP)]
    canned.append(_completion(content=json.dumps({"verdict": "clean"})))

    posts = _stub_completion_queue(monkeypatch, canned)

    out = audit_commit._call_model("sys", "user", "tok", "L", registry=registry)
    assert out == {"verdict": "clean"}
    # Final ( forcing ) request omits tools and sets response_format.
    final_payload = posts[-1]["payload"]
    assert "tools" not in final_payload
    assert final_payload["response_format"] == {"type": "json_object"}


# ---------------------------------------------------------------------------
# Registry: malformed tool-call arguments do not crash the loop
# ---------------------------------------------------------------------------

def test_call_model_recovers_from_bad_tool_arguments(monkeypatch):
    def demo(ctx, args):
        raise AssertionError("should not be called")

    registry = _build_registry(demo)
    bad = [{
        "id": "tc_bad",
        "type": "function",
        "function": {"name": "demo", "arguments": "this-isnt-json"},
    }]
    final = json.dumps({"verdict": "clean"})
    _stub_completion_queue(
        monkeypatch,
        [
            _completion(tool_calls=bad),
            _completion(content=final),
        ],
    )
    out = audit_commit._call_model("sys", "user", "tok", "L", registry=registry)
    assert out == {"verdict": "clean"}


# ---------------------------------------------------------------------------
# Registry: unknown tool name returns structured error to model
# ---------------------------------------------------------------------------

def test_call_model_passes_unknown_tool_back_to_model(monkeypatch):
    registry = _build_registry(lambda *_: {"unused": True})
    tc = [{
        "id": "tc_x",
        "type": "function",
        "function": {"name": "missing", "arguments": "{}"},
    }]
    final = json.dumps({"verdict": "clean"})
    posts = _stub_completion_queue(
        monkeypatch,
        [
            _completion(tool_calls=tc),
            _completion(content=final),
        ],
    )
    audit_commit._call_model("sys", "user", "tok", "L", registry=registry)
    second_msgs = posts[1]["payload"]["messages"]
    tool_msg = next(m for m in second_msgs if m["role"] == "tool")
    assert json.loads(tool_msg["content"])["error"] == "unknown_tool"


# ---------------------------------------------------------------------------
# run_agent_discussion threads the registry through specialist calls
# ---------------------------------------------------------------------------

def test_run_agent_discussion_passes_registry_to_specialists(monkeypatch):
    """Specialists get the registry; the moderator does not."""
    seen_kwargs: list[dict] = []

    def fake_call(system, user, token, label, *, registry=None):
        seen_kwargs.append({"label": label, "registry": registry})
        return {"verdict": "clean", "concerns": [], "confidence": "high",
                "reasoning": "ok"}

    monkeypatch.setattr(audit_commit, "_call_model", fake_call)
    registry = _build_registry(lambda c, a: {"ok": True})

    audit_commit.run_agent_discussion(
        "ctx", "tok", max_rounds=1, registry=registry
    )

    # Three specialist calls + one moderator call.
    assert len(seen_kwargs) == 4
    for k in seen_kwargs[:3]:
        assert k["registry"] is registry
    assert seen_kwargs[3]["label"] == "Moderator"
    assert seen_kwargs[3]["registry"] is None
