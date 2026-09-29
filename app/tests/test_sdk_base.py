"""Tests for the SDK-level reporter (`collector/sdk_base.py`).

This module was at 0% coverage despite being the front-end every SDK wrapper
(Azure OpenAI, Anthropic) reports through — and it holds a deliberate
fail-open contract plus a URL-scheme guard, both of which are exactly the kind
of behaviour that should not go unasserted (CR-24).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from sentinel.collector.sdk_base import SentinelReporter


class _FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


@pytest.fixture
def captured(monkeypatch):
    """Capture the urllib Request the reporter builds, without any network."""
    seen: dict[str, Any] = {}

    def _fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["method"] = req.method
        seen["headers"] = dict(req.headers)
        seen["body"] = json.loads(req.data.decode())
        seen["timeout"] = timeout
        return _FakeResponse({"findings": 0, "items": []})

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)
    return seen


def test_report_posts_a_flowin_shaped_payload_to_ingest(captured):
    reporter = SentinelReporter(agent_id="recon-bot", session_id="s1")
    result = reporter.report(host="api.anthropic.com", request_body='{"model":"x"}')

    assert result == {"findings": 0, "items": []}
    assert captured["url"] == "http://localhost:8000/ingest"
    assert captured["method"] == "POST"
    assert captured["body"]["agent_id"] == "recon-bot"
    assert captured["body"]["session_id"] == "s1"
    assert captured["body"]["host"] == "api.anthropic.com"
    assert captured["timeout"] == 2  # never block the agent it protects


def test_report_strips_a_trailing_slash_from_the_configured_api(captured):
    SentinelReporter("a", "s", sentinel_api="http://sentinel.internal:9000/").report(host="h")
    assert captured["url"] == "http://sentinel.internal:9000/ingest"


def test_report_is_fail_open_when_sentinel_is_unreachable(monkeypatch):
    """A Sentinel outage must never take down the agent it is monitoring."""

    def _boom(req, timeout=None):
        raise OSError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", _boom)
    assert SentinelReporter("a", "s").report(host="h") == {}


def test_report_is_fail_open_on_an_unparseable_response(monkeypatch):
    class _Garbage:
        def read(self):
            return b"not json at all"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=None: _Garbage())
    assert SentinelReporter("a", "s").report(host="h") == {}


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x/y", "localhost:8000", ""])
def test_report_refuses_non_http_schemes(url, monkeypatch):
    """The scheme guard must hold even though it is reached through the same
    broad `except Exception` that implements fail-open — so assert the network
    was never touched, not merely that the result was empty."""
    called = False

    def _tripwire(req, timeout=None):
        nonlocal called
        called = True
        raise AssertionError("urlopen must not be reached for a non-http(s) URL")

    monkeypatch.setattr("urllib.request.urlopen", _tripwire)
    assert SentinelReporter("a", "s", sentinel_api=url).report(host="h") == {}
    assert not called


def test_report_tool_call_emits_a_json_rpc_body_the_mcp_parser_understands(captured):
    SentinelReporter("kyc-agent", "s2").report_tool_call(
        host="kyc.internal", tool_name="check_sanctions", args={"customer": "c-1"}
    )
    body = json.loads(captured["body"]["request_body"])
    assert body["jsonrpc"] == "2.0"
    assert body["method"] == "tools/call"
    assert body["params"]["name"] == "check_sanctions"
    assert body["params"]["arguments"] == {"customer": "c-1"}
    assert captured["body"]["path"] == "/mcp/tools/call"


def test_report_tool_call_parses_string_arguments(captured):
    SentinelReporter("a", "s").report_tool_call(host="h", tool_name="t", args='{"k": "v"}')
    body = json.loads(captured["body"]["request_body"])
    assert body["params"]["arguments"] == {"k": "v"}


def test_report_tool_call_keeps_unparseable_arguments_as_raw(captured):
    """Evidence must survive even when the arguments are not valid JSON."""
    SentinelReporter("a", "s").report_tool_call(host="h", tool_name="t", args="not json")
    body = json.loads(captured["body"]["request_body"])
    assert body["params"]["arguments"] == {"raw": "not json"}


def test_reported_tool_call_round_trips_through_the_real_parser():
    """The contract that matters: what this reporter emits must normalize into
    a TOOL_CALL event, not degrade to a generic NETWORK_CALL."""
    from sentinel.collector.parsers import parse_flow
    from sentinel.schema.events import ActionType

    captured_body: dict[str, Any] = {}

    reporter = SentinelReporter("kyc-agent", "s3")
    reporter.report = lambda **kw: captured_body.update(kw) or {}  # type: ignore[method-assign]
    reporter.report_tool_call(host="kyc.internal", tool_name="check_sanctions", args={"c": 1})

    event = parse_flow(
        agent_id="kyc-agent",
        session_id="s3",
        host=captured_body["host"],
        method=captured_body["method"],
        path=captured_body["path"],
        request_body=captured_body["request_body"],
    )
    assert event.action == ActionType.TOOL_CALL
    assert event.tool_name == "check_sanctions"
