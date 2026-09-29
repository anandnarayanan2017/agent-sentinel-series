from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from sentinel.collector.anthropic_sdk import _AsyncMessagesSentinel
from sentinel.collector.azure_openai import _AsyncCompletionsSentinel
from sentinel.collector.parsers import parse_flow
from sentinel.collector.redaction import redact_text
from sentinel.collector.sdk_base import SentinelReporter
from sentinel.detection.engine import Engine
from sentinel.detection.policy import PolicySet
from sentinel.schema.events import ActionType


def test_redaction_removes_sensitive_json_fields_and_common_identifiers():
    raw = json.dumps(
        {
            "api_key": "sk-abcdefghijklmnopqrstuvwxyz",
            "message": "email alice@example.com IBAN LU280019400644750000",
        }
    )
    result = redact_text(raw)
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in result
    assert "alice@example.com" not in result
    assert "LU280019400644750000" not in result
    assert result.count("[REDACTED]") >= 3


def test_reporter_sends_bearer_token_and_redacts_before_transport(monkeypatch):
    captured = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"findings":0}'

    def _urlopen(req, timeout):
        captured["authorization"] = req.get_header("Authorization")
        captured["payload"] = json.loads(req.data.decode())
        return _Response()

    monkeypatch.setattr("urllib.request.urlopen", _urlopen)
    reporter = SentinelReporter("agent-1", "session-1", auth_token="token-value")
    reporter.report(host="api.openai.com", request_body='{"password":"secret"}')

    assert captured["authorization"] == "Bearer token-value"
    assert "secret" not in captured["payload"]["request_body"]


def test_model_proposal_is_tool_requested_not_executed(monkeypatch):
    captured = {}
    reporter = SentinelReporter("agent-1", "session-1")

    def _capture(**kwargs):
        captured.update(kwargs)
        return {}

    monkeypatch.setattr(reporter, "report", _capture)
    reporter.report_tool_request(host="api.openai.com", tool_name="wire_transfer", args={})
    event = parse_flow(
        agent_id="agent-1",
        session_id="session-1",
        host="api.openai.com",
        method="POST",
        path=captured["path"],
        request_body=captured["request_body"],
    )
    assert event.action == ActionType.TOOL_REQUESTED


def test_tool_policy_does_not_treat_requested_tool_as_executed(tmp_path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "agents:\n  - agent_id: agent-1\n    allowed_tools: [safe_tool]\n",
        encoding="utf-8",
    )
    engine = Engine(PolicySet.from_yaml(policy_path))
    event = parse_flow(
        agent_id="agent-1",
        session_id="session-1",
        host="api.openai.com",
        method="POST",
        path="/model/tool-requested",
        request_body=json.dumps(
            {"jsonrpc": "2.0", "method": "tools/requested", "params": {"name": "dangerous"}}
        ),
    )
    assert not [
        finding for finding in engine.evaluate(event) if finding.rule_id == "tool.not_allowed"
    ]


def test_async_azure_wrapper_exposes_awaitable_create(monkeypatch):
    class _Completions:
        async def create(self, **kwargs):
            return SimpleNamespace(
                choices=[], model_dump_json=lambda: json.dumps({"model": kwargs["model"]})
            )

    reports = []
    reporter = SentinelReporter("agent-1", "session-1")
    monkeypatch.setattr(reporter, "report", lambda **kwargs: reports.append(kwargs) or {})
    wrapper = _AsyncCompletionsSentinel(_Completions(), reporter, "azure.example")

    response = asyncio.run(wrapper.create(model="gpt-4o", messages=[]))
    assert response is not None
    assert len(reports) == 1


def test_async_anthropic_wrapper_exposes_awaitable_create(monkeypatch):
    class _Messages:
        async def create(self, **kwargs):
            return SimpleNamespace(
                content=[], model_dump_json=lambda: json.dumps({"model": kwargs["model"]})
            )

    reports = []
    reporter = SentinelReporter("agent-1", "session-1")
    monkeypatch.setattr(reporter, "report", lambda **kwargs: reports.append(kwargs) or {})
    wrapper = _AsyncMessagesSentinel(_Messages(), reporter)

    response = asyncio.run(wrapper.create(model="claude", messages=[], max_tokens=32))
    assert response is not None
    assert len(reports) == 1
