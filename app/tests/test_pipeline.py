"""Test suite for the Agent Sentinel core pipeline."""

import json
from pathlib import Path

import pytest

from sentinel.collector.parsers import parse_flow
from sentinel.detection.engine import Engine
from sentinel.detection.policy import PolicySet
from sentinel.pipeline import Pipeline
from sentinel.schema.events import ActionType, Severity

POLICY = str(Path(__file__).resolve().parents[1].parent / "policies" / "example.yaml")


# ---- parsers ---------------------------------------------------------------
def test_parse_llm_call():
    e = parse_flow(
        agent_id="a",
        session_id="s",
        host="api.anthropic.com",
        method="POST",
        path="/v1/messages",
        request_body=json.dumps(
            {"model": "claude-sonnet-4-6", "messages": [{"role": "user", "content": "hi"}]}
        ),
    )
    assert e.action == ActionType.LLM_CALL
    assert e.model == "claude-sonnet-4-6"
    assert e.attributes["provider"] == "anthropic"
    assert any(ev.key == "prompt_preview" and ev.redacted for ev in e.evidence)


def test_parse_mcp_tool_call():
    e = parse_flow(
        agent_id="a",
        session_id="s",
        host="ledger.internal",
        method="POST",
        path="/rpc",
        request_body=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_ledger", "arguments": {}},
            }
        ),
    )
    assert e.action == ActionType.TOOL_CALL
    assert e.tool_name == "read_ledger"


def test_parse_generic_network_call():
    e = parse_flow(
        agent_id="a",
        session_id="s",
        host="evil.example",
        method="POST",
        path="/x",
        request_body="data",
    )
    assert e.action == ActionType.NETWORK_CALL
    assert e.host == "evil.example"


def test_parser_survives_malformed_body():
    e = parse_flow(
        agent_id="a",
        session_id="s",
        host="api.anthropic.com",
        method="POST",
        path="/v1/messages",
        request_body=b"\xff\xfenot json",
    )
    assert e.action == ActionType.LLM_CALL  # still classified by host
    assert e.model is None


# ---- detection: deterministic policy --------------------------------------
@pytest.fixture
def engine():
    return Engine(PolicySet.from_yaml(POLICY))


def _event(engine, **kw):
    return parse_flow(agent_id="recon-bot", session_id="s", **kw)


def test_allowed_host_no_finding(engine):
    e = _event(engine, host="ledger.internal", method="GET", path="/t")
    assert engine.evaluate(e) == []


def test_disallowed_host_flagged(engine):
    e = _event(engine, host="attacker-exfil.example", method="POST", path="/c", request_body="x")
    findings = engine.evaluate(e)
    assert any(f.rule_id == "net.host_not_allowed" for f in findings)
    assert findings[0].severity == Severity.HIGH
    assert findings[0].control_refs  # compliance mapping flows through


def test_disallowed_tool_flagged(engine):
    e = _event(
        engine,
        host="ledger.internal",
        method="POST",
        path="/rpc",
        request_body=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "dump_all_accounts"},
            }
        ),
    )
    findings = engine.evaluate(e)
    assert any(f.rule_id == "tool.not_allowed" for f in findings)


def test_unapproved_model_flagged(engine):
    e = _event(
        engine,
        host="api.anthropic.com",
        method="POST",
        path="/v1/messages",
        request_body=json.dumps({"model": "rogue-model", "messages": []}),
    )
    findings = engine.evaluate(e)
    assert any(f.rule_id == "model.not_allowed" for f in findings)


def test_oversize_payload_flagged(engine):
    e = _event(engine, host="ledger.internal", method="POST", path="/x", request_body="X" * 200000)
    findings = engine.evaluate(e)
    assert any(f.rule_id == "net.oversize_egress" for f in findings)


# ---- explainability --------------------------------------------------------
def test_findings_are_explainable(engine):
    e = _event(engine, host="attacker-exfil.example", method="POST", path="/c", request_body="x")
    f = engine.evaluate(e)[0]
    assert f.explanation
    assert f.severity_rationale
    assert f.policy_clause is not None
    assert len(f.evidence) >= 3  # agent, session, action at minimum


# ---- full pipeline + storage ----------------------------------------------
def test_pipeline_persists_events_and_findings():
    pipe = Pipeline(POLICY, ":memory:")
    pipe.ingest_flow(
        agent_id="recon-bot",
        session_id="s",
        host="attacker-exfil.example",
        method="POST",
        path="/c",
        request_body="x",
    )
    assert len(pipe.store.events_for_agent("recon-bot")) == 1
    assert len(pipe.store.list_findings()) >= 1
