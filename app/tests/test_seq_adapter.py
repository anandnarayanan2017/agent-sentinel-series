"""Unit tests for `sentinel.detection.seq_adapter` — the single AgentEvent ->
sequence-event adapter, role resolution, and severity mapping.

Traces to spec/SPEC.md (FR-6, FR-7, FR-10, A-1, A-2), spec/ACCEPTANCE.md
(AC-6, AC-7), spec/UAT.md (UAT-6, UAT-7), and design/DESIGN.md (§3.1 "the
single adapter", §3.2 "role resolution", mini-ADR-6 "missing name").

`seq_adapter.py` is documented as deliberately free of any `sentinel_sequence`/
`numpy` import so it is testable in a minimal environment (NFR-3) — this file
imports nothing beyond `sentinel.schema.events` and `sentinel.detection.seq_adapter`,
matching that contract. Tests are written against the CONTRACT stated in
ACCEPTANCE.md/DESIGN.md's derivation table (A-2) and role-resolution precedence
(A-1), not against whatever the adapter happens to compute internally.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from sentinel.detection.seq_adapter import (
    is_valid_role,
    map_severity,
    resolve_role,
    to_seq_event,
)
from sentinel.schema.events import ActionType, AgentEvent, Severity

_TS = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _event(**kw) -> AgentEvent:
    kw.setdefault("agent_id", "recon-bot")
    kw.setdefault("session_id", "s1")
    kw.setdefault("ts", _TS)
    kw.setdefault("action", ActionType.TOOL_CALL)
    return AgentEvent(**kw)


# =============================================================================
# AC-6 / FR-6 / UAT-6 — the single adapter's locked derivation table (A-2)
# =============================================================================


def test_ac6_tool_call_maps_to_tool_kind_and_tool_name():
    e = _event(action=ActionType.TOOL_CALL, tool_name="x")
    out = to_seq_event(e)
    assert out["kind"] == "tool"
    assert out["name"] == "x"


def test_ac6_llm_call_maps_to_llm_kind_and_model():
    e = _event(action=ActionType.LLM_CALL, model="claude-sonnet-4-6")
    out = to_seq_event(e)
    assert out["kind"] == "llm"
    assert out["name"] == "claude-sonnet-4-6"


def test_ac6_network_call_maps_to_net_kind_and_host():
    e = _event(action=ActionType.NETWORK_CALL, host="evil.example")
    out = to_seq_event(e)
    assert out["kind"] == "net"
    assert out["name"] == "evil.example"


def test_ac6_data_access_maps_to_data_kind_and_host():
    e = _event(action=ActionType.DATA_ACCESS, host="ledger.internal")
    out = to_seq_event(e)
    assert out["kind"] == "data"
    assert out["name"] == "ledger.internal"


def test_ac6_data_access_falls_back_to_attributes_source_when_no_host():
    e = _event(action=ActionType.DATA_ACCESS, host=None, attributes={"source": "s3://bucket/x"})
    out = to_seq_event(e)
    assert out["kind"] == "data"
    assert out["name"] == "s3://bucket/x"


def test_ac6_identity_and_ts_ride_along():
    e = _event(agent_id="a1", session_id="s9", action=ActionType.TOOL_CALL, tool_name="x", ts=_TS)
    out = to_seq_event(e)
    assert out["agent_id"] == "a1"
    assert out["session_id"] == "s9"
    assert out["ts"] == _TS.timestamp()


# mini-ADR-6: a missing/falsy name collapses to the literal "unknown", never
# `str(None)`, so `event_to_token` is deterministic and never sees "none".
def test_missing_name_collapses_to_literal_unknown_not_str_none():
    e = _event(action=ActionType.LLM_CALL, model=None)
    out = to_seq_event(e)
    assert out["name"] == "unknown"
    assert out["name"] != str(None)


def test_missing_tool_name_collapses_to_unknown():
    e = _event(action=ActionType.TOOL_CALL, tool_name=None)
    out = to_seq_event(e)
    assert out["name"] == "unknown"


# =============================================================================
# AC-7 / FR-7 / UAT-7 — role resolution precedence + validation (A-1)
# =============================================================================


def test_ac7_no_override_resolves_to_agent_id():
    e = _event(agent_id="recon-bot")
    assert resolve_role(e, role_map=None) == "recon-bot"


def test_ac7_attributes_role_takes_precedence_over_role_map():
    e = _event(agent_id="recon-bot", attributes={"role": "kyc"})
    assert resolve_role(e, role_map={"recon-bot": "other-role"}) == "kyc"


def test_ac7_role_map_used_when_no_attributes_role():
    e = _event(agent_id="recon-bot", attributes={})
    assert resolve_role(e, role_map={"recon-bot": "kyc"}) == "kyc"


def test_ac7_role_map_miss_falls_back_to_agent_id():
    e = _event(agent_id="recon-bot", attributes={})
    assert resolve_role(e, role_map={"someone-else": "kyc"}) == "recon-bot"


def test_ac7_empty_string_attributes_role_is_ignored():
    e = _event(agent_id="recon-bot", attributes={"role": ""})
    assert resolve_role(e, role_map={"recon-bot": "kyc"}) == "kyc"


def test_ac7_non_string_attributes_role_is_ignored():
    e = _event(agent_id="recon-bot", attributes={"role": 12345})
    assert resolve_role(e, role_map=None) == "recon-bot"


@pytest.mark.parametrize(
    "role,expected",
    [
        ("recon-bot", True),
        ("kyc_bot-1", True),
        ("a", True),
        ("a" * 64, True),  # boundary: exactly the max length is legal
        ("a" * 65, False),  # boundary: one over the max length is illegal
        ("", False),  # empty is illegal
        ("bad role!", False),  # illegal characters (space, punctuation)
        ("../etc/passwd", False),
    ],
)
def test_ac7_is_valid_role_boundaries(role, expected):
    assert is_valid_role(role) is expected


# =============================================================================
# FR-10 — detector severity string -> schema Severity mapping
# =============================================================================


@pytest.mark.parametrize(
    "value,expected",
    [
        ("high", Severity.HIGH),
        ("medium", Severity.MEDIUM),
        ("info", Severity.INFO),
        ("something-unrecognized", Severity.INFO),  # unknown degrades to INFO, never raises
    ],
)
def test_map_severity(value, expected):
    assert map_severity(value) == expected
