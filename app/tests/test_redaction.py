"""Tests for collector-edge redaction (CR-25).

Complements `test_collector_contracts.py`, which covers the module's baseline
contract. These cover the defect that motivated the work and the pattern
coverage added when the two independently-written redaction modules were
merged: evidence was flagged `redacted=True` and the schema claimed the
payload was "already redacted by the collector", while the only transformation
applied was truncation to 256 characters. For a KYC agent that is exactly
where the customer's document number sits.
"""

from __future__ import annotations

import json

import pytest

from sentinel.collector.parsers import parse_flow
from sentinel.collector.redaction import redact_text

MARKER = "[REDACTED]"


@pytest.mark.parametrize(
    "secret",
    [
        "alice.smith@example.com",
        "4111 1111 1111 1111",
        "4111111111111111",
        "LU28 0019 4006 4475 0000",
        "LU280019400644750000",
        "sk-proj-AbCdEf0123456789",
        "AKIAIOSFODNN7EXAMPLE",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r",
        "+352 621 123 456",
    ],
)
def test_the_secret_does_not_survive(secret):
    out = redact_text(f"prefix {secret} suffix")
    assert secret not in out, out
    assert MARKER in out


def test_sensitive_json_keys_are_redacted_whatever_the_value_looks_like():
    """The structural half: a password has no recognisable shape, so only
    key-based redaction can catch it."""
    out = redact_text(json.dumps({"password": "hunter2", "note": "ok"}))
    assert "hunter2" not in out
    assert "ok" in out


def test_sensitive_keys_are_redacted_recursively():
    out = redact_text(json.dumps({"outer": {"items": [{"api_key": "plainvalue"}]}}))
    assert "plainvalue" not in out


def test_patterns_apply_inside_innocuous_json_keys():
    """The pattern half: a card number pasted under a harmless key name is
    still a card number."""
    out = redact_text(json.dumps({"note": "charge 4111111111111111 today"}))
    assert "4111111111111111" not in out


def test_ordinary_text_is_left_alone():
    """Over-redaction destroys the explainability this evidence exists for."""
    text = "agent read_ledger returned 42 rows for account group B"
    assert redact_text(text) == text


def test_epoch_timestamps_and_counts_are_not_redacted():
    """Guards the deliberate absence of a bare long-digit-run rule: it would
    eat timestamps and byte counts and gut the evidence chain."""
    out = redact_text(json.dumps({"ts_ms": 1758441600000, "bytes_out": 250000}))
    assert "1758441600000" in out
    assert "250000" in out


@pytest.mark.parametrize(
    "hostile",
    [
        "",
        "\x00\xff",
        "𝔘𝔫𝔦𝔠𝔬𝔡𝔢",
        "+" * 10_000,
        "1" * 10_000,  # trips CPython's int-string conversion limit in json.loads
        "[" * 2_000,  # deep nesting -> RecursionError
        "{",
        '{"a": ' + "1" * 5_000 + "}",
    ],
)
def test_redaction_never_raises_on_hostile_input(hostile):
    """A monitoring tool must not crash on the traffic it is monitoring.

    `"1" * 10_000` is not a contrived case: `json.loads` parses it as an
    integer and CPython refuses to convert a string that long, raising a bare
    ValueError that the original `except (JSONDecodeError, TypeError)` did not
    catch — a crash in the collector path on attacker-supplied input."""
    assert isinstance(redact_text(hostile), str)


# ---- end to end through the parser -----------------------------------------


def test_redaction_runs_before_truncation():
    """The bug this ordering prevents: a secret past the preview window is
    removed from the payload rather than merely cropped out of the view."""
    padding = "x" * 400
    event = parse_flow(
        agent_id="recon-bot",
        session_id="s1",
        host="reports.internal",
        method="POST",
        path="/upload",
        request_body=f"{padding} sk-proj-AbCdEf0123456789",
    )
    preview = [e for e in event.evidence if e.key == "body_preview"][0]
    assert "sk-proj" not in preview.value
    assert len(preview.value) <= 256


def test_prompt_evidence_from_a_real_flow_is_redacted():
    """A KYC-shaped prompt must not put the customer's details into the
    evidence chain."""
    body = json.dumps(
        {
            "model": "claude-sonnet-5",
            "messages": [
                {
                    "role": "user",
                    "content": "Verify alice.smith@example.com, card 4111111111111111",
                }
            ],
        }
    )
    event = parse_flow(
        agent_id="kyc-agent",
        session_id="s1",
        host="api.anthropic.com",
        method="POST",
        path="/v1/messages",
        request_body=body,
    )
    preview = [e for e in event.evidence if e.key == "prompt_preview"][0]
    assert preview.redacted is True
    assert "alice.smith@example.com" not in preview.value
    assert "4111111111111111" not in preview.value
    assert MARKER in preview.value


def test_tool_arguments_are_redacted_but_context_survives():
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "initiate_sepa_transfer",
                "arguments": {"iban": "LU280019400644750000", "ref": "invoice-9"},
            },
        }
    )
    event = parse_flow(
        agent_id="payment-processor",
        session_id="s1",
        host="sepa.internal",
        method="POST",
        path="/mcp",
        request_body=body,
    )
    args = [e for e in event.evidence if e.key == "tool_args"][0]
    assert "LU280019400644750000" not in args.value
    assert "invoice-9" in args.value


def test_an_undecodable_body_has_no_preview_rather_than_the_string_none():
    """`mitmproxy`'s `get_text(strict=False)` returns None for a body it cannot
    decode. That used to reach `str(None)` and store the literal "None" as the
    evidence preview for every binary payload."""
    assert redact_text(None) == ""


def test_bytes_out_still_reflects_the_real_payload_size():
    """Redaction must not distort the exfiltration signal — `net.oversize_egress`
    depends on the true byte count, not the redacted preview's length."""
    raw = "alice@example.com " * 1000
    event = parse_flow(
        agent_id="recon-bot",
        session_id="s1",
        host="reports.internal",
        method="POST",
        path="/upload",
        request_body=raw,
    )
    assert event.bytes_out == len(raw.encode())
