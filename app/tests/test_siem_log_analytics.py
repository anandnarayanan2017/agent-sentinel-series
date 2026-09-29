"""Azure Log Analytics SIEM export tests (app/sentinel/siem/log_analytics.py).

The Azure Monitor SDK is never invoked for real: `_get_client()` is the
module's documented lazy-import seam and is monkeypatched to return a fake
upload client. `push`/`push_bulk` must never raise on delivery failure
(fail-open), matching the posture of the audit middleware and the webhook
alerter elsewhere in this codebase.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

import sentinel.siem.log_analytics as siem
from sentinel.schema.events import Evidence, Finding, Severity


class _FakeUploadClient:
    def __init__(self, raise_on_upload: bool = False) -> None:
        self.raise_on_upload = raise_on_upload
        self.calls: list[dict] = []

    def upload(self, *, rule_id, stream_name, logs):
        if self.raise_on_upload:
            raise RuntimeError("Log Analytics ingestion endpoint unreachable")
        self.calls.append({"rule_id": rule_id, "stream_name": stream_name, "logs": logs})


def _finding(**overrides) -> Finding:
    defaults: dict[str, Any] = dict(
        agent_id="recon-bot",
        session_id="s1",
        rule_id="R-1",
        title="Suspicious egress",
        severity=Severity.HIGH,
        explanation="host not seen before",
        control_refs=["DORA-Art.25"],
        evidence=[Evidence(key="host", value="evil.example.com")],
    )
    defaults.update(overrides)
    return Finding(**defaults)


@pytest.fixture(autouse=True)
def _reset_client_cache(monkeypatch):
    """`_client` is a lazily-built module-level singleton; never let it leak
    a fake client between tests."""
    monkeypatch.setattr(siem, "_client", None)
    yield
    monkeypatch.setattr(siem, "_client", None)


# ---- activation gate (AZURE_LOG_ANALYTICS_DCE / _DCR_ID unset) -------------


def test_push_is_a_noop_when_not_active(monkeypatch):
    monkeypatch.setattr(siem, "_ACTIVE", False)
    built = []
    monkeypatch.setattr(siem, "_get_client", lambda: built.append(1) or _FakeUploadClient())

    siem.push(_finding())

    assert built == []


def test_push_bulk_is_a_noop_when_not_active(monkeypatch):
    monkeypatch.setattr(siem, "_ACTIVE", False)
    built = []
    monkeypatch.setattr(siem, "_get_client", lambda: built.append(1) or _FakeUploadClient())

    siem.push_bulk([_finding()])

    assert built == []


def test_push_bulk_is_a_noop_on_empty_list_even_when_active(monkeypatch):
    monkeypatch.setattr(siem, "_ACTIVE", True)
    built = []
    monkeypatch.setattr(siem, "_get_client", lambda: built.append(1) or _FakeUploadClient())

    siem.push_bulk([])

    assert built == []


# ---- happy path --------------------------------------------------------------


def test_push_uploads_one_row_with_configured_rule_and_stream(monkeypatch):
    monkeypatch.setattr(siem, "_ACTIVE", True)
    monkeypatch.setattr(siem, "_DCR_ID", "dcr-123")
    monkeypatch.setattr(siem, "_STREAM", "Custom-Stream_CL")
    fake = _FakeUploadClient()
    monkeypatch.setattr(siem, "_get_client", lambda: fake)

    f = _finding()
    siem.push(f)

    assert len(fake.calls) == 1
    call = fake.calls[0]
    assert call["rule_id"] == "dcr-123"
    assert call["stream_name"] == "Custom-Stream_CL"
    assert len(call["logs"]) == 1
    row = call["logs"][0]
    assert row["FindingId"] == f.finding_id
    assert row["AgentId"] == "recon-bot"
    assert row["Severity"] == "high"


def test_push_builds_and_caches_the_client_once(monkeypatch):
    monkeypatch.setattr(siem, "_ACTIVE", True)
    fake = _FakeUploadClient()
    build_calls = []
    monkeypatch.setattr(siem, "_get_client", lambda: build_calls.append(1) or fake)

    siem.push(_finding())
    siem.push(_finding())

    assert len(build_calls) == 1
    assert len(fake.calls) == 2


def test_push_bulk_batches_at_500_rows_per_upload_call(monkeypatch):
    monkeypatch.setattr(siem, "_ACTIVE", True)
    fake = _FakeUploadClient()
    monkeypatch.setattr(siem, "_get_client", lambda: fake)

    findings = [_finding() for _ in range(1201)]
    siem.push_bulk(findings)

    assert [len(c["logs"]) for c in fake.calls] == [500, 500, 201]


# ---- fail-open: push/push_bulk never raise ----------------------------------


def test_push_never_raises_when_client_construction_fails(monkeypatch, capsys):
    monkeypatch.setattr(siem, "_ACTIVE", True)

    def _boom():
        raise RuntimeError("Azure Monitor SDK not installed")

    monkeypatch.setattr(siem, "_get_client", _boom)

    siem.push(_finding())  # must not raise

    assert "Log Analytics push failed" in capsys.readouterr().err


def test_push_never_raises_when_upload_fails(monkeypatch, capsys):
    monkeypatch.setattr(siem, "_ACTIVE", True)
    fake = _FakeUploadClient(raise_on_upload=True)
    monkeypatch.setattr(siem, "_get_client", lambda: fake)

    siem.push(_finding())  # must not raise

    assert "Log Analytics push failed" in capsys.readouterr().err


def test_push_bulk_never_raises_when_upload_fails(monkeypatch, capsys):
    monkeypatch.setattr(siem, "_ACTIVE", True)
    fake = _FakeUploadClient(raise_on_upload=True)
    monkeypatch.setattr(siem, "_get_client", lambda: fake)

    siem.push_bulk([_finding(), _finding()])  # must not raise

    assert "bulk push failed" in capsys.readouterr().err


# ---- row shape / known input -> output --------------------------------------


def test_finding_to_row_evidence_fingerprint_matches_known_sha256_digest():
    f = _finding(evidence=[Evidence(key="host", value="evil.example.com", redacted=False)])

    row = siem._finding_to_row(f)

    expected = hashlib.sha256(
        json.dumps(
            [{"key": "host", "value": "evil.example.com", "redacted": False}], sort_keys=True
        ).encode()
    ).hexdigest()[:16]
    assert row["EvidenceFP"] == expected
    assert len(row["EvidenceFP"]) == 16


def test_finding_to_row_includes_dashboard_url_and_control_refs():
    f = _finding(control_refs=["DORA-Art.25", "CSSF-1"])

    row = siem._finding_to_row(f)

    assert row["FindingUrl"].endswith(f"#finding-{f.finding_id}")
    assert json.loads(row["ControlRefs"]) == ["DORA-Art.25", "CSSF-1"]
