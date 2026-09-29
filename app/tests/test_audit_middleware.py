"""Audit-write failure observability (design/DESIGN.md §7.2, UAT-7..10).

The audit log is fire-and-forget by design: a write failure must never alter
the HTTP response, must be logged with a bounded, non-sensitive field set, and
must be counted so an operator can discover silent audit-trail degradation.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from sentinel.api.audit import AuditMiddleware, audit_write_failures


class FakeStore:
    def __init__(self, raise_on_insert: bool = False) -> None:
        self.raise_on_insert = raise_on_insert
        self.entries: list[dict] = []

    def insert_audit(self, entry: dict) -> None:
        if self.raise_on_insert:
            raise RuntimeError("db down")
        self.entries.append(entry)


def audited_app(store: FakeStore) -> FastAPI:
    app = FastAPI()
    app.add_middleware(AuditMiddleware, store=store)

    @app.get("/stats")
    def stats():
        return {"ok": True}

    @app.post("/ingest")
    def ingest(payload: dict):
        return {"received": True}

    @app.post("/approvals/{approval_id}")
    def approve(approval_id: str):
        return {"approval_id": approval_id}

    return app


# ---- T7 (UAT-7, AC-6/AC-11) — response never changes -----------------------
def test_audit_write_failure_never_alters_response():
    ok_client = TestClient(audited_app(FakeStore(raise_on_insert=False)))
    fail_client = TestClient(audited_app(FakeStore(raise_on_insert=True)))

    ok_resp = ok_client.get("/stats")
    fail_resp = fail_client.get("/stats")

    assert ok_resp.status_code == fail_resp.status_code == 200
    assert ok_resp.json() == fail_resp.json()
    assert "X-Audit-Hash" in ok_resp.headers
    assert "X-Audit-Hash" in fail_resp.headers


# ---- T8 (UAT-8, AC-7/AC-9) — diagnosable, bounded log ----------------------
def test_audit_write_failure_is_logged_with_bounded_fields(caplog):
    store = FakeStore(raise_on_insert=True)
    client = TestClient(audited_app(store))

    with caplog.at_level(logging.WARNING, logger="sentinel.api.audit"):
        resp = client.post("/ingest", json={"agent_id": "recon-bot"})

    assert resp.status_code == 200
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    msg = warnings[0].getMessage()
    assert "/ingest" in msg
    assert "recon-bot" in msg
    assert "RuntimeError" in msg or "db down" in msg
    # forbidden: raw request body bytes must never appear in the log line
    assert '{"agent_id": "recon-bot"}' not in msg


# ---- T9 (UAT-9, AC-8) — machine-observable counter -------------------------
def test_audit_write_failure_increments_counter():
    baseline = audit_write_failures()

    fail_client = TestClient(audited_app(FakeStore(raise_on_insert=True)))
    fail_client.get("/stats")
    assert audit_write_failures() == baseline + 1

    ok_client = TestClient(audited_app(FakeStore(raise_on_insert=False)))
    ok_client.get("/stats")
    assert audit_write_failures() == baseline + 1


# ---- CR-2: audit user_id comes from the verified principal, not a header ---
class _FakePrincipal:
    def __init__(self, user_id: str) -> None:
        self.user_id = user_id


def test_user_id_comes_from_request_state_principal_not_header():
    """A client-supplied X-User-Id header must never determine audit
    attribution — that's exactly what made the trail forgeable pre-fix."""
    store = FakeStore()
    app = FastAPI()
    app.add_middleware(AuditMiddleware, store=store)

    @app.get("/stats")
    def stats(request: Request):
        # Stands in for what require_auth() does after verifying a token.
        request.state.principal = _FakePrincipal("verified-user-1")
        return {"ok": True}

    client = TestClient(app)
    client.get("/stats", headers={"X-User-Id": "attacker-spoofed-id"})

    assert store.entries[0]["user_id"] == "verified-user-1"


def test_user_id_is_none_when_no_principal_was_resolved():
    """No auth dependency ran (shouldn't happen for a real audited route,
    but the middleware must degrade safely) -> user_id is None, never the
    header value."""
    store = FakeStore()
    client = TestClient(audited_app(store))

    client.get("/stats", headers={"X-User-Id": "attacker-spoofed-id"})

    assert store.entries[0]["user_id"] is None


def test_dynamic_approval_decision_is_audited():
    store = FakeStore()
    client = TestClient(audited_app(store))
    response = client.post("/approvals/ap-123")
    assert response.status_code == 200
    assert store.entries[0]["endpoint"] == "/approvals/ap-123"


# ---- T10 (UAT-10, AC-10) — happy path unchanged -----------------------------
def test_successful_audit_write_is_unchanged(caplog):
    store = FakeStore(raise_on_insert=False)
    client = TestClient(audited_app(store))
    baseline = audit_write_failures()

    with caplog.at_level(logging.WARNING, logger="sentinel.api.audit"):
        resp = client.get("/stats")

    assert resp.status_code == 200
    assert "X-Audit-Hash" in resp.headers
    assert len(store.entries) == 1
    assert not any(r.levelno == logging.WARNING for r in caplog.records)
    assert audit_write_failures() == baseline
