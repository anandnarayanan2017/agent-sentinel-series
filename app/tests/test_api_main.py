"""Endpoint tests for app/sentinel/api/main.py (CR-8: this module was at 0%
unit coverage — exactly where CR-1 (unauthenticated reads) and CR-10 (masked
500s) lived).

Auth is exercised two ways:
  - "no override" tests hit the real `require_auth` dependency to confirm
    CR-1 (read endpoints now require it) and CR-13 (fail-closed by default,
    no AZURE_* config and no SENTINEL_DEV_MODE=1 in this test process).
  - all other tests override `require_auth` via FastAPI's
    `dependency_overrides` so endpoint *behavior* can be tested without
    depending on real Entra ID token verification (already covered in
    isolation by test_auth.py).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel.api.auth import ALL_ROLES, _Principal, require_auth
from sentinel.api.main import app
from sentinel.api.main import pipeline as _pipeline
from sentinel.storage.base import (
    ApprovalNotFoundError,
    ApprovalsNotSupportedError,
    AuditNotSupportedError,
)

# A real `_Principal`, not a stub: role separation (CR-20) and agent-identity
# binding (CR-21) are decided by methods on this class, so a duck-typed
# SimpleNamespace would test a shape the app no longer uses.
_FAKE_PRINCIPAL = _Principal(
    {"oid": "test-user", "preferred_username": "test@localhost", "roles": list(ALL_ROLES)}
)


@pytest.fixture
def authed_client():
    app.dependency_overrides[require_auth] = lambda: _FAKE_PRINCIPAL
    yield TestClient(app)
    app.dependency_overrides.pop(require_auth, None)


@pytest.fixture
def client():
    """No auth override — exercises the real (fail-closed, CR-13) dependency."""
    app.dependency_overrides.pop(require_auth, None)
    return TestClient(app)


# ---- unauthenticated basics -------------------------------------------------


def test_healthz_ok(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_dashboard_root_serves_html(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


# ---- CR-1: read endpoints now require auth ---------------------------------


@pytest.mark.parametrize("path", ["/findings", "/events", "/stats"])
def test_read_endpoints_reject_unauthenticated_requests(client, path):
    """No AZURE_* config and no SENTINEL_DEV_MODE=1 in this test process ->
    require_auth fails closed with 503 (CR-13), not a silent bypass."""
    resp = client.get(path)
    assert resp.status_code == 503


@pytest.mark.parametrize("path", ["/findings", "/events", "/stats"])
def test_read_endpoints_succeed_once_authenticated(authed_client, path):
    resp = authed_client.get(path)
    assert resp.status_code == 200
    assert "items" in resp.json() or path == "/stats"


def test_stream_requires_auth(client):
    resp = client.get("/stream")
    assert resp.status_code == 503


def test_stream_route_declares_require_auth_dependency():
    # /stream's generator loop never terminates (`while True` + periodic
    # push): actually issuing a request via TestClient.stream() blocks
    # indefinitely on this platform's ASGI streaming transport even just to
    # enter the context manager (confirmed via SIGABRT'd hang, not something
    # a response timeout on the test side can bound). Asserting the
    # dependency is wired, statically, is the non-flaky way to guard CR-1
    # for this specific route without executing the infinite generator.
    route = next(r for r in app.routes if getattr(r, "path", None) == "/stream")

    def _calls(dependant):
        """Walk the dependency tree — `require_auth` is now reached through the
        per-endpoint `require_roles(...)` wrapper rather than declared directly
        (CR-20), so a flat scan of the top level would miss it."""
        for dep in dependant.dependencies:
            yield dep.call
            yield from _calls(dep)

    assert require_auth in set(_calls(route.dependant))


# ---- /ingest + /findings round trip -----------------------------------------


def _flow_payload(**overrides) -> dict:
    payload = {
        "agent_id": "recon-bot",
        "session_id": "s-api-main-test",
        "host": "example.com",
        "method": "POST",
        "path": "/",
    }
    payload.update(overrides)
    return payload


def test_ingest_requires_auth(client):
    resp = client.post("/ingest", json=_flow_payload())
    assert resp.status_code == 503


def test_ingest_then_findings_round_trip(authed_client):
    ingest_resp = authed_client.post("/ingest", json=_flow_payload())
    assert ingest_resp.status_code == 200
    body = ingest_resp.json()
    assert "findings" in body
    assert body["ingested_by"] == str(_FAKE_PRINCIPAL)

    events_resp = authed_client.get("/events")
    assert events_resp.status_code == 200
    assert any(e["agent_id"] == "recon-bot" for e in events_resp.json()["items"])


# ---- /approvals/{id} review — CR-10: 404 only on "not found", not on any
# exception; a genuine backend error must propagate as a real 500 -----------


def test_review_approval_rejects_bad_status(authed_client):
    resp = authed_client.post(
        "/approvals/whatever",
        json={"status": "not-a-real-status"},
    )
    assert resp.status_code == 422


def test_review_approval_uses_verified_principal_not_client_reviewer(authed_client, monkeypatch):
    """CR-22: the reviewer is the authenticated principal. A `reviewer` in the
    request body is ignored — it used to be written straight into the approvals
    table, so any write token could sign off as anyone."""
    captured = {}

    def _capture(*args, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(_pipeline.store, "review_approval", _capture)
    resp = authed_client.post(
        "/approvals/whatever",
        json={"status": "approved", "reviewer": "spoofed-user"},
    )
    assert resp.status_code == 200
    assert captured["reviewer"] == _FAKE_PRINCIPAL.user_id
    assert resp.json()["reviewer"] == _FAKE_PRINCIPAL.user_id


def test_review_approval_body_has_no_reviewer_field_at_all(authed_client):
    """Stronger than ignoring it: the field is gone from the schema. Leaving it
    in would invite the next caller to set it."""
    from sentinel.api.main import ReviewIn

    assert "reviewer" not in ReviewIn.model_fields


def test_review_approval_not_found_maps_to_404(authed_client, monkeypatch):
    def _raise_not_found(*a, **k):
        raise ApprovalNotFoundError("missing-id")

    monkeypatch.setattr(_pipeline.store, "review_approval", _raise_not_found)

    resp = authed_client.post("/approvals/missing-id", json={"status": "approved"})
    assert resp.status_code == 404


def test_review_approval_genuine_backend_error_is_not_masked_as_404(monkeypatch):
    """The pre-fix code caught *any* exception and reported 404 — a real DB
    outage looked identical to 'approval not found'. It must now surface as
    a 500 (or whatever FastAPI's default unhandled-exception status is),
    never a silently-wrong 404 (CR-10)."""

    def _raise_backend_error(*a, **k):
        raise RuntimeError("db connection lost")

    monkeypatch.setattr(_pipeline.store, "review_approval", _raise_backend_error)
    app.dependency_overrides[require_auth] = lambda: _FAKE_PRINCIPAL
    try:
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/approvals/some-id", json={"status": "approved"})
        assert resp.status_code == 500
        assert resp.status_code != 404
    finally:
        app.dependency_overrides.pop(require_auth, None)


# ---- CR-18: a backend that cannot record must refuse, not return 200 --------


def test_review_approval_on_unsupported_backend_returns_501(authed_client, monkeypatch):
    """The DuckDB default used to silently no-op and return 200 "recorded".
    A reviewer saw a green response and the decision evaporated."""

    def _unsupported(*a, **k):
        raise ApprovalsNotSupportedError(ApprovalsNotSupportedError.detail)

    monkeypatch.setattr(_pipeline.store, "review_approval", _unsupported)

    resp = authed_client.post("/approvals/any-id", json={"status": "approved"})
    assert resp.status_code == 501
    assert "DATABASE_URL" in resp.json()["detail"]


def test_list_approvals_on_unsupported_backend_returns_501(authed_client, monkeypatch):
    def _unsupported(*a, **k):
        raise ApprovalsNotSupportedError(ApprovalsNotSupportedError.detail)

    monkeypatch.setattr(_pipeline.store, "list_approvals", _unsupported)
    resp = authed_client.get("/approvals")
    assert resp.status_code == 501


def test_audit_log_on_unsupported_backend_returns_501_not_empty_list(authed_client, monkeypatch):
    """An empty list was indistinguishable from "no activity recorded"."""

    def _unsupported(*a, **k):
        raise AuditNotSupportedError(AuditNotSupportedError.detail)

    monkeypatch.setattr(_pipeline.store, "list_audit", _unsupported)
    resp = authed_client.get("/audit-log")
    assert resp.status_code == 501
    assert "DATABASE_URL" in resp.json()["detail"]


def test_audit_verify_on_unsupported_backend_returns_501(authed_client, monkeypatch):
    def _unsupported(*a, **k):
        raise AuditNotSupportedError(AuditNotSupportedError.detail)

    monkeypatch.setattr(_pipeline.store, "verify_audit_chain", _unsupported)
    resp = authed_client.get("/audit-log/verify")
    assert resp.status_code == 501


def test_duckdb_store_really_raises_rather_than_no_op():
    """Guards the base-class contract directly, not just the endpoint mapping:
    the default backend must refuse these surfaces at the storage layer."""
    with pytest.raises(ApprovalsNotSupportedError):
        _pipeline.store.review_approval("x", status="approved", reviewer="y")
    with pytest.raises(AuditNotSupportedError):
        _pipeline.store.list_audit()


# ---- CR-20: segregation of duties -------------------------------------------


def _client_as(roles):
    principal = _Principal({"oid": "role-test", "roles": list(roles)})
    app.dependency_overrides[require_auth] = lambda: principal
    return TestClient(app)


@pytest.mark.parametrize(
    "roles,path,expected",
    [
        (["sentinel.read"], "/findings", 200),
        (["sentinel.read"], "/audit-log", 403),
        (["sentinel.write"], "/audit-log", 403),
        (["sentinel.approver"], "/audit-log", 403),
        (["sentinel.admin"], "/audit-log", 501),  # allowed through; backend refuses
        (["sentinel.read"], "/approvals", 501),  # allowed through; backend refuses
    ],
)
def test_read_endpoint_role_separation(roles, path, expected):
    try:
        resp = _client_as(roles).get(path)
        assert resp.status_code == expected
    finally:
        app.dependency_overrides.pop(require_auth, None)


def test_read_only_role_cannot_ingest():
    try:
        resp = _client_as(["sentinel.read"]).post("/ingest", json=_flow_payload())
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.pop(require_auth, None)


def test_write_role_cannot_record_a_review_decision():
    """The collector credential that pushes events must not be able to clear
    the findings it generates."""
    try:
        resp = _client_as(["sentinel.write"]).post("/approvals/x", json={"status": "approved"})
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.pop(require_auth, None)


def test_admin_role_satisfies_every_endpoint():
    try:
        client = _client_as(["sentinel.admin"])
        assert client.get("/findings").status_code == 200
        assert client.post("/ingest", json=_flow_payload()).status_code == 200
    finally:
        app.dependency_overrides.pop(require_auth, None)


# ---- CR-21: agent-identity binding ------------------------------------------


def test_ingest_rejects_agent_id_outside_the_tokens_allow_list():
    principal = _Principal(
        {"oid": "bound", "roles": ["sentinel.write"], "agent_ids": ["recon-bot"]}
    )
    app.dependency_overrides[require_auth] = lambda: principal
    try:
        client = TestClient(app)
        assert client.post("/ingest", json=_flow_payload()).status_code == 200
        resp = client.post("/ingest", json=_flow_payload(agent_id="someone-elses-bot"))
        assert resp.status_code == 403
        assert "someone-elses-bot" in resp.json()["detail"]
    finally:
        app.dependency_overrides.pop(require_auth, None)


def test_ingest_stamps_the_verified_principal_onto_the_event(authed_client):
    """Even when a token carries no agent_ids constraint, the claimed identity
    and the authenticated one must be reconcilable after the fact."""
    authed_client.post("/ingest", json=_flow_payload(session_id="s-stamp"))
    events = authed_client.get("/events").json()["items"]
    stamped = [e for e in events if e.get("session_id") == "s-stamp"]
    assert stamped
    assert stamped[0]["attributes"]["ingested_by"] == "test-user"
