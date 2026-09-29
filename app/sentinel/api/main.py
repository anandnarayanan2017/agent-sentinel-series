"""FastAPI collector/query service.

POST /ingest              <- collectors push captured flows here
GET  /findings            -> dashboard / analysts read explainable findings
GET  /stats               -> aggregated counts by severity
GET  /events              -> raw event stream
GET  /stream              -> SSE live push
GET  /approvals           -> pending HIGH/CRITICAL finding reviews
POST /approvals/{id}      -> reviewer approves / escalates / suppresses
GET  /audit-log           -> hash-chained, fingerprinted audit log (PostgreSQL only)
GET  /audit-log/verify    -> walk the chain and report the first broken link
GET  /healthz             -> liveness

Authority is separated per endpoint (see api/auth.py): reading findings,
pushing events, recording a review decision and reading the audit trail are
four different roles, not one.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from sentinel.api.audit import AuditMiddleware
from sentinel.api.auth import (
    ROLE_ADMIN,
    ROLE_APPROVER,
    ROLE_READ,
    ROLE_WRITE,
    require_roles,
)
from sentinel.pipeline import Pipeline
from sentinel.storage.base import ApprovalNotFoundError, BackendCapabilityError

POLICY_PATH = os.environ.get("SENTINEL_POLICY", "policies/example.yaml")
DB_PATH = os.environ.get("SENTINEL_DB", ":memory:")

app = FastAPI(title="Agent Sentinel", version="2.1.0")
_CORS_ORIGINS = [
    o.strip()
    for o in os.environ.get("SENTINEL_CORS_ORIGINS", "http://localhost:8000").split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

pipeline = Pipeline(POLICY_PATH, DB_PATH)

# Audit middleware must be added AFTER pipeline is ready so it has a store ref
app.add_middleware(AuditMiddleware, store=pipeline.store)

_DASHBOARD = Path("dashboard/index.html").resolve()
if not _DASHBOARD.exists():
    _DASHBOARD = Path(__file__).resolve().parents[3] / "dashboard" / "index.html"

# Read dependencies, named once so the authority each endpoint needs is
# declarative and greppable rather than repeated inline.
_read = require_roles(ROLE_READ, ROLE_WRITE, ROLE_APPROVER)
_write = require_roles(ROLE_WRITE)
_approve = require_roles(ROLE_APPROVER)
_admin = require_roles(ROLE_ADMIN)


# ── request models ────────────────────────────────────────────────────────────


class FlowIn(BaseModel):
    agent_id: str
    session_id: str
    host: str
    method: str = "POST"
    path: str = "/"
    request_body: Optional[str] = None
    response_body: Optional[str] = None
    status_code: Optional[int] = None


class ReviewIn(BaseModel):
    """A reviewer's decision on a finding.

    There is deliberately no `reviewer` field. It used to be a free-text string
    taken from the request body and written straight into the approvals table —
    so any holder of a write token could sign off a CRITICAL finding as anyone
    they liked. The reviewer is now always the authenticated principal, which is
    the same rule CR-2 already applied to the audit trail (CR-22).
    """

    status: str  # approved | escalated | suppressed
    comment: str = ""


# ── static ────────────────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def dashboard() -> str:
    if _DASHBOARD.exists():
        return _DASHBOARD.read_text(encoding="utf-8")
    return "<h1>Agent Sentinel</h1><p>Run <code>sentinel demo</code> to start.</p>"


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


# ── core API ──────────────────────────────────────────────────────────────────


@app.post("/ingest")
def ingest(
    flow: FlowIn,
    principal=Depends(_write),
) -> dict[str, object]:
    # The claimed agent_id is data from the request body; the principal is
    # verified. Where the token constrains which identities it may act for,
    # enforce it — and stamp the event with the principal either way so a
    # claimed identity can always be reconciled with an authenticated one.
    if not principal.may_act_for(flow.agent_id):
        raise HTTPException(
            status_code=403,
            detail=(f"Token is not permitted to submit events for agent_id '{flow.agent_id}'."),
        )
    findings = pipeline.ingest_flow(**flow.model_dump(), ingested_by=str(principal.user_id))
    return {
        "findings": len(findings),
        "items": [f.model_dump(mode="json") for f in findings],
        "ingested_by": str(principal),
    }


@app.get("/findings")
def findings(
    limit: int = Query(default=100, le=1000),
    principal=Depends(_read),
) -> dict[str, object]:
    return {"items": pipeline.store.list_findings(limit)}


@app.get("/events")
def events_list(
    limit: int = Query(default=50, le=1000),
    principal=Depends(_read),
) -> dict[str, object]:
    return {"items": pipeline.store.list_events(limit)}


@app.get("/stats")
def stats(principal=Depends(_read)) -> dict[str, object]:
    return pipeline.store.stats()


# ── approval workflow ─────────────────────────────────────────────────────────


@app.get("/approvals")
def list_approvals(
    status: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    principal=Depends(_read),
) -> dict[str, object]:
    """List finding approvals. Filter by status: pending | approved | escalated | suppressed."""
    try:
        items = pipeline.store.list_approvals(status=status, limit=limit)
    except BackendCapabilityError as exc:
        raise HTTPException(status_code=501, detail=exc.detail) from exc
    return {"items": items, "count": len(items)}


@app.post("/approvals/{approval_id}")
def review_approval(
    approval_id: str,
    body: ReviewIn,
    principal=Depends(_approve),
) -> dict[str, object]:
    """Record a compliance officer's decision on a HIGH/CRITICAL finding.

    The decision is attributed to the authenticated principal — never to a
    name supplied in the request body.

    Accepted statuses:
    - approved    — finding reviewed, no further action required
    - escalated   — finding escalated to CISO / incident response
    - suppressed  — finding is a known false-positive, suppressed with reason
    """
    if body.status not in ("approved", "escalated", "suppressed"):
        raise HTTPException(status_code=422, detail="status must be approved|escalated|suppressed")
    reviewer = principal.user_id
    try:
        pipeline.store.review_approval(
            approval_id,
            status=body.status,
            reviewer=reviewer,
            comment=body.comment,
        )
    except BackendCapabilityError as exc:
        # A backend that cannot record the decision must refuse it. Returning
        # 200 "recorded" while storing nothing is the loudest possible lie in a
        # compliance workflow (CR-18).
        raise HTTPException(status_code=501, detail=exc.detail) from exc
    except ApprovalNotFoundError:
        raise HTTPException(status_code=404, detail="Approval not found or already reviewed")
    return {
        "approval_id": approval_id,
        "status": body.status,
        "reviewer": reviewer,
        "msg": "recorded",
    }


# ── audit trail ───────────────────────────────────────────────────────────────


@app.get("/audit-log")
def audit_log(
    limit: int = Query(default=200, le=1000),
    offset: int = Query(default=0, ge=0),
    principal=Depends(_admin),
) -> dict[str, object]:
    """Hash-chained audit log. Requires the PostgreSQL backend.

    Each entry includes endpoint, verified actor (when resolved), agent_id,
    source IP, SHA-256 request fingerprint, status, latency, and the hash of
    its predecessor. The fingerprint alone is not tamper-evidence; the chain
    is what makes edits, deletions and reordering detectable (ADR-0010), and
    `/audit-log/verify` is how you check it. Detecting an attacker who can
    rewrite the entire chain forward additionally needs an independently
    protected anchor — a deployment control, not provided here.
    """
    try:
        items = pipeline.store.list_audit(limit=limit, offset=offset)
    except BackendCapabilityError as exc:
        raise HTTPException(status_code=501, detail=exc.detail) from exc
    return {"items": items, "count": len(items)}


@app.get("/audit-log/verify")
def audit_log_verify(
    limit: int = Query(default=10_000, le=100_000),
    principal=Depends(_admin),
) -> dict[str, object]:
    """Walk the audit chain and report the first broken link, if any.

    This is what makes the trail *evidently* tamper-evident: an auditor runs
    this and gets either a clean verdict or the exact record where the chain
    stops reconciling.
    """
    try:
        return pipeline.store.verify_audit_chain(limit=limit)
    except BackendCapabilityError as exc:
        raise HTTPException(status_code=501, detail=exc.detail) from exc


# ── SSE live stream ───────────────────────────────────────────────────────────

#: How long a computed stream snapshot may be reused across connected clients.
#: Without this each connected dashboard tab ran its own full re-read of
#: findings and events every tick, so cost scaled with the number of open tabs
#: rather than with the data (CR-19).
_STREAM_CACHE_TTL = 1.0


@dataclass
class _StreamCache:
    """One snapshot shared by every connected SSE client."""

    payload: Optional[dict[str, Any]] = None
    at: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock)


_stream_cache = _StreamCache()


def _stream_snapshot() -> dict[str, Any]:
    """Build (or reuse) the snapshot pushed to every connected SSE client."""
    now = time.monotonic()
    with _stream_cache.lock:
        cached = _stream_cache.payload
        if cached is not None and (now - _stream_cache.at) < _STREAM_CACHE_TTL:
            return cached

        s = pipeline.store.stats()
        payload: dict[str, Any] = {
            "type": "update",
            "stats": s,
            "findings": pipeline.store.list_findings(200),
            "events": pipeline.store.list_events(100),
            "pending_approvals": s.get("pending_approvals", 0),
        }
        _stream_cache.payload = payload
        _stream_cache.at = now
        return payload


@app.get("/stream", include_in_schema=False)
async def stream(principal=Depends(_read)) -> StreamingResponse:
    """Server-Sent Events — pushes delta updates whenever new findings or events arrive."""

    async def _generator():
        last_key: Optional[tuple[int, int]] = None
        while True:
            try:
                payload = _stream_snapshot()
                stats_now: dict[str, Any] = payload["stats"]
                key = (
                    stats_now.get("total_findings", 0),
                    stats_now.get("total_events", 0),
                )
                if key != last_key:
                    last_key = key
                    yield f"data: {json.dumps(payload, default=str)}\n\n"
                else:
                    yield 'data: {"type":"ping"}\n\n'
            except Exception:
                yield 'data: {"type":"error","msg":"stream error"}\n\n'
            await asyncio.sleep(1.5)

    return StreamingResponse(
        _generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
