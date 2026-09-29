"""Audit-trail middleware — logs protected API requests to ``audit_log``.

Captures: timestamp, endpoint, method, agent_id (from JSON body on /ingest),
source IP, SHA-256 hash of request payload, HTTP status, and latency.

The SHA-256 value binds a request body to its audit row: replay a mutated
payload and the hash no longer matches. On its own that is a request
fingerprint, not a tamper-evident log.

The log-level property comes from the hash chain the storage layer applies on
write (`storage/audit_chain.py`, ADR-0010): each entry commits to its
predecessor, so an altered, deleted or reordered row breaks every link after
it, and `GET /audit-log/verify` names the first break.

The remaining half is a deployment control and is deliberately not claimed
here: detecting an attacker who can rewrite the *whole* chain forward needs an
independently protected anchor — a periodic export of the chain head to
append-only storage, a signature, or a WORM store.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from sentinel.storage.base import AuditNotSupportedError

logger = logging.getLogger("sentinel.api.audit")

# Protected endpoints worth auditing. Dynamic approval decisions are matched
# separately so `/approvals/{id}` cannot fall through an exact-string set.
_AUDIT_PATHS = {
    "/ingest",
    "/findings",
    "/events",
    "/stream",
    "/approvals",
    "/stats",
    "/audit-log",
    "/audit-log/verify",
}


def _should_audit(path: str) -> bool:
    return path in _AUDIT_PATHS or path.startswith("/approvals/")


# Process-wide count of audit-write failures observed since import. Deltas
# (baseline -> act -> re-read), not the absolute value, are the meaningful
# signal — see design/DESIGN.md §5 for why a module-level counter was chosen
# over an instance attribute (not test-reachable) or a new endpoint (OOS-3).
_audit_write_failures = 0


def audit_write_failures() -> int:
    """Process-wide total of audit-write failures observed since import."""
    return _audit_write_failures


def _record_audit_write_failure() -> None:
    global _audit_write_failures
    _audit_write_failures += 1


# A backend that cannot audit at all is a deployment *configuration* state, not
# a per-request failure: it would otherwise log a warning and increment the
# failure counter on every single audited request, burying real write failures
# in noise. Report it once per process, and leave the counter for genuine
# failures (CR-18).
_unsupported_warned = False


def _warn_audit_unsupported_once(detail: str) -> None:
    global _unsupported_warned
    if not _unsupported_warned:
        _unsupported_warned = True
        logger.warning("audit trail unavailable on this storage backend: %s", detail)


class AuditMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, store) -> None:
        super().__init__(app)
        self._store = store

    async def dispatch(self, request: Request, call_next) -> Response:
        if not _should_audit(request.url.path):
            return await call_next(request)

        t0 = time.monotonic()

        # Read + cache body so the endpoint can still read it
        body = await request.body()
        payload_hash = hashlib.sha256(body).hexdigest() if body else None

        agent_id: str | None = None
        if body and request.headers.get("content-type", "").startswith("application/json"):
            try:
                agent_id = json.loads(body).get("agent_id")
            except Exception:
                pass

        response = await call_next(request)

        duration_ms = int((time.monotonic() - t0) * 1000)

        # Actor attribution comes from the verified principal that
        # require_auth() stashed on request.state during the request — never
        # from a client-supplied header, which would be trivially forgeable
        # on an attributed audit trail (CR-2). None if the endpoint has no
        # auth dependency (shouldn't happen for anything in _AUDIT_PATHS).
        principal = getattr(request.state, "principal", None)
        user_id = principal.user_id if principal is not None else None

        # Fire-and-forget — never raise, never block the response
        try:
            self._store.insert_audit(
                {
                    "ts": datetime.now(timezone.utc),
                    "endpoint": request.url.path,
                    "method": request.method,
                    "agent_id": agent_id,
                    "source_ip": (request.client.host if request.client else None),
                    "payload_hash": payload_hash,
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                    "user_id": user_id,
                }
            )
        except AuditNotSupportedError as exc:
            _warn_audit_unsupported_once(str(exc))
        except Exception as exc:  # noqa: BLE001 — audit middleware must stay fire-and-forget
            logger.warning(
                "audit write failed: endpoint=%s method=%s agent_id=%s status=%s "
                "payload_hash=%s err=%r",
                request.url.path,
                request.method,
                agent_id,
                response.status_code,
                payload_hash,
                exc,
            )
            _record_audit_write_failure()

        # Stamp every response with a request fingerprint for correlation
        response.headers["X-Audit-Hash"] = (payload_hash or "")[:16]
        return response
