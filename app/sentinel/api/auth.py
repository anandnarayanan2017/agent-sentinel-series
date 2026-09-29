"""Entra ID (Azure AD) JWT authentication for Agent Sentinel Phase 3.

Activated when AZURE_TENANT_ID + AZURE_CLIENT_ID env vars are set.
When absent, auth is only bypassed if SENTINEL_DEV_MODE=1 is also explicitly
set; otherwise every request is rejected (fail-closed — see require_auth).

How it works:
  1. FastAPI dependency `require_auth` extracts the Bearer token from
     Authorization header.
  2. Token is verified against the tenant's JWKS endpoint — signature,
     audience, expiry, issuer.
  3. The `oid` claim becomes the audit-trail user_id (threaded into
     `request.state.principal` for AuditMiddleware — never a client header).
  4. The `roles` claim is checked against the roles the endpoint requires.

Roles (assign in Azure AD → App registrations → App roles):

  sentinel.read      read findings, events, stats, the approvals queue
  sentinel.write     the above, plus POST /ingest
  sentinel.approver  the above, plus recording a review decision
  sentinel.admin     everything, including reading the audit trail

These are separated deliberately. One undifferentiated role meant the
collector credential that pushes events could also clear HIGH/CRITICAL
findings and read the whole audit trail — no segregation of duties, in a
product whose own development process requires that the author of a change
never approves it (CR-20).

Agent-identity binding: a token may carry an `agent_ids` claim listing the
agent identities that principal is allowed to file events for. When present it
is enforced; `/ingest` rejects a mismatch. See `_Principal.may_act_for`.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any

from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_TENANT = os.environ.get("AZURE_TENANT_ID", "")
_AUDIENCE = os.environ.get("AZURE_CLIENT_ID", "")
_AUTH_ON = bool(_TENANT and _AUDIENCE)
_DEV_MODE = os.environ.get("SENTINEL_DEV_MODE", "") == "1"

if not _AUTH_ON:
    if _DEV_MODE:
        print(
            "WARNING: Agent Sentinel running in AUTH BYPASS mode (SENTINEL_DEV_MODE=1) — "
            "AZURE_TENANT_ID / AZURE_CLIENT_ID not set. "
            "All requests are unauthenticated. Never set this in production.",
            file=sys.stderr,
            flush=True,
        )
    else:
        print(
            "WARNING: Agent Sentinel has no Entra ID auth configured "
            "(AZURE_TENANT_ID / AZURE_CLIENT_ID unset) and SENTINEL_DEV_MODE is not "
            "set to '1' — every request will be rejected with 503 until one of "
            "those is fixed. This is deliberate: omission must fail closed, not "
            "silently bypass auth.",
            file=sys.stderr,
            flush=True,
        )

ROLE_READ = "sentinel.read"
ROLE_WRITE = "sentinel.write"
ROLE_APPROVER = "sentinel.approver"
ROLE_ADMIN = "sentinel.admin"

#: Admin is a superset of every other role, so endpoint dependencies name only
#: the specific role they need and never have to remember to also allow admin.
_SUPERUSER_ROLE = ROLE_ADMIN

ALL_ROLES = (ROLE_READ, ROLE_WRITE, ROLE_APPROVER, ROLE_ADMIN)

_bearer = HTTPBearer(auto_error=False)

# JWKS TTL cache (CR-7): a bare @lru_cache(maxsize=1) never refreshes, so an
# Entra ID signing-key rotation breaks verification until process restart.
_JWKS_TTL_SECONDS = 3600
_jwks_state: dict[str, Any] = {"data": None, "fetched_at": 0.0}


def _fetch_jwks() -> dict[str, Any]:
    """Fetch the tenant's JWKS from its OpenID Connect discovery endpoint."""
    try:
        from jose.backends import RSAKey  # noqa: F401  (import check only)
        import json
        import urllib.request

        oid_url = (
            f"https://login.microsoftonline.com/{_TENANT}/v2.0/.well-known/openid-configuration"
        )
        # bandit B310: scheme is hardcoded above (only _TENANT, an operator env
        # var, is interpolated) — always https, but urlopen still flagged.
        with urllib.request.urlopen(oid_url, timeout=10) as r:  # nosec B310 — scheme is fixed above
            meta = json.load(r)
        jwks_uri = meta["jwks_uri"]
        # jwks_uri comes from Microsoft's own TLS-verified discovery response
        # (not attacker input), but validate the scheme anyway before following it.
        if not jwks_uri.startswith("https://"):
            raise RuntimeError(f"Entra ID discovery returned non-https jwks_uri: {jwks_uri!r}")
        with urllib.request.urlopen(jwks_uri, timeout=10) as r:  # nosec B310 — scheme validated above
            return json.load(r)
    except Exception as exc:
        raise RuntimeError(f"Cannot fetch JWKS from Entra ID: {exc}") from exc


def _get_jwks(force: bool = False) -> dict[str, Any]:
    """TTL-cached JWKS, with an explicit force-refresh for unknown-kid retries."""
    now = time.time()
    stale = (now - _jwks_state["fetched_at"]) > _JWKS_TTL_SECONDS
    if force or _jwks_state["data"] is None or stale:
        _jwks_state["data"] = _fetch_jwks()
        _jwks_state["fetched_at"] = now
    return _jwks_state["data"]


def _verify_token(token: str) -> dict[str, Any]:
    from jose import jwt, JWTError

    try:
        unverified_header = jwt.get_unverified_header(token)
    except JWTError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}")

    # If the token's kid isn't in our cached key set, it may be a rotated key
    # we haven't picked up yet — refresh once before rejecting (CR-7).
    kid = unverified_header.get("kid")
    jwks = _get_jwks()
    known_kids = {k.get("kid") for k in jwks.get("keys", [])}
    if kid is not None and kid not in known_kids:
        jwks = _get_jwks(force=True)

    try:
        payload = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            audience=_AUDIENCE,
            issuer=f"https://login.microsoftonline.com/{_TENANT}/v2.0",
            options={"verify_at_hash": False},
        )
        return payload
    except JWTError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}")


class _Principal:
    """Slim identity object injected into endpoints that call require_auth."""

    def __init__(self, claims: dict[str, Any]) -> None:
        self.user_id: str = claims.get("oid", "unknown")
        self.name: str = claims.get("name", "")
        self.email: str = claims.get("preferred_username", "")
        self.roles: list[str] = claims.get("roles", [])
        # Optional allow-list of agent identities this principal may file
        # events for. None means "unconstrained by the token" — the event is
        # still stamped with this principal so the two can be reconciled.
        raw_agents = claims.get("agent_ids")
        self.allowed_agent_ids: set[str] | None = (
            set(raw_agents) if isinstance(raw_agents, (list, tuple, set)) else None
        )

    def has_role(self, *roles: str) -> bool:
        return bool(set(self.roles) & ({_SUPERUSER_ROLE} | set(roles)))

    def may_act_for(self, agent_id: str) -> bool:
        """Whether this principal may submit events under `agent_id`.

        Unconstrained when the token carries no `agent_ids` claim — but
        `/ingest` stamps every event with `ingested_by` regardless, so claimed
        identity and authenticated identity can always be reconciled after the
        fact (CR-21).
        """
        if self.allowed_agent_ids is None:
            return True
        return agent_id in self.allowed_agent_ids

    def __str__(self) -> str:
        return self.email or self.user_id


_DEV_PRINCIPAL = _Principal(
    {
        "oid": "dev-bypass",
        "name": "Dev Mode",
        "preferred_username": "dev@localhost",
        # Dev bypass stands in for a fully-privileged operator so local work
        # is not blocked by role separation. Never set SENTINEL_DEV_MODE in
        # production — the warning above says so on every start.
        "roles": list(ALL_ROLES),
    }
)


def require_auth(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> _Principal:
    """FastAPI dependency — validate Entra ID Bearer token.

    In dev mode (AZURE_TENANT_ID/AZURE_CLIENT_ID unset AND SENTINEL_DEV_MODE=1),
    returns a fixed dev principal and logs a warning. If Azure auth isn't
    configured and dev mode isn't explicitly opted into, every request is
    rejected (503) — omission must fail closed, never silently bypass auth
    (CR-13). Never set SENTINEL_DEV_MODE in production.

    The resolved principal is stashed on `request.state.principal` so
    AuditMiddleware can attribute the audit-trail `user_id` to the verified
    identity instead of a spoofable client header (CR-2).
    """
    if not _AUTH_ON:
        if not _DEV_MODE:
            raise HTTPException(
                status_code=503,
                detail=(
                    "Auth not configured: set AZURE_TENANT_ID/AZURE_CLIENT_ID for "
                    "production, or SENTINEL_DEV_MODE=1 for local dev."
                ),
            )
        request.state.principal = _DEV_PRINCIPAL
        return _DEV_PRINCIPAL

    if creds is None:
        raise HTTPException(status_code=401, detail="Authorization header required")

    claims = _verify_token(creds.credentials)

    principal = _Principal(claims)
    if not principal.has_role(*ALL_ROLES):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Token lacks a recognised Agent Sentinel role. "
                f"Got: {principal.roles}. Need one of: {list(ALL_ROLES)}"
            ),
        )

    request.state.principal = principal
    return principal


def require_roles(*roles: str):
    """Build a dependency that additionally requires one of `roles`.

    Layered on top of `require_auth` rather than replacing it, so the
    authentication path (and its dev-mode and fail-closed behaviour) stays in
    exactly one place and each endpoint only declares the extra authority it
    needs (CR-20).
    """

    def _dependency(principal: _Principal = Depends(require_auth)) -> _Principal:
        if not principal.has_role(*roles):
            raise HTTPException(
                status_code=403,
                detail=(
                    f"This endpoint requires one of: {list(roles)} "
                    f"(or {_SUPERUSER_ROLE}). Token has: {principal.roles}"
                ),
            )
        return principal

    return _dependency
