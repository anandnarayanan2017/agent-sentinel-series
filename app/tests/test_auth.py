"""Entra ID (Azure AD) JWT auth tests (app/sentinel/api/auth.py).

`_AUTH_ON`, `_TENANT`, `_AUDIENCE`, `_DEV_MODE` are computed once at module
import time from AZURE_TENANT_ID / AZURE_CLIENT_ID / SENTINEL_DEV_MODE, so
tests that need a different combination reload the module after setting the
env vars (see `_reload_auth` below) rather than hitting the real Microsoft
OIDC/JWKS endpoints. The real network call lives entirely in `_fetch_jwks()`;
the real signature/claims check lives entirely in `_verify_token()` — both
are module-level functions and both are exercised here via monkeypatching at
those exact seams, never by contacting login.microsoftonline.com.
"""

from __future__ import annotations

import base64
import importlib
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException


class _FakeRequest:
    """Duck-types the one thing require_auth touches on fastapi.Request:
    a mutable `.state` it stashes the resolved principal onto (CR-2)."""

    def __init__(self) -> None:
        self.state = SimpleNamespace()


def _reload_auth(
    monkeypatch,
    *,
    tenant: str | None,
    client_id: str | None,
    dev_mode: bool | None = None,
):
    """Reload sentinel.api.auth with given AZURE_TENANT_ID/AZURE_CLIENT_ID/SENTINEL_DEV_MODE."""
    if tenant is None:
        monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    else:
        monkeypatch.setenv("AZURE_TENANT_ID", tenant)
    if client_id is None:
        monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    else:
        monkeypatch.setenv("AZURE_CLIENT_ID", client_id)
    if dev_mode is None:
        monkeypatch.delenv("SENTINEL_DEV_MODE", raising=False)
    else:
        monkeypatch.setenv("SENTINEL_DEV_MODE", "1" if dev_mode else "0")

    import sentinel.api.auth as auth_module

    importlib.reload(auth_module)
    return auth_module


def _fake_jwt(kid: str = "kid-1") -> str:
    """A syntactically-valid (unsigned) JWT: real base64url header/payload
    segments so `jwt.get_unverified_header()` succeeds, garbage signature —
    only the header is ever read by these tests."""

    def _b64(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    header = _b64({"alg": "RS256", "typ": "JWT", "kid": kid})
    payload = _b64({"oid": "user-1"})
    return f"{header}.{payload}.sig"


@pytest.fixture(scope="module", autouse=True)
def _restore_module_state_after_file():
    """Leave sentinel.api.auth in dev-bypass state (this repo's baseline) once
    this file's tests are done, regardless of the last test's env reload, so
    later-imported test modules never see a stale auth-on module."""
    yield
    import os

    os.environ.pop("AZURE_TENANT_ID", None)
    os.environ.pop("AZURE_CLIENT_ID", None)
    os.environ["SENTINEL_DEV_MODE"] = "1"
    import sentinel.api.auth as auth_module

    importlib.reload(auth_module)


# ---- dev-bypass mode requires explicit opt-in (CR-13) ----------------------


def test_dev_bypass_mode_returns_dev_principal_when_explicitly_opted_in(monkeypatch):
    auth = _reload_auth(monkeypatch, tenant=None, client_id=None, dev_mode=True)
    assert auth._AUTH_ON is False
    assert auth._DEV_MODE is True

    req = _FakeRequest()
    principal = auth.require_auth(req, creds=None)

    assert principal is auth._DEV_PRINCIPAL
    assert principal.user_id == "dev-bypass"
    assert "sentinel.write" in principal.roles
    # CR-2: resolved principal is threaded onto request.state for the audit
    # middleware to read, never a client-supplied header.
    assert req.state.principal is auth._DEV_PRINCIPAL


def test_dev_bypass_mode_active_when_only_tenant_id_is_set_but_dev_mode_on(monkeypatch):
    auth = _reload_auth(monkeypatch, tenant="some-tenant", client_id=None, dev_mode=True)
    assert auth._AUTH_ON is False
    assert auth.require_auth(_FakeRequest(), creds=None) is auth._DEV_PRINCIPAL


def test_dev_bypass_mode_active_when_only_client_id_is_set_but_dev_mode_on(monkeypatch):
    auth = _reload_auth(monkeypatch, tenant=None, client_id="some-client", dev_mode=True)
    assert auth._AUTH_ON is False
    assert auth.require_auth(_FakeRequest(), creds=None) is auth._DEV_PRINCIPAL


# ---- omission (no Azure config, no explicit dev mode) fails closed (CR-13) -


def test_auth_unconfigured_and_no_dev_mode_rejects_every_request_with_503(monkeypatch):
    auth = _reload_auth(monkeypatch, tenant=None, client_id=None, dev_mode=False)
    assert auth._AUTH_ON is False
    assert auth._DEV_MODE is False

    with pytest.raises(HTTPException) as exc_info:
        auth.require_auth(_FakeRequest(), creds=None)

    assert exc_info.value.status_code == 503


def test_auth_unconfigured_and_dev_mode_unset_rejects_with_503(monkeypatch):
    """SENTINEL_DEV_MODE simply absent (not '0') must behave the same as
    explicitly '0' — omission must fail closed, not silently bypass."""
    auth = _reload_auth(monkeypatch, tenant=None, client_id=None, dev_mode=None)
    assert auth._AUTH_ON is False
    assert auth._DEV_MODE is False

    with pytest.raises(HTTPException) as exc_info:
        auth.require_auth(_FakeRequest(), creds=None)

    assert exc_info.value.status_code == 503


# ---- auth-on: missing Authorization header -> 401 --------------------------


def test_auth_on_missing_authorization_header_returns_401(monkeypatch):
    auth = _reload_auth(monkeypatch, tenant="tenant-1", client_id="client-1")
    assert auth._AUTH_ON is True

    with pytest.raises(HTTPException) as exc_info:
        auth.require_auth(_FakeRequest(), creds=None)

    assert exc_info.value.status_code == 401


# ---- auth-on: unrecognised roles -> 403 listing the recognised ones ---------


def test_auth_on_unrecognised_role_returns_403_listing_known_roles(monkeypatch):
    """`sentinel.read` is a real role since CR-20, so this uses a genuinely
    unknown one. `require_auth` now authenticates and checks the principal
    carries *some* Agent Sentinel role; per-endpoint authority is enforced by
    `require_roles`, covered below."""
    auth = _reload_auth(monkeypatch, tenant="tenant-1", client_id="client-1")
    monkeypatch.setattr(
        auth,
        "_verify_token",
        lambda token: {"oid": "user-1", "roles": ["some.unrelated.role"]},
    )

    with pytest.raises(HTTPException) as exc_info:
        auth.require_auth(_FakeRequest(), creds=SimpleNamespace(credentials="some-jwt"))

    assert exc_info.value.status_code == 403
    detail = exc_info.value.detail
    assert "sentinel.write" in detail
    assert "sentinel.admin" in detail


def test_auth_on_no_roles_claim_at_all_returns_403(monkeypatch):
    auth = _reload_auth(monkeypatch, tenant="tenant-1", client_id="client-1")
    monkeypatch.setattr(auth, "_verify_token", lambda token: {"oid": "user-1"})

    with pytest.raises(HTTPException) as exc_info:
        auth.require_auth(_FakeRequest(), creds=SimpleNamespace(credentials="some-jwt"))

    assert exc_info.value.status_code == 403


@pytest.mark.parametrize(
    "role", ["sentinel.read", "sentinel.write", "sentinel.approver", "sentinel.admin"]
)
def test_auth_on_any_recognised_role_is_sufficient_to_authenticate(monkeypatch, role):
    auth = _reload_auth(monkeypatch, tenant="tenant-1", client_id="client-1")
    monkeypatch.setattr(
        auth,
        "_verify_token",
        lambda token: {
            "oid": "user-1",
            "name": "Alice",
            "preferred_username": "alice@example.com",
            "roles": [role],
        },
    )

    req = _FakeRequest()
    principal = auth.require_auth(req, creds=SimpleNamespace(credentials="some-jwt"))

    assert principal.user_id == "user-1"
    assert principal.roles == [role]
    # CR-2: verified principal (not a client header) reaches request.state.
    assert req.state.principal is principal


# ---- _Principal.__str__ prefers email over user_id --------------------------


def test_principal_str_prefers_email_over_user_id(monkeypatch):
    auth = _reload_auth(monkeypatch, tenant=None, client_id=None, dev_mode=True)
    p = auth._Principal({"oid": "abc-123", "preferred_username": "user@example.com"})
    assert str(p) == "user@example.com"


def test_principal_str_falls_back_to_user_id_when_no_email(monkeypatch):
    auth = _reload_auth(monkeypatch, tenant=None, client_id=None, dev_mode=True)
    p = auth._Principal({"oid": "abc-123", "preferred_username": ""})
    assert str(p) == "abc-123"


def test_principal_str_falls_back_to_unknown_when_no_oid_or_email(monkeypatch):
    auth = _reload_auth(monkeypatch, tenant=None, client_id=None, dev_mode=True)
    p = auth._Principal({})
    assert str(p) == "unknown"
    assert p.user_id == "unknown"


# ---- deeper seam: _fetch_jwks() / _get_jwks() / _verify_token() with jose --
# These only run when the optional `auth` extra (python-jose[cryptography])
# is installed; they are skipped (not failed) in the default dev-extras CI
# job, matching the project's importorskip pattern for optional deps.


def test_fetch_jwks_fetches_discovery_then_jwks_document(monkeypatch):
    pytest.importorskip("jose")
    auth = _reload_auth(monkeypatch, tenant="tenant-1", client_id="client-1")

    discovery_url = (
        "https://login.microsoftonline.com/tenant-1/v2.0/.well-known/openid-configuration"
    )
    jwks_uri = "https://login.microsoftonline.com/tenant-1/discovery/v2.0/keys"

    class _FakeHTTPResponse:
        def __init__(self, payload: dict) -> None:
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps(self._payload).encode()

    responses = {
        discovery_url: _FakeHTTPResponse({"jwks_uri": jwks_uri}),
        jwks_uri: _FakeHTTPResponse({"keys": [{"kid": "abc"}]}),
    }

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", lambda url, timeout=10: responses[url])

    assert auth._fetch_jwks() == {"keys": [{"kid": "abc"}]}


def test_fetch_jwks_wraps_non_https_jwks_uri_as_runtime_error(monkeypatch):
    pytest.importorskip("jose")
    auth = _reload_auth(monkeypatch, tenant="tenant-1", client_id="client-1")

    import urllib.request

    class _FakeHTTPResponse:
        def __init__(self, payload: dict) -> None:
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps(self._payload).encode()

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda url, timeout=10: _FakeHTTPResponse({"jwks_uri": "http://evil.example.com/keys"}),
    )

    with pytest.raises(RuntimeError, match="non-https"):
        auth._fetch_jwks()


def test_fetch_jwks_wraps_network_failure_as_runtime_error(monkeypatch):
    pytest.importorskip("jose")
    auth = _reload_auth(monkeypatch, tenant="tenant-1", client_id="client-1")

    import urllib.request

    def _boom(url, timeout=10):
        raise OSError("network unreachable")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)

    with pytest.raises(RuntimeError, match="Cannot fetch JWKS"):
        auth._fetch_jwks()


def test_get_jwks_caches_and_only_refetches_after_ttl_or_force(monkeypatch):
    """CR-7: a bare lru_cache(maxsize=1) never refreshes for process
    lifetime. _get_jwks must reuse the cache within TTL, and support an
    explicit force-refresh (used on an unrecognized kid)."""
    auth = _reload_auth(monkeypatch, tenant="tenant-1", client_id="client-1")

    calls = {"n": 0}

    def _fake_fetch():
        calls["n"] += 1
        return {"keys": [{"kid": f"kid-{calls['n']}"}]}

    monkeypatch.setattr(auth, "_fetch_jwks", _fake_fetch)

    first = auth._get_jwks()
    second = auth._get_jwks()
    assert first == second
    assert calls["n"] == 1  # cached, no second network call

    forced = auth._get_jwks(force=True)
    assert calls["n"] == 2
    assert forced != first

    # simulate TTL expiry
    auth._jwks_state["fetched_at"] -= auth._JWKS_TTL_SECONDS + 1
    auth._get_jwks()
    assert calls["n"] == 3


def test_verify_token_refreshes_jwks_once_on_unrecognized_kid(monkeypatch):
    """CR-7: a token signed with a newly-rotated key (kid not in our cached
    JWKS) must trigger exactly one forced refresh before verification is
    attempted against the refreshed key set."""
    pytest.importorskip("jose")
    auth = _reload_auth(monkeypatch, tenant="tenant-1", client_id="client-1")

    jwks_versions = [{"keys": [{"kid": "old-kid"}]}, {"keys": [{"kid": "new-kid"}]}]
    calls = {"n": 0}

    def _fake_get_jwks(force: bool = False):
        if force:
            calls["n"] += 1
            return jwks_versions[1]
        return jwks_versions[0]

    monkeypatch.setattr(auth, "_get_jwks", _fake_get_jwks)

    from jose import jwt as jose_jwt

    seen_jwks = []

    def _fake_decode(token, jwks, **kwargs):
        seen_jwks.append(jwks)
        return {"oid": "u1", "roles": ["sentinel.write"]}

    monkeypatch.setattr(jose_jwt, "decode", _fake_decode)

    claims = auth._verify_token(_fake_jwt(kid="new-kid"))

    assert claims == {"oid": "u1", "roles": ["sentinel.write"]}
    assert calls["n"] == 1  # exactly one forced refresh
    assert seen_jwks[-1] == jwks_versions[1]  # verified against the refreshed set


def test_verify_token_does_not_refresh_when_kid_already_known(monkeypatch):
    pytest.importorskip("jose")
    auth = _reload_auth(monkeypatch, tenant="tenant-1", client_id="client-1")

    calls = {"forced": 0}

    def _fake_get_jwks(force: bool = False):
        if force:
            calls["forced"] += 1
        return {"keys": [{"kid": "known-kid"}]}

    monkeypatch.setattr(auth, "_get_jwks", _fake_get_jwks)

    from jose import jwt as jose_jwt

    monkeypatch.setattr(
        jose_jwt, "decode", lambda *a, **k: {"oid": "u1", "roles": ["sentinel.write"]}
    )

    auth._verify_token(_fake_jwt(kid="known-kid"))

    assert calls["forced"] == 0


def test_verify_token_returns_claims_from_jwt_decode(monkeypatch):
    pytest.importorskip("jose")
    auth = _reload_auth(monkeypatch, tenant="tenant-1", client_id="client-1")
    monkeypatch.setattr(auth, "_get_jwks", lambda force=False: {"keys": [{"kid": "kid-1"}]})

    from jose import jwt as jose_jwt

    monkeypatch.setattr(
        jose_jwt, "decode", lambda *a, **k: {"oid": "u1", "roles": ["sentinel.write"]}
    )

    claims = auth._verify_token(_fake_jwt())

    assert claims == {"oid": "u1", "roles": ["sentinel.write"]}


def test_verify_token_wraps_jwt_error_as_401(monkeypatch):
    pytest.importorskip("jose")
    auth = _reload_auth(monkeypatch, tenant="tenant-1", client_id="client-1")
    monkeypatch.setattr(auth, "_get_jwks", lambda force=False: {"keys": [{"kid": "kid-1"}]})

    from jose import JWTError
    from jose import jwt as jose_jwt

    def _boom(*a, **k):
        raise JWTError("signature verification failed")

    monkeypatch.setattr(jose_jwt, "decode", _boom)

    with pytest.raises(HTTPException) as exc_info:
        auth._verify_token(_fake_jwt())

    assert exc_info.value.status_code == 401


def test_verify_token_wraps_malformed_token_header_as_401(monkeypatch):
    pytest.importorskip("jose")
    auth = _reload_auth(monkeypatch, tenant="tenant-1", client_id="client-1")

    with pytest.raises(HTTPException) as exc_info:
        auth._verify_token("not-a-real-jwt")

    assert exc_info.value.status_code == 401


# ---- CR-20: require_roles enforces per-endpoint authority -------------------


def _principal(roles, **extra):
    from sentinel.api.auth import _Principal

    return _Principal({"oid": "u", "roles": list(roles), **extra})


def test_require_roles_allows_the_named_role():
    from sentinel.api.auth import ROLE_APPROVER, require_roles

    dep = require_roles(ROLE_APPROVER)
    principal = _principal(["sentinel.approver"])
    assert dep(principal=principal) is principal


def test_require_roles_rejects_a_role_it_does_not_name():
    from sentinel.api.auth import ROLE_APPROVER, require_roles

    dep = require_roles(ROLE_APPROVER)
    with pytest.raises(HTTPException) as exc_info:
        dep(principal=_principal(["sentinel.write"]))
    assert exc_info.value.status_code == 403


def test_admin_is_a_superset_of_every_role():
    from sentinel.api.auth import ROLE_APPROVER, ROLE_WRITE, require_roles

    admin = _principal(["sentinel.admin"])
    for role in (ROLE_APPROVER, ROLE_WRITE):
        assert require_roles(role)(principal=admin) is admin


# ---- CR-21: agent-identity binding on the principal -------------------------


def test_may_act_for_is_unconstrained_without_an_agent_ids_claim():
    p = _principal(["sentinel.write"])
    assert p.allowed_agent_ids is None
    assert p.may_act_for("anything-at-all")


def test_may_act_for_enforces_the_agent_ids_claim_when_present():
    p = _principal(["sentinel.write"], agent_ids=["recon-bot", "kyc-bot"])
    assert p.may_act_for("recon-bot")
    assert p.may_act_for("kyc-bot")
    assert not p.may_act_for("payments-bot")


def test_empty_agent_ids_claim_permits_nothing():
    """An explicitly empty allow-list is a constraint, not an absence of one."""
    p = _principal(["sentinel.write"], agent_ids=[])
    assert p.allowed_agent_ids == set()
    assert not p.may_act_for("recon-bot")


def test_malformed_agent_ids_claim_is_treated_as_absent_not_as_empty():
    """A string where a list was expected must not silently become a
    character-by-character allow-list."""
    p = _principal(["sentinel.write"], agent_ids="recon-bot")
    assert p.allowed_agent_ids is None
