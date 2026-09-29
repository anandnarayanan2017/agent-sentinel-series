"""Parsers: raw captured traffic -> normalized AgentEvent.

The collector (proxy/SDK/eBPF) hands us provider-shaped payloads; these
functions translate the major shapes into the single normalized schema. Keeping
this isolated means adding a new provider is a one-function change.

All parsers are defensive: malformed/partial payloads degrade to a generic
NETWORK_CALL rather than raising, because a monitoring tool must never crash on
hostile input.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from sentinel.schema.events import ActionType, AgentEvent, Direction

# Hosts we recognise as model providers (exact match).
LLM_HOSTS = {
    "api.anthropic.com": "anthropic",
    "api.openai.com": "openai",
}

# Suffix patterns for cloud-hosted endpoints (e.g. acme.openai.azure.com).
_LLM_SUFFIXES: list[tuple[str, str]] = [
    (".openai.azure.com", "azure_openai"),
    (".api.cognitive.microsoft.com", "azure_cognitive"),
    (".inference.ai.azure.com", "azure_ai_studio"),
    ("bedrock-runtime.amazonaws.com", "aws_bedrock"),
    (".generativelanguage.googleapis.com", "google_gemini"),
]


def _classify_host(host: str) -> str | None:
    """Return provider name for a hostname, or None if not an LLM endpoint."""
    if host in LLM_HOSTS:
        return LLM_HOSTS[host]
    for suffix, provider in _LLM_SUFFIXES:
        if host.endswith(suffix):
            return provider
    return None


_REDACT_PREVIEW = 256  # chars kept AFTER best-effort sensitive-value redaction


def _safe_json(body: bytes | str | None) -> Optional[dict[str, Any]]:
    if not body:
        return None
    try:
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def parse_flow(
    *,
    agent_id: str,
    session_id: str,
    host: str,
    method: str,
    path: str,
    request_body: bytes | str | None = None,
    response_body: bytes | str | None = None,
    status_code: Optional[int] = None,
) -> AgentEvent:
    """Top-level entry: classify a single captured HTTP flow."""

    provider = _classify_host(host)
    body = _safe_json(request_body)

    # Tool telemetry uses JSON-RPC regardless of the transport host. Check it
    # before provider classification; model-proposed tool requests are often
    # reported with the model provider's hostname.
    if body and body.get("jsonrpc") == "2.0" and "method" in body:
        return _parse_mcp_call(
            agent_id=agent_id,
            session_id=session_id,
            host=host,
            method=method,
            path=path,
            body=body,
            status_code=status_code,
        )

    if provider:
        return _parse_llm_call(
            agent_id=agent_id,
            session_id=session_id,
            host=host,
            method=method,
            path=path,
            provider=provider,
            body=body,
            request_body=request_body,
            response_body=response_body,
            status_code=status_code,
        )

    return _parse_network_call(
        agent_id=agent_id,
        session_id=session_id,
        host=host,
        method=method,
        path=path,
        request_body=request_body,
        response_body=response_body,
        status_code=status_code,
    )


def _parse_llm_call(
    *,
    agent_id,
    session_id,
    host,
    method,
    path,
    provider,
    body,
    request_body,
    response_body,
    status_code,
) -> AgentEvent:
    model = (body or {}).get("model")
    ev = AgentEvent(
        agent_id=agent_id,
        session_id=session_id,
        action=ActionType.LLM_CALL,
        direction=Direction.EGRESS,
        host=host,
        method=method,
        path=path,
        model=model,
        bytes_out=_blen(request_body),
        bytes_in=_blen(response_body),
        attributes={"provider": provider, "status_code": status_code},
    )
    # Evidence: best-effort-redacted, bounded prompt preview for context.
    msgs = (body or {}).get("messages")
    if msgs:
        ev.add_evidence("prompt_preview", _preview(json.dumps(msgs)), redacted=True)
        ev.attributes["message_count"] = len(msgs)
    return ev


def _parse_mcp_call(*, agent_id, session_id, host, method, path, body, status_code) -> AgentEvent:
    rpc_method = body.get("method", "")
    params = body.get("params", {}) or {}
    tool_name = params.get("name") or rpc_method
    ev = AgentEvent(
        agent_id=agent_id,
        session_id=session_id,
        action=(
            ActionType.TOOL_REQUESTED if rpc_method == "tools/requested" else ActionType.TOOL_CALL
        ),
        direction=Direction.EGRESS,
        host=host,
        method=method,
        path=path,
        tool_name=tool_name,
        attributes={"rpc_method": rpc_method, "status_code": status_code},
    )
    if params.get("arguments"):
        ev.add_evidence("tool_args", _preview(json.dumps(params["arguments"])), redacted=True)
    return ev


def _parse_network_call(
    *, agent_id, session_id, host, method, path, request_body, response_body, status_code
) -> AgentEvent:
    ev = AgentEvent(
        agent_id=agent_id,
        session_id=session_id,
        action=ActionType.NETWORK_CALL,
        direction=Direction.EGRESS,
        host=host,
        method=method,
        path=path,
        bytes_out=_blen(request_body),
        bytes_in=_blen(response_body),
        attributes={"status_code": status_code},
    )
    if request_body:
        ev.add_evidence("body_preview", _preview(request_body), redacted=True)
    return ev


def _blen(b: bytes | str | None) -> int:
    if b is None:
        return 0
    return len(b if isinstance(b, (bytes, bytearray)) else b.encode("utf-8"))


def _preview(s: bytes | str) -> str:
    """Redact sensitive values, THEN truncate — see collector/redaction.py.

    The order is the point. Truncating first would crop a secret out of the
    preview while leaving it in the text the redactor never saw; redacting
    first removes it wherever it sits in the payload. Truncation alone is not
    redaction, and the evidence this produces is flagged `redacted=True`
    (CR-25).
    """
    from sentinel.collector.redaction import redact_text

    if isinstance(s, (bytes, bytearray)):
        s = s.decode("utf-8", errors="replace")
    return redact_text(s)[:_REDACT_PREVIEW]
