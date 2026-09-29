"""Anthropic SDK interceptor — Phase 2 collector.

Drop-in replacement for ``anthropic.Anthropic``.  Every messages.create() call
and embedded tool_use block is reported to Sentinel automatically.

Install:
    pip install "agent-sentinel[anthropic]"

Usage::

    from sentinel.collector.anthropic_sdk import AnthropicSentinel

    client = AnthropicSentinel(
        api_key=os.environ["ANTHROPIC_API_KEY"],
        # Sentinel kwargs:
        agent_id="kyc-agent",
        session_id="sess-20240601",
        sentinel_api="http://localhost:8000",
    )

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=512,
        messages=[{"role": "user", "content": "Verify identity for customer #8821."}],
    )
"""

from __future__ import annotations

import json
from typing import Any

from sentinel.collector.sdk_base import SentinelReporter

_ANTHROPIC_HOST = "api.anthropic.com"


# ── Proxy wrappers ────────────────────────────────────────────────────────────


class _MessagesSentinel:
    """Intercepts messages.create() calls."""

    def __init__(self, messages: Any, reporter: SentinelReporter) -> None:
        self._messages = messages
        self._rep = reporter

    def create(self, *, model: str, messages: list[dict], max_tokens: int, **kwargs: Any) -> Any:
        req_body = _serialise_request(model, messages, max_tokens, kwargs)
        response = self._messages.create(
            model=model, messages=messages, max_tokens=max_tokens, **kwargs
        )

        self._rep.report(
            host=_ANTHROPIC_HOST,
            method="POST",
            path="/v1/messages",
            request_body=req_body,
            response_body=_serialise_response(response),
            status_code=200,
        )
        _report_tool_use(response, self._rep)
        return response


class _AsyncMessagesSentinel:
    """Async SDK surface: callers use ``await client.messages.create``."""

    def __init__(self, messages: Any, reporter: SentinelReporter) -> None:
        self._messages = messages
        self._rep = reporter

    async def create(
        self, *, model: str, messages: list[dict], max_tokens: int, **kwargs: Any
    ) -> Any:
        req_body = _serialise_request(model, messages, max_tokens, kwargs)
        response = await self._messages.create(
            model=model, messages=messages, max_tokens=max_tokens, **kwargs
        )
        self._rep.report(
            host=_ANTHROPIC_HOST,
            method="POST",
            path="/v1/messages",
            request_body=req_body,
            response_body=_serialise_response(response),
            status_code=200,
        )
        _report_tool_use(response, self._rep)
        return response

    async def acreate(
        self, *, model: str, messages: list[dict], max_tokens: int, **kwargs: Any
    ) -> Any:
        req_body = _serialise_request(model, messages, max_tokens, kwargs)
        response = await self._messages.create(
            model=model, messages=messages, max_tokens=max_tokens, **kwargs
        )
        self._rep.report(
            host=_ANTHROPIC_HOST,
            method="POST",
            path="/v1/messages",
            request_body=req_body,
            response_body=_serialise_response(response),
            status_code=200,
        )
        _report_tool_use(response, self._rep)
        return response


# ── Public wrapper ────────────────────────────────────────────────────────────


class AnthropicSentinel:
    """Wraps Anthropic messages.create() and reports covered calls to Sentinel.

    Sentinel-specific identity, endpoint, and auth-token kwargs are consumed by
    this wrapper; remaining kwargs are forwarded to ``anthropic.Anthropic``.
    """

    def __init__(
        self,
        *,
        agent_id: str,
        session_id: str = "default",
        sentinel_api: str = "http://localhost:8000",
        sentinel_auth_token: str | None = None,
        sentinel_token_provider: Any = None,
        **anthropic_kwargs: Any,
    ) -> None:
        try:
            # anthropic is an optional extra (`pip install 'agent-sentinel[anthropic]'`);
            # this lazy import is the documented seam that keeps it out of core
            # deps, so a missing-in-this-env import is expected, not a code bug.
            import anthropic  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ImportError(
                "Install the Anthropic extra:  pip install 'agent-sentinel[anthropic]'"
            ) from exc

        self._client = anthropic.Anthropic(**anthropic_kwargs)
        self._reporter = SentinelReporter(
            agent_id=agent_id,
            session_id=session_id,
            sentinel_api=sentinel_api,
            auth_token=sentinel_auth_token,
            token_provider=sentinel_token_provider,
        )
        self.messages = _MessagesSentinel(self._client.messages, self._reporter)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class AsyncAnthropicSentinel:
    """Async variant — wraps ``anthropic.AsyncAnthropic``."""

    def __init__(
        self,
        *,
        agent_id: str,
        session_id: str = "default",
        sentinel_api: str = "http://localhost:8000",
        sentinel_auth_token: str | None = None,
        sentinel_token_provider: Any = None,
        **anthropic_kwargs: Any,
    ) -> None:
        try:
            import anthropic
        except ImportError as exc:
            raise ImportError(
                "Install the Anthropic extra:  pip install 'agent-sentinel[anthropic]'"
            ) from exc

        self._client = anthropic.AsyncAnthropic(**anthropic_kwargs)
        self._reporter = SentinelReporter(
            agent_id=agent_id,
            session_id=session_id,
            sentinel_api=sentinel_api,
            auth_token=sentinel_auth_token,
            token_provider=sentinel_token_provider,
        )
        self.messages = _AsyncMessagesSentinel(self._client.messages, self._reporter)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _serialise_request(model: str, messages: list, max_tokens: int, kwargs: dict) -> str:
    return json.dumps(
        {"model": model, "messages": messages, "max_tokens": max_tokens, **kwargs},
        default=str,
    )[:8192]


def _serialise_response(response: Any) -> str:
    try:
        return response.model_dump_json()[:4096]
    except Exception:
        return str(response)[:4096]


def _report_tool_use(response: Any, reporter: SentinelReporter) -> None:
    """Report Anthropic tool_use blocks as requested, not executed, tools."""
    try:
        for block in response.content:
            if getattr(block, "type", None) == "tool_use":
                reporter.report_tool_request(
                    host=_ANTHROPIC_HOST,
                    tool_name=block.name,
                    args=block.input if isinstance(block.input, dict) else {},
                )
    except Exception:
        pass
