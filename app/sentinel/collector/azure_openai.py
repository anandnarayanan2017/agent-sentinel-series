"""Azure OpenAI SDK interceptor — Phase 2 collector.

Drop-in replacement for ``openai.AzureOpenAI``.  Every chat completion and
tool call is forwarded to Sentinel before being returned to the caller.
If Sentinel is unreachable the call succeeds normally (fail-open).

Install:
    pip install "agent-sentinel[azure]"

Usage::

    from sentinel.collector.azure_openai import AzureOpenAISentinel

    client = AzureOpenAISentinel(
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        api_key=os.environ["AZURE_OPENAI_KEY"],
        api_version="2024-12-01-preview",
        # Sentinel kwargs:
        agent_id="payment-processor",
        session_id="sess-001",
        sentinel_api="http://localhost:8000",
    )

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Check balance for IBAN DE89…"}],
    )
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from sentinel.collector.sdk_base import SentinelReporter


# ── Proxy wrappers ────────────────────────────────────────────────────────────


class _CompletionsSentinel:
    """Intercepts chat.completions.create() calls."""

    def __init__(self, completions: Any, reporter: SentinelReporter, host: str) -> None:
        self._completions = completions
        self._rep = reporter
        self._host = host

    def create(self, *, model: str, messages: list[dict], **kwargs: Any) -> Any:
        req_body = _serialise_request(model, messages, kwargs)
        response = self._completions.create(model=model, messages=messages, **kwargs)

        self._rep.report(
            host=self._host,
            method="POST",
            path=f"/openai/deployments/{model}/chat/completions",
            request_body=req_body,
            response_body=_serialise_response(response),
            status_code=200,
        )
        _report_tool_requests(response, self._rep, self._host)
        return response

    async def acreate(self, *, model: str, messages: list[dict], **kwargs: Any) -> Any:
        req_body = _serialise_request(model, messages, kwargs)
        response = await self._completions.create(model=model, messages=messages, **kwargs)
        self._rep.report(
            host=self._host,
            method="POST",
            path=f"/openai/deployments/{model}/chat/completions",
            request_body=req_body,
            response_body=_serialise_response(response),
            status_code=200,
        )
        _report_tool_requests(response, self._rep, self._host)
        return response


class _ChatSentinel:
    def __init__(self, chat: Any, reporter: SentinelReporter, host: str) -> None:
        self.completions = _CompletionsSentinel(chat.completions, reporter, host)


class _AsyncCompletionsSentinel:
    """Async SDK surface: callers still use ``await ...completions.create``."""

    def __init__(self, completions: Any, reporter: SentinelReporter, host: str) -> None:
        self._completions = completions
        self._rep = reporter
        self._host = host

    async def create(self, *, model: str, messages: list[dict], **kwargs: Any) -> Any:
        req_body = _serialise_request(model, messages, kwargs)
        response = await self._completions.create(model=model, messages=messages, **kwargs)
        self._rep.report(
            host=self._host,
            method="POST",
            path=f"/openai/deployments/{model}/chat/completions",
            request_body=req_body,
            response_body=_serialise_response(response),
            status_code=200,
        )
        _report_tool_requests(response, self._rep, self._host)
        return response


class _AsyncChatSentinel:
    def __init__(self, chat: Any, reporter: SentinelReporter, host: str) -> None:
        self.completions = _AsyncCompletionsSentinel(chat.completions, reporter, host)


# ── Public wrapper ────────────────────────────────────────────────────────────


class AzureOpenAISentinel:
    """Wraps Azure OpenAI chat completions and reports covered calls to Sentinel.

    Sentinel-specific identity, endpoint, and auth-token kwargs are consumed by
    this wrapper; remaining kwargs are forwarded to ``openai.AzureOpenAI``.
    """

    def __init__(
        self,
        *,
        agent_id: str,
        session_id: str = "default",
        sentinel_api: str = "http://localhost:8000",
        sentinel_auth_token: str | None = None,
        sentinel_token_provider: Any = None,
        **azure_kwargs: Any,
    ) -> None:
        try:
            # openai is an optional extra (`pip install 'agent-sentinel[azure]'`);
            # this lazy import is the documented seam that keeps it out of core
            # deps, so a missing-in-this-env import is expected, not a code bug.
            from openai import AzureOpenAI  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ImportError(
                "Install the Azure extra:  pip install 'agent-sentinel[azure]'"
            ) from exc

        self._client = AzureOpenAI(**azure_kwargs)
        self._reporter = SentinelReporter(
            agent_id=agent_id,
            session_id=session_id,
            sentinel_api=sentinel_api,
            auth_token=sentinel_auth_token,
            token_provider=sentinel_token_provider,
        )
        endpoint = azure_kwargs.get("azure_endpoint", "")
        self._host = urlparse(endpoint).hostname or "api.openai.azure.com"
        self.chat = _ChatSentinel(self._client.chat, self._reporter, self._host)

    # Expose the underlying client for anything we don't wrap yet
    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class AsyncAzureOpenAISentinel:
    """Async variant — wraps ``openai.AsyncAzureOpenAI``."""

    def __init__(
        self,
        *,
        agent_id: str,
        session_id: str = "default",
        sentinel_api: str = "http://localhost:8000",
        sentinel_auth_token: str | None = None,
        sentinel_token_provider: Any = None,
        **azure_kwargs: Any,
    ) -> None:
        try:
            from openai import AsyncAzureOpenAI
        except ImportError as exc:
            raise ImportError(
                "Install the Azure extra:  pip install 'agent-sentinel[azure]'"
            ) from exc

        self._client = AsyncAzureOpenAI(**azure_kwargs)
        self._reporter = SentinelReporter(
            agent_id=agent_id,
            session_id=session_id,
            sentinel_api=sentinel_api,
            auth_token=sentinel_auth_token,
            token_provider=sentinel_token_provider,
        )
        endpoint = azure_kwargs.get("azure_endpoint", "")
        self._host = urlparse(endpoint).hostname or "api.openai.azure.com"
        self.chat = _AsyncChatSentinel(self._client.chat, self._reporter, self._host)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _serialise_request(model: str, messages: list, kwargs: dict) -> str:
    safe = {k: v for k, v in kwargs.items() if k not in ("stream",)}
    return json.dumps({"model": model, "messages": messages, **safe}, default=str)[:8192]


def _serialise_response(response: Any) -> str:
    try:
        return response.model_dump_json()[:4096]
    except Exception:
        return str(response)[:4096]


def _report_tool_requests(response: Any, reporter: SentinelReporter, host: str) -> None:
    """Report model-proposed tool calls without claiming they executed."""
    try:
        for choice in response.choices:
            for tc in choice.message.tool_calls or []:
                reporter.report_tool_request(
                    host=host,
                    tool_name=tc.function.name,
                    args=tc.function.arguments,
                )
    except Exception:
        pass
