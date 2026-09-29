"""Base reporter shared by all SDK-level interceptors.

Every SDK wrapper (Azure OpenAI, Anthropic, …) holds a SentinelReporter and
calls .report() after each intercepted call.  Failures are silently swallowed
so a Sentinel outage never blocks the agent it is protecting (fail-open).

The reporter serialises events in the same FlowIn shape that the HTTP /ingest
endpoint expects, so no new schema is needed.
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Callable

from sentinel.collector.redaction import redact_text

logger = logging.getLogger("sentinel.collector.sdk")


@dataclass
class SentinelReporter:
    agent_id: str
    session_id: str
    sentinel_api: str = "http://localhost:8000"
    auth_token: str | None = None
    token_provider: Callable[[], str] | None = None

    def report(
        self,
        *,
        host: str,
        method: str = "POST",
        path: str = "/",
        request_body: str | None = None,
        response_body: str | None = None,
        status_code: int = 200,
    ) -> dict:
        """POST one event to Sentinel.  Returns the ingest response or {} on error."""
        payload = {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "host": host,
            "method": method,
            "path": path,
            # Redact at the collection edge so sensitive values are not sent
            # over the wire to Sentinel in the first place.
            "request_body": redact_text(request_body) if request_body is not None else None,
            "response_body": redact_text(response_body) if response_body is not None else None,
            "status_code": status_code,
        }
        try:
            # bandit B310: sentinel_api is a deployment-time constructor arg
            # (operator config), never attacker-controlled — validated anyway
            # so a misconfiguration can't reach file:/ or another scheme.
            if not self.sentinel_api.startswith(("http://", "https://")):
                raise ValueError(f"Refusing to report to non-http(s) URL: {self.sentinel_api!r}")
            data = json.dumps(payload).encode()
            headers = {"Content-Type": "application/json"}
            token = self.token_provider() if self.token_provider is not None else self.auth_token
            if token:
                headers["Authorization"] = f"Bearer {token}"
            req = urllib.request.Request(
                f"{self.sentinel_api.rstrip('/')}/ingest",
                data=data,
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=2) as r:  # nosec B310 — scheme validated above
                return json.loads(r.read().decode())
        except Exception as exc:
            logger.warning(
                "sentinel telemetry delivery failed: endpoint=%s error=%s",
                self.sentinel_api,
                type(exc).__name__,
            )
            return {}

    def report_tool_call(self, *, host: str, tool_name: str, args: str | dict) -> dict:
        """Report an MCP/function tool invocation as a TOOL_CALL event."""
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:
                args = {"raw": args}
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": args},
            }
        )
        return self.report(host=host, method="POST", path="/mcp/tools/call", request_body=body)

    def report_tool_request(self, *, host: str, tool_name: str, args: str | dict) -> dict:
        """Report a model-proposed tool request; this does not assert execution."""
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:
                args = {"raw": args}
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "tools/requested",
                "params": {"name": tool_name, "arguments": args},
            }
        )
        return self.report(
            host=host, method="POST", path="/model/tool-requested", request_body=body
        )
