"""mitmproxy addon: transparent egress capture for AI agents.

Run agents behind this proxy and every outbound HTTP(S) flow is normalized and
POSTed to the Sentinel collector. This is the production interception front-end;
the core pipeline is transport-agnostic so an SDK hook or eBPF probe could feed
the same /ingest endpoint.

Usage:
    mitmdump -s app/sentinel/collector/proxy.py \
        --set sentinel_url=http://localhost:8000/ingest \
        --set agent_id=recon-bot --set session_id=run-001
"""

from __future__ import annotations

import json
import os
import urllib.request

from sentinel.collector.redaction import redact_text

# mitmproxy is an optional runtime dependency (`pip install 'agent-sentinel[proxy]'`);
# this module is never imported by the core package, only loaded by `mitmdump -s`
# itself (see module docstring), so mitmproxy is always present when this actually
# runs. No stub package exists on PyPI, so a narrow ignore is the correct fix here.
from mitmproxy import ctx, http  # type: ignore[import-not-found]


class SentinelCapture:
    def load(self, loader) -> None:
        loader.add_option(
            "sentinel_url",
            str,
            os.environ.get("SENTINEL_URL", "http://localhost:8000/ingest"),
            "Sentinel collector ingest URL",
        )
        loader.add_option(
            "agent_id",
            str,
            os.environ.get("AGENT_ID", "unknown"),
            "Stable identity of the monitored agent",
        )
        loader.add_option(
            "session_id", str, os.environ.get("SESSION_ID", "session"), "Current run/session id"
        )
        loader.add_option(
            "sentinel_token",
            str,
            os.environ.get("SENTINEL_AUTH_TOKEN", ""),
            "Bearer token for the Sentinel ingest API",
        )

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            payload = {
                "agent_id": ctx.options.agent_id,
                "session_id": ctx.options.session_id,
                "host": flow.request.host,
                "method": flow.request.method,
                "path": flow.request.path,
                "request_body": redact_text(flow.request.get_text(strict=False))[:8192],
                "response_body": (
                    redact_text(flow.response.get_text(strict=False))[:4096]
                    if flow.response
                    else None
                ),
                "status_code": flow.response.status_code if flow.response else None,
            }
            # bandit B310: sentinel_url is a mitmdump --set operator flag, never
            # attacker-controlled — validated anyway so a misconfiguration can't
            # reach file:/ or another scheme.
            if not ctx.options.sentinel_url.startswith(("http://", "https://")):
                raise ValueError(
                    f"Refusing to POST to non-http(s) URL: {ctx.options.sentinel_url!r}"
                )
            data = json.dumps(payload).encode()
            headers = {"Content-Type": "application/json"}
            if ctx.options.sentinel_token:
                headers["Authorization"] = f"Bearer {ctx.options.sentinel_token}"
            req = urllib.request.Request(
                ctx.options.sentinel_url,
                data=data,
                headers=headers,
                method="POST",
            )
            urllib.request.urlopen(req, timeout=2)  # nosec B310 — scheme validated above
        except Exception as exc:  # never break the agent's traffic
            ctx.log.warn(f"sentinel capture failed: {exc}")


addons = [SentinelCapture()]
