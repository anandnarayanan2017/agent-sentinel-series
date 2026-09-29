"""Webhook alerter — fires on HIGH/CRITICAL findings.

Supported targets (configured via env vars):
  ALERT_TEAMS_WEBHOOK    — Microsoft Teams Incoming Webhook URL
  ALERT_PAGERDUTY_KEY    — PagerDuty Events API v2 routing key
  ALERT_SLACK_WEBHOOK    — Slack Incoming Webhook URL

Severity threshold:
  ALERT_MIN_SEVERITY     — minimum severity to fire (default: high)

Fail-open: any delivery failure is logged to stderr but never re-raised.
The sentinel pipeline is never blocked by a failed alert.

Each alert carries:
  - finding_id, rule_id, severity
  - title + explanation (human-readable)
  - agent_id, control_refs (DORA/CSSF compliance codes)
  - direct link to the dashboard finding
  - SHA-256 fingerprint of the evidence chain (for SOC audit trail)
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from typing import Any

from sentinel.schema.events import Finding

_MIN_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_THRESHOLD = os.environ.get("ALERT_MIN_SEVERITY", "high")
_DASHBOARD_URL = os.environ.get("SENTINEL_DASHBOARD_URL", "http://localhost:8000")

_TEAMS_WEBHOOK = os.environ.get("ALERT_TEAMS_WEBHOOK", "")
_PAGERDUTY_KEY = os.environ.get("ALERT_PAGERDUTY_KEY", "")
_SLACK_WEBHOOK = os.environ.get("ALERT_SLACK_WEBHOOK", "")


def _evidence_fingerprint(finding: Finding) -> str:
    raw = json.dumps([e.model_dump() for e in finding.evidence], sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _severity_emoji(sev: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(
        sev, "⚪"
    )


def _should_alert(finding: Finding) -> bool:
    return _MIN_SEV_ORDER.get(finding.severity.value, 0) >= _MIN_SEV_ORDER.get(_THRESHOLD, 3)


def _post(url: str, payload: dict[str, Any], headers: dict[str, str] | None = None) -> None:
    # bandit B310: url is always an operator-configured webhook (env var) or the
    # hardcoded PagerDuty endpoint, never attacker-controlled request data — but
    # validate the scheme anyway so a misconfigured env var can't reach file:/
    # or another unexpected scheme via urlopen.
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"Refusing to POST to non-http(s) URL: {url!r}")
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=5)  # nosec B310 — scheme validated above


# ── Teams ─────────────────────────────────────────────────────────────────────


def _alert_teams(finding: Finding) -> None:
    sev = finding.severity.value
    fp = _evidence_fingerprint(finding)
    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": "D13438" if sev == "critical" else "FFA500",
        "summary": finding.title,
        "sections": [
            {
                "activityTitle": f"{_severity_emoji(sev)} [{sev.upper()}] {finding.title}",
                "activitySubtitle": f"Agent: `{finding.agent_id}` · Rule: `{finding.rule_id}`",
                "facts": [
                    {"name": "Explanation", "value": finding.explanation},
                    {"name": "Controls", "value": ", ".join(finding.control_refs) or "—"},
                    {"name": "Finding ID", "value": finding.finding_id},
                    {"name": "Evidence SHA", "value": fp},
                    {"name": "Timestamp", "value": str(finding.ts)},
                ],
                "markdown": True,
            }
        ],
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": "Open Dashboard",
                "targets": [
                    {"os": "default", "uri": f"{_DASHBOARD_URL}/#finding-{finding.finding_id}"}
                ],
            }
        ],
    }
    _post(_TEAMS_WEBHOOK, payload)


# ── PagerDuty ─────────────────────────────────────────────────────────────────


def _alert_pagerduty(finding: Finding) -> None:
    sev = finding.severity.value
    pg_sev = {"critical": "critical", "high": "error", "medium": "warning"}.get(sev, "info")
    payload = {
        "routing_key": _PAGERDUTY_KEY,
        "event_action": "trigger",
        "dedup_key": finding.finding_id,
        "payload": {
            "summary": f"[{sev.upper()}] {finding.title} — {finding.agent_id}",
            "source": "agent-sentinel",
            "severity": pg_sev,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": finding.agent_id,
            "group": finding.rule_id,
            "class": "behavioral-firewall",
            "custom_details": {
                "explanation": finding.explanation,
                "control_refs": finding.control_refs,
                "finding_id": finding.finding_id,
                "evidence_fp": _evidence_fingerprint(finding),
                "dashboard": f"{_DASHBOARD_URL}/#finding-{finding.finding_id}",
            },
        },
    }
    _post("https://events.pagerduty.com/v2/enqueue", payload)


# ── Slack ─────────────────────────────────────────────────────────────────────


def _alert_slack(finding: Finding) -> None:
    sev = finding.severity.value
    fp = _evidence_fingerprint(finding)
    color = {"critical": "#D13438", "high": "#FFA500", "medium": "#FFC300"}.get(sev, "#36A2EB")
    payload = {
        "attachments": [
            {
                "color": color,
                "title": f"{_severity_emoji(sev)} [{sev.upper()}] {finding.title}",
                "title_link": f"{_DASHBOARD_URL}/#finding-{finding.finding_id}",
                "fields": [
                    {"title": "Agent", "value": finding.agent_id, "short": True},
                    {"title": "Rule", "value": finding.rule_id, "short": True},
                    {
                        "title": "Controls",
                        "value": ", ".join(finding.control_refs) or "—",
                        "short": True,
                    },
                    {"title": "Evidence SHA", "value": fp, "short": True},
                    {"title": "Explanation", "value": finding.explanation, "short": False},
                ],
                "footer": "Agent Sentinel",
                "ts": int(finding.ts.timestamp()),
            }
        ]
    }
    _post(_SLACK_WEBHOOK, payload)


# ── Public interface ──────────────────────────────────────────────────────────


def fire(finding: Finding) -> None:
    """Dispatch alerts for a finding.  Never raises."""
    if not _should_alert(finding):
        return

    errors: list[str] = []

    if _TEAMS_WEBHOOK:
        try:
            _alert_teams(finding)
        except Exception as exc:
            errors.append(f"teams: {exc}")

    if _PAGERDUTY_KEY:
        try:
            _alert_pagerduty(finding)
        except Exception as exc:
            errors.append(f"pagerduty: {exc}")

    if _SLACK_WEBHOOK:
        try:
            _alert_slack(finding)
        except Exception as exc:
            errors.append(f"slack: {exc}")

    if errors:
        print(f"[sentinel:alerter] delivery failures: {errors}", file=sys.stderr)
