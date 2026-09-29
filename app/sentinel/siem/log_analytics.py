"""Azure Monitor / Log Analytics ingestion connector (SIEM Phase 3).

Pushes findings to a Log Analytics workspace so Microsoft Sentinel
(or any KQL-based SOC tooling) can query them alongside other security signals.

Configuration (env vars):
  AZURE_LOG_ANALYTICS_DCE          — Data Collection Endpoint URL
  AZURE_LOG_ANALYTICS_DCR_ID       — Data Collection Rule immutable ID
  AZURE_LOG_ANALYTICS_STREAM       — Custom stream name (e.g. Custom-AgentSentinelFindings_CL)
  AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET  — service principal for auth

Activation:
  pip install 'agent-sentinel[siem]'
  Set the three AZURE_LOG_ANALYTICS_* vars → connector activates automatically.

Schema pushed to Log Analytics (each finding becomes one row):
  TimeGenerated, FindingId, AgentId, SessionId, RuleId, Title, Severity,
  Explanation, PolicyClause, ControlRefs, EvidenceFP, FindingUrl

Retention:
  Configure workspace retention from the entity's legal, risk, investigation,
  and evidence requirements. DORA Article 25 concerns operational-resilience
  testing; it does not impose a blanket five-year log-retention period.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any

from sentinel.schema.events import Finding

_DCE = os.environ.get("AZURE_LOG_ANALYTICS_DCE", "")
_DCR_ID = os.environ.get("AZURE_LOG_ANALYTICS_DCR_ID", "")
_STREAM = os.environ.get("AZURE_LOG_ANALYTICS_STREAM", "Custom-AgentSentinelFindings_CL")
_ACTIVE = bool(_DCE and _DCR_ID)
_DASHBOARD = os.environ.get("SENTINEL_DASHBOARD_URL", "http://localhost:8000")


def _get_client():
    """Lazy-load the Azure SDK client (only if siem extra is installed)."""
    try:
        # azure-identity / azure-monitor-ingestion are optional extras
        # (`pip install 'agent-sentinel[siem]'`); this lazy import is the
        # documented seam that keeps them out of core deps, so a
        # missing-in-this-env import is expected, not a code bug.
        from azure.identity import ClientSecretCredential  # type: ignore[import-not-found]
        from azure.monitor.ingestion import LogsIngestionClient  # type: ignore[import-not-found]
    except ImportError:
        raise RuntimeError(
            "Azure Monitor SDK not installed — run: pip install 'agent-sentinel[siem]'"
        )
    tenant = os.environ["AZURE_TENANT_ID"]
    client_id = os.environ["AZURE_CLIENT_ID"]
    secret = os.environ["AZURE_CLIENT_SECRET"]
    cred = ClientSecretCredential(tenant_id=tenant, client_id=client_id, client_secret=secret)
    return LogsIngestionClient(endpoint=_DCE, credential=cred)


_client = None


def _finding_to_row(f: Finding) -> dict[str, Any]:
    fp = hashlib.sha256(
        json.dumps([e.model_dump() for e in f.evidence], sort_keys=True).encode()
    ).hexdigest()[:16]
    return {
        "TimeGenerated": f.ts.isoformat(),
        "FindingId": f.finding_id,
        "AgentId": f.agent_id,
        "SessionId": f.session_id,
        "RuleId": f.rule_id,
        "Title": f.title,
        "Severity": f.severity.value,
        "Explanation": f.explanation,
        "PolicyClause": f.policy_clause or "",
        "SeverityRationale": f.severity_rationale,
        "ControlRefs": json.dumps(f.control_refs),
        "EvidenceFP": fp,
        "FindingUrl": f"{_DASHBOARD}/#finding-{f.finding_id}",
    }


def push(finding: Finding) -> None:
    """Push one finding to Azure Log Analytics.  Never raises (fail-open)."""
    if not _ACTIVE:
        return

    global _client
    try:
        if _client is None:
            _client = _get_client()
        _client.upload(
            rule_id=_DCR_ID,
            stream_name=_STREAM,
            logs=[_finding_to_row(finding)],
        )
    except Exception as exc:
        print(f"[sentinel:siem] Log Analytics push failed: {exc}", file=sys.stderr)


def push_bulk(findings: list[Finding]) -> None:
    """Push multiple findings in one API call (max 1 MB per batch)."""
    if not _ACTIVE or not findings:
        return

    global _client
    try:
        if _client is None:
            _client = _get_client()
        rows = [_finding_to_row(f) for f in findings]
        # Log Analytics API limit: 1 MB body, ~1000 events per call
        batch_size = 500
        for i in range(0, len(rows), batch_size):
            _client.upload(
                rule_id=_DCR_ID,
                stream_name=_STREAM,
                logs=rows[i : i + batch_size],
            )
    except Exception as exc:
        print(f"[sentinel:siem] bulk push failed: {exc}", file=sys.stderr)
