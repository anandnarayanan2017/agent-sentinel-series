"""Normalized event schema for AI-agent / machine-to-machine actions.

Every observable thing an agent does over the wire is reduced to one of a small
number of `ActionType`s wrapped in an `AgentEvent`. Detection, storage and
explainability all operate on this single shape so that new collectors (proxy,
SDK hook, eBPF) never leak their transport details downstream.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ActionType(str, Enum):
    """The kinds of action an agent can take that we care about."""

    LLM_CALL = "llm_call"  # a call to a model provider (Anthropic/OpenAI/...)
    TOOL_REQUESTED = "tool_requested"  # model proposed a tool; execution not proven
    TOOL_CALL = "tool_call"  # an MCP / function tool invocation
    NETWORK_CALL = "network_call"  # raw outbound HTTP to some host
    DATA_ACCESS = "data_access"  # read/write against a known data source


class Direction(str, Enum):
    EGRESS = "egress"
    INGRESS = "ingress"


class Evidence(BaseModel):
    """A single piece of raw signal that backs an event or a finding.

    Evidence is what makes alerts explainable: every finding can point back at
    the exact spans/payload fragments that triggered it.
    """

    key: str
    value: str
    redacted: bool = False

    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.key}={self.value}".encode()).hexdigest()[:12]


class AgentEvent(BaseModel):
    """One normalized action taken by one agent identity."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ts: datetime = Field(default_factory=_utcnow)

    # identity
    agent_id: str  # stable identity of the agent ("recon-bot")
    session_id: str  # one run / conversation of that agent

    # action
    action: ActionType
    direction: Direction = Direction.EGRESS

    # destination
    host: Optional[str] = None  # e.g. api.anthropic.com, ledger.internal
    method: Optional[str] = None  # HTTP verb where relevant
    path: Optional[str] = None

    # semantics
    model: Optional[str] = None  # for LLM_CALL
    tool_name: Optional[str] = None  # for TOOL_REQUESTED or TOOL_CALL
    bytes_out: int = 0
    bytes_in: int = 0

    # arbitrary normalized attributes (token counts, status, etc.)
    attributes: dict[str, Any] = Field(default_factory=dict)

    # Bounded signal kept for explainability, best-effort redacted at the
    # collector edge (collector/redaction.py) before it reaches this schema.
    # "Best-effort" is the honest word: structured identifiers and sensitive
    # JSON keys are removed; free-text personal data is not (CR-25).
    evidence: list[Evidence] = Field(default_factory=list)

    def add_evidence(self, key: str, value: str, redacted: bool = False) -> None:
        self.evidence.append(Evidence(key=key, value=str(value), redacted=redacted))


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """An explainable detection produced from one or more events."""

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ts: datetime = Field(default_factory=_utcnow)

    agent_id: str
    session_id: str
    rule_id: str
    title: str
    severity: Severity

    # the human-readable narrative + the machine-checkable reason
    explanation: str = ""
    policy_clause: Optional[str] = None
    severity_rationale: str = ""

    # which events triggered this
    event_ids: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)

    # compliance hooks (filled from the rule)
    control_refs: list[str] = Field(default_factory=list)
