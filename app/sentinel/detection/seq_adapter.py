"""Adapter: `AgentEvent` -> the `sentinel_sequence` subsystem's plain-dict shape.

This is the single, centrally defined conversion (FR-6, A-2) between the main
product's `AgentEvent` schema and the sequence subsystem's event mapping
(`{agent_id, session_id, ts, kind, name}`, consumed by
`sentinel_sequence.tokenizer.event_to_token`). It also owns role resolution
(FR-7, A-1) and the detector-severity-string -> schema `Severity` mapping
(FR-10).

Deliberately free of any `sentinel_sequence`/`numpy` import so this module is
importable — and FR-6/FR-7 are unit-testable — even in an environment where the
optional ML dependency chain is absent (NFR-3).

The same `to_seq_event` derivation must be reused for any AgentEvent-based
training-data preparation; otherwise the tokenizer's train-time and score-time
vocabularies diverge and every event maps to `<UNK>` (see SPEC A-2 / risk R5).
"""

from __future__ import annotations

import re
from typing import Optional

from sentinel.schema.events import ActionType, AgentEvent, Severity

# Mirrors sentinel_sequence.registry._ROLE_RE. Re-declared here (rather than
# imported) so role validation never requires importing the optional package
# (FR-7, A-1).
_ROLE_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")

# detector.score() only ever emits "high" / "medium" / "info" (detector.py);
# unrecognized strings degrade to INFO rather than raising (FR-10).
_SEVERITY_MAP: dict[str, Severity] = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "info": Severity.INFO,
}


def to_seq_event(e: AgentEvent) -> dict:
    """Convert one `AgentEvent` into the sequence subsystem's event mapping.

    The ONLY place `kind`/`name` are derived (FR-6). Locked derivation table
    (SPEC A-2):
        TOOL_CALL     -> kind="tool", name=tool_name
        LLM_CALL      -> kind="llm",  name=model
        NETWORK_CALL  -> kind="net",  name=host
        DATA_ACCESS   -> kind="data", name=host or attributes["source"]
    """
    if e.action == ActionType.TOOL_CALL:
        kind, name = "tool", e.tool_name
    elif e.action == ActionType.LLM_CALL:
        kind, name = "llm", e.model
    elif e.action == ActionType.NETWORK_CALL:
        kind, name = "net", e.host
    elif e.action == ActionType.DATA_ACCESS:
        kind, name = "data", (e.host or e.attributes.get("source"))
    else:  # pragma: no cover — ActionType is exhaustive; defensive only
        kind, name = "unknown", None

    return {
        "agent_id": e.agent_id,
        "session_id": e.session_id,
        "ts": e.ts.timestamp(),
        "kind": kind,
        # A missing name collapses to the literal "unknown" (mini-ADR-6) so
        # `event_to_token` never raises and the token stays deterministic
        # rather than becoming `str(None)` ("llm:none").
        "name": name or "unknown",
    }


def resolve_role(e: AgentEvent, role_map: Optional[dict] = None) -> str:
    """Resolve the `role` string passed to `SequenceDetector.score` (FR-7).

    Precedence (A-1):
      1. `e.attributes["role"]` if a non-empty string.
      2. `role_map[e.agent_id]` if `role_map` is given and contains the agent.
      3. `e.agent_id` (default, 1:1 role mapping).
    """
    attr_role = e.attributes.get("role")
    if isinstance(attr_role, str) and attr_role:
        return attr_role
    if role_map and e.agent_id in role_map:
        return role_map[e.agent_id]
    return e.agent_id


def is_valid_role(role: str) -> bool:
    """Validate `role` against the registry's `^[a-zA-Z0-9_\\-]{1,64}$` constraint.

    A non-conforming role is not an error (FR-7) — callers route it to the
    graceful-degradation path.
    """
    return bool(_ROLE_RE.match(role))


def map_severity(value: str) -> Severity:
    """Map the detector's severity string to the schema `Severity` enum (FR-10)."""
    return _SEVERITY_MAP.get(value, Severity.INFO)
