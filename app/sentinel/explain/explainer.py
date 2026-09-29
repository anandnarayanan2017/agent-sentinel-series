"""Explainability layer — the product differentiator.

Every finding must answer four questions in plain language:
  1. WHAT happened          (title + reason)
  2. WHY it is a problem     (policy clause / baseline deviation)
  3. WHAT proves it          (evidence chain copied from the event)
  4. HOW bad it is, and why  (severity + rationale)

The narrative is assembled deterministically from STRUCTURED inputs. An LLM may
optionally polish the prose, but it is never the detector — the decision and the
evidence come from the engine, so the system stays auditable.
"""

from __future__ import annotations

from typing import Optional

from sentinel.schema.events import AgentEvent, Evidence, Finding, Severity

_SEVERITY_RATIONALE = {
    Severity.CRITICAL: "Direct, high-confidence indicator of active compromise or exfiltration.",
    Severity.HIGH: "Clear policy violation with plausible security impact; warrants immediate review.",
    Severity.MEDIUM: "Deviation from declared behavior; review to confirm intent.",
    Severity.LOW: "Statistical anomaly only; provides context for correlation.",
    Severity.INFO: "Informational; no action required.",
}


class Explainer:
    def __init__(self, narrator=None) -> None:
        # `narrator` is an optional callable(structured_dict) -> str that can be
        # wired to an LLM to rewrite the explanation. Default: deterministic.
        self.narrator = narrator

    def build(
        self,
        event: AgentEvent,
        *,
        rule_id: str,
        title: str,
        severity: Severity,
        reason: str,
        policy_clause: Optional[str],
        control_refs: list[str],
    ) -> Finding:
        evidence = self._evidence_chain(event)
        rationale = _SEVERITY_RATIONALE[severity]

        explanation = self._narrate(
            reason=reason,
            event=event,
            policy_clause=policy_clause,
            evidence=evidence,
        )

        return Finding(
            agent_id=event.agent_id,
            session_id=event.session_id,
            rule_id=rule_id,
            title=title,
            severity=severity,
            explanation=explanation,
            policy_clause=policy_clause,
            severity_rationale=rationale,
            event_ids=[event.event_id],
            evidence=evidence,
            control_refs=control_refs,
        )

    def build_sequence(
        self,
        event: AgentEvent,
        *,
        explanation: str,
        severity: Severity,
        evidence: list[Evidence],
        event_ids: list[str],
        control_refs: list[str],
        title: str = "Sequence behavior anomaly",
    ) -> Finding:
        """Build an advisory L3 `sequence.anomaly` Finding (additive; FR-10).

        Distinct from `build()` — never modifies it — because the L3 shape
        differs from the L1/L2 shape in three ways: `explanation` is used
        verbatim from the detector (no "Observed at..." narration suffix),
        `event_ids` spans the whole buffered session rather than one event,
        and `evidence` is caller-supplied (evidence-chain sentences + score
        fields) merged with the base identity evidence. `policy_clause` is
        always None: this layer is advisory-only and never denies (FR-2).
        """
        base_evidence = self._evidence_chain(event)
        rationale = _SEVERITY_RATIONALE[severity]

        return Finding(
            agent_id=event.agent_id,
            session_id=event.session_id,
            rule_id="sequence.anomaly",
            title=title,
            severity=severity,
            explanation=explanation,
            policy_clause=None,
            severity_rationale=rationale,
            event_ids=list(event_ids),
            evidence=base_evidence + list(evidence),
            control_refs=control_refs,
        )

    def _evidence_chain(self, event: AgentEvent) -> list[Evidence]:
        chain = [
            Evidence(key="agent_id", value=event.agent_id),
            Evidence(key="session_id", value=event.session_id),
            Evidence(key="action", value=event.action.value),
        ]
        if event.host:
            chain.append(Evidence(key="host", value=event.host))
        if event.tool_name:
            chain.append(Evidence(key="tool", value=event.tool_name))
        if event.model:
            chain.append(Evidence(key="model", value=event.model))
        if event.bytes_out:
            chain.append(Evidence(key="bytes_out", value=str(event.bytes_out)))
        # carry forward the bounded, best-effort-redacted signal from the edge
        chain.extend(event.evidence)
        return chain

    def _narrate(self, *, reason, event, policy_clause, evidence) -> str:
        if self.narrator:
            return self.narrator(
                {
                    "reason": reason,
                    "event": event.model_dump(mode="json"),
                    "policy_clause": policy_clause,
                    "evidence": [e.model_dump() for e in evidence],
                }
            )
        clause = f" Violated clause: {policy_clause}." if policy_clause else ""
        return (
            f"{reason}{clause} "
            f"Observed at {event.ts.isoformat()} on {event.action.value} "
            f"to host '{event.host or 'n/a'}'."
        )
