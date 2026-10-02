"""Detection engine: events -> findings.

Order of operations per event:
  1. Deterministic policy checks (allow-lists, volume guards)   -> high signal
  2. Statistical baseline checks (new host, payload anomaly)    -> context
  3. Optional advisory sequence-anomaly layer (L3, off by default) -> context

Each potential violation is handed to the explainability layer, which turns the
structured reason into a human narrative + evidence chain before it becomes a
Finding.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from typing import TYPE_CHECKING

from sentinel.detection.baseline import BaselineStore
from sentinel.detection.policy import AgentPolicy, PolicySet
from sentinel.detection.seq_config import SeqLayerConfig
from sentinel.explain.explainer import Explainer
from sentinel.schema.events import (
    ActionType,
    AgentEvent,
    Direction,
    Finding,
    Severity,
)

if TYPE_CHECKING:
    from sentinel.storage.base import StoreBase

logger = logging.getLogger("sentinel.detection.sequence")

# Bound for the per-session tool-call counter LRU (CR-9): one key per
# session_id, previously never evicted. Mirrors sequence_layer.py's
# insert-then-evict-if-over-cap OrderedDict convention for session state.
_MAX_TRACKED_SESSIONS = 10_000

# Identity control references for `identity.unregistered_agent` (CR-16). An
# agent acting without a policy entry is an access-management failure before
# it is a detection one, hence DORA Art. 9 rather than Art. 10 alone.
IDENTITY_CONTROL_REFS: list[str] = [
    "DORA Art. 9 (Protection and prevention)",
    "DORA Art. 5 (ICT governance)",
    "EU AI Act Art. 14 (Human oversight)",
    "CSSF 20/750 (ICT risk management)",
]

# Bound for the unregistered-identity dedupe LRU. The finding is about the
# identity, not the event, so it fires once per (agent_id, session_id) rather
# than on every event — otherwise one unregistered agent buries the queue.
_MAX_TRACKED_IDENTITIES = 10_000


class Engine:
    def __init__(
        self,
        policies: PolicySet,
        explainer: Explainer | None = None,
        seq_config: SeqLayerConfig | None = None,
        store: "StoreBase | None" = None,
    ) -> None:
        self.policies = policies
        self.baselines = BaselineStore(store)
        self.explainer = explainer or Explainer()
        # per-session counters for volume guards (bounded LRU — CR-9)
        self._tool_calls: "OrderedDict[str, int]" = OrderedDict()
        # (agent_id, session_id) pairs already reported as unregistered (CR-16)
        self._seen_unregistered: "OrderedDict[tuple[str, str], bool]" = OrderedDict()

        # ---- optional L3 sequence-anomaly layer (advisory only, FR-11) -----
        # The `sentinel_sequence` import (transitively `numpy`) happens only
        # here, lazily and guarded, so a missing optional dependency never
        # breaks startup (NFR-3). Default (no seq_config, or disabled) leaves
        # self._l3 as None and evaluate() behaves exactly as before (NFR-6).
        self._l3 = None
        if seq_config is not None and seq_config.enabled:
            try:
                from sentinel.detection.sequence_layer import L3SequenceLayer

                self._l3 = L3SequenceLayer(seq_config, self.explainer)
            except Exception as exc:  # noqa: BLE001 — advisory layer must fail open at construction
                logger.warning(
                    "L3 sequence layer enabled but construction failed "
                    "(registry_dir=%s); continuing with the layer disabled: %r",
                    seq_config.registry_dir,
                    exc,
                )
                self._l3 = None
        elif seq_config is not None:
            logger.info("L3 sequence layer disabled")

    def evaluate(self, e: AgentEvent) -> list[Finding]:
        findings: list[Finding] = []

        # An identity with no policy entry of its own is itself a finding, and
        # is then evaluated against `default_policy` when the operator has
        # authored one. Previously `if policy:` meant such an agent received
        # no layer-1 check at all, permanently — the one case that most
        # warrants a deterministic verdict was the one case that got none
        # (CR-16).
        if not self.policies.is_registered(e.agent_id):
            findings.extend(self._unregistered_identity_check(e))
        policy = self.policies.effective_policy(e.agent_id)

        if policy:
            findings.extend(self._policy_checks(e, policy))

        findings.extend(self._baseline_checks(e, policy))

        # ---- layer 3: optional advisory sequence-anomaly step -------------
        # Fail-open: any exception here is caught, logged, and treated as "no
        # finding" for this event — L3 must never crash ingest_flow (NFR-2).
        if self._l3 is not None:
            try:
                findings.extend(self._l3.evaluate(e, policy))
            except Exception:  # noqa: BLE001 — advisory layer must fail open
                logger.exception(
                    "L3 sequence layer raised while evaluating event %s; "
                    "continuing without a sequence finding",
                    e.event_id,
                )

        # learn AFTER evaluating so the first sighting of a host can still flag.
        self.baselines.learn(e)
        return findings

    # ---- layer 1: identity ---------------------------------------------------
    def _unregistered_identity_check(self, e: AgentEvent) -> list[Finding]:
        """Flag an agent identity that has no policy entry authored for it.

        Deduped per (agent_id, session_id) through the same insert-then-evict
        bounded-LRU convention `_tool_calls` uses, so a chatty unregistered
        agent produces one finding per session rather than one per event.
        """
        key = (e.agent_id, e.session_id)
        if key in self._seen_unregistered:
            self._seen_unregistered.move_to_end(key)
            return []
        self._seen_unregistered[key] = True
        if len(self._seen_unregistered) > _MAX_TRACKED_IDENTITIES:
            self._seen_unregistered.popitem(last=False)

        default = self.policies.default_policy
        clause = (
            "default_policy (applied: this agent has no entry of its own)"
            if default
            else "no policy entry and no default_policy configured"
        )
        return [
            self.explainer.build(
                e,
                rule_id="identity.unregistered_agent",
                title=f"Unregistered agent identity: {e.agent_id}",
                severity=Severity.MEDIUM,
                policy_clause=clause,
                reason=(
                    f"Agent '{e.agent_id}' is acting without a policy entry. No "
                    f"operator has declared what this identity is permitted to do, "
                    f"so its declared-behaviour checks cannot be evaluated"
                    + (
                        "; the configured default_policy is being applied in its place."
                        if default
                        else " and no default_policy is configured to stand in."
                    )
                ),
                control_refs=(default.control_refs if default else IDENTITY_CONTROL_REFS),
            )
        ]

    # ---- layer 1: deterministic policy -------------------------------------
    def _policy_checks(self, e: AgentEvent, p: AgentPolicy) -> list[Finding]:
        out: list[Finding] = []

        if (
            e.direction == Direction.EGRESS
            and e.host
            and p.allowed_hosts
            and e.host not in p.allowed_hosts
        ):
            out.append(
                self.explainer.build(
                    e,
                    rule_id="net.host_not_allowed",
                    title=f"Egress to non-allow-listed host {e.host}",
                    severity=p.severity_for("net.host_not_allowed"),
                    policy_clause=f"allowed_hosts={p.allowed_hosts}",
                    reason=(
                        f"Agent '{e.agent_id}' sent traffic to '{e.host}', which is "
                        f"not in its permitted egress allow-list."
                    ),
                    control_refs=p.control_refs,
                )
            )

        if (
            e.action == ActionType.TOOL_CALL
            and e.tool_name
            and p.allowed_tools
            and e.tool_name not in p.allowed_tools
        ):
            out.append(
                self.explainer.build(
                    e,
                    rule_id="tool.not_allowed",
                    title=f"Disallowed tool invoked: {e.tool_name}",
                    severity=p.severity_for("tool.not_allowed"),
                    policy_clause=f"allowed_tools={p.allowed_tools}",
                    reason=(
                        f"Agent '{e.agent_id}' invoked tool '{e.tool_name}', outside "
                        f"its declared tool scope (scope creep)."
                    ),
                    control_refs=p.control_refs,
                )
            )

        if (
            e.action == ActionType.LLM_CALL
            and e.model
            and p.allowed_models
            and e.model not in p.allowed_models
        ):
            out.append(
                self.explainer.build(
                    e,
                    rule_id="model.not_allowed",
                    title=f"Unapproved model used: {e.model}",
                    severity=p.severity_for("model.not_allowed"),
                    policy_clause=f"allowed_models={p.allowed_models}",
                    reason=(
                        f"Agent '{e.agent_id}' called model '{e.model}', which is not "
                        f"on its approved-model list."
                    ),
                    control_refs=p.control_refs,
                )
            )

        if p.max_bytes_out_per_call and e.bytes_out > p.max_bytes_out_per_call:
            out.append(
                self.explainer.build(
                    e,
                    rule_id="net.oversize_egress",
                    title="Oversize outbound payload",
                    severity=p.severity_for("net.oversize_egress"),
                    policy_clause=f"max_bytes_out_per_call={p.max_bytes_out_per_call}",
                    reason=(
                        f"Outbound payload of {e.bytes_out} bytes exceeds the per-call "
                        f"limit of {p.max_bytes_out_per_call} bytes (possible exfil)."
                    ),
                    control_refs=p.control_refs,
                )
            )

        if p.max_tool_calls_per_session and e.action == ActionType.TOOL_CALL:
            if e.session_id in self._tool_calls:
                self._tool_calls.move_to_end(e.session_id)
                n = self._tool_calls[e.session_id] + 1
            else:
                n = 1
            self._tool_calls[e.session_id] = n
            if len(self._tool_calls) > _MAX_TRACKED_SESSIONS:
                self._tool_calls.popitem(last=False)
            if n > p.max_tool_calls_per_session:
                out.append(
                    self.explainer.build(
                        e,
                        rule_id="tool.rate_exceeded",
                        title="Tool-call budget exceeded (possible runaway loop)",
                        severity=p.severity_for("tool.rate_exceeded"),
                        policy_clause=f"max_tool_calls_per_session={p.max_tool_calls_per_session}",
                        reason=(
                            f"Session '{e.session_id}' has made {n} tool calls, over its "
                            f"budget of {p.max_tool_calls_per_session}."
                        ),
                        control_refs=p.control_refs,
                    )
                )
        return out

    # ---- layer 2: statistical baseline -------------------------------------
    def _baseline_checks(self, e: AgentEvent, p: AgentPolicy | None) -> list[Finding]:
        out: list[Finding] = []
        bl = self.baselines.get(e.agent_id)

        # only flag "new host" anomalies when there is NO explicit allow-list,
        # otherwise the deterministic check already owns that decision.
        if (not (p and p.allowed_hosts)) and bl.is_new_host(e.host) and bl.seen_hosts:
            out.append(
                self.explainer.build(
                    e,
                    rule_id="baseline.new_host",
                    title=f"First-seen egress host {e.host}",
                    severity=Severity.LOW,
                    policy_clause=None,
                    reason=(
                        f"Agent '{e.agent_id}' contacted '{e.host}' for the first time; "
                        f"it has no prior history with this destination."
                    ),
                    control_refs=(p.control_refs if p else []),
                )
            )

        # A perfectly constant payload history has no standard deviation, so
        # `bytes_out_z` cannot score against it. That is the *strongest*
        # baseline an agent can have, not the weakest, so it gets its own
        # explainable rule rather than being silently skipped (CR-14).
        constant = bl.constant_value()
        if constant is not None and e.bytes_out and e.bytes_out != constant:
            out.append(
                self.explainer.build(
                    e,
                    rule_id="baseline.constant_history_deviation",
                    title="Payload size departs from a constant history",
                    severity=Severity.LOW,
                    policy_clause=None,
                    reason=(
                        f"Every prior outbound payload from agent '{e.agent_id}' "
                        f"measured exactly {constant} bytes; this one is "
                        f"{e.bytes_out} bytes. The history has no variance to "
                        f"score against, so any change is itself the deviation."
                    ),
                    control_refs=(p.control_refs if p else []),
                )
            )

        z = bl.bytes_out_z(e.bytes_out)
        if z >= 3.0:
            out.append(
                self.explainer.build(
                    e,
                    rule_id="baseline.payload_anomaly",
                    title="Outbound payload size anomaly",
                    severity=Severity.LOW,
                    policy_clause=None,
                    reason=(
                        f"Outbound payload is {z:.1f}σ above this agent's normal size, "
                        f"a statistical outlier worth review."
                    ),
                    control_refs=(p.control_refs if p else []),
                )
            )
        return out
