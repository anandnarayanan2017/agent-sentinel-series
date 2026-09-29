"""Policy-as-code: declarative conformance rules per agent identity.

Rules are deterministic and human-auditable on purpose. Fintech buyers trust a
YAML clause they can read in a change review far more than an opaque model
score, so the rules engine is the *primary* detector and statistics/ML are
secondary signal only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field

from sentinel.schema.events import Severity

#: Per-rule severity defaults. A rule mapped to `None` takes the owning
#: policy's `severity` field; the rest carry a deliberate fixed default
#: because their meaning does not vary with how sensitive an agent is
#: (an oversize payload is an exfil indicator regardless).
#:
#: Declared here — rather than inline at each `explainer.build(...)` call —
#: so `AgentPolicy.severity_for()` is the single place severity is decided
#: and an operator can see the whole table at once (CR-15).
RULE_SEVERITY_DEFAULTS: dict[str, Optional[Severity]] = {
    "net.host_not_allowed": None,
    "tool.not_allowed": None,
    "model.not_allowed": Severity.MEDIUM,
    "net.oversize_egress": Severity.HIGH,
    "tool.rate_exceeded": Severity.MEDIUM,
}


class AgentPolicy(BaseModel):
    agent_id: str
    description: str = ""

    # network egress allow-list (exact host match)
    allowed_hosts: list[str] = Field(default_factory=list)
    # tools this agent is permitted to call
    allowed_tools: list[str] = Field(default_factory=list)
    # models this agent is permitted to use
    allowed_models: list[str] = Field(default_factory=list)

    # rate / volume guards
    max_tool_calls_per_session: Optional[int] = None
    max_bytes_out_per_call: Optional[int] = None

    # Default severity for violations of this policy. Applies to the rules
    # mapped to `None` in RULE_SEVERITY_DEFAULTS; the others keep their own
    # documented default unless `severity_overrides` names them explicitly.
    severity: Severity = Severity.HIGH

    # Per-rule severity dial, e.g. {"net.oversize_egress": "medium"}. Wins over
    # both RULE_SEVERITY_DEFAULTS and `severity`. Previously `severity` was
    # honoured by only two of the five rules, so lowering it for a noisy
    # sandbox agent silently changed nothing for the other three — and
    # severity drives both the alert threshold and approval creation, so
    # ignored tuning quietly changed who got paged (CR-15).
    severity_overrides: dict[str, Severity] = Field(default_factory=dict)

    # compliance controls this policy supports (free-form refs)
    control_refs: list[str] = Field(default_factory=list)

    def severity_for(self, rule_id: str) -> Severity:
        """Resolve the severity this policy assigns to `rule_id`.

        Precedence: explicit override -> the rule's documented default ->
        this policy's `severity`.
        """
        if rule_id in self.severity_overrides:
            return self.severity_overrides[rule_id]
        default = RULE_SEVERITY_DEFAULTS.get(rule_id)
        return default if default is not None else self.severity


class PolicySet(BaseModel):
    policies: dict[str, AgentPolicy] = Field(default_factory=dict)

    # Optional catch-all applied to agent identities with no policy entry of
    # their own. Without it, an unregistered `agent_id` receives NO layer-1
    # check at all — not merely on its first event but permanently — so the
    # strongest verdict it could ever produce was a LOW advisory carrying no
    # control references. For a behavioural firewall the unknown-identity
    # posture is the whole question, and it must be an operator-authored
    # clause rather than an accident of a missing dict key (CR-16, ADR-0009).
    default_policy: Optional[AgentPolicy] = None

    @classmethod
    def from_yaml(cls, path: str | Path) -> "PolicySet":
        data = yaml.safe_load(Path(path).read_text()) or {}
        policies: dict[str, AgentPolicy] = {}
        for raw in data.get("agents", []):
            p = AgentPolicy(**raw)
            policies[p.agent_id] = p

        default_raw = data.get("default_policy")
        default_policy = None
        if default_raw:
            # agent_id is structural here, not an identity — this policy is
            # applied to whichever unregistered agent triggered it.
            default_raw = {"agent_id": "<unregistered>", **default_raw}
            default_policy = AgentPolicy(**default_raw)

        return cls(policies=policies, default_policy=default_policy)

    def for_agent(self, agent_id: str) -> Optional[AgentPolicy]:
        return self.policies.get(agent_id)

    def is_registered(self, agent_id: str) -> bool:
        """True when this identity has a policy entry authored for it."""
        return agent_id in self.policies

    def effective_policy(self, agent_id: str) -> Optional[AgentPolicy]:
        """The policy whose clauses should be evaluated for `agent_id`.

        The agent's own entry when it has one, otherwise `default_policy`
        (which may itself be None when the operator has not authored one).
        """
        return self.policies.get(agent_id) or self.default_policy
