"""`L3SequenceLayer`: the optional, advisory sequence-anomaly detection step.

This is the **only** module in `sentinel` that imports `sentinel_sequence`
(and transitively `numpy`). `Engine.__init__` imports this module lazily,
inside a guarded `try/except ImportError`, so a missing optional dependency
never breaks startup or `ingest_flow` (FR-11, NFR-3).

Responsibilities (see `design/DESIGN.md` §2.3-§3.5, §4 FR-3..FR-13):
  - Maintain an in-memory, bounded session buffer keyed by
    `(agent_id, session_id)` (FR-3, FR-13).
  - Score the session-so-far on every event, synchronously (FR-4).
  - Emit at most one `sequence.anomaly` `Finding` per session unless severity
    escalates (FR-5).
  - Discriminate *persistent* unavailability (no model / illegal role /
    corrupt bundle) from *transient* scoring errors, per mini-ADR-3 (§5.3),
    so a single transient error never permanently blinds a role (NFR-2).
  - Keep the persistent-unavailability cache itself bounded (§3.5).

This layer NEVER denies (FR-2): every finding it can produce carries a
`sequence.*` rule_id and `policy_clause=None`.
"""

from __future__ import annotations

import json
import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

from sentinel_sequence import RegistryError, SequenceConfig, SequenceDetector

from sentinel.detection.policy import AgentPolicy
from sentinel.detection.seq_adapter import (
    is_valid_role,
    map_severity,
    resolve_role,
    to_seq_event,
)
from sentinel.detection.seq_config import SeqLayerConfig
from sentinel.explain.explainer import Explainer
from sentinel.schema.events import AgentEvent, Evidence, Finding, Severity

logger = logging.getLogger("sentinel.detection.sequence")

# Rank used to decide whether a new emission strictly escalates the last one
# emitted for a session (FR-5).
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass
class SessionBuffer:
    """Per-`(agent_id, session_id)` in-memory scoring state (FR-3, §3.3)."""

    events: list[dict] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    last_emitted_severity: Optional[Severity] = None
    last_ts: float = 0.0


class L3SequenceLayer:
    """The advisory L3 sequence-anomaly step. Constructed once per `Engine`.

    `SequenceDetector` (and thus its per-role `ModelBundle` cache) lives for
    the lifetime of this object, so scoring reuses a cached bundle across
    events (FR-12).
    """

    def __init__(self, cfg: SeqLayerConfig, explainer: Explainer) -> None:
        self.cfg = cfg
        self.explainer = explainer
        self._detector = SequenceDetector(SequenceConfig(registry_dir=cfg.registry_dir))

        # LRU-ordered, bounded session buffer (FR-3, FR-13, §3.3).
        self._buffers: "OrderedDict[tuple[str, str], SessionBuffer]" = OrderedDict()

        # Bounded LRU of roles whose unavailability is PERSISTENT (§3.5).
        # A transient scoring error never enters this set (mini-ADR-3).
        self._unavailable_roles: "OrderedDict[str, None]" = OrderedDict()

        logger.info(
            "L3 sequence layer enabled (registry_dir=%s, max_sessions=%d, "
            "max_events_per_session=%d, max_unavailable_roles=%d)",
            cfg.registry_dir,
            cfg.max_sessions,
            cfg.max_events_per_session,
            cfg.max_unavailable_roles,
        )

    # ------------------------------------------------------------------ eval
    def evaluate(self, e: AgentEvent, policy: Optional[AgentPolicy]) -> list[Finding]:
        now = e.ts.timestamp()

        # step 1 (design §4 FR-8): adapt + buffer + evict, always, regardless
        # of role availability.
        self._evict_idle(now)
        buf = self._get_buffer((e.agent_id, e.session_id))
        buf.events.append(to_seq_event(e))
        buf.event_ids.append(e.event_id)
        buf.last_ts = now
        self._trim_session(buf)

        role = resolve_role(e, self.cfg.role_map)

        # step 3: illegal role -> persistent graceful degradation, no raise.
        if not is_valid_role(role):
            self._mark_unavailable(role, f"invalid role name {role!r} (illegal format)")
            return []

        # step 4: known-persistently-unavailable role -> short-circuit, touch LRU.
        if role in self._unavailable_roles:
            self._unavailable_roles.move_to_end(role)
            return []

        # step 5: score the session-so-far, synchronously, exactly once (FR-4).
        try:
            result = self._detector.score(role, buf.events)
        except (
            RegistryError,
            json.JSONDecodeError,
            KeyError,
            ValueError,
            TypeError,
            OSError,
        ) as exc:
            # `SequenceDetector.score()` (detector.py, frozen/out of scope)
            # only guards `RegistryError` around its internal `_bundle()` /
            # `registry.load()` call. `registry.load()` itself does
            # `json.loads(meta.json)` and `float(meta["threshold"])` BEFORE
            # checksum verification, so a malformed meta.json, a missing key,
            # a non-numeric threshold, or an unreadable file raises straight
            # out of `score()` uncaught rather than degrading to a
            # "sequence_scoring_unavailable" dict. Classify it exactly like a
            # persistent "no usable model" result — the bundle will not
            # self-heal until someone fixes the file on disk, and the
            # `_unavailable_roles` short-circuit (step 4) stops this layer
            # from re-attempting `registry.load()` — and re-reading/re-hashing
            # the corrupt artifact — on every subsequent event for this role.
            self._mark_unavailable(role, f"no usable model for role {role!r}: {exc}")
            return []
        rtype = result.get("type")

        if rtype == "sequence_scoring_unavailable":
            return self._handle_unavailable(role, result)
        if rtype == "sequence_anomaly":
            return self._maybe_emit(e, buf, policy, role, result)
        # "sequence_ok" (or any other/unknown type) -> no finding, no log
        # (FR-9, NFR-7 — no per-event spam).
        return []

    # ---- persistent vs. transient unavailability (mini-ADR-3, §5.3) --------
    def _handle_unavailable(self, role: str, result: dict) -> list[Finding]:
        try:
            self._detector.registry.load(role)
        except (RegistryError, json.JSONDecodeError, KeyError, OSError):
            # RegistryError reproduces the detector's own persistent branch
            # (no model / illegal role / checksum-verified corruption). The
            # other three cover artifact corruption that ModelRegistry.load()
            # itself doesn't wrap in RegistryError: json.loads(meta.json) runs
            # before checksum verification, so a malformed meta.json raises
            # JSONDecodeError, one missing "threshold"/etc. raises KeyError,
            # and an unreadable file raises OSError. All are exactly as
            # persistent as a missing model until someone fixes the file on
            # disk — cache it, log once.
            self._mark_unavailable(
                role, f"no usable model for role {role!r}: {result.get('explanation')}"
            )
            return []
        # The bundle loads fine, so the unavailable result came from the
        # detector's scoring-exception guard: transient. Do NOT cache it —
        # retry on the next event (the bundle is already cached, so the
        # retry costs no extra registry I/O).
        logger.warning(
            "transient sequence scoring error for role %s: %s",
            role,
            result.get("explanation"),
        )
        return []

    def _mark_unavailable(self, role: str, log_msg: str) -> None:
        """Insert-or-touch `role` in the bounded `_unavailable_roles` LRU.

        Logs exactly once per role (on first insertion); a repeat hit only
        touches the LRU position (NFR-7).
        """
        if role in self._unavailable_roles:
            self._unavailable_roles.move_to_end(role)
            return
        self._unavailable_roles[role] = None
        if len(self._unavailable_roles) > self.cfg.max_unavailable_roles:
            self._unavailable_roles.popitem(last=False)
        logger.info("sequence scoring unavailable for role %s: %s", role, log_msg)

    # ---- once-per-session emission / escalation (FR-5) ----------------------
    def _maybe_emit(
        self,
        e: AgentEvent,
        buf: SessionBuffer,
        policy: Optional[AgentPolicy],
        role: str,
        result: dict,
    ) -> list[Finding]:
        severity = map_severity(result["severity"])
        last = buf.last_emitted_severity
        if last is not None and _SEVERITY_RANK[severity] <= _SEVERITY_RANK[last]:
            return []

        score = result.get("score") or {}
        evidence: list[Evidence] = [
            Evidence(key=f"seq_step_{i}", value=str(sentence))
            for i, sentence in enumerate(result.get("evidence_chain", []))
        ]
        evidence.append(Evidence(key="model_version", value=str(result.get("model_version"))))
        evidence.append(Evidence(key="topk_surprise", value=str(score.get("topk_surprise"))))
        evidence.append(Evidence(key="threshold", value=str(score.get("threshold"))))

        finding = self.explainer.build_sequence(
            e,
            explanation=result["explanation"],
            severity=severity,
            evidence=evidence,
            event_ids=list(buf.event_ids),
            control_refs=(policy.control_refs if policy else []),
            title=f"Sequence behavior anomaly for role '{role}'",
        )

        # Commit escalation state only after the Finding is successfully
        # built — if build_sequence had raised above, we must not have
        # already mutated last_emitted_severity, which would permanently
        # suppress a legitimate future re-emission at this severity.
        buf.last_emitted_severity = severity

        logger.info(
            "sequence.anomaly emitted: agent=%s session=%s role=%s severity=%s model=%s",
            e.agent_id,
            e.session_id,
            role,
            severity.value,
            result.get("model_version"),
        )
        return [finding]

    # ---- session buffer: bounds + eviction (FR-13, §3.3) ---------------------
    def _get_buffer(self, key: tuple[str, str]) -> SessionBuffer:
        if key in self._buffers:
            self._buffers.move_to_end(key)
            return self._buffers[key]
        # Convention: insert first, then evict LRU-front if over cap — mirrors
        # `_mark_unavailable`'s insert-then-evict ordering so both bounded LRUs
        # in this module follow the same pattern.
        buf = SessionBuffer()
        self._buffers[key] = buf
        if len(self._buffers) > self.cfg.max_sessions:
            self._buffers.popitem(last=False)
        return buf

    def _trim_session(self, buf: SessionBuffer) -> None:
        cap = self.cfg.max_events_per_session
        while len(buf.events) > cap:
            buf.events.pop(0)
            buf.event_ids.pop(0)

    def _evict_idle(self, now: float) -> None:
        gap = self.cfg.idle_gap_seconds
        while self._buffers:
            front_key = next(iter(self._buffers))
            if self._buffers[front_key].last_ts < now - gap:
                self._buffers.popitem(last=False)
            else:
                break
