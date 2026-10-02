"""Behavioral baselining: learn what normal looks like per machine identity.

Layer 1 (engine.py) creates deterministic policy findings. This layer is the soft,
statistical complement: it learns the agent's observed footprint and flags
*deviation* (a host never seen before, a payload an order of magnitude larger
than usual). It never blocks on its own; it raises lower-severity findings that
add context to the deterministic ones.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from statistics import mean, pstdev
from typing import TYPE_CHECKING
from typing import Deque

from sentinel.schema.events import AgentEvent

if TYPE_CHECKING:
    from sentinel.storage.base import StoreBase

# Bound the payload-size sample window instead of recomputing mean/pstdev over
# unbounded full history on every event (CR-4).
_MAX_BYTES_OUT_SAMPLES = 500

# Minimum payload observations before either payload check will speak. Shared
# by `bytes_out_z` and `is_constant_history` so they can never disagree about
# what counts as a warmed-up baseline.
_MIN_SAMPLES = 5


@dataclass
class AgentBaseline:
    agent_id: str
    seen_hosts: set[str] = field(default_factory=set)
    seen_tools: set[str] = field(default_factory=set)
    bytes_out_samples: "Deque[int]" = field(
        default_factory=lambda: deque(maxlen=_MAX_BYTES_OUT_SAMPLES)
    )

    def update(self, e: AgentEvent) -> None:
        if e.host:
            self.seen_hosts.add(e.host)
        if e.tool_name:
            self.seen_tools.add(e.tool_name)
        if e.bytes_out:
            self.bytes_out_samples.append(e.bytes_out)

    def is_new_host(self, host: str | None) -> bool:
        return bool(host) and host not in self.seen_hosts

    def bytes_out_z(self, value: int) -> float:
        """Z-score of a bytes_out value against the learned distribution.

        Returns 0.0 when the distribution has no spread (`sigma == 0`): a
        z-score is genuinely undefined there, so this method does not try to
        fake one. That case is NOT "nothing to see" — it is the
        *strongest* possible baseline — and it is handled by
        `is_constant_history()` / `constant_value()` below, which the engine
        turns into its own `baseline.constant_history_deviation` rule.
        Previously `sigma == 0` returned 0.0 and nothing else looked at it,
        so the most predictable agents — a reconciliation bot sending an
        identically-sized payload every run — had payload-anomaly detection
        silently disabled, while an agent with one byte of jitter was fully
        covered (CR-14).
        """
        if len(self.bytes_out_samples) < _MIN_SAMPLES:
            return 0.0
        mu = mean(self.bytes_out_samples)
        sigma = pstdev(self.bytes_out_samples)
        if sigma == 0:
            return 0.0
        return (value - mu) / sigma

    def is_constant_history(self) -> bool:
        """True when this agent's payload history has settled on one exact size.

        Requires the same `_MIN_SAMPLES` warm-up as `bytes_out_z` so a single
        observation is never mistaken for an established constant.
        """
        return len(self.bytes_out_samples) >= _MIN_SAMPLES and pstdev(self.bytes_out_samples) == 0

    def constant_value(self) -> int | None:
        """The single size this agent always sends, or None if it varies."""
        if not self.is_constant_history():
            return None
        return self.bytes_out_samples[0]


class BaselineStore:
    """In-memory baselines keyed by agent_id.

    Per-process cache, not itself durable. When a `store` is supplied,
    `seen_hosts` is lazily seeded from `store.distinct_hosts(agent_id)` the
    first time an agent is touched in this process — so a restart (or a
    fresh uvicorn worker) re-derives prior host history from the SQL store
    instead of re-flagging every host as new (CR-4; previously this
    docstring claimed persistence the class didn't actually implement).
    """

    def __init__(self, store: "StoreBase | None" = None) -> None:
        self._baselines: dict[str, AgentBaseline] = {}
        self._store = store

    def get(self, agent_id: str) -> AgentBaseline:
        existing = self._baselines.get(agent_id)
        if existing is not None:
            return existing
        baseline = AgentBaseline(agent_id)
        if self._store is not None:
            try:
                baseline.seen_hosts = set(self._store.distinct_hosts(agent_id))
            except Exception:
                pass  # store unavailable/erroring — fall back to empty, in-memory-only
        self._baselines[agent_id] = baseline
        return baseline

    def learn(self, e: AgentEvent) -> None:
        self.get(e.agent_id).update(e)
