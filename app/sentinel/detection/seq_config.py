"""`SeqLayerConfig`: pure-stdlib configuration for the optional L3 sequence layer.

A new thin config object rather than reuse/extension of
`sentinel_sequence.SequenceConfig` (mini-ADR-2, design §5.2): `SequenceConfig`
lives in the optional (`numpy`-importing) package and lacks the engine-side
concerns (feature flag, role-map override, buffer/eviction bounds).
`SeqLayerConfig` is deliberately free of any `sentinel_sequence`/`numpy` import
so `Pipeline` can read it even when the optional ML dependency chain is absent
or the layer is disabled (NFR-3).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class SeqLayerConfig:
    # Feature flag — default OFF preserves NFR-6 by default.
    enabled: bool = False

    # Passed through to `sentinel_sequence.SequenceConfig(registry_dir=...)`.
    registry_dir: str = "models/sequence"

    # Optional agent_id -> role override map (FR-7). `attributes["role"]` on
    # the event takes precedence over this map; both are optional.
    role_map: Optional[dict] = None

    # Buffer bounds (FR-13).
    max_events_per_session: int = 200
    max_sessions: int = 10000
    # Bounded LRU cap on the persistent-unavailability cache (design §3.5,
    # §5.2). Default aligned with `max_sessions`.
    max_unavailable_roles: int = 10000

    # Idle-session eviction window, keyed off event `ts` (mini-ADR-5). Mirrors
    # `sentinel_sequence.SequenceConfig.gap_seconds`'s default, used here only
    # for buffer eviction, never for session-boundary grouping (SPEC A-6).
    idle_gap_seconds: float = 600.0
