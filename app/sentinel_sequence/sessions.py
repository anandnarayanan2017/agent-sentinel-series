"""Session boundary logic.

Rule (documented in ADR-004): use explicit session_id when present; otherwise
split an agent's event stream wherever the idle gap exceeds `gap_seconds`
(default 600s = 10 minutes). Events must carry a `ts` field (unix seconds or
ISO-8601 string) and an `agent_id`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Mapping, Sequence

DEFAULT_GAP_SECONDS = 600.0


def _to_epoch(ts) -> float:
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except ValueError as e:
            raise ValueError(f"Unparseable timestamp for field 'ts': {ts!r}") from e
    raise ValueError(f"Unsupported timestamp: {ts!r}")


def split_sessions(
    events: Sequence[Mapping],
    gap_seconds: float = DEFAULT_GAP_SECONDS,
) -> list[list[Mapping]]:
    """Split a flat event stream into sessions.

    - Groups by agent_id first (sessions never span agents).
    - Within an agent: use session_id if every event has one; otherwise
      fall back to gap-based splitting on `ts`.
    - Events are sorted by ts within each agent before splitting.
    """
    by_agent: dict[str, list[Mapping]] = {}
    for ev in events:
        by_agent.setdefault(str(ev.get("agent_id", "unknown")), []).append(ev)

    sessions: list[list[Mapping]] = []
    for agent_events in by_agent.values():
        if all(ev.get("session_id") for ev in agent_events):
            by_sid: dict[str, list[Mapping]] = {}
            for ev in agent_events:
                by_sid.setdefault(str(ev["session_id"]), []).append(ev)
            for sid_events in by_sid.values():
                sid_events[:] = [
                    t[2]
                    for t in sorted(
                        ((_to_epoch(e["ts"]), i, e) for i, e in enumerate(sid_events)),
                        key=lambda t: (t[0], t[1]),
                    )
                ]
                sessions.append(sid_events)
            continue

        agent_events[:] = [
            t[2]
            for t in sorted(
                ((_to_epoch(e["ts"]), i, e) for i, e in enumerate(agent_events)),
                key=lambda t: (t[0], t[1]),
            )
        ]
        current: list[Mapping] = []
        last_ts: float | None = None
        for ev in agent_events:
            t = _to_epoch(ev["ts"])
            if last_ts is not None and (t - last_ts) > gap_seconds:
                if current:
                    sessions.append(current)
                current = []
            current.append(ev)
            last_ts = t
        if current:
            sessions.append(current)
    return sessions
