"""DuckDB event-store integration.

Reads AgentEvents from the existing Sentinel DuckDB store and yields
session-split event lists ready for the tokenizer. Column mapping is
configurable so this adapts to the exact `agent_events` schema without
code changes.

Expected minimal schema (names remappable via `columns`):

    agent_events(agent_id VARCHAR, ts TIMESTAMP/DOUBLE, kind VARCHAR,
                 name VARCHAR, session_id VARCHAR NULL, role VARCHAR NULL)
"""

from __future__ import annotations

import logging
from typing import Mapping

from .sessions import split_sessions

logger = logging.getLogger("sentinel.sequence.store")

DEFAULT_COLUMNS = {
    "agent_id": "agent_id",
    "ts": "ts",
    "kind": "kind",
    "name": "name",
    "session_id": "session_id",
    "role": "role",
}


class EventStore:
    """Thin reader over the Sentinel DuckDB event table.

    Assumes the table schema is stable for its lifetime: `_ts_expr` is
    computed once at construction and cached, so altering the table's `ts`
    column type after construction leaves the expression stale.
    """

    def __init__(
        self,
        db_path: str,
        table: str = "agent_events",
        columns: Mapping[str, str] | None = None,
        read_only: bool = True,
    ):
        self.table = table
        self.cols = {**DEFAULT_COLUMNS, **(columns or {})}
        # FR-4: validate every column-mapping value BEFORE any DB work, so the
        # injection guard is reachable without a live DB (AC-4 / A-6). This is a
        # NEW guard (no prior column validation existed), so it introduces no
        # exception-type change on any pre-existing path.
        for key, val in self.cols.items():
            if not (isinstance(val, str) and val and val.replace("_", "").isalnum()):
                raise ValueError(f"Suspicious column mapping {key!r} -> {val!r}")
        try:
            import duckdb  # local import: keep duckdb an optional dependency
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("duckdb is required for EventStore; pip install duckdb") from e
        self._duckdb = duckdb
        self.conn = duckdb.connect(db_path, read_only=read_only)
        # UNCHANGED: the table-name check stays post-connect, exactly as today, so
        # its pre-existing behavior (a missing-db duckdb error surfaces before this
        # ValueError) is preserved verbatim (NFR-1).
        if not table.replace("_", "").isalnum():
            raise ValueError(f"Suspicious table name: {table!r}")
        self._ts_expr = self._build_ts_expr()

    def _build_ts_expr(self) -> str:
        """epoch(col) for TIMESTAMP-typed ts columns; pass-through for numeric.

        Assumes the table schema is stable for the store's lifetime: this
        expression is computed once here and cached, so altering the table's
        `ts` column type after construction leaves the expression stale.
        """
        rows = self.conn.execute(f"DESCRIBE {self.table}").fetchall()
        types = {r[0]: r[1].upper() for r in rows}
        col = self.cols["ts"]
        if col not in types:
            raise ValueError(
                f"ts column {col!r} not found in table {self.table!r}; check the 'columns' mapping"
            )
        col_type = types[col]
        if "TIMESTAMP" in col_type or col_type == "DATE":
            return f"epoch({col})"
        return col

    def fetch_events(
        self,
        role: str | None = None,
        since_epoch: float | None = None,
        until_epoch: float | None = None,
    ) -> list[dict]:
        c = self.cols
        # bandit B608: every value interpolated here (c[...], self.table) is
        # validated alnum+underscore-only in __init__ before any DB work
        # (FR-4 guard above) — this can't carry injected SQL. Query params
        # (role/since/until below) go through ? placeholders as normal.
        select = (
            f"SELECT {c['agent_id']} AS agent_id, "  # nosec B608
            f"{self._ts_expr} AS ts, {c['kind']} AS kind, {c['name']} AS name, "
            f"{c['session_id']} AS session_id FROM {self.table}"
        )
        where: list[str] = []
        params: list[str | float] = []
        if role is not None:
            where.append(f"{c['role']} = ?")
            params.append(role)
        if since_epoch is not None:
            where.append(f"{self._ts_expr} >= ?")
            params.append(since_epoch)
        if until_epoch is not None:
            where.append(f"{self._ts_expr} < ?")
            params.append(until_epoch)
        if where:
            select += " WHERE " + " AND ".join(where)
        select += f" ORDER BY {c['agent_id']}, ts"

        rows = self.conn.execute(select, params).fetchall()
        events = [
            {"agent_id": r[0], "ts": r[1], "kind": r[2], "name": r[3], "session_id": r[4]}
            for r in rows
        ]
        logger.info("fetched %d events (role=%s)", len(events), role)
        return events

    def fetch_sessions(
        self,
        role: str | None = None,
        gap_seconds: float = 600.0,
        since_epoch: float | None = None,
        until_epoch: float | None = None,
    ) -> list[list[Mapping]]:
        events = self.fetch_events(role=role, since_epoch=since_epoch, until_epoch=until_epoch)
        sessions = split_sessions(events, gap_seconds=gap_seconds)
        logger.info("split into %d sessions", len(sessions))
        return sessions

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "EventStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
