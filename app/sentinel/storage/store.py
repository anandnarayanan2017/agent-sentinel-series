"""DuckDB-backed storage for events and findings.

DuckDB chosen for the MVP because it is embedded (no server to run), columnar
(fast aggregation for baselining), and speaks SQL (analysts can query it
directly). Swapping for Postgres/ClickHouse later is a single-module change
behind this interface.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import duckdb

from sentinel.schema.events import AgentEvent, Finding
from sentinel.storage.base import StoreBase


class Store(StoreBase):
    #: One embedded DuckDB connection, not safe to share across threads —
    #: `Pipeline` serializes its writes accordingly (CR-19).
    thread_safe = False

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.conn = duckdb.connect(str(path))
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id    VARCHAR PRIMARY KEY,
                ts          TIMESTAMP,
                agent_id    VARCHAR,
                session_id  VARCHAR,
                action      VARCHAR,
                host        VARCHAR,
                method      VARCHAR,
                path        VARCHAR,
                model       VARCHAR,
                tool_name   VARCHAR,
                bytes_out   BIGINT,
                bytes_in    BIGINT,
                attributes  JSON,
                evidence    JSON
            );
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                finding_id        VARCHAR PRIMARY KEY,
                ts                TIMESTAMP,
                agent_id          VARCHAR,
                session_id        VARCHAR,
                rule_id           VARCHAR,
                title             VARCHAR,
                severity          VARCHAR,
                explanation       VARCHAR,
                policy_clause     VARCHAR,
                severity_rationale VARCHAR,
                event_ids         JSON,
                evidence          JSON,
                control_refs      JSON
            );
            """
        )

    # ---- writes -------------------------------------------------------------
    def insert_event(self, e: AgentEvent) -> None:
        # Columns are named explicitly (design/DESIGN.md §5.3's recommendation)
        # so the placeholder/column/param count triple (14 == 14 == 14) is
        # self-evident and any future drift fails loudly, not silently.
        self.conn.execute(
            """
            INSERT OR REPLACE INTO events (
                event_id, ts, agent_id, session_id, action,
                host, method, path, model, tool_name,
                bytes_out, bytes_in, attributes, evidence
            ) VALUES (?,?,?,?,?, ?,?,?,?,?, ?,?,?,?)
            """,
            [
                e.event_id,
                e.ts,
                e.agent_id,
                e.session_id,
                e.action.value,
                e.host,
                e.method,
                e.path,
                e.model,
                e.tool_name,
                e.bytes_out,
                e.bytes_in,
                json.dumps(e.attributes),
                json.dumps([ev.model_dump() for ev in e.evidence]),
            ],
        )

    def insert_finding(self, f: Finding) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                f.finding_id,
                f.ts,
                f.agent_id,
                f.session_id,
                f.rule_id,
                f.title,
                f.severity.value,
                f.explanation,
                f.policy_clause,
                f.severity_rationale,
                json.dumps(f.event_ids),
                json.dumps([ev.model_dump() for ev in f.evidence]),
                json.dumps(f.control_refs),
            ],
        )

    # ---- reads --------------------------------------------------------------
    def events_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM events WHERE agent_id = ? ORDER BY ts", [agent_id]
        ).fetchall()
        cols = [c[0] for c in self.conn.description]
        return [dict(zip(cols, r)) for r in rows]

    def list_findings(
        self, limit: int = 100, since: Optional[datetime] = None
    ) -> list[dict[str, Any]]:
        if since is not None:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE ts > ? ORDER BY ts DESC LIMIT ?",
                [since, limit],
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM findings ORDER BY ts DESC LIMIT ?", [limit]
            ).fetchall()
        cols = [c[0] for c in self.conn.description]
        result = []
        for r in rows:
            d = dict(zip(cols, r))
            # Decode JSON columns to match list_events()'s shape and PGStore's
            # list_findings() — was returning these as raw JSON strings while
            # every other read path decodes them (CR-12).
            for col in ("event_ids", "evidence", "control_refs"):
                if isinstance(d.get(col), str):
                    try:
                        d[col] = json.loads(d[col])
                    except Exception:
                        pass
            result.append(d)
        return result

    def list_events(
        self, limit: int = 50, since: Optional[datetime] = None
    ) -> list[dict[str, Any]]:
        if since is not None:
            rows = self.conn.execute(
                "SELECT * FROM events WHERE ts > ? ORDER BY ts DESC LIMIT ?",
                [since, limit],
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM events ORDER BY ts DESC LIMIT ?", [limit]
            ).fetchall()
        cols = [c[0] for c in self.conn.description]
        result = []
        for r in rows:
            d = dict(zip(cols, r))
            for col in ("attributes", "evidence"):
                if isinstance(d.get(col), str):
                    try:
                        d[col] = json.loads(d[col])
                    except Exception:
                        pass
            result.append(d)
        return result

    def stats(self) -> dict[str, Any]:
        sev_rows = self.conn.execute(
            "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
        ).fetchall()
        findings_row = self.conn.execute("SELECT COUNT(*) FROM findings").fetchone()
        events_row = self.conn.execute("SELECT COUNT(*) FROM events").fetchone()
        agents_row = self.conn.execute("SELECT COUNT(DISTINCT agent_id) FROM events").fetchone()
        # COUNT(*) always yields exactly one row, even over an empty table, so
        # these three cannot legitimately be None here; if they ever are, the
        # connection/query is broken and failing loudly beats indexing None.
        if findings_row is None or events_row is None or agents_row is None:
            raise RuntimeError("stats() aggregate query returned no row — storage connection issue")
        total_findings = findings_row[0]
        total_events = events_row[0]
        active_agents = agents_row[0]
        return {
            "by_severity": {r[0]: r[1] for r in sev_rows},
            "total_findings": total_findings,
            "total_events": total_events,
            "active_agents": active_agents,
        }

    def distinct_hosts(self, agent_id: str) -> set[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT host FROM events WHERE agent_id = ? AND host IS NOT NULL",
            [agent_id],
        ).fetchall()
        return {r[0] for r in rows}

    def close(self) -> None:
        self.conn.close()
