"""PostgreSQL/TimescaleDB storage backend for Phase 3.

Activated when DATABASE_URL env var is set.  Falls back to plain PostgreSQL if
TimescaleDB extension is not present (create_hypertable is attempted but
errors are swallowed).

Schema:
  events      — hypertable by ts (time-series agent events)
  findings    — detection results with full evidence chains
  audit_log   — hypertable; protected API requests fingerprinted, stamped, and
                hash-chained to their predecessor (see storage/audit_chain.py)
  audit_chain — single-row chain head, locked FOR UPDATE on every audit write
  approvals   — review workflow for HIGH/CRITICAL findings
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sentinel.schema.events import AgentEvent, Finding
from sentinel.storage.audit_chain import GENESIS_HASH, entry_hash, verify_chain
from sentinel.storage.base import ApprovalNotFoundError, StoreBase

try:
    import psycopg2
    import psycopg2.extras
    import psycopg2.pool

    _PSYCOPG2 = True
except ImportError:
    _PSYCOPG2 = False

_DDL = """
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

CREATE TABLE IF NOT EXISTS events (
    event_id    VARCHAR(36) NOT NULL,
    ts          TIMESTAMPTZ NOT NULL,
    agent_id    VARCHAR,
    session_id  VARCHAR,
    action      VARCHAR,
    host        VARCHAR,
    method      VARCHAR,
    path        VARCHAR,
    model       VARCHAR,
    tool_name   VARCHAR,
    bytes_out   BIGINT DEFAULT 0,
    bytes_in    BIGINT DEFAULT 0,
    attributes  JSONB,
    evidence    JSONB,
    PRIMARY KEY (event_id, ts)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id         VARCHAR(36) PRIMARY KEY,
    ts                 TIMESTAMPTZ NOT NULL,
    agent_id           VARCHAR,
    session_id         VARCHAR,
    rule_id            VARCHAR,
    title              VARCHAR,
    severity           VARCHAR,
    explanation        TEXT,
    policy_clause      VARCHAR,
    severity_rationale TEXT,
    event_ids          JSONB,
    evidence           JSONB,
    control_refs       JSONB
);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id     UUID DEFAULT gen_random_uuid(),
    ts           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    endpoint     VARCHAR NOT NULL,
    method       VARCHAR NOT NULL,
    agent_id     VARCHAR,
    source_ip    VARCHAR,
    payload_hash VARCHAR(64),
    status_code  INTEGER,
    duration_ms  INTEGER,
    user_id      VARCHAR,
    prev_hash    VARCHAR(64),
    entry_hash   VARCHAR(64),
    PRIMARY KEY (audit_id, ts)
);

-- Single-row chain head. Locked FOR UPDATE on every audit write so concurrent
-- writers serialize and can never fork the chain (CR-17).
CREATE TABLE IF NOT EXISTS audit_chain (
    id         INTEGER PRIMARY KEY,
    last_hash  VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id  UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    finding_id   VARCHAR(36) NOT NULL,
    ts_created   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ts_reviewed  TIMESTAMPTZ,
    status       VARCHAR NOT NULL DEFAULT 'pending',
    reviewer     VARCHAR,
    comment      TEXT,
    severity     VARCHAR NOT NULL,
    CONSTRAINT fk_finding FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);
"""


class StorageMigrationError(Exception):
    """Raised when a schema migration cannot be verified. Defined here, not in
    `storage/base.py` — the migration is backend-internal and must not grow
    the abstract interface (B6a)."""


# Separate from `_DDL` on purpose (design/DESIGN.md §5.2): `_DDL` runs inside
# `_init_schema`'s per-statement try/except/rollback loop, which exists so a
# `CREATE EXTENSION timescaledb` failure on plain Postgres doesn't undo tables
# already created in the same pass (CR-5). Folding this migration into that
# loop would let its failure be silently swallowed the same way. `ADD COLUMN
# IF NOT EXISTS` is supported from Postgres 9.6, so this list is idempotent
# on its own — no separate existence check is needed before running it.
_MIGRATIONS = [
    # Audit hash-chain columns (CR-17). An audit_log predating the chain has
    # NULLs here; `verify_audit_chain` reports the first such row as the break
    # rather than pretending history it never hashed is verified.
    "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash  VARCHAR(64);",
    "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS entry_hash VARCHAR(64);",
]

_HYPERTABLES = [
    ("events", "ts"),
    ("audit_log", "ts"),
]

_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_events_agent    ON events    (agent_id, ts DESC);",
    "CREATE INDEX IF NOT EXISTS idx_findings_agent  ON findings  (agent_id, ts DESC);",
    "CREATE INDEX IF NOT EXISTS idx_findings_sev    ON findings  (severity, ts DESC);",
    "CREATE INDEX IF NOT EXISTS idx_audit_ts        ON audit_log (ts DESC);",
    "CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals (status, ts_created DESC);",
    # Real conflict target for insert_finding's ON CONFLICT (finding_id) DO
    # NOTHING — without this, that clause had nothing to dedupe against and a
    # re-inserted finding spawned a duplicate pending approval (CR-6).
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_approvals_finding_id ON approvals (finding_id);",
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


class PGStore(StoreBase):
    #: Connections are pooled per thread, so concurrent calls are safe and
    #: `Pipeline` does not serialize storage writes on this backend (CR-19).
    thread_safe = True

    def __init__(self, dsn: str, pool_size: int = 5) -> None:
        if not _PSYCOPG2:
            raise RuntimeError(
                "psycopg2 not installed — run: pip install 'agent-sentinel[postgres]'"
            )
        self._pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=1,
            maxconn=pool_size,
            dsn=dsn,
        )
        self._init_schema()

    # ── schema setup ─────────────────────────────────────────────────────────
    def _init_schema(self) -> None:
        # Each DDL statement gets its own commit/rollback boundary (CR-5): the
        # old code ran every statement in one open transaction, so a later
        # failure (e.g. `CREATE EXTENSION timescaledb` on plain Postgres)
        # called conn.rollback() and undid tables the same transaction had
        # already created. Committing per-statement means a downstream
        # failure only loses that one statement, never earlier successes.
        # The pool connection is always returned via `finally` — the previous
        # `with self._conn() as conn` never called `self._put(conn)`, leaking
        # a connection out of the pool on every PGStore construction.
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                for stmt in _DDL.split(";"):
                    stmt = stmt.strip()
                    if not stmt:
                        continue
                    try:
                        cur.execute(stmt)
                        conn.commit()
                    except Exception:
                        conn.rollback()

                # Network-visibility column migration (design/DESIGN.md §5.2).
                # Deliberately OUTSIDE the swallow-all loop above and in its
                # own try/except that rolls back THEN re-raises — a silently
                # swallowed migration failure must never let PGStore report
                # success against an unmigrated table (FR-18, NFR-9).
                try:
                    for stmt in _MIGRATIONS:
                        cur.execute(stmt)
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise

                # TimescaleDB hypertables (optional — skip if extension unavailable)
                for table, col in _HYPERTABLES:
                    try:
                        cur.execute(
                            f"SELECT create_hypertable('{table}', '{col}', "
                            f"if_not_exists => TRUE, migrate_data => TRUE);"
                        )
                        conn.commit()
                    except Exception:
                        conn.rollback()

                for idx in _INDEXES:
                    try:
                        cur.execute(idx)
                        conn.commit()
                    except Exception:
                        conn.rollback()
        finally:
            self._put(conn)

    def _conn(self):
        return self._pool.getconn()

    def _put(self, conn) -> None:
        self._pool.putconn(conn)

    # ── core writes ──────────────────────────────────────────────────────────
    def insert_event(self, e: AgentEvent) -> None:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                # Columns are named explicitly (design/DESIGN.md §5.3's
                # recommendation) so the placeholder/column/param count
                # triple (14 == 14 == 14) is self-evident and any future
                # drift fails loudly, not silently.
                cur.execute(
                    """
                    INSERT INTO events (
                        event_id, ts, agent_id, session_id, action,
                        host, method, path, model, tool_name,
                        bytes_out, bytes_in, attributes, evidence
                    ) VALUES (%s,%s,%s,%s,%s, %s,%s,%s,%s,%s, %s,%s,%s,%s)
                    ON CONFLICT (event_id, ts) DO NOTHING
                    """,
                    (
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
                    ),
                )
            conn.commit()
        finally:
            self._put(conn)

    def insert_finding(self, f: Finding) -> None:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO findings VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (finding_id) DO UPDATE SET ts = EXCLUDED.ts
                    """,
                    (
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
                    ),
                )
                # Auto-create approval record for HIGH/CRITICAL findings.
                # Explicit conflict target (CR-6): ux_approvals_finding_id
                # (see _INDEXES) is what actually makes this dedupe — a bare
                # ON CONFLICT DO NOTHING with no matching constraint silently
                # deduped nothing and let re-inserted findings spawn
                # duplicate pending approvals.
                if f.severity.value in ("high", "critical"):
                    cur.execute(
                        """
                        INSERT INTO approvals (finding_id, severity)
                        VALUES (%s, %s)
                        ON CONFLICT (finding_id) DO NOTHING
                        """,
                        (f.finding_id, f.severity.value),
                    )
            conn.commit()
        finally:
            self._put(conn)

    # ── audit trail ──────────────────────────────────────────────────────────
    def insert_audit(self, entry: dict[str, Any]) -> None:
        """Append one hash-chained audit entry.

        The chain head row is locked FOR UPDATE for the duration of the
        transaction, so two concurrent writers cannot read the same
        predecessor and fork the chain — they serialize, and the log stays a
        single verifiable line (CR-17).
        """
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT last_hash FROM audit_chain WHERE id = 1 FOR UPDATE")
                row = cur.fetchone()
                prev_hash = row[0] if row else GENESIS_HASH

                record = {
                    "ts": entry.get("ts", _now()),
                    "endpoint": entry["endpoint"],
                    "method": entry["method"],
                    "agent_id": entry.get("agent_id"),
                    "source_ip": entry.get("source_ip"),
                    "payload_hash": entry.get("payload_hash"),
                    "status_code": entry.get("status_code"),
                    "duration_ms": entry.get("duration_ms"),
                    "user_id": entry.get("user_id"),
                }
                this_hash = entry_hash(prev_hash, record)

                cur.execute(
                    """
                    INSERT INTO audit_log
                        (ts, endpoint, method, agent_id, source_ip,
                         payload_hash, status_code, duration_ms, user_id,
                         prev_hash, entry_hash)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        record["ts"],
                        record["endpoint"],
                        record["method"],
                        record["agent_id"],
                        record["source_ip"],
                        record["payload_hash"],
                        record["status_code"],
                        record["duration_ms"],
                        record["user_id"],
                        prev_hash,
                        this_hash,
                    ),
                )
                if row:
                    cur.execute("UPDATE audit_chain SET last_hash = %s WHERE id = 1", (this_hash,))
                else:
                    cur.execute(
                        "INSERT INTO audit_chain (id, last_hash) VALUES (1, %s)", (this_hash,)
                    )
            conn.commit()
        finally:
            self._put(conn)

    def verify_audit_chain(self, limit: int = 10_000) -> dict[str, Any]:
        """Walk the audit log oldest-first and report the first broken link.

        This is the check that makes "tamper-evident" a property rather than a
        claim: an auditor can run it and get back either a clean verdict or the
        exact record where the chain stops reconciling.
        """
        conn = self._conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM audit_log ORDER BY ts ASC, audit_id ASC LIMIT %s",
                    (limit,),
                )
                rows = [dict(r) for r in cur.fetchall()]
        finally:
            self._put(conn)
        break_at = verify_chain(rows)
        return {
            "verified": break_at is None,
            "entries_checked": len(rows),
            "first_break": break_at,
        }

    def list_audit(self, limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
        conn = self._conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM audit_log ORDER BY ts DESC LIMIT %s OFFSET %s",
                    (limit, offset),
                )
                return [dict(r) for r in cur.fetchall()]
        finally:
            self._put(conn)

    # ── approval workflow ─────────────────────────────────────────────────────
    def create_approval(self, finding_id: str, severity: str) -> str:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                approval_id = str(uuid.uuid4())
                cur.execute(
                    "INSERT INTO approvals (approval_id, finding_id, severity) VALUES (%s,%s,%s)",
                    (approval_id, finding_id, severity),
                )
            conn.commit()
            return approval_id
        finally:
            self._put(conn)

    def review_approval(
        self,
        approval_id: str,
        *,
        status: str,
        reviewer: str,
        comment: str = "",
    ) -> None:
        if status not in ("approved", "escalated", "suppressed"):
            raise ValueError(f"Invalid status: {status}")
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                # Restrict to status='pending' so this doubles as the
                # "already reviewed" check the endpoint's error message always
                # claimed to make (CR-10): previously an UPDATE matching zero
                # rows (bad approval_id, or already reviewed) wasn't an error
                # at all, so the caller's broad `except Exception: 404` never
                # actually caught the "not found" case — it only fired on
                # genuine DB errors, which it then mislabeled as 404.
                cur.execute(
                    """
                    UPDATE approvals
                    SET status=%s, reviewer=%s, comment=%s, ts_reviewed=NOW()
                    WHERE approval_id=%s AND status='pending'
                    """,
                    (status, reviewer, comment, approval_id),
                )
                found = cur.rowcount > 0
            if not found:
                conn.rollback()
                raise ApprovalNotFoundError(approval_id)
            conn.commit()
        finally:
            self._put(conn)

    def list_approvals(
        self,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        conn = self._conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if status:
                    cur.execute(
                        """
                        SELECT a.*, f.title, f.agent_id, f.explanation, f.rule_id,
                               f.control_refs, f.evidence
                        FROM approvals a
                        JOIN findings f USING (finding_id)
                        WHERE a.status = %s
                        ORDER BY a.ts_created DESC LIMIT %s
                        """,
                        (status, limit),
                    )
                else:
                    cur.execute(
                        """
                        SELECT a.*, f.title, f.agent_id, f.explanation, f.rule_id,
                               f.control_refs, f.evidence
                        FROM approvals a
                        JOIN findings f USING (finding_id)
                        ORDER BY a.ts_created DESC LIMIT %s
                        """,
                        (limit,),
                    )
                return [dict(r) for r in cur.fetchall()]
        finally:
            self._put(conn)

    # ── core reads ───────────────────────────────────────────────────────────
    def list_findings(
        self, limit: int = 100, since: Optional[datetime] = None
    ) -> list[dict[str, Any]]:
        conn = self._conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if since is not None:
                    cur.execute(
                        "SELECT * FROM findings WHERE ts > %s ORDER BY ts DESC LIMIT %s",
                        (since, limit),
                    )
                else:
                    cur.execute("SELECT * FROM findings ORDER BY ts DESC LIMIT %s", (limit,))
                rows = cur.fetchall()
                result = []
                for r in rows:
                    d = dict(r)
                    for col in ("event_ids", "evidence", "control_refs"):
                        if isinstance(d.get(col), str):
                            try:
                                d[col] = json.loads(d[col])
                            except Exception:
                                pass
                    result.append(d)
                return result
        finally:
            self._put(conn)

    def list_events(
        self, limit: int = 50, since: Optional[datetime] = None
    ) -> list[dict[str, Any]]:
        conn = self._conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if since is not None:
                    cur.execute(
                        "SELECT * FROM events WHERE ts > %s ORDER BY ts DESC LIMIT %s",
                        (since, limit),
                    )
                else:
                    cur.execute("SELECT * FROM events ORDER BY ts DESC LIMIT %s", (limit,))
                rows = cur.fetchall()
                result = []
                for r in rows:
                    d = dict(r)
                    for col in ("attributes", "evidence"):
                        if isinstance(d.get(col), str):
                            try:
                                d[col] = json.loads(d[col])
                            except Exception:
                                pass
                    result.append(d)
                return result
        finally:
            self._put(conn)

    def events_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        conn = self._conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM events WHERE agent_id=%s ORDER BY ts", (agent_id,))
                return [dict(r) for r in cur.fetchall()]
        finally:
            self._put(conn)

    def stats(self) -> dict[str, Any]:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
                sev_rows = cur.fetchall()
                cur.execute("SELECT COUNT(*) FROM findings")
                total_findings = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM events")
                total_events = cur.fetchone()[0]
                cur.execute("SELECT COUNT(DISTINCT agent_id) FROM events")
                active_agents = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM approvals WHERE status='pending'")
                pending_approvals = cur.fetchone()[0]
            return {
                "by_severity": {r[0]: r[1] for r in sev_rows},
                "total_findings": total_findings,
                "total_events": total_events,
                "active_agents": active_agents,
                "pending_approvals": pending_approvals,
            }
        finally:
            self._put(conn)

    def distinct_hosts(self, agent_id: str) -> set[str]:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT DISTINCT host FROM events WHERE agent_id=%s AND host IS NOT NULL",
                    (agent_id,),
                )
                return {r[0] for r in cur.fetchall()}
        finally:
            self._put(conn)

    def close(self) -> None:
        self._pool.closeall()
