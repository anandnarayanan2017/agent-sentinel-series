"""Pipeline: the single object the API and CLI both drive.

Ingest a captured flow -> normalize -> persist event -> evaluate -> persist
findings. Keeping this orchestration in one place means the collector front-ends
(proxy, SDK) only ever need to call `ingest_flow`.

Storage backend selection:
  - DATABASE_URL set → PostgreSQL/TimescaleDB (Phase 3)
  - SENTINEL_DB set  → DuckDB at that path (Phase 1/2, default :memory:)

Alerter and SIEM are imported lazily inside ingest_flow so that missing
optional packages (psycopg2, azure-monitor-ingestion) never crash the server
on startup — Phase 1/2 installs work without Phase 3 extras.

The optional L3 sequence layer follows the same lazy/guarded philosophy: its
config (`SeqLayerConfig`) is pure stdlib and always readable here, but the flag
defaults OFF (SENTINEL_SEQ_ENABLED unset) so `Pipeline`'s behavior is
byte-identical to pre-integration unless an operator opts in (NFR-6).
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path

from sentinel.collector.parsers import parse_flow
from sentinel.detection.engine import Engine
from sentinel.detection.policy import PolicySet
from sentinel.detection.seq_config import SeqLayerConfig
from sentinel.schema.events import AgentEvent, Finding
from sentinel.storage.base import StoreBase

logger = logging.getLogger("sentinel.pipeline")

# Process-wide counts of export failures since import, mirroring
# api/audit.py's `_audit_write_failures` convention. Export is one of this
# product's four pillars ("Detect. Explain. Enforce. Export."), and a silent
# `except Exception: pass` made a dropped SIEM push or alert indistinguishable
# from one that was never attempted (CR-23).
_export_failures = {"alerter": 0, "siem": 0}


def export_failures() -> dict[str, int]:
    """Process-wide totals of alerter/SIEM delivery failures since import."""
    return dict(_export_failures)


def _build_store(db_path: str) -> StoreBase:
    dsn = os.environ.get("DATABASE_URL")
    if dsn:
        from sentinel.storage.pg_store import PGStore

        return PGStore(dsn)
    from sentinel.storage.store import Store

    return Store(db_path)


def _fire_alerter(finding: Finding) -> None:
    """Deliver a finding to the configured alert targets. Never raises.

    Fail-open is correct here — a webhook outage must not block ingest — but
    fail-*silent* is not: a dropped alert is only acceptable if someone can
    tell it happened.
    """
    try:
        from sentinel.alerting.webhook import fire

        fire(finding)
    except Exception as exc:  # noqa: BLE001 — export must never block ingest
        _export_failures["alerter"] += 1
        logger.warning(
            "alert delivery failed: finding_id=%s rule_id=%s severity=%s err=%r",
            finding.finding_id,
            finding.rule_id,
            finding.severity.value,
            exc,
        )


def _push_siem(finding: Finding) -> None:
    """Push a finding to the SIEM connector. Never raises (see _fire_alerter)."""
    try:
        from sentinel.siem.log_analytics import push

        push(finding)
    except Exception as exc:  # noqa: BLE001 — export must never block ingest
        _export_failures["siem"] += 1
        logger.warning(
            "SIEM export failed: finding_id=%s rule_id=%s severity=%s err=%r",
            finding.finding_id,
            finding.rule_id,
            finding.severity.value,
            exc,
        )


def _truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {"1", "true", "yes", "on"}


def _seq_config_from_env() -> SeqLayerConfig:
    """Build a `SeqLayerConfig` from `SENTINEL_SEQ_*` env vars (default OFF).

    These reads are new to `Pipeline.__init__`: today it reads no `SENTINEL_*`
    var directly (only `_build_store` reads `DATABASE_URL`). The new vars
    follow the `SENTINEL_*` naming used at the API layer but are read here
    (design §2.2).
    """
    role_map = None
    raw_role_map = os.environ.get("SENTINEL_SEQ_ROLE_MAP")
    if raw_role_map:
        try:
            role_map = json.loads(raw_role_map)
        except (json.JSONDecodeError, TypeError):
            role_map = None

    kwargs: dict = {
        "enabled": _truthy(os.environ.get("SENTINEL_SEQ_ENABLED")),
        "registry_dir": os.environ.get("SENTINEL_SEQ_REGISTRY_DIR", "models/sequence"),
        "role_map": role_map,
    }
    for env_name, field_name in (
        ("SENTINEL_SEQ_MAX_EVENTS_PER_SESSION", "max_events_per_session"),
        ("SENTINEL_SEQ_MAX_SESSIONS", "max_sessions"),
        ("SENTINEL_SEQ_MAX_UNAVAILABLE_ROLES", "max_unavailable_roles"),
    ):
        raw = os.environ.get(env_name)
        if raw is not None:
            try:
                kwargs[field_name] = int(raw)
            except (ValueError, TypeError):
                pass  # malformed env var -> fall back to the SeqLayerConfig default

    raw_gap = os.environ.get("SENTINEL_SEQ_IDLE_GAP_SECONDS")
    if raw_gap is not None:
        try:
            kwargs["idle_gap_seconds"] = float(raw_gap)
        except (ValueError, TypeError):
            pass  # malformed env var -> fall back to the SeqLayerConfig default

    return SeqLayerConfig(**kwargs)


class Pipeline:
    def __init__(
        self,
        policy_path: str | Path,
        db_path: str = ":memory:",
        seq_config: SeqLayerConfig | None = None,
    ) -> None:
        self.store: StoreBase = _build_store(db_path)
        cfg = seq_config if seq_config is not None else _seq_config_from_env()
        self.engine = Engine(PolicySet.from_yaml(policy_path), seq_config=cfg, store=self.store)
        # /ingest is a sync def, so Starlette runs concurrent requests on its
        # threadpool, and the engine's in-memory state (Engine._tool_calls,
        # BaselineStore, the L3 session buffers) is shared across them. That
        # state always needs a lock (CR-3).
        #
        # Storage is a separate question. Originally one lock wrapped the
        # storage writes AND evaluation, which serialized ingest even on
        # PostgreSQL, whose pooled per-thread connections are already safe —
        # a throughput ceiling for a recorder that sits in the path of every
        # LLM and tool call. The lock is now scoped to what actually needs it,
        # and storage writes are serialized only on a backend that says it
        # needs that (`StoreBase.thread_safe`) (CR-19).
        #
        # RLock, not Lock: `engine.evaluate` reads the store through
        # `BaselineStore.get` -> `store.distinct_hosts`, so on a
        # non-thread-safe backend the store lock IS the engine lock and is
        # re-entered by the same thread.
        self._engine_lock = threading.RLock()
        self._store_lock = threading.RLock() if self.store.thread_safe else self._engine_lock

    def ingest_flow(self, ingested_by: str | None = None, **flow_kwargs) -> list[Finding]:
        """HTTP-flow-shaped entry point (proxy/SDK collectors).

        Still parses `flow_kwargs` via `parse_flow`, then hands the resulting
        `AgentEvent` to `ingest_event` — the single shared ingest body every
        collector goes through (design/DESIGN.md §2.8 "I-8"; DD-4).

        `ingested_by` is the verified principal that submitted the flow, if
        any. `agent_id` is a claim made in the request body; recording who
        actually presented it means the two can be reconciled after the fact
        even when a token carries no `agent_ids` constraint (CR-21).
        """
        event = parse_flow(**flow_kwargs)
        if ingested_by:
            event.attributes["ingested_by"] = ingested_by
        return self.ingest_event(event)

    def ingest_event(self, event: AgentEvent) -> list[Finding]:
        """Ingest an already-constructed `AgentEvent` (design §2.8, "I-8"; DD-4).

        This is the body formerly inlined in `ingest_flow` (lock, insert_event,
        evaluate, insert_finding loop, alerter, SIEM), extracted verbatim so a
        collector that builds its own `AgentEvent`s directly — never through
        `parse_flow`, since it is not parsing an HTTP flow — enters the same
        pipeline `ingest_flow` uses, through the same locks, at the same point
        in the flow.
        """
        with self._store_lock:
            self.store.insert_event(event)
        with self._engine_lock:
            findings = self.engine.evaluate(event)
        with self._store_lock:
            for f in findings:
                self.store.insert_finding(f)
        for f in findings:
            _fire_alerter(f)  # fail-open — lazy import, never raises
            _push_siem(f)  # fail-open — no-op if AZURE_LOG_ANALYTICS_DCE unset
        return findings
