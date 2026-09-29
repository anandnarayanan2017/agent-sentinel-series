"""Abstract storage interface — DuckDB and PostgreSQL both implement this."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Optional

from sentinel.schema.events import AgentEvent, Finding


class ApprovalNotFoundError(Exception):
    """Raised by review_approval() when approval_id doesn't exist or was
    already reviewed (not pending) — distinct from a genuine backend error,
    so callers can map it to 404 without masking real 5xx failures (CR-10)."""


class BackendCapabilityError(NotImplementedError):
    """Raised when a surface is asked of a backend that cannot provide it.

    Subclasses `NotImplementedError` so it reads correctly at the call site,
    and carries the operator's remedy in `.detail` so the API layer can pass
    it straight through instead of inventing its own wording.
    """

    detail = "This surface requires the PostgreSQL backend (set DATABASE_URL)."


class AuditNotSupportedError(BackendCapabilityError):
    detail = (
        "Audit logging requires the PostgreSQL backend. Set DATABASE_URL to a "
        "PostgreSQL/TimescaleDB DSN; the embedded DuckDB backend cannot retain "
        "an audit trail."
    )


class ApprovalsNotSupportedError(BackendCapabilityError):
    detail = (
        "The approval workflow requires the PostgreSQL backend. Set DATABASE_URL "
        "to a PostgreSQL/TimescaleDB DSN; the embedded DuckDB backend cannot "
        "record a review decision."
    )


class StoreBase(ABC):
    #: Whether concurrent calls from multiple threads are safe on this backend.
    #: PGStore pools a connection per thread and is safe; the DuckDB backend
    #: holds one non-thread-safe connection and is not. `Pipeline` reads this
    #: to decide whether its storage writes need the engine lock (CR-19).
    thread_safe: bool = False

    # ── core writes ──────────────────────────────────────────────────────────
    @abstractmethod
    def insert_event(self, e: AgentEvent) -> None: ...

    @abstractmethod
    def insert_finding(self, f: Finding) -> None: ...

    # ── core reads ───────────────────────────────────────────────────────────
    @abstractmethod
    def list_findings(
        self, limit: int = 100, since: Optional[datetime] = None
    ) -> list[dict[str, Any]]: ...

    @abstractmethod
    def list_events(
        self, limit: int = 50, since: Optional[datetime] = None
    ) -> list[dict[str, Any]]: ...

    @abstractmethod
    def stats(self) -> dict[str, Any]: ...

    @abstractmethod
    def distinct_hosts(self, agent_id: str) -> set[str]: ...

    @abstractmethod
    def close(self) -> None: ...

    # ── audit trail (PostgreSQL only) ────────────────────────────────────────
    # These used to be silent no-ops returning success. A no-op that reports
    # success is not "safe": a reviewer saw HTTP 200 and an empty audit log
    # that was indistinguishable from "no activity", on the backend the
    # quickstart actually runs. A backend that cannot record a compliance
    # decision must refuse it, loudly, and name the remedy (CR-18).
    def insert_audit(self, entry: dict[str, Any]) -> None:
        raise AuditNotSupportedError(AuditNotSupportedError.detail)

    def list_audit(self, limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
        raise AuditNotSupportedError(AuditNotSupportedError.detail)

    def verify_audit_chain(self, limit: int = 10_000) -> dict[str, Any]:
        raise AuditNotSupportedError(AuditNotSupportedError.detail)

    # ── approval workflow (PostgreSQL only) ──────────────────────────────────
    def create_approval(self, finding_id: str, severity: str) -> str:
        raise ApprovalsNotSupportedError(ApprovalsNotSupportedError.detail)

    def review_approval(
        self,
        approval_id: str,
        *,
        status: str,
        reviewer: str,
        comment: str = "",
    ) -> None:
        raise ApprovalsNotSupportedError(ApprovalsNotSupportedError.detail)

    def list_approvals(
        self,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        raise ApprovalsNotSupportedError(ApprovalsNotSupportedError.detail)
