"""Typed configuration for the sequence-detection subsystem.

Single source of truth for every tunable. Loadable from a dict (YAML-parsed
upstream by the main Sentinel config loader) with validation at construction
time — fail fast at startup, not mid-scoring.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Mapping


@dataclass(frozen=True)
class SequenceConfig:
    # session splitting
    gap_seconds: float = 600.0
    # model
    order: int = 2
    alpha: float = 0.5
    # scoring
    top_k: int = 3
    k_expected: int = 3
    # calibration
    percentile: float = 99.0
    min_calibration_sessions: int = 50
    # drift / staleness
    drift_window_days: int = 7
    drift_ratio_threshold: float = 1.5  # median surprise vs calibration median
    # registry
    registry_dir: str = "models/sequence"

    def __post_init__(self) -> None:
        errs = []
        if self.gap_seconds <= 0:
            errs.append("gap_seconds must be > 0")
        if self.order not in (1, 2):
            errs.append("order must be 1 or 2")
        if self.alpha <= 0:
            errs.append("alpha must be > 0 (zero breaks smoothing)")
        if self.top_k < 1:
            errs.append("top_k must be >= 1")
        if not (50.0 <= self.percentile < 100.0):
            errs.append("percentile must be in [50, 100)")
        if self.min_calibration_sessions < 10:
            errs.append("min_calibration_sessions must be >= 10")
        if self.drift_ratio_threshold <= 1.0:
            errs.append("drift_ratio_threshold must be > 1.0")
        if errs:
            raise ValueError("Invalid SequenceConfig: " + "; ".join(errs))

    @classmethod
    def from_dict(cls, d: Mapping) -> "SequenceConfig":
        # Single authoritative unknown-key gate (see DESIGN mini-ADR-1). The
        # manual check pre-empts cls(**d), whose TypeError path is thus unreachable.
        allowed = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        unknown = set(d) - allowed
        if unknown:
            raise ValueError(f"Unknown SequenceConfig keys: {sorted(unknown)}")
        return cls(**d)

    def to_dict(self) -> dict:
        return asdict(self)
