"""Concept-drift / model-staleness detection.

When an agent's prompt or toolset legitimately changes, "normal" moves and
the model starts alert-storming. Rather than paging a human per alert, we
detect the *pattern of the pattern*: if the median session surprise over a
recent window rises well above the calibration-time median, the model is
stale — emit a single "retrain me" finding instead of N false alerts.

Rule: stale iff  recent_median > drift_ratio_threshold * calibration_median
      and n_recent >= min_sessions.
Median (not mean) so a handful of genuine attacks in the window cannot
fake a drift signal.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np

logger = logging.getLogger("sentinel.sequence.drift")

_DEGENERATE_MEDIAN_EPSILON = 1e-9  # see DESIGN mini-ADR-2


@dataclass(frozen=True)
class DriftReport:
    stale: bool
    recent_median: float
    calibration_median: float
    ratio: float
    n_recent: int
    reason: str

    def to_evidence(self) -> str:
        return (
            f"median session surprise over last {self.n_recent} sessions is "
            f"{self.recent_median:.3f} vs {self.calibration_median:.3f} at calibration "
            f"(ratio {self.ratio:.2f}) — {self.reason}"
        )


def check_drift(
    recent_scores: list[float],
    calibration_median: float,
    ratio_threshold: float = 1.5,
    min_sessions: int = 30,
) -> DriftReport:
    n = len(recent_scores)
    if calibration_median <= _DEGENERATE_MEDIAN_EPSILON:
        return DriftReport(
            stale=False,
            recent_median=float("nan"),
            calibration_median=calibration_median,
            ratio=float("nan"),
            n_recent=n,
            reason="insufficient baseline: calibration median is zero/near-zero",
        )
    if n < min_sessions:
        return DriftReport(
            stale=False,
            recent_median=float("nan"),
            calibration_median=calibration_median,
            ratio=float("nan"),
            n_recent=n,
            reason=f"insufficient data ({n} < {min_sessions} sessions)",
        )
    recent_median = float(np.median(recent_scores))
    ratio = recent_median / calibration_median
    stale = ratio > ratio_threshold
    reason = (
        "behavioral baseline has shifted; retrain and recalibrate"
        if stale
        else "within normal variation"
    )
    if stale:
        logger.warning("drift detected: ratio=%.2f (threshold %.2f)", ratio, ratio_threshold)
    return DriftReport(
        stale=stale,
        recent_median=recent_median,
        calibration_median=calibration_median,
        ratio=ratio,
        n_recent=n,
        reason=reason,
    )
