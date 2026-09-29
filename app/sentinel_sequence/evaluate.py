"""Evaluation harness: PR curve + percentile-calibrated threshold.

Split discipline: train/val split happens at the SESSION level (never
event level) to avoid leakage. The model is trained only on normal
training sessions (one-class framing); attacks appear only in the eval set.

Threshold selection: rather than tuning on attack labels (which we won't
have in production), the operating threshold is calibrated as a percentile
of NLL scores on held-out NORMAL sessions (default p99) — i.e. "accept a
~1% false-positive budget". Attack recall is then reported at that threshold.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np


@dataclass
class EvalReport:
    threshold: float
    percentile: float
    precision: float
    recall: float
    f1: float
    n_normal_eval: int
    n_attack_eval: int
    pr_curve: list[tuple[float, float, float]] = field(default_factory=list)  # (thr, P, R)
    per_attack_recall: dict[str, float] = field(default_factory=dict)

    def summary(self) -> str:
        lines = [
            f"threshold (p{self.percentile:.0f} of normal NLL): {self.threshold:.4f}",
            f"precision={self.precision:.3f}  recall={self.recall:.3f}  f1={self.f1:.3f}",
            f"eval set: {self.n_normal_eval} normal / {self.n_attack_eval} attack sessions",
            "recall by attack type:",
        ]
        for k, v in sorted(self.per_attack_recall.items()):
            lines.append(f"  - {k}: {v:.3f}")
        return "\n".join(lines)


def precision_recall_at(scores_normal, scores_attack, threshold) -> tuple[float, float]:
    """Strict > : a session must be MORE surprising than the calibrated
    normal-percentile threshold to be flagged (>= would flag the calibration
    sessions themselves when scores tie at the percentile)."""
    tp = int(np.sum(np.asarray(scores_attack) > threshold))
    fp = int(np.sum(np.asarray(scores_normal) > threshold))
    fn = len(scores_attack) - tp
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return precision, recall


def evaluate(
    scores_normal_eval: list[float],
    attack_scores: list[tuple[str, float]],  # (attack_type, score)
    percentile: float = 99.0,
) -> EvalReport:
    sn = np.asarray(scores_normal_eval, dtype=float)
    sa = np.asarray([s for _, s in attack_scores], dtype=float)
    threshold = float(np.percentile(sn, percentile))

    precision, recall = precision_recall_at(sn, sa, threshold)
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    # PR curve over a sweep of candidate thresholds
    all_scores = np.unique(np.concatenate([sn, sa]))
    curve = []
    for thr in all_scores:
        p, r = precision_recall_at(sn, sa, float(thr))
        curve.append((float(thr), p, r))

    per_type: dict[str, float] = {}
    for atk_type in sorted({t for t, _ in attack_scores}):
        subset = np.asarray([s for t, s in attack_scores if t == atk_type])
        per_type[atk_type] = float(np.mean(subset > threshold)) if len(subset) else 0.0

    return EvalReport(
        threshold=threshold,
        percentile=percentile,
        precision=precision,
        recall=recall,
        f1=f1,
        n_normal_eval=len(sn),
        n_attack_eval=len(sa),
        pr_curve=curve,
        per_attack_recall=per_type,
    )
