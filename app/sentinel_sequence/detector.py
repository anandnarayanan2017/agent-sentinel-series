"""SequenceDetector: the single integration point for the Sentinel engine.

Responsibilities:
- train_and_publish(role, sessions): fit tokenizer+model on normal sessions,
  calibrate the threshold on a held-out split, publish atomically to the
  registry (refuses to publish on insufficient data).
- score(role, session): score one session against the role's LATEST model
  and return a Finding-shaped dict (advisory severity only — this layer
  NEVER denies; denial belongs to the policy engine).

Failure policy: scoring failures degrade to a "sequence_scoring_unavailable"
finding rather than raising into the hot path — the collector pipeline must
never drop events because the ML layer hiccuped.
"""

from __future__ import annotations

import logging
import random
from typing import Mapping, Sequence

import numpy as np

from .config import SequenceConfig
from .markov import MarkovModel
from .registry import ModelBundle, ModelRegistry, RegistryError
from .scoring import score_session
from .tokenizer import Tokenizer

logger = logging.getLogger("sentinel.sequence.detector")


class InsufficientDataError(RuntimeError):
    pass


class SequenceDetector:
    def __init__(self, config: SequenceConfig | None = None, registry: ModelRegistry | None = None):
        self.cfg = config or SequenceConfig()
        self.registry = registry or ModelRegistry(self.cfg.registry_dir)
        self._cache: dict[str, ModelBundle] = {}

    # ------------------------------------------------------------------ train
    def train_and_publish(
        self,
        role: str,
        normal_sessions: Sequence[Sequence[Mapping]],
        seed: int = 42,
    ) -> dict:
        """Fit on normal sessions, calibrate on a held-out session split, publish."""
        n = len(normal_sessions)
        if n < self.cfg.min_calibration_sessions * 2:
            raise InsufficientDataError(
                f"{n} sessions for role {role!r}; need >= "
                f"{self.cfg.min_calibration_sessions * 2} (train + calibration)"
            )

        sessions = list(normal_sessions)
        random.Random(seed).shuffle(sessions)
        n_cal = max(self.cfg.min_calibration_sessions, int(0.2 * n))
        train, cal = sessions[:-n_cal], sessions[-n_cal:]

        tokenizer = Tokenizer().fit(train)
        enc_train = [tokenizer.encode_session(s) for s in train]
        model = MarkovModel(order=self.cfg.order, alpha=self.cfg.alpha).fit(
            enc_train, tokenizer.vocab_size
        )

        cal_scores = np.asarray(
            [
                score_session(
                    model, tokenizer, tokenizer.encode_session(s), top_n=self.cfg.top_k
                ).topk_surprise
                for s in cal
            ]
        )
        threshold = float(np.percentile(cal_scores, self.cfg.percentile))
        calibration = {
            "percentile": self.cfg.percentile,
            "n_sessions": len(cal),
            "median": float(np.median(cal_scores)),
            "p99": float(np.percentile(cal_scores, 99.0)),
            "score": "topk_surprise",
            "top_k": self.cfg.top_k,
        }
        version = self.registry.publish(role, model, tokenizer, threshold, calibration)
        self._cache.pop(role, None)
        logger.info(
            "trained %s: %d train / %d cal sessions, vocab=%d, thr=%.4f",
            role,
            len(train),
            len(cal),
            tokenizer.vocab_size,
            threshold,
        )
        return {
            "role": role,
            "version": version,
            "threshold": threshold,
            "vocab_size": tokenizer.vocab_size,
            "calibration": calibration,
        }

    # ------------------------------------------------------------------ score
    def _bundle(self, role: str) -> ModelBundle:
        if role not in self._cache:
            self._cache[role] = self.registry.load(role)
        return self._cache[role]

    def score(self, role: str, session: Sequence[Mapping]) -> dict:
        """Score one session → Finding-shaped dict. Never raises into the hot path."""
        try:
            b = self._bundle(role)
        except RegistryError as e:
            logger.error("no model for role %s: %s", role, e)
            return self._unavailable_finding(role, str(e))

        try:
            sc = score_session(
                b.model,
                b.tokenizer,
                b.tokenizer.encode_session(session),
                top_n=self.cfg.top_k,
                k_expected=self.cfg.k_expected,
            )
        except Exception as e:  # noqa: BLE001 — hot path guard
            logger.exception("scoring failed for role %s", role)
            return self._unavailable_finding(role, f"scoring error: {e}")

        flagged = sc.topk_surprise > b.threshold
        margin = sc.topk_surprise / b.threshold if b.threshold > 0 else float("inf")
        severity = "high" if flagged and margin > 2.0 else "medium" if flagged else "info"
        return {
            "type": "sequence_anomaly" if flagged else "sequence_ok",
            "advisory": True,  # NEVER a deny
            "role": role,
            "model_version": b.version,
            "severity": severity,
            "score": {
                "topk_surprise": sc.topk_surprise,
                "nll_per_step": sc.nll_per_step,
                "threshold": b.threshold,
                "n_transitions": sc.n_transitions,
            },
            "evidence_chain": sc.to_evidence_chain() if flagged else [],
            "explanation": (
                f"session behavior deviates from learned {role} baseline "
                f"(surprise {sc.topk_surprise:.2f} > threshold {b.threshold:.2f}, "
                f"model {b.version})"
                if flagged
                else f"session consistent with learned {role} baseline"
            ),
        }

    @staticmethod
    def _unavailable_finding(role: str, reason: str) -> dict:
        return {
            "type": "sequence_scoring_unavailable",
            "advisory": True,
            "role": role,
            "severity": "info",
            "score": None,
            "evidence_chain": [],
            "explanation": f"sequence scoring unavailable for role {role!r}: {reason}",
        }
