"""Markov sequence models over tokenized sessions.

MarkovModel(order=1): P(next | current)
MarkovModel(order=2): P(next | (prev, current))  — falls back to order-1 for
the first transition of a session where no 2-token history exists.

Laplace (additive) smoothing with `alpha` guarantees no zero-probability
transition, so novel behavior scores as *surprising*, never as *impossible*
(which would produce infinite NLL and break threshold calibration).
"""

from __future__ import annotations

import heapq
import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence


@dataclass
class MarkovModel:
    order: int = 1
    alpha: float = 1.0  # Laplace smoothing
    vocab_size: int = 0
    # counts[context][next_token] = count ; context is a tuple of token ids
    counts: dict = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    # context_totals caches sum(counts[ctx].values()); maintained in _count_sequence
    # and load, kept so prob() is O(1) rather than O(vocab) per call.
    context_totals: dict = field(default_factory=lambda: defaultdict(int))
    _fitted: bool = False

    def __post_init__(self):
        if self.order not in (1, 2):
            raise ValueError("Only order 1 and 2 are supported.")

    # -- training ----------------------------------------------------------
    def fit(self, encoded_sessions: Sequence[Sequence[int]], vocab_size: int) -> "MarkovModel":
        if vocab_size <= 0:
            raise ValueError("vocab_size must be positive.")
        self.vocab_size = vocab_size
        for seq in encoded_sessions:
            self._count_sequence(seq)
        self._fitted = True
        return self

    def _count_sequence(self, seq: Sequence[int]) -> None:
        n = len(seq)
        for i in range(1, n):
            # order-1 context always counted (also serves as order-2 fallback)
            ctx1 = (seq[i - 1],)
            self.counts[ctx1][seq[i]] += 1
            self.context_totals[ctx1] += 1
            if self.order == 2 and i >= 2:
                ctx2 = (seq[i - 2], seq[i - 1])
                self.counts[ctx2][seq[i]] += 1
                self.context_totals[ctx2] += 1

    # -- inference ---------------------------------------------------------
    def prob(self, context: tuple, next_id: int) -> float:
        """Smoothed P(next | context). Unseen contexts get a uniform prior."""
        if not self._fitted:
            raise RuntimeError("Model must be fitted before scoring.")
        c = self.counts.get(context, {})
        total = self.context_totals.get(context, 0)
        count = c.get(next_id, 0)
        return (count + self.alpha) / (total + self.alpha * self.vocab_size)

    def _context_at(self, seq: Sequence[int], i: int) -> tuple:
        """Context for predicting position i (order-2 falls back to order-1)."""
        if self.order == 2 and i >= 2:
            ctx = (seq[i - 2], seq[i - 1])
            if ctx in self.counts:
                return ctx
        return (seq[i - 1],)

    def step_probs(self, seq: Sequence[int]) -> list[tuple[tuple, int, float]]:
        """Per-transition (context, observed_next, probability) for a session."""
        out = []
        for i in range(1, len(seq)):
            ctx = self._context_at(seq, i)
            out.append((ctx, seq[i], self.prob(ctx, seq[i])))
        return out

    def top_k(self, context: tuple, k: int = 3) -> list[tuple[int, float]]:
        """Most-expected next tokens for a context (for explanations).

        k must be >= 0. Unlike list slicing, heapq.nlargest treats a negative
        k as "give me nothing" rather than "all but the last |k|", so a
        negative k is rejected explicitly instead of silently diverging.
        """
        if k < 0:
            raise ValueError(f"k must be >= 0, got {k}")
        c = self.counts.get(context)
        if not c:
            return []
        ranked = heapq.nlargest(k, c.items(), key=lambda kv: kv[1])
        return [(tok, self.prob(context, tok)) for tok, _ in ranked]

    # -- persistence -------------------------------------------------------
    def save(self, path: str | Path) -> None:
        blob = {
            "order": self.order,
            "alpha": self.alpha,
            "vocab_size": self.vocab_size,
            "counts": {json.dumps(list(ctx)): dict(nxt) for ctx, nxt in self.counts.items()},
        }
        Path(path).write_text(json.dumps(blob))

    @classmethod
    def _from_blob(cls, blob: dict) -> "MarkovModel":
        m = cls(order=blob["order"], alpha=blob["alpha"], vocab_size=blob["vocab_size"])
        for ctx_s, nxt in blob["counts"].items():
            ctx = tuple(json.loads(ctx_s))
            for tok_s, cnt in nxt.items():
                tok = int(tok_s)
                m.counts[ctx][tok] = cnt
                m.context_totals[ctx] += cnt
        m._fitted = True
        return m

    @classmethod
    def load(cls, path: str | Path) -> "MarkovModel":
        return cls._from_blob(json.loads(Path(path).read_text()))
