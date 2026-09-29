"""Session scoring + explainability.

Score = mean negative log-likelihood (NLL) per transition, so scores are
comparable across sessions of different lengths. Higher = more surprising.

Every score comes with an evidence chain: the top-N most surprising steps,
each rendered as "expected {A (p=..), B (p=..)}, observed C (p=..)" — the
same sentence format the existing explain/ layer consumes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

import numpy as np

from .markov import MarkovModel
from .tokenizer import Tokenizer


@dataclass
class StepSurprise:
    position: int  # index of the transition within the session
    context: list[str]  # decoded context tokens
    observed: str  # decoded observed token
    observed_prob: float
    surprise: float  # -log(p)
    expected: list[tuple[str, float]]  # top-k (token, prob)

    def to_sentence(self) -> str:
        if self.expected:
            exp = ", ".join(f"{t} (p={p:.2f})" for t, p in self.expected)
        else:
            exp = "no learned expectation for this context"
        ctx = " → ".join(self.context)
        return (
            f"step {self.position}: after [{ctx}], expected {{{exp}}}; "
            f"observed {self.observed} (p={self.observed_prob:.4f})"
        )


@dataclass
class SessionScore:
    nll_per_step: float  # mean NLL — catches diffuse anomalies (bursts, drift)
    topk_surprise: float  # mean of the K most surprising steps — catches
    # concentrated anomalies diluted by long sessions
    # (e.g. 2 injected steps in a 10-step session)
    n_transitions: int
    top_surprises: list[StepSurprise] = field(default_factory=list)

    def to_evidence_chain(self) -> list[str]:
        return [s.to_sentence() for s in self.top_surprises]


def score_session(
    model: MarkovModel,
    tokenizer: Tokenizer,
    encoded: Sequence[int],
    top_n: int = 3,
    k_expected: int = 3,
) -> SessionScore:
    steps = model.step_probs(encoded)
    if not steps:
        return SessionScore(nll_per_step=0.0, topk_surprise=0.0, n_transitions=0)

    # Phase 1 — cheap, all steps: compute per-step NLL only. No decode, no top_k.
    raw = []
    nlls = []
    for pos, (ctx, observed, p) in enumerate(steps, start=1):
        nll = -float(np.log(p))
        nlls.append(nll)
        raw.append((pos, ctx, observed, p, nll))

    # Selection: stable-sort by nll descending, keep first top_n.
    top_raw = sorted(raw, key=lambda r: r[4], reverse=True)[:top_n]

    # Phase 2 — expensive, only survivors: decode + top_k for the selected steps.
    rev = tokenizer.id_to_token
    top = [
        StepSurprise(
            position=pos,
            context=[rev.get(t, "?") for t in ctx],
            observed=rev.get(observed, "?"),
            observed_prob=p,
            surprise=nll,
            expected=[(rev.get(t, "?"), pr) for t, pr in model.top_k(ctx, k_expected)],
        )
        for pos, ctx, observed, p, nll in top_raw
    ]
    return SessionScore(
        nll_per_step=float(np.mean(nlls)),
        topk_surprise=float(np.mean([r[4] for r in top_raw])),
        n_transitions=len(nlls),
        top_surprises=top,
    )
