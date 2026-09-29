# Phase 2 — Sequence Modeling for Agent Behavior

> Historical design doc, recovered/re-published here because
> `app/sentinel_sequence/data_gen.py`'s module docstring references it. The
> original copy lived in a working-copy duplicate directory
> (`phase2_sequence_prod/`) that has since been removed from the repo; this is
> that same content, restored to `docs/` as its permanent home. Paths below
> are updated to the current layout (`app/sentinel_sequence/`, not
> `sentinel_sequence/`).

Sequence-level anomaly detection for Agent Sentinel. Learns each agent role's normal action patterns from recorded sessions and scores new sessions by how surprising they are — catching behavioral attacks (wrong tool order, privilege creep, low-and-slow exfiltration, bursts) that per-event rules structurally cannot express.

This layer is **advisory**: it raises severity and produces evidence; only the deterministic YAML policy engine can deny. See "Fusion contract" below.

## Quick start

```bash
uv run python -m sentinel_sequence.cli demo   # synthetic end-to-end: train, publish, score attacks
uv run pytest -q app/tests/                   # full test suite
```

Integration sketch (inside the Sentinel pipeline):

```python
from sentinel_sequence import Tokenizer, MarkovModel, split_sessions, score_session

sessions  = split_sessions(events)                       # events from DuckDB
tokenizer = Tokenizer().fit(train_sessions)              # vocab from training only
model     = MarkovModel(order=2, alpha=0.5).fit(
              [tokenizer.encode_session(s) for s in train_sessions],
              tokenizer.vocab_size)

sc = score_session(model, tokenizer, tokenizer.encode_session(new_session))
sc.topk_surprise          # anomaly score (primary detector)
sc.to_evidence_chain()    # explanation lines for the Finding
```

## Design

```
AgentEvents ─▶ split_sessions ─▶ Tokenizer ─▶ MarkovModel ─▶ score_session ─▶ evidence chain
   (DuckDB)     (gap or          (frozen        (order 1/2,     (mean NLL +      ("expected {A,B},
                 session_id)      vocab, UNK)    smoothed)       top-k surprise)   observed C")
```

Key decisions (referenced as "ADR-004" in this module's source docstrings —
that ADR was never actually written; the numbering doesn't correspond to
`docs/adr/000N-*.md`, which covers the main-product decisions only. Rationale
below is the closest thing to it that exists today):

- **Frozen vocabulary + `<UNK>`** — tools unseen at training time map to `<UNK>` instead of crashing; novelty itself becomes signal.
- **Laplace smoothing** — no transition ever has probability zero, so scores stay finite and thresholds calibratable.
- **Order-2 with order-1 fallback** — second-order context where history exists, graceful degradation at session start and for unseen bigram contexts.
- **Two scores per session:**
  - `nll_per_step` (mean surprise) — catches *diffuse* anomalies: bursts, drift, pervasive weirdness.
  - `topk_surprise` (mean of the 3 most surprising steps) — catches *concentrated* anomalies: a few injected malicious steps diluted inside an otherwise normal session. This was added after evaluation showed mean-NLL missing 48–100% of privilege-escalation sessions (the dilution problem).
- **Threshold calibration without attack labels** — the operating threshold is the p99 of scores on held-out *normal* sessions, i.e. an explicit ~1% false-positive budget. Attack labels are used only to *report* recall, never to tune.

## Fusion contract

| Layer | May deny? | Role |
|---|---|---|
| YAML policy engine | Yes | Compliance-binding allow/deny (DORA/AI Act/CSSF mapped) |
| Phase 1 IsolationForest | No | Windowed feature anomalies → severity signal |
| Phase 2 sequence model | No | Behavioral-sequence anomalies → severity signal + evidence chain |

## Evaluation results (synthetic KYC workload)

600 normal sessions (480 train / 120 val, split **by session**), 100 attack sessions (25 × 4 types). Threshold = p99 of validation-normal scores.

| Model / score | Precision | Recall | F1 | Weakness |
|---|---|---|---|---|
| order-1, mean NLL | 1.000 | 0.740 | 0.851 | misses all privilege-escalation |
| order-2, mean NLL | 0.978 | 0.880 | 0.926 | 52% privilege-escalation recall |
| order-1, top-3 surprise | 0.980 | 1.000 | 0.990 | — |
| **order-2, top-3 surprise** | **0.980** | **1.000** | **0.990** | — |

Per-attack recall at the operating threshold (order-2, top-3): privilege_escalation 1.00, exfiltration 1.00, tool_order_abuse 1.00, burst_loop 1.00.

Notable negative result: on this workload, order-1 with top-k scoring matches order-2 — the added context did not pay for itself here, though it did under mean-NLL scoring. Re-test on real traffic before choosing.

## Evaluation honesty & limitations

- **Synthetic data, designed by the same author as the detector.** Attack scenarios were written from the threat model before inspecting model behavior, and normal sessions are perturbed (drop/swap/insert) — but this remains a validity ceiling. Real traffic will have richer vocabularies, messier sessions, and lower separability. Treat the 0.99 F1 as pipeline validation, not a performance claim.
- **Evasion:** an attacker who knows the learned distribution can mimic normal sequences and act slowly. Mitigations: fusion with the rules engine (hard envelopes are order-independent) and Phase 1 windowed volume/egress features. Documented, not solved.
- **Concept drift:** when an agent's prompt or toolset legitimately changes, "normal" moves. Staleness detection (see below) addresses this: if median surprise across all sessions rises for N consecutive days, emit a "model stale, retrain" finding instead of alert-storming.
- **Small vocab (12 tokens)** makes this workload easy. Expect threshold recalibration per role on real data.

## Files

| Path | Purpose |
|---|---|
| `app/sentinel_sequence/tokenizer.py` | event→token mapping, frozen vocab, UNK/SOS/EOS |
| `app/sentinel_sequence/sessions.py` | session_id-preferred, gap-based splitting |
| `app/sentinel_sequence/store.py` | DuckDB event-store reader (session-split events ready for the tokenizer) |
| `app/sentinel_sequence/markov.py` | order-1/2 Markov, Laplace smoothing, save/load |
| `app/sentinel_sequence/scoring.py` | mean-NLL + top-k surprise, evidence chains |
| `app/sentinel_sequence/registry.py` | versioned per-role model registry, atomic publish, sha256 integrity |
| `app/sentinel_sequence/drift.py` | staleness/drift detection (median-surprise-ratio) |
| `app/sentinel_sequence/detector.py` | glue: tokenizer+model+registry+scoring into train/score/publish |
| `app/sentinel_sequence/evaluate.py` | session-level split discipline, PR metrics, percentile calibration |
| `app/sentinel_sequence/data_gen.py` | synthetic normal + 4 attack scenarios |
| `app/sentinel_sequence/data_gen_payments.py` | second-role (`payments_bot_demo`) synthetic data, composed attacks — see `docs/EVAL_PAYMENTS_BOT.md` |
| `app/sentinel_sequence/cli.py` | `train` / `score` / `drift` / `demo` subcommands |
| `app/tests/test_sentinel_sequence*.py` | test suite (94 tests, 95.68% coverage as of the 2026-07 hardening pass) |

## Next (Phase 2.5 → 3) — status as of the 2026-07 hardening pass

1. ~~Wire `split_sessions` to the DuckDB event store (replace `data_gen`).~~ **Done** — `store.py`'s `EventStore`.
2. ~~Per-role model registry (train/store one model per agent role).~~ **Done** — `registry.py`'s `ModelRegistry`.
3. ~~Staleness/drift detector.~~ **Done** — `drift.py`'s `check_drift`.
4. Tiny decoder-only transformer — only if real-traffic eval shows Markov missing long-range dependencies. Still open; the eval harness here remains the comparison baseline.
5. ~~Wire this subsystem's findings into the main `app/sentinel/` detection pipeline (`detection/engine.py`) as a third advisory layer alongside the policy engine and statistical baseline.~~ **Done** — `detection/engine.py` takes an optional `SeqLayerConfig` (`detection/seq_config.py`) and runs the L3 advisory step (`sequence.anomaly` finding) alongside the policy and statistical-baseline layers; `pipeline.py`'s `ingest_flow` builds that config from `SENTINEL_SEQ_*` env vars (off by default) and passes it through. See `docs/EVAL_PAYMENTS_BOT.md` for the real-`Engine` integration proof.
