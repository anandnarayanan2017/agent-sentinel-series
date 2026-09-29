# Second-role evaluation: `payments_bot_demo`

Companion to `docs/PHASE2.md`'s evaluation section — read that first for the
methodology (session-level split, percentile threshold calibration, the
dilution problem). This document extends the same methodology to a second,
harder synthetic role, and — new since the L3 pipeline-integration work —
proves detection through the real `app.sentinel` `Engine`, not just the
standalone `sentinel_sequence` CLI.

**Status honesty, up front:** this is still synthetic data I generated. It
does **not** clear the "author-designed" validity ceiling `docs/PHASE2.md`
already documents for `kyc_bot_demo` — I designed both the normal workflows
and the attack primitives below. Treat everything in this document as a
harder robustness stress-test and an integration proof, not a real-world
performance claim. Real evaluation still needs real (or at least
independently-authored) traffic — see the "what remains" list this was
written in response to.

Reproduce: `uv run python examples/phase2/sequence_eval_payments_demo.py`.

## What's genuinely different from the `kyc_bot_demo` eval

1. **~2x larger vocabulary** — 25 distinct tool/net actions across 8 normal
   workflow templates, vs. `kyc_bot_demo`'s 12 actions / 4 templates
   (`app/sentinel_sequence/data_gen_payments.py`). The `Tokenizer`'s
   `vocab_size` reports 28 — the 25 actions plus 3 special tokens (`<SOS>`,
   `<EOS>`, `<UNK>`) — a different quantity than the raw action count above;
   both numbers are correct, just measuring different things.
2. **Composed, not enumerated, attacks.** `data_gen.py` has 4 fixed attack
   functions. Here, a library of 7 attack *primitives* (`unauthorized_override`,
   `limit_bypass`, `exfiltration_burst`, `order_abuse`, `burst_loop`,
   `credential_probe`, `silent_cancel_replay`) is randomly composed 1-2 at a
   time into normal sessions at randomized injection points — producing 24
   distinct observed attack-label combinations in a 100-session eval set,
   not 4.
3. **Verified through the real `Engine`, not just `SequenceDetector.score()`
   directly.** This wasn't possible before this session — `sentinel_sequence`
   had no live wiring into `app/sentinel/`.

## Results

*Synthetic data — these figures come from normal workflows and attack primitives I wrote myself; they do not clear the "author-designed" validity ceiling documented in `docs/PHASE2.md` and are not a real-world performance claim.*

600 normal sessions (480 train / 120 val), 100 composed-attack sessions.
Threshold = p99 of validation-normal scores (order-2, published as
`models/sequence/payments_bot_demo/v0001`).

| Model / score | Precision | Recall | F1 |
|---|---|---|---|
| order-1, mean NLL | 0.976 | 0.830 | 0.897 |
| order-1, top-3 surprise | 0.972 | 0.700 | 0.814 |
| order-2, mean NLL | 0.974 | 0.740 | 0.841 |
| **order-2, top-3 surprise** | **0.987** | **0.770** | **0.865** |

Lower than `kyc_bot_demo`'s reported 0.99 F1/1.00 recall across the board —
expected, and the more informative result is *why*:

### Per-composed-attack-label recall (order-2, top-3 surprise)

*Synthetic data — every recall below is measured against self-authored attacks on self-authored normal traffic, so it does not clear the `docs/PHASE2.md` "author-designed" validity ceiling; it characterises this construction, not real-world detection rates.*

Every **multi-primitive** composed attack (2 primitives injected together)
scores **1.000 recall** — 17/17 combinations perfectly caught. The gap is
entirely in **single-primitive, small injections**:

| Single primitive alone | Recall |
|---|---|
| `unauthorized_override` (2 extra events: approve + wire) | **0.167** |
| `limit_bypass` (3 extra events) | **0.500** |
| `order_abuse` (whole-session reorder, no extra length) | 0.875 |
| `exfiltration_burst` (3-6 extra net-egress events) | **0.000** |
| `burst_loop`, `credential_probe`, `silent_cancel_replay` alone | 1.000 |

**This is a genuinely useful finding this exercise surfaces that the
original narrower eval didn't:** a small, low-signature injection (2-3 extra
events in an otherwise-normal 9-14 event session) is much harder for
top-k=3 surprise scoring to catch than a burst or a full reorder — because
the "surprise budget" (top 3 steps) gets diluted across a longer session
when only 2-3 steps are actually anomalous relative to session length. This
is the same "dilution problem" `docs/PHASE2.md` describes mean-NLL having
relative to top-k, just recurring one level up: top-3 has its own dilution
floor once sessions get long enough and injections small enough. Whether
this generalizes to real traffic is unknown — it's the kind of question
real-traffic evaluation would need to answer, not something resolvable with
more synthetic data from the same author.

## Real-`Engine` integration proof

*Synthetic data — the session, the score, the threshold and the model all derive from the self-authored synthetic set above, which does not clear the `docs/PHASE2.md` "author-designed" validity ceiling; this is an integration proof of the L3 wiring and evidence chain, not a performance claim.*

Ran a composed attack (`credential_probe+silent_cancel_replay`, 15 events)
through the actual `app.sentinel.detection.engine.Engine` with
`SeqLayerConfig(enabled=True)` pointed at the freshly-trained registry — the
same code path production traffic would go through, not the standalone CLI:

```
rule_id=sequence.anomaly severity=MEDIUM
  title="Sequence behavior anomaly for role 'payments_bot_demo'"
  explanation: session behavior deviates from learned payments_bot_demo
    baseline (surprise 4.95 > threshold 4.37, model v0001)
  evidence: seq_step_0=step 9: after [tool:cancel_payment], expected
    {tool:write_case_note (p=0.70), tool:close_case (p=0.08),
    llm:call (p=0.04)}; observed tool:verify_2fa (p=0.0064)
```

One `sequence.anomaly` finding, correctly evidenced down to the exact
step/expected-vs-observed transition, produced entirely through
`Engine.evaluate()` — confirming the L3 wiring from this session's pipeline
integration work functions correctly on a role/vocabulary it wasn't
designed around.

## Registry state

`models/sequence/payments_bot_demo/v0001/` is now published alongside
`models/sequence/kyc_bot_demo/`, demonstrating the per-role registry (§9
registry.py) actually holds more than one role.

## What this does and doesn't move on the "what remains" list

**Addressed:**
- A second published role exists, proving multi-role registry support.
- A genuinely harder, more varied synthetic eval (composed attacks, richer
  vocabulary) — and it found a real weakness (single small injections)
  the original 4-type eval didn't surface.
- First proof of L3 detection firing through the real production `Engine`
  code path end-to-end, not just the standalone detector.

**Not addressed, still requires real/external input:**
- Still zero real (or independently-authored) traffic — the validity
  ceiling stands.
- Threshold is still calibrated on synthetic "normal," not real sessions.
- Evasion resistance against an adversary who knows the model is untested.
- Whether the single-primitive detection gap found here is a real problem
  or an artifact of this synthetic construction is unknown without real
  data.
