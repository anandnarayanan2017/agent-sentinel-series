"""Phase 2.5 — Second-role sequence-model evaluation + real-pipeline proof
============================================================================
Trains order-1/order-2 sequence-anomaly models on a SECOND synthetic agent
role (`payments-bot`, see `sentinel_sequence/data_gen_payments.py`) with a
richer vocabulary and compositionally-generated attacks, reports
precision/recall/F1 the same way `docs/PHASE2.md` does for `kyc_bot_demo`,
then proves detection fires through the REAL `app.sentinel` `Engine` (not
just the standalone `sentinel_sequence` CLI) — the thing this session's L3
pipeline-integration build actually unlocked.

This remains synthetic, self-authored data. It does not clear the
"author-designed" validity ceiling documented in `docs/PHASE2.md`'s honesty
section — see that file, and `data_gen_payments.py`'s module docstring, for
what it does and doesn't establish. Treat it as a harder stress test and an
integration proof, not a real-world performance claim.

Run:
    uv run python examples/phase2/sequence_eval_payments_demo.py
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

_APP_DIR = str(Path(__file__).resolve().parents[2] / "app")
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

from sentinel_sequence.config import SequenceConfig  # noqa: E402
from sentinel_sequence.data_gen_payments import (  # noqa: E402
    generate_attack_sessions,
    generate_normal_sessions,
)
from sentinel_sequence.detector import SequenceDetector  # noqa: E402
from sentinel_sequence.evaluate import evaluate  # noqa: E402
from sentinel_sequence.markov import MarkovModel  # noqa: E402
from sentinel_sequence.scoring import score_session  # noqa: E402
from sentinel_sequence.tokenizer import Tokenizer  # noqa: E402

ROLE = "payments_bot_demo"


def run_offline_eval(registry_dir: str) -> None:
    print("=" * 78)
    print("OFFLINE EVAL - payments-bot synthetic dataset (28-token vocab, composed attacks)")
    print("=" * 78)

    normal = generate_normal_sessions(600)
    train, val = normal[:480], normal[480:]  # session-level split, never event-level
    attacks = generate_attack_sessions(100)

    tokenizer = Tokenizer().fit(train)
    print(f"vocab_size={tokenizer.vocab_size} (data_gen.py's kyc_bot_demo vocab is 12)")

    for order in (1, 2):
        model = MarkovModel(order=order, alpha=0.5).fit(
            [tokenizer.encode_session(s) for s in train], tokenizer.vocab_size
        )

        def nll_score(sess):
            return score_session(model, tokenizer, tokenizer.encode_session(sess), top_n=3)

        val_topk = [nll_score(s).topk_surprise for s in val]
        val_nll = [nll_score(s).nll_per_step for s in val]
        atk_topk = [(t, nll_score(s).topk_surprise) for t, s in attacks]
        atk_nll = [(t, nll_score(s).nll_per_step) for t, s in attacks]

        rep_nll = evaluate(val_nll, atk_nll)
        rep_topk = evaluate(val_topk, atk_topk)

        print(f"\n--- order-{order} ---")
        print(
            f"  mean-NLL      : P={rep_nll.precision:.3f} R={rep_nll.recall:.3f} F1={rep_nll.f1:.3f}"
        )
        print(
            f"  top-3 surprise: P={rep_topk.precision:.3f} R={rep_topk.recall:.3f} F1={rep_topk.f1:.3f}"
        )
        if order == 2:
            print("  per-composed-attack-label recall (top-3 surprise):")
            for k, v in sorted(rep_topk.per_attack_recall.items()):
                print(f"    {k:40s} {v:.3f}")

    det = SequenceDetector(SequenceConfig(registry_dir=registry_dir, order=2, alpha=0.5))
    info = det.train_and_publish(ROLE, normal)
    print(f"\npublished: {info}")


def run_integration_through_real_engine(registry_dir: str) -> None:
    print()
    print("=" * 78)
    print("INTEGRATION - through the real app.sentinel Engine (not the standalone CLI)")
    print("=" * 78)

    os.environ["SENTINEL_SEQ_ENABLED"] = "true"
    os.environ["SENTINEL_SEQ_REGISTRY_DIR"] = registry_dir
    for mod in list(sys.modules):
        if mod.startswith("sentinel."):
            del sys.modules[mod]  # fresh import so the env vars above are picked up

    from sentinel.detection.engine import Engine
    from sentinel.detection.policy import PolicySet
    from sentinel.detection.seq_config import SeqLayerConfig
    from sentinel.explain.explainer import Explainer
    from sentinel.schema.events import ActionType, AgentEvent

    engine = Engine(
        policies=PolicySet(policies={}),
        explainer=Explainer(),
        seq_config=SeqLayerConfig(enabled=True, registry_dir=registry_dir),
    )

    # pick a composed (2-primitive) attack for a livelier demo
    for seed in range(1, 200):
        label, attack_session = generate_attack_sessions(1, seed=seed)[0]
        if "+" in label:
            break

    findings_total = []
    for i, ev in enumerate(attack_session):
        agent_event = AgentEvent(
            event_id=f"evt-{i}",
            agent_id=ROLE,  # role = agent_id, 1:1 (A-1) - must match the published role
            session_id="sess-integration-demo",
            ts=datetime.fromtimestamp(1_720_000_000.0 + i, tz=timezone.utc),
            action=ActionType.TOOL_CALL
            if ev["kind"] == "tool"
            else (ActionType.LLM_CALL if ev["kind"] == "llm" else ActionType.NETWORK_CALL),
            tool_name=ev["name"] if ev["kind"] == "tool" else None,
            model=ev["name"] if ev["kind"] == "llm" else None,
            host=ev["name"] if ev["kind"] == "net" else None,
        )
        findings_total.extend(engine.evaluate(agent_event))

    seq_findings = [f for f in findings_total if f.rule_id.startswith("sequence.")]
    print(f"attack label (composed): {label}")
    print(f"session length: {len(attack_session)} events")
    print(f"total findings from real Engine.evaluate(): {len(findings_total)}")
    print(f"sequence.* findings: {len(seq_findings)}")
    for f in seq_findings:
        print(f"  rule_id={f.rule_id} severity={f.severity} title={f.title!r}")
        print(f"    explanation: {f.explanation}")
        print(f"    event_ids: {f.event_ids}")
        for e in f.evidence[:5]:
            print(f"    evidence: {e.key}={e.value}")


if __name__ == "__main__":
    tmpdir = tempfile.mkdtemp(prefix="payments_eval_")
    try:
        run_offline_eval(tmpdir)
        run_integration_through_real_engine(tmpdir)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
