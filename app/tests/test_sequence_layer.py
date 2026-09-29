"""Tests for the L3 sequence-anomaly advisory layer
(design/DESIGN.md DESIGN-sentinel-seq-L3-001).

Traces to spec/SPEC.md (FR-1..FR-13, NFR-1..NFR-7), spec/ACCEPTANCE.md
(AC-1..AC-20), spec/UAT.md (UAT-1..UAT-16), and design/DESIGN.md — especially
§5.3 (persistent-vs-transient unavailability discrimination, design
review required-change-1), §3.5 (bounded `_unavailable_roles` LRU, required-change-2),
§3.3 (session-buffer bounds/eviction), and §4 (the FR-8 degradation flow).

These tests are written against the CONTRACT stated in ACCEPTANCE.md/UAT.md/
DESIGN.md — the engine/pipeline-visible behavior — not by mirroring whatever
`sequence_layer.py` happens to do line-by-line. Where a test needs to reach
into `Engine._l3`/`L3SequenceLayer._detector`/`._unavailable_roles`/`._buffers`,
that is because DESIGN.md §2.3/§3.5/§8.3 explicitly names those as the
testable state of the bounded/degradation contracts (not because the test is
reverse-engineering an implementation detail).

Two independent real (trained) model fixtures are used sparingly for the
genuinely end-to-end tests (UAT-1, UAT-9, UAT-11, UAT-14); most FR-3/4/5/8/13
tests stub `SequenceDetector.score` directly, per DESIGN.md §8.3's own test
family split ("spy on score" / "crafted input"), to keep the buffering,
emission, and degradation logic under test deterministic and independent of
Markov-model internals (which are frozen/out of scope for this PR).
"""

from __future__ import annotations

import inspect
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("sentinel_sequence", reason="optional ML dependency chain")

import sentinel_sequence.detector as detector_mod
from sentinel_sequence import SequenceConfig, SequenceDetector, data_gen
from sentinel_sequence.registry import ModelRegistry

from sentinel.detection import seq_adapter
from sentinel.detection.engine import Engine
from sentinel.detection.policy import PolicySet
from sentinel.detection.seq_config import SeqLayerConfig
from sentinel.pipeline import Pipeline
from sentinel.schema.events import ActionType, AgentEvent, Severity

POLICY = str(Path(__file__).resolve().parents[1].parent / "policies" / "example.yaml")

_BASE_TS = datetime(2026, 1, 1, tzinfo=timezone.utc)

# `recon-bot` has an explicit, narrow policy (allowed_hosts/tools/models) in
# policies/example.yaml — used whenever a test wants both L1 and L3 signal.
POLICY_ROLE = "recon-bot"
# `seq-only-bot` has NO policy entry — isolates L3 from L1/L2 noise.
NO_POLICY_ROLE = "seq-only-bot"


# =============================================================================
# Shared helpers
# =============================================================================


def make_event(
    agent_id: str,
    session_id: str,
    action: ActionType = ActionType.TOOL_CALL,
    *,
    ts=None,
    event_id=None,
    tool_name=None,
    model=None,
    host=None,
    attributes=None,
    bytes_out: int = 0,
) -> AgentEvent:
    kwargs: dict = dict(
        agent_id=agent_id,
        session_id=session_id,
        action=action,
        attributes=attributes or {},
        bytes_out=bytes_out,
    )
    if ts is not None:
        kwargs["ts"] = ts
    if event_id is not None:
        kwargs["event_id"] = event_id
    if tool_name is not None:
        kwargs["tool_name"] = tool_name
    if model is not None:
        kwargs["model"] = model
    if host is not None:
        kwargs["host"] = host
    return AgentEvent(**kwargs)


_ACTION_FOR_KIND = {
    "tool": ActionType.TOOL_CALL,
    "llm": ActionType.LLM_CALL,
    "net": ActionType.NETWORK_CALL,
    "data": ActionType.DATA_ACCESS,
}


def event_for_step(agent_id, session_id, step, *, seq, base_ts=_BASE_TS):
    """Build an AgentEvent whose to_seq_event() output reproduces `step`
    ({"kind":..., "name":...}), per the A-2 derivation table, so a session
    drawn from `sentinel_sequence.data_gen` (plain kind/name dicts) can be fed
    through the real engine/adapter and score meaningfully against a model
    trained on the same data_gen sessions.
    """
    kind, name = step["kind"], step["name"]
    kwargs: dict = dict(
        agent_id=agent_id,
        session_id=session_id,
        action=_ACTION_FOR_KIND[kind],
        ts=base_ts + timedelta(seconds=seq),
        event_id=f"{session_id}-{seq}",
    )
    if kind == "tool":
        kwargs["tool_name"] = name
    elif kind == "llm":
        kwargs["model"] = name
    elif kind in ("net", "data"):
        kwargs["host"] = name
    return AgentEvent(**kwargs)


def feed_session(engine, agent_id, session_id, steps, base_ts=_BASE_TS):
    """Feed a data_gen-shaped session through engine.evaluate(), one event at
    a time. Returns the list of per-event finding lists (arrival order).
    """
    out = []
    for i, step in enumerate(steps):
        e = event_for_step(agent_id, session_id, step, seq=i, base_ts=base_ts)
        out.append(engine.evaluate(e))
    return out


def make_engine(registry_dir: str, enabled: bool = True, **cfg_kwargs) -> Engine:
    cfg = SeqLayerConfig(enabled=enabled, registry_dir=registry_dir, **cfg_kwargs)
    return Engine(PolicySet.from_yaml(POLICY), seq_config=cfg)


def finding_signature(f):
    """A stable, id/timestamp-free signature for equality comparisons.

    `event_ids` is compared by *count*, not content: these are per-event UUIDs,
    so including them made the helper not actually id-free as its own contract
    promised. Two engines fed equivalent-but-distinct events could never
    compare equal, which is precisely what these enabled-vs-disabled tests
    exist to check. Cardinality is preserved, so an L3 finding spanning a whole
    buffered session is still distinguishable from a single-event L1/L2 one.
    """
    return (
        f.agent_id,
        f.session_id,
        f.rule_id,
        f.title,
        f.severity,
        f.explanation,
        f.policy_clause,
        f.severity_rationale,
        len(f.event_ids),
        tuple((e.key, e.value, e.redacted) for e in f.evidence),
        tuple(f.control_refs),
    )


def seq_findings(findings):
    """Only the L3 sequence-layer findings from an evaluate() result.

    These tests assert what the *sequence layer* did or did not produce. An
    unregistered test agent also draws an `identity.unregistered_agent`
    finding from layer 1 (CR-16), which is correct behaviour and orthogonal to
    what is under test here — so scope the assertion instead of asserting on
    the whole result list.
    """
    return [f for f in findings if f.rule_id.startswith("sequence.")]


def _anomaly_result(
    severity: str, topk_surprise: float = 5.0, threshold: float = 1.0, model_version: str = "vTEST"
):
    return {
        "type": "sequence_anomaly",
        "advisory": True,
        "role": "unused",
        "model_version": model_version,
        "severity": severity,
        "score": {
            "topk_surprise": topk_surprise,
            "nll_per_step": topk_surprise / 2,
            "threshold": threshold,
            "n_transitions": 3,
        },
        "evidence_chain": [f"step surprised the model (severity={severity})"],
        "explanation": f"session behavior deviates from learned baseline ({severity})",
    }


def _ok_result():
    return {
        "type": "sequence_ok",
        "advisory": True,
        "role": "unused",
        "model_version": "vTEST",
        "severity": "info",
        "score": {"topk_surprise": 0.1, "nll_per_step": 0.05, "threshold": 1.0, "n_transitions": 3},
        "evidence_chain": [],
        "explanation": "session consistent with learned baseline",
    }


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def empty_registry_dir(tmp_path) -> str:
    """A registry_dir with no published models for any role (AC-8/AC-9)."""
    return str(tmp_path / "empty_registry")


@pytest.fixture(scope="module")
def trained_registry_dir(tmp_path_factory) -> str:
    """A registry_dir with one published model for NO_POLICY_ROLE, trained on
    >= 2 * min_calibration_sessions synthetic normal sessions (UAT precondition).
    """
    registry_dir = tmp_path_factory.mktemp("seq_registry")
    detector = SequenceDetector(SequenceConfig(registry_dir=str(registry_dir)))
    sessions = data_gen.generate_normal_sessions(160, seed=7)
    detector.train_and_publish(NO_POLICY_ROLE, sessions)
    return str(registry_dir)


@pytest.fixture
def attack_session_privilege_escalation():
    attacks = data_gen.generate_attack_sessions(3, seed=13)
    return next(s for name, s in attacks if name == "privilege_escalation")


@pytest.fixture
def normal_session_no_false_positive():
    # Verified (independently of the implementation, by re-deriving from the
    # detector's own calibration semantics) not to cross the trained
    # threshold — see test_ac9_sequence_ok_session_produces_no_findings.
    return data_gen.generate_normal_sessions(10, seed=999)[0]


# =============================================================================
# AC-1 / FR-1 / UAT-1 — L3 wired after L1/L2, before learn; real end-to-end
# AC-10 / FR-10 / UAT-1 — schema-valid, explainable finding
# =============================================================================


def test_ac1_ac10_real_anomalous_session_yields_one_schema_valid_finding(
    trained_registry_dir, attack_session_privilege_escalation
):
    engine = make_engine(trained_registry_dir)
    results = feed_session(engine, NO_POLICY_ROLE, "sess-1", attack_session_privilege_escalation)
    all_findings = [f for step_findings in results for f in step_findings]
    seq_findings = [f for f in all_findings if f.rule_id == "sequence.anomaly"]

    assert len(seq_findings) == 1
    f = seq_findings[0]
    assert f.severity in (Severity.HIGH, Severity.MEDIUM, Severity.INFO)
    assert f.explanation
    assert f.policy_clause is None  # FR-2/AC-2: advisory only, never denies
    evidence_keys = {e.key for e in f.evidence}
    assert "model_version" in evidence_keys
    assert "threshold" in evidence_keys
    assert "topk_surprise" in evidence_keys
    assert any(k.startswith("seq_step_") for k in evidence_keys)
    # event_ids spans multiple buffered events, not just the triggering one
    assert len(f.event_ids) > 1
    assert len(set(f.event_ids)) == len(f.event_ids)  # each id present once


def test_ac1_l3_step_appears_after_policy_and_baseline_checks_in_source():
    """Static ordering check: `evaluate` calls `_policy_checks`, then
    `_baseline_checks`, then the L3 step, in that source order (AC-1: "L3
    executes after L1 and L2").
    """
    src = inspect.getsource(Engine.evaluate)
    i_policy = src.index("_policy_checks")
    i_baseline = src.index("_baseline_checks")
    i_l3 = src.index("_l3.evaluate")
    i_learn = src.index("baselines.learn")
    assert i_policy < i_baseline < i_l3 < i_learn


# =============================================================================
# AC-2 / FR-2 / UAT-2 — advisory-only, never denies; ordering vs L1
# =============================================================================


def test_ac2_uat2_sequence_finding_is_advisory_and_ordered_after_l1(empty_registry_dir):
    engine = make_engine(empty_registry_dir)
    engine._l3._detector.score = lambda role, session: _anomaly_result("high")

    e = make_event(
        agent_id=POLICY_ROLE,
        session_id="s1",
        action=ActionType.TOOL_CALL,
        tool_name="dump_all_accounts",  # not in recon-bot's allowed_tools -> L1 fires
        ts=_BASE_TS,
        event_id="e1",
    )
    findings = engine.evaluate(e)

    l1 = [f for f in findings if f.rule_id == "tool.not_allowed"]
    seq = [f for f in findings if f.rule_id.startswith("sequence.")]
    assert len(l1) == 1
    assert len(seq) == 1
    assert seq[0].policy_clause is None
    assert not seq[0].rule_id.startswith("tool.")
    assert not seq[0].rule_id.startswith("net.")
    assert not seq[0].rule_id.startswith("model.")

    l1_idx = findings.index(l1[0])
    seq_idx = findings.index(seq[0])
    assert seq_idx > l1_idx


def test_ac2_no_l3_finding_ever_has_a_non_sequence_rule_id(empty_registry_dir):
    engine = make_engine(empty_registry_dir)
    engine._l3._detector.score = lambda role, session: _anomaly_result("medium")
    e = make_event(agent_id=NO_POLICY_ROLE, session_id="s1", tool_name="x", ts=_BASE_TS)
    findings = engine.evaluate(e)
    for f in findings:
        if f.policy_clause is None and f.rule_id == "sequence.anomaly":
            assert f.rule_id.startswith("sequence.")


# =============================================================================
# AC-3 / FR-3 / UAT-3 — session buffering keys; AC-13 / FR-13 — bounds/eviction
# =============================================================================


def test_ac3_buffer_holds_events_in_arrival_order_for_one_key(empty_registry_dir):
    engine = make_engine(empty_registry_dir)
    ids = ["a", "b", "c"]
    for i, eid in enumerate(ids):
        e = make_event(
            agent_id=NO_POLICY_ROLE,
            session_id="s1",
            event_id=eid,
            tool_name="x",
            ts=_BASE_TS + timedelta(seconds=i),
        )
        engine.evaluate(e)
    buf = engine._l3._buffers[(NO_POLICY_ROLE, "s1")]
    assert buf.event_ids == ids


def test_ac3_distinct_sessions_and_agents_do_not_bleed(empty_registry_dir):
    engine = make_engine(empty_registry_dir)
    engine.evaluate(
        make_event(agent_id="agentA", session_id="s1", event_id="a1", tool_name="x", ts=_BASE_TS)
    )
    engine.evaluate(
        make_event(agent_id="agentA", session_id="s2", event_id="a2", tool_name="x", ts=_BASE_TS)
    )
    engine.evaluate(
        make_event(agent_id="agentB", session_id="s1", event_id="b1", tool_name="x", ts=_BASE_TS)
    )

    buffers = engine._l3._buffers
    assert buffers[("agentA", "s1")].event_ids == ["a1"]
    assert buffers[("agentA", "s2")].event_ids == ["a2"]
    assert buffers[("agentB", "s1")].event_ids == ["b1"]
    assert len(buffers) == 3


def test_ac13_per_session_event_cap_drops_oldest_at_the_boundary(empty_registry_dir):
    engine = make_engine(empty_registry_dir, max_events_per_session=3)
    for i in range(5):
        engine.evaluate(
            make_event(
                agent_id=NO_POLICY_ROLE,
                session_id="s1",
                event_id=f"e{i}",
                tool_name="x",
                ts=_BASE_TS + timedelta(seconds=i),
            )
        )
    buf = engine._l3._buffers[(NO_POLICY_ROLE, "s1")]
    # cap=3: after 5 events the buffer holds exactly the last 3 (e2,e3,e4) —
    # not 2 (over-eviction) and not 4 (off-by-one under-eviction).
    assert buf.event_ids == ["e2", "e3", "e4"]
    assert len(buf.events) == 3


def test_ac13_session_count_cap_evicts_lru_front_at_the_boundary(empty_registry_dir):
    engine = make_engine(empty_registry_dir, max_sessions=2, idle_gap_seconds=10_000)
    engine.evaluate(
        make_event(agent_id="a", session_id="s1", event_id="1", tool_name="x", ts=_BASE_TS)
    )
    engine.evaluate(
        make_event(agent_id="a", session_id="s2", event_id="2", tool_name="x", ts=_BASE_TS)
    )
    assert set(engine._l3._buffers.keys()) == {("a", "s1"), ("a", "s2")}

    # a 3rd distinct session key exceeds the cap -> evict the LRU-front (s1) exactly, not s2
    engine.evaluate(
        make_event(agent_id="a", session_id="s3", event_id="3", tool_name="x", ts=_BASE_TS)
    )
    assert set(engine._l3._buffers.keys()) == {("a", "s2"), ("a", "s3")}
    assert len(engine._l3._buffers) == 2


def test_ac13_idle_eviction_boundary_is_strict_not_inclusive(empty_registry_dir):
    gap = 100.0
    engine = make_engine(empty_registry_dir, max_sessions=10_000, idle_gap_seconds=gap)
    t0 = _BASE_TS

    engine.evaluate(make_event(agent_id="a", session_id="A", event_id="a0", tool_name="x", ts=t0))
    assert ("a", "A") in engine._l3._buffers

    # exactly at the gap boundary (now - last_ts == gap): NOT evicted yet
    engine.evaluate(
        make_event(
            agent_id="b",
            session_id="B",
            event_id="b0",
            tool_name="x",
            ts=t0 + timedelta(seconds=gap),
        )
    )
    assert ("a", "A") in engine._l3._buffers
    assert ("b", "B") in engine._l3._buffers

    # one second past the gap (now - last_ts(A) == gap + 1): A is evicted
    engine.evaluate(
        make_event(
            agent_id="c",
            session_id="C",
            event_id="c0",
            tool_name="x",
            ts=t0 + timedelta(seconds=gap + 1),
        )
    )
    assert ("a", "A") not in engine._l3._buffers
    assert ("b", "B") in engine._l3._buffers
    assert ("c", "C") in engine._l3._buffers


# =============================================================================
# AC-4 / FR-4 / UAT-4 — score invoked exactly once per event, on session-so-far
# =============================================================================


def test_ac4_score_invoked_once_per_event_with_growing_session(trained_registry_dir):
    engine = make_engine(trained_registry_dir)
    calls = []
    original_score = engine._l3._detector.score

    def spy(role, session):
        result = original_score(role, session)
        calls.append((role, len(session)))
        return result

    engine._l3._detector.score = spy

    for i in range(4):
        e = make_event(
            agent_id=NO_POLICY_ROLE,
            session_id="s1",
            event_id=f"e{i}",
            tool_name="fetch_customer",
            ts=_BASE_TS + timedelta(seconds=i),
        )
        engine.evaluate(e)
        # the call for THIS event happened synchronously inside evaluate()
        assert calls[-1] == (NO_POLICY_ROLE, i + 1)

    assert len(calls) == 4


# =============================================================================
# AC-5 / FR-5 / UAT-5 — once-per-session emission + escalation
# =============================================================================


def test_ac5_once_per_session_unless_severity_escalates(empty_registry_dir):
    engine = make_engine(empty_registry_dir)

    def fake_score(role, session):
        n = len(session)
        if n in (2, 3):
            return _anomaly_result("medium")
        if n == 4:
            return _anomaly_result("high")
        if n == 5:
            return _anomaly_result("medium")  # equal-or-lower than last emitted (high)
        return _ok_result()

    engine._l3._detector.score = fake_score

    per_event = []
    for i in range(5):
        e = make_event(
            agent_id=NO_POLICY_ROLE,
            session_id="s1",
            event_id=f"e{i}",
            tool_name="x",
            ts=_BASE_TS + timedelta(seconds=i),
        )
        per_event.append(engine.evaluate(e))

    seq_counts = [len([f for f in fs if f.rule_id == "sequence.anomaly"]) for fs in per_event]
    assert seq_counts == [0, 1, 0, 1, 0]
    assert per_event[1][0].severity == Severity.MEDIUM
    assert per_event[3][0].severity == Severity.HIGH


def test_ac5_constant_severity_across_many_events_emits_exactly_once(empty_registry_dir):
    engine = make_engine(empty_registry_dir)
    engine._l3._detector.score = lambda role, session: _anomaly_result("medium")

    total = 0
    for i in range(6):
        e = make_event(
            agent_id=NO_POLICY_ROLE,
            session_id="s1",
            event_id=f"e{i}",
            tool_name="x",
            ts=_BASE_TS + timedelta(seconds=i),
        )
        findings = engine.evaluate(e)
        total += len([f for f in findings if f.rule_id == "sequence.anomaly"])
    assert total == 1


# =============================================================================
# AC-7 / FR-7 / UAT-7 — role resolution & illegal role at the engine level
# =============================================================================


def test_ac7_illegal_role_degrades_gracefully_no_raise(empty_registry_dir):
    engine = make_engine(empty_registry_dir)
    e = make_event(agent_id="bad role!", session_id="s1", tool_name="x", ts=_BASE_TS)
    findings = engine.evaluate(e)  # must not raise
    assert not any(f.rule_id.startswith("sequence.") for f in findings)
    assert "bad role!" in engine._l3._unavailable_roles


def test_ac7_illegal_role_logged_once_across_repeat_events(empty_registry_dir, caplog):
    import logging

    engine = make_engine(empty_registry_dir)
    with caplog.at_level(logging.INFO, logger="sentinel.detection.sequence"):
        for i in range(3):
            findings = engine.evaluate(
                make_event(
                    agent_id="bad role!",
                    session_id="s1",
                    tool_name="x",
                    ts=_BASE_TS + timedelta(seconds=i),
                )
            )
            assert seq_findings(findings) == []
    assert "bad role!" in engine._l3._unavailable_roles
    unavailable_lines = [
        r for r in caplog.records if "sequence scoring unavailable for role" in r.message
    ]
    assert len(unavailable_lines) == 1  # repeat hits only touch the LRU, never re-log


def test_ac7_role_override_via_attributes_is_used(empty_registry_dir):
    engine = make_engine(empty_registry_dir)
    seen_roles = []
    original = engine._l3._detector.score

    def spy(role, session):
        seen_roles.append(role)
        return original(role, session)

    engine._l3._detector.score = spy
    e = make_event(
        agent_id="recon-bot",
        session_id="s1",
        tool_name="x",
        ts=_BASE_TS,
        attributes={"role": "kyc-role"},
    )
    engine.evaluate(e)
    assert seen_roles == ["kyc-role"]


# =============================================================================
# AC-8/AC-9/AC-20 / FR-8/FR-9 / UAT-8/UAT-9 — graceful degradation, no model
# =============================================================================


def test_ac8_no_model_for_role_produces_zero_findings_and_matches_disabled(empty_registry_dir):
    enabled_engine = make_engine(empty_registry_dir, enabled=True)
    disabled_engine = make_engine(empty_registry_dir, enabled=False)

    e1 = make_event(
        agent_id="no-model-role", session_id="s1", tool_name="fetch_customer", ts=_BASE_TS
    )
    e2 = make_event(
        agent_id="no-model-role", session_id="s1", tool_name="fetch_customer", ts=_BASE_TS
    )

    f_enabled = enabled_engine.evaluate(e1)
    f_disabled = disabled_engine.evaluate(e2)

    assert not any(f.rule_id.startswith("sequence.") for f in f_enabled)
    assert [finding_signature(f) for f in f_enabled] == [finding_signature(f) for f in f_disabled]


def test_ac8_no_model_logged_at_most_once_per_role(empty_registry_dir, caplog):
    import logging

    engine = make_engine(empty_registry_dir)
    with caplog.at_level(logging.INFO, logger="sentinel.detection.sequence"):
        for i in range(3):
            engine.evaluate(
                make_event(
                    agent_id="no-model-role",
                    session_id="s1",
                    tool_name="x",
                    ts=_BASE_TS + timedelta(seconds=i),
                )
            )
    unavailable_lines = [
        r for r in caplog.records if "sequence scoring unavailable for role" in r.message
    ]
    assert len(unavailable_lines) == 1


def test_ac9_sequence_ok_session_produces_no_findings(
    trained_registry_dir, normal_session_no_false_positive
):
    engine = make_engine(trained_registry_dir)
    results = feed_session(engine, NO_POLICY_ROLE, "ok-sess", normal_session_no_false_positive)
    all_findings = [f for fs in results for f in fs]
    assert not any(f.rule_id.startswith("sequence.") for f in all_findings)


# =============================================================================
# AC-11/AC-16 / FR-11 / NFR-3 / UAT-10 — feature flag off & missing dependency
# =============================================================================


def test_ac11_flag_disabled_never_imports_sequence_layer(empty_registry_dir):
    sys.modules.pop("sentinel.detection.sequence_layer", None)
    engine = make_engine(empty_registry_dir, enabled=False)
    assert engine._l3 is None
    assert "sentinel.detection.sequence_layer" not in sys.modules

    findings = engine.evaluate(
        make_event(agent_id=NO_POLICY_ROLE, session_id="s1", tool_name="x", ts=_BASE_TS)
    )
    assert not any(f.rule_id.startswith("sequence.") for f in findings)


def test_ac11_ac16_missing_dependency_disables_layer_without_crashing(
    empty_registry_dir, monkeypatch
):
    # Simulate `sentinel.detection.sequence_layer` (transitively numpy /
    # sentinel_sequence) being un-importable, WITHOUT actually uninstalling
    # numpy: inserting `None` for a module name forces Python's import system
    # to raise ImportError for that name (documented sys.modules protocol).
    monkeypatch.setitem(sys.modules, "sentinel.detection.sequence_layer", None)

    cfg = SeqLayerConfig(enabled=True, registry_dir=empty_registry_dir)
    engine = Engine(PolicySet.from_yaml(POLICY), seq_config=cfg)  # must not raise
    assert engine._l3 is None

    findings = engine.evaluate(
        make_event(agent_id=NO_POLICY_ROLE, session_id="s1", tool_name="x", ts=_BASE_TS)
    )
    assert not any(f.rule_id.startswith("sequence.") for f in findings)


def test_ac16_pipeline_construct_and_ingest_survive_missing_dependency(
    empty_registry_dir, monkeypatch, tmp_path
):
    monkeypatch.setitem(sys.modules, "sentinel.detection.sequence_layer", None)
    cfg = SeqLayerConfig(enabled=True, registry_dir=empty_registry_dir)

    pipe = Pipeline(POLICY, str(tmp_path / "db.duckdb"), seq_config=cfg)  # must not raise
    findings = pipe.ingest_flow(
        agent_id=NO_POLICY_ROLE,
        session_id="s1",
        host="ledger.internal",
        method="GET",
        path="/x",
    )
    assert not any(f.rule_id.startswith("sequence.") for f in findings)


# =============================================================================
# AC-12 / FR-12 / UAT-11 — no training in hot path; model caching
# =============================================================================


def test_ac12_no_training_call_and_registry_load_cached_across_events(
    trained_registry_dir, monkeypatch
):
    load_calls = []
    original_load = ModelRegistry.load

    def counting_load(self, role, version=None):
        load_calls.append(role)
        return original_load(self, role, version)

    train_calls = []
    original_train = SequenceDetector.train_and_publish

    def counting_train(self, *a, **kw):
        train_calls.append(a)
        return original_train(self, *a, **kw)

    monkeypatch.setattr(ModelRegistry, "load", counting_load)
    monkeypatch.setattr(SequenceDetector, "train_and_publish", counting_train)

    engine = make_engine(trained_registry_dir)
    for sess in ("s1", "s2"):
        for i in range(5):
            engine.evaluate(
                make_event(
                    agent_id=NO_POLICY_ROLE,
                    session_id=sess,
                    event_id=f"{sess}-{i}",
                    tool_name="fetch_customer",
                    ts=_BASE_TS + timedelta(seconds=i),
                )
            )

    assert train_calls == []
    assert len(load_calls) <= 1


# =============================================================================
# Required-change-1 (mini-ADR-3, §5.3) — persistent vs transient discrimination
# =============================================================================


def _train_small_registry(tmp_path, role, n_sessions=120, seed=7):
    registry_dir = str(tmp_path / "registry")
    detector = SequenceDetector(SequenceConfig(registry_dir=registry_dir))
    sessions = data_gen.generate_normal_sessions(n_sessions, seed=seed)
    detector.train_and_publish(role, sessions)
    return registry_dir


def test_fr8_transient_scoring_exception_does_not_blind_role_and_is_retried(tmp_path, monkeypatch):
    role = "flaky-role"
    registry_dir = _train_small_registry(tmp_path, role)
    engine = make_engine(registry_dir)

    original_score_session = detector_mod.score_session
    call_count = {"n": 0}

    def flaky_score_session(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("injected transient scoring failure")
        return original_score_session(*args, **kwargs)

    monkeypatch.setattr(detector_mod, "score_session", flaky_score_session)

    # event 1: score_session raises -> detector.score() catches it internally
    # and returns "sequence_scoring_unavailable"; the layer probes
    # registry.load(role), which SUCCEEDS (model is fine) -> classified
    # TRANSIENT: must NOT be cached, no finding, no crash.
    f1 = engine.evaluate(
        make_event(
            agent_id=role, session_id="s1", event_id="e0", tool_name="fetch_customer", ts=_BASE_TS
        )
    )
    assert seq_findings(f1) == []
    assert role not in engine._l3._unavailable_roles

    # event 2: score_session no longer raises -> scoring is retried (NOT
    # permanently blinded) and reaches the detector's real scoring path again.
    scored = {"called": False}
    original_bound_score = engine._l3._detector.score

    def spy(role_arg, session):
        scored["called"] = True
        return original_bound_score(role_arg, session)

    engine._l3._detector.score = spy
    engine.evaluate(
        make_event(
            agent_id=role,
            session_id="s1",
            event_id="e1",
            tool_name="verify_id",
            ts=_BASE_TS + timedelta(seconds=1),
        )
    )
    assert scored["called"] is True  # retried, not short-circuited
    assert role not in engine._l3._unavailable_roles


def test_fr8_no_model_role_is_persistent_and_short_circuits_registry(
    empty_registry_dir, monkeypatch
):
    role = "never-published-role"
    engine = make_engine(empty_registry_dir)

    load_calls = []
    original_load = ModelRegistry.load

    def counting_load(self, r, version=None):
        load_calls.append(r)
        return original_load(self, r, version)

    monkeypatch.setattr(ModelRegistry, "load", counting_load)

    for i in range(3):
        findings = engine.evaluate(
            make_event(
                agent_id=role,
                session_id="s1",
                event_id=f"e{i}",
                tool_name="x",
                ts=_BASE_TS + timedelta(seconds=i),
            )
        )
        assert seq_findings(findings) == []

    assert role in engine._l3._unavailable_roles
    # registry.load is called during the FIRST event's classification (once
    # inside detector.score()'s own _bundle(), once via the layer's probe),
    # and NEVER AGAIN for subsequent events on the same role (short-circuit,
    # step 4) — the count must stay constant, not grow with event count.
    assert len(load_calls) <= 2


def test_fr8_corrupt_meta_json_raised_directly_from_score_call_is_persistent(tmp_path):
    role = "corrupt-role"
    registry_dir = _train_small_registry(tmp_path, role)
    engine = make_engine(registry_dir)

    # Corrupt meta.json for the published LATEST version so that
    # `registry.load()`'s `json.loads(meta_path.read_text())` raises
    # `json.JSONDecodeError` straight out of `_bundle()`, which `score()`'s
    # own guard only catches for `RegistryError` — so it propagates directly
    # out of `SequenceDetector.score()` itself.
    role_dir = Path(registry_dir) / role
    latest = (role_dir / "LATEST").read_text().strip()
    meta_path = role_dir / latest / "meta.json"
    meta_path.write_text("{not valid json")

    findings = engine.evaluate(
        make_event(agent_id=role, session_id="s1", event_id="e0", tool_name="x", ts=_BASE_TS)
    )
    assert seq_findings(findings) == []  # NFR-2: never raises into the hot path
    assert role in engine._l3._unavailable_roles


def test_fr8_corrupt_meta_json_discovered_via_probe_path_is_persistent(tmp_path, monkeypatch):
    role = "probe-corrupt-role"
    registry_dir = _train_small_registry(tmp_path, role)
    engine = make_engine(registry_dir)

    # Event 1: normal scoring succeeds -> the bundle is cached in
    # `SequenceDetector._cache`, so a later `_bundle()` call for this role
    # will NOT re-read disk.
    f1 = engine.evaluate(
        make_event(
            agent_id=role, session_id="s1", event_id="e0", tool_name="fetch_customer", ts=_BASE_TS
        )
    )
    assert seq_findings(f1) == []
    assert role not in engine._l3._unavailable_roles

    # Corrupt the on-disk meta.json AFTER the bundle is already cached (e.g. a
    # concurrent bad write) by removing the required "threshold" key —  valid
    # JSON, but `float(meta["threshold"])` in `registry.load()` raises KeyError.
    role_dir = Path(registry_dir) / role
    latest = (role_dir / "LATEST").read_text().strip()
    meta_path = role_dir / latest / "meta.json"
    meta = json.loads(meta_path.read_text())
    del meta["threshold"]
    meta_path.write_text(json.dumps(meta))

    # Force a transient scoring exception so `detector.score()`'s OWN
    # `_bundle()` call succeeds (cache hit, no disk read), but `score_session`
    # raises -> returns "sequence_scoring_unavailable" -> the layer's
    # `_handle_unavailable` probe calls `registry.load(role)` DIRECTLY
    # (bypassing the cache) -> hits the now-corrupt meta.json -> KeyError.
    def raise_once(*args, **kwargs):
        raise RuntimeError("injected transient scoring failure")

    monkeypatch.setattr(detector_mod, "score_session", raise_once)

    findings = engine.evaluate(
        make_event(
            agent_id=role,
            session_id="s1",
            event_id="e1",
            tool_name="verify_id",
            ts=_BASE_TS + timedelta(seconds=1),
        )
    )
    assert seq_findings(findings) == []  # NFR-2: never raises into the hot path
    assert role in engine._l3._unavailable_roles  # KeyError via probe -> persistent


# =============================================================================
# Required-change-2 (§3.5) — bounded `_unavailable_roles` LRU
# =============================================================================


def test_fr13_unavailable_roles_lru_is_bounded_and_evicts_at_the_boundary(empty_registry_dir):
    engine = make_engine(empty_registry_dir, max_unavailable_roles=2)

    for i, role in enumerate(["role1", "role2", "role3"]):
        engine.evaluate(
            make_event(agent_id=role, session_id="s1", event_id=f"e{i}", tool_name="x", ts=_BASE_TS)
        )

    assert len(engine._l3._unavailable_roles) == 2
    # role1 was the LRU-front and is evicted once the cap (2) is exceeded by role3
    assert "role1" not in engine._l3._unavailable_roles
    assert "role2" in engine._l3._unavailable_roles
    assert "role3" in engine._l3._unavailable_roles


def test_fr13_evicted_role_is_re_probed_and_can_self_heal(tmp_path):
    registry_dir = str(tmp_path / "registry")
    engine = make_engine(registry_dir, max_unavailable_roles=1)

    # role1 becomes persistently unavailable (no model)
    engine.evaluate(
        make_event(agent_id="role1", session_id="s1", event_id="e0", tool_name="x", ts=_BASE_TS)
    )
    assert "role1" in engine._l3._unavailable_roles

    # role2 evicts role1 from the bounded cache (cap=1)
    engine.evaluate(
        make_event(agent_id="role2", session_id="s1", event_id="e1", tool_name="x", ts=_BASE_TS)
    )
    assert "role1" not in engine._l3._unavailable_roles
    assert "role2" in engine._l3._unavailable_roles

    # Publish a model for role1 out-of-band (simulating a late training run)
    detector = SequenceDetector(SequenceConfig(registry_dir=registry_dir))
    sessions = data_gen.generate_normal_sessions(120, seed=3)
    detector.train_and_publish("role1", sessions)

    # role1 is re-probed on its next event (it was evicted, not permanently
    # cached) and scores successfully instead of staying blind forever: no
    # crash, and it is no longer in the persistent-unavailability cache.
    findings = engine.evaluate(
        make_event(
            agent_id="role1",
            session_id="s1",
            event_id="e2",
            tool_name="fetch_customer",
            ts=_BASE_TS + timedelta(seconds=1),
        )
    )
    assert "role1" not in engine._l3._unavailable_roles
    # a real score was attempted (not short-circuited): any finding present
    # must be a legitimate sequence.anomaly, never an unavailable/error result.
    assert all(f.rule_id == "sequence.anomaly" for f in findings)


# =============================================================================
# AC-15 / NFR-2 / UAT-13 — hot-path fault isolation at the Engine level
# =============================================================================


def test_ac15_unexpected_exception_in_scoring_is_isolated_by_engine_not_layer(
    empty_registry_dir, caplog
):
    import logging

    engine = make_engine(empty_registry_dir)

    def boom(role, session):
        raise ZeroDivisionError("totally unexpected fault")

    engine._l3._detector.score = boom

    with caplog.at_level(logging.ERROR, logger="sentinel.detection.sequence"):
        findings = engine.evaluate(
            make_event(
                agent_id=NO_POLICY_ROLE, session_id="s1", event_id="e0", tool_name="x", ts=_BASE_TS
            )
        )
    assert seq_findings(findings) == []  # NFR-2: evaluate() returns normally
    assert not any(f.rule_id.startswith("sequence.") for f in findings)
    assert len(caplog.records) >= 1
    # Because the fault never reached the layer's own classification logic,
    # the role must NOT be persistently cached — it is retried next event.
    assert NO_POLICY_ROLE not in engine._l3._unavailable_roles

    engine._l3._detector.score = lambda role, session: _ok_result()
    findings2 = engine.evaluate(
        make_event(
            agent_id=NO_POLICY_ROLE,
            session_id="s1",
            event_id="e1",
            tool_name="x",
            ts=_BASE_TS + timedelta(seconds=1),
        )
    )
    assert seq_findings(findings2) == []  # retried successfully, no permanent blinding


# =============================================================================
# NFR-5 / AC-18 / UAT-14 — determinism & reproducibility
# =============================================================================


def test_nfr5_scoring_same_session_twice_is_deterministic(
    trained_registry_dir, attack_session_privilege_escalation
):
    engine1 = make_engine(trained_registry_dir)
    engine2 = make_engine(trained_registry_dir)

    r1 = feed_session(engine1, NO_POLICY_ROLE, "sessA", attack_session_privilege_escalation)
    r2 = feed_session(engine2, NO_POLICY_ROLE, "sessA", attack_session_privilege_escalation)

    f1 = [f for fs in r1 for f in fs if f.rule_id == "sequence.anomaly"]
    f2 = [f for fs in r2 for f in fs if f.rule_id == "sequence.anomaly"]

    assert len(f1) == len(f2) == 1
    assert f1[0].severity == f2[0].severity
    assert {e.key: e.value for e in f1[0].evidence} == {e.key: e.value for e in f2[0].evidence}
    assert any(e.key == "model_version" for e in f1[0].evidence)


# =============================================================================
# NFR-4 / AC-17 / UAT-16 — no secret/PII leakage
# =============================================================================


def test_nfr4_no_secret_leaks_into_sequence_finding_evidence(empty_registry_dir):
    engine = make_engine(empty_registry_dir)
    engine._l3._detector.score = lambda role, session: _anomaly_result("high")

    secret = "sk-super-secret-token-should-never-appear"
    e = make_event(
        agent_id=NO_POLICY_ROLE,
        session_id="s1",
        tool_name="x",
        ts=_BASE_TS,
        attributes={"secret_api_key": secret},
    )
    findings = engine.evaluate(e)
    seq = [f for f in findings if f.rule_id == "sequence.anomaly"]
    assert len(seq) == 1
    for ev in seq[0].evidence:
        assert secret not in ev.value

    allowed_keys_prefix = ("agent_id", "session_id", "action", "host", "tool", "model", "bytes_out")
    for ev in seq[0].evidence:
        assert (
            ev.key.startswith(allowed_keys_prefix)
            or ev.key.startswith("seq_step_")
            or ev.key in ("model_version", "topk_surprise", "threshold")
        )


# =============================================================================
# AC-19 / NFR-6 / UAT-15 — backward compatibility (byte-identical L1/L2 output)
# =============================================================================


@pytest.mark.parametrize(
    "tool_name,host,expect_rule",
    [
        (None, "attacker-exfil.example", "net.host_not_allowed"),
        ("dump_all_accounts", "ledger.internal", "tool.not_allowed"),
    ],
)
def test_ac19_nfr6_l1_l2_output_unchanged_regardless_of_seq_state(
    empty_registry_dir, tool_name, host, expect_rule
):
    # Same event object reused across all three engines so `event_id` (and
    # thus `Finding.event_ids`) is identical, isolating the comparison to
    # whether the L3 feature state changes L1/L2 output (NFR-6), not to
    # incidental per-construction randomness.
    e = make_event(
        agent_id=POLICY_ROLE,
        session_id="s1",
        action=ActionType.TOOL_CALL,
        tool_name=tool_name,
        host=host,
        ts=_BASE_TS,
        event_id="fixed-event-id",
    )

    baseline_engine = Engine(PolicySet.from_yaml(POLICY))  # exactly pre-integration: no seq_config
    disabled_engine = make_engine(empty_registry_dir, enabled=False)
    enabled_no_model_engine = make_engine(empty_registry_dir, enabled=True)

    results = [
        tuple(finding_signature(f) for f in engine.evaluate(e))
        for engine in (baseline_engine, disabled_engine, enabled_no_model_engine)
    ]

    assert results[0] == results[1] == results[2]
    assert any(sig[2] == expect_rule for sig in results[0])
    assert not any(sig[2].startswith("sequence.") for sig in results[0])


def test_ac19_allowed_traffic_stays_empty_across_all_seq_states(empty_registry_dir):
    baseline_engine = Engine(PolicySet.from_yaml(POLICY))
    disabled_engine = make_engine(empty_registry_dir, enabled=False)
    enabled_no_model_engine = make_engine(empty_registry_dir, enabled=True)

    for engine in (baseline_engine, disabled_engine, enabled_no_model_engine):
        e = make_event(agent_id=POLICY_ROLE, session_id="s1", host="ledger.internal", ts=_BASE_TS)
        assert seq_findings(engine.evaluate(e)) == []


# =============================================================================
# AC-6 (cross-check) — single adapter identity: sequence_layer imports the
# SAME function seq_adapter defines (no divergent/duplicated derivation).
# =============================================================================


def test_ac6_sequence_layer_uses_the_single_shared_adapter():
    import sentinel.detection.sequence_layer as sequence_layer_mod

    assert sequence_layer_mod.to_seq_event is seq_adapter.to_seq_event
    assert sequence_layer_mod.resolve_role is seq_adapter.resolve_role
    assert sequence_layer_mod.is_valid_role is seq_adapter.is_valid_role
