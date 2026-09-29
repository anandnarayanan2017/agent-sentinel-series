"""Tests for the sentinel_sequence bug-fix + cleanup hardening effort.

Traces to SPEC.md, ACCEPTANCE.md (AC-1..AC-10, AC-NFR-7) and UAT.md
(UAT-1..UAT-10, UAT-NFR-7) from that pipeline run. Each test function/group
is named after the FR/AC/UAT it validates. That pipeline's spec/design/
evidence artifacts have since been archived (their Gate 2 evidence trail is
preserved intact) to make room for a later pipeline run in spec/design/
evidence/ — see archive/2026-07-13-sentinel_sequence-hardening/{spec,design,evidence}/
for the frozen SPEC.md, ACCEPTANCE.md, UAT.md, DESIGN.md this file was
written against.

These tests are written against the CONTRACT described in that archived
ACCEPTANCE.md and DESIGN.md (§2, §4.1, §5) — not by mirroring whatever the
current implementation happens to do. Golden/expected values for the
equivalence tests (FR-5, FR-7) are derived independently from the algorithms
documented in SPEC.md / the module docstrings (mean-NLL scoring,
Laplace-smoothed Markov probabilities, "sorted(..., reverse=True)" tie
semantics) rather than copied from the fixed implementation.

DB-touching tests (FR-3, and the non-injection paths of FR-4) are marked
`integration` per the project's test conventions so they stay
opt-in and are excluded from UNIT_TEST_CMD ("pytest -m 'not integration'").
Pure-Python validation (FR-4's injection guard) remains a fast unit test
per spec Assumption A-6.
"""

from __future__ import annotations

import math
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace

import pytest

duckdb = pytest.importorskip("duckdb", reason="duckdb is required for store.py tests (A-6)")

import sentinel_sequence.cli as cli
from sentinel_sequence import (
    ModelBundle,
    ModelRegistry,
    RegistryError,
    SequenceConfig,
    check_drift,
    score_session,
    split_sessions,
)
from sentinel_sequence import data_gen
from sentinel_sequence.markov import MarkovModel
from sentinel_sequence.store import DEFAULT_COLUMNS, EventStore
from sentinel_sequence.tokenizer import EOS, SOS, UNK, Tokenizer

pytestmark: list[pytest.MarkDecorator] = []


# =============================================================================
# FR-1 / AC-1 / UAT-1 — Tokenizer.from_dict validation
# =============================================================================


def test_fr1_valid_vocab_round_trips():
    sessions = [
        [{"kind": "tool", "name": "fetch_customer"}, {"kind": "llm", "name": "call"}],
        [{"kind": "tool", "name": "verify_id"}],
    ]
    tok = Tokenizer().fit(sessions)
    d = tok.to_dict()
    restored = Tokenizer.from_dict(d)
    assert restored.token_to_id == tok.token_to_id


def test_fr1_missing_special_token_raises_naming_it():
    d = {"token_to_id": {SOS: 0, EOS: 1, "a:b": 2}}  # missing <UNK>
    with pytest.raises(ValueError) as exc:
        Tokenizer.from_dict(d)
    assert UNK in str(exc.value)


def test_fr1_non_contiguous_ids_raise():
    d = {"token_to_id": {SOS: 0, EOS: 1, UNK: 2, "a:b": 4}}  # gap: no id 3
    with pytest.raises(ValueError) as exc:
        Tokenizer.from_dict(d)
    msg = str(exc.value).lower()
    assert "contiguous" in msg or "id space" in msg


def test_fr1_duplicate_id_raises():
    d = {"token_to_id": {SOS: 0, EOS: 0, UNK: 1}}  # duplicate id 0
    with pytest.raises(ValueError):
        Tokenizer.from_dict(d)


def test_fr1_non_int_id_value_raises():
    d = {"token_to_id": {SOS: 0, EOS: 1, UNK: 2, "a:b": "not-an-int"}}
    with pytest.raises(ValueError) as exc:
        Tokenizer.from_dict(d)
    assert "a:b" in str(exc.value) or "int" in str(exc.value).lower()


def test_fr1_missing_token_to_id_key_raises():
    with pytest.raises(ValueError) as exc:
        Tokenizer.from_dict({})
    assert "token_to_id" in str(exc.value)


def test_fr1_bool_id_value_rejected():
    """bool is an int subclass; FR-1(a) requires ids to be exactly int, not bool."""
    d = {"token_to_id": {SOS: 0, EOS: 1, UNK: True, "a:b": 3}}
    with pytest.raises(ValueError):
        Tokenizer.from_dict(d)


# =============================================================================
# FR-2 / AC-2 / UAT-2 — timestamp robustness + stable ordering
# =============================================================================


def test_fr2_malformed_timestamp_raises_naming_value_and_field():
    events = [{"agent_id": "a", "ts": "not-a-date", "kind": "tool", "name": "x"}]
    with pytest.raises(ValueError) as exc:
        split_sessions(events)
    msg = str(exc.value)
    assert "not-a-date" in msg
    assert "ts" in msg


def test_fr2_iso_timestamp_without_offset_parses():
    events = [{"agent_id": "a", "ts": "2026-07-12T00:00:00", "kind": "tool", "name": "x"}]
    sessions = split_sessions(events)
    assert sessions
    assert sum(len(s) for s in sessions) == 1


def test_fr2_tied_timestamps_are_deterministic_across_runs():
    events = [
        {
            "agent_id": "a",
            "session_id": "s1",
            "ts": "2026-01-01T00:00:00Z",
            "kind": "tool",
            "name": "first",
        },
        {
            "agent_id": "a",
            "session_id": "s1",
            "ts": "2026-01-01T00:00:00Z",
            "kind": "tool",
            "name": "second",
        },
    ]
    for _ in range(3):
        sessions = split_sessions(list(events))
        assert len(sessions) == 1
        names = [e["name"] for e in sessions[0]]
        assert names == ["first", "second"], "tie must break by original input index"


def test_fr2_tied_timestamps_deterministic_in_gap_based_branch():
    """Same as above but for agents without session_id (the gap-based branch)."""
    events = [
        {"agent_id": "a", "ts": "2026-01-01T00:00:00Z", "kind": "tool", "name": "first"},
        {"agent_id": "a", "ts": "2026-01-01T00:00:00Z", "kind": "tool", "name": "second"},
    ]
    for _ in range(3):
        sessions = split_sessions(list(events))
        assert len(sessions) == 1
        names = [e["name"] for e in sessions[0]]
        assert names == ["first", "second"]


def test_fr2_unique_timestamps_golden_split():
    """Independently-derived expected split for a fixture with unique, well-formed
    timestamps: group by agent_id, sort by ts ascending, split on gap > gap_seconds.
    """
    events = [
        {"agent_id": "a1", "ts": "2026-01-01T00:00:00Z", "kind": "tool", "name": "e1"},
        {"agent_id": "a1", "ts": "2026-01-01T00:01:00Z", "kind": "tool", "name": "e2"},
        # gap of 20 minutes > default 600s -> new session for a1
        {"agent_id": "a1", "ts": "2026-01-01T00:21:00Z", "kind": "tool", "name": "e3"},
        {"agent_id": "a2", "ts": "2026-01-01T00:00:30Z", "kind": "tool", "name": "e4"},
    ]
    sessions = split_sessions(events)
    by_name = {tuple(e["name"] for e in s) for s in sessions}
    assert by_name == {("e1", "e2"), ("e3",), ("e4",)}


# =============================================================================
# FR-3 / AC-3 / UAT-3 — EventStore._build_ts_expr fails loudly on column miss
# =============================================================================


def _make_events_db(tmp_path, ts_col_name="ts", ts_col_type="TIMESTAMP", table="agent_events"):
    db_path = tmp_path / "events.duckdb"
    con = duckdb.connect(str(db_path))
    con.execute(
        f"CREATE TABLE {table} (agent_id VARCHAR, {ts_col_name} {ts_col_type}, "
        f"kind VARCHAR, name VARCHAR, session_id VARCHAR, role VARCHAR)"
    )
    con.close()
    return str(db_path)


@pytest.mark.integration
def test_fr3_timestamp_column_produces_epoch_expr(tmp_path):
    db = _make_events_db(tmp_path, ts_col_name="ts", ts_col_type="TIMESTAMP")
    with EventStore(db) as store:
        assert store._ts_expr == "epoch(ts)"


@pytest.mark.integration
def test_fr3_numeric_column_is_passthrough_expr(tmp_path):
    db = _make_events_db(tmp_path, ts_col_name="ts", ts_col_type="DOUBLE")
    with EventStore(db) as store:
        assert store._ts_expr == "ts"


@pytest.mark.integration
def test_fr3_missing_ts_column_fails_loudly(tmp_path):
    db = _make_events_db(tmp_path, ts_col_name="ts", ts_col_type="TIMESTAMP")
    with pytest.raises(ValueError) as exc:
        EventStore(db, columns={"ts": "does_not_exist"})
    assert "does_not_exist" in str(exc.value)


def test_fr3_schema_stability_assumption_documented():
    doc = (EventStore.__doc__ or "") + (EventStore._build_ts_expr.__doc__ or "")
    doc_l = doc.lower()
    assert "stable" in doc_l
    assert "lifetime" in doc_l


# =============================================================================
# FR-4 / AC-4 / UAT-4 — column-mapping SQL-injection validation + CLEAN-C/D
# =============================================================================


def test_fr4_malicious_columns_rejected_without_live_db(tmp_path):
    """Validation MUST fire in __init__ before any DB work — proven by using a
    path to a DB file that does not exist. If the malicious value reached a
    query, we'd see a duckdb I/O error instead of this ValueError.
    """
    nonexistent_db = str(tmp_path / "does_not_exist.duckdb")
    with pytest.raises(ValueError) as exc:
        EventStore(
            nonexistent_db,
            columns={"agent_id": "agent_id; DROP TABLE agent_events;--"},
        )
    assert "agent_id" in str(exc.value)


@pytest.mark.parametrize("col_key", sorted(DEFAULT_COLUMNS.keys()))
def test_fr4_clean_d_every_column_key_is_validated(tmp_path, col_key):
    """CLEAN-D: every self.cols value (not just agent_id) must be validated."""
    nonexistent_db = str(tmp_path / "nope.duckdb")
    with pytest.raises(ValueError):
        EventStore(nonexistent_db, columns={col_key: "x; DROP TABLE agent_events;--"})


@pytest.mark.integration
def test_fr4_benign_remap_still_works_clean_c(tmp_path):
    db = _make_events_db(tmp_path, ts_col_name="event_ts", ts_col_type="TIMESTAMP")
    with EventStore(db, columns={"ts": "event_ts"}) as store:
        assert store._ts_expr == "epoch(event_ts)"


@pytest.mark.integration
def test_fr4_default_columns_still_construct(tmp_path):
    db = _make_events_db(tmp_path)
    with EventStore(db) as store:
        assert store.cols == DEFAULT_COLUMNS


# =============================================================================
# FR-5 / AC-5 / UAT-5 — deferred decode/top_k equivalence + work reduction
# =============================================================================


def _fixed_model_tokenizer():
    """A tiny, fully hand-specified model+tokenizer so every SessionScore field
    can be computed independently (Laplace smoothing: p = (c+alpha)/(t+alpha*V)).
    """
    tok = Tokenizer(token_to_id={SOS: 0, EOS: 1, UNK: 2, "tool:a": 3, "tool:b": 4})
    tok._fitted = True

    model = MarkovModel(order=1, alpha=1.0, vocab_size=5)
    model.counts = {(0,): {3: 2}, (3,): {4: 1, 1: 3}, (4,): {3: 5}}
    model.context_totals = {(0,): 2, (3,): 4, (4,): 5}
    model._fitted = True
    return model, tok


def test_fr5_score_session_exact_field_values():
    model, tok = _fixed_model_tokenizer()
    encoded = [0, 3, 4, 3, 1]  # <SOS> tool:a tool:b tool:a <EOS>

    score = score_session(model, tok, encoded, top_n=2, k_expected=2)

    p1 = 3 / 7  # P(3 | ctx=(0,))
    p2 = 2 / 9  # P(4 | ctx=(3,))
    p3 = 6 / 10  # P(3 | ctx=(4,))
    p4 = 4 / 9  # P(1 | ctx=(3,))
    nll1, nll2, nll3, nll4 = (-math.log(p) for p in (p1, p2, p3, p4))

    assert score.n_transitions == 4
    assert score.nll_per_step == pytest.approx((nll1 + nll2 + nll3 + nll4) / 4)
    # top_n=2 highest-nll transitions are position 2 (nll2) then position 1 (nll1)
    assert score.topk_surprise == pytest.approx((nll2 + nll1) / 2)
    assert len(score.top_surprises) == 2

    s0, s1 = score.top_surprises
    assert s0.position == 2
    assert s0.context == ["tool:a"]
    assert s0.observed == "tool:b"
    assert s0.observed_prob == pytest.approx(p2)
    assert s0.surprise == pytest.approx(nll2)
    assert s0.expected == [("<EOS>", pytest.approx(p4)), ("tool:b", pytest.approx(p2))]

    assert s1.position == 1
    assert s1.context == [SOS]
    assert s1.observed == "tool:a"
    assert s1.observed_prob == pytest.approx(p1)
    assert s1.surprise == pytest.approx(nll1)
    assert s1.expected == [("tool:a", pytest.approx(p1))]

    # evidence-chain sentences derived independently from the documented format
    # ("step N: after [...], expected {...}; observed X (p=..)")
    sentence1 = s1.to_sentence()
    assert sentence1.startswith("step 1: after [<SOS>], expected {tool:a (p=0.43)}")
    assert "observed tool:a (p=0.4286)" in sentence1
    assert score.to_evidence_chain() == [s0.to_sentence(), s1.to_sentence()]


def test_fr5_score_session_empty_encoded_session():
    model, tok = _fixed_model_tokenizer()
    score = score_session(model, tok, [0, 1])  # SOS, EOS only => 1 transition, or []
    # a single-element / empty transition set must not crash and yields the
    # documented zero SessionScore when there are no transitions at all
    empty_score = score_session(model, tok, [])
    assert empty_score.n_transitions == 0
    assert empty_score.nll_per_step == 0.0
    assert empty_score.topk_surprise == 0.0
    assert empty_score.top_surprises == []
    assert score.n_transitions == 1


def test_fr5_top_k_called_at_most_top_n_times_work_reduction():
    sessions = data_gen.generate_normal_sessions(80)
    tok = Tokenizer().fit(sessions)
    encoded = [tok.encode_session(s) for s in sessions]
    model = MarkovModel(order=1, alpha=0.5).fit(encoded, tok.vocab_size)

    # a longer session with more transitions than top_n
    long_session = max(sessions, key=len) + sessions[0]
    long_encoded = tok.encode_session(long_session)
    assert len(long_encoded) - 1 > 3, "fixture must have more transitions than top_n"

    original_bound_top_k = model.top_k
    calls = {"n": 0}

    def counting_top_k(context, k=3):
        calls["n"] += 1
        return original_bound_top_k(context, k)

    model.top_k = counting_top_k

    top_n = 3
    score = score_session(model, tok, long_encoded, top_n=top_n, k_expected=2)

    assert score.n_transitions == len(long_encoded) - 1
    assert calls["n"] <= top_n
    assert len(score.top_surprises) <= top_n


# =============================================================================
# FR-6 / AC-6 / UAT-6 — shared cli time-to-epoch helper
# =============================================================================


def test_fr6_epoch_hours_ago_none_for_falsy_hours():
    assert cli._epoch_hours_ago(None) is None
    assert cli._epoch_hours_ago(0) is None


def test_fr6_epoch_hours_ago_fixed_value(monkeypatch):
    fixed = 1_700_000_000.0
    monkeypatch.setattr(cli.time, "time", lambda: fixed)
    hours = 24
    got = cli._epoch_hours_ago(hours)
    assert got == pytest.approx(fixed - hours * 3600, abs=1e-6)


def test_fr6_cmd_train_and_cmd_score_use_shared_helper(monkeypatch, tmp_path):
    fixed = 1_700_000_000.0
    monkeypatch.setattr(cli.time, "time", lambda: fixed)

    captured = {}

    class FakeStore:
        def __init__(self, db):
            captured["db"] = db

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def fetch_sessions(self, role=None, gap_seconds=600.0, since_epoch=None, until_epoch=None):
            captured["since"] = since_epoch
            captured["until"] = until_epoch
            return []

    monkeypatch.setattr("sentinel_sequence.store.EventStore", FakeStore)

    args = SimpleNamespace(
        role="r",
        db="ignored.duckdb",
        since_hours=24,
        until_hours=1,
        since_epoch=None,
        until_epoch=None,
        registry=str(tmp_path / "registry"),
    )
    with pytest.raises(Exception):
        # insufficient training data -> raises past the epoch computation,
        # which is exactly what we want to observe
        cli.cmd_train(args)
    assert captured["since"] == pytest.approx(fixed - 24 * 3600)
    assert captured["until"] == pytest.approx(fixed - 1 * 3600)

    # --since-epoch / --until-epoch overrides win over the hours computation
    captured.clear()
    args2 = SimpleNamespace(
        role="r",
        db="ignored.duckdb",
        since_hours=24,
        until_hours=1,
        since_epoch=111.0,
        until_epoch=222.0,
        registry=str(tmp_path / "registry"),
    )
    with pytest.raises(Exception):
        cli.cmd_train(args2)
    assert captured["since"] == 111.0
    assert captured["until"] == 222.0

    # cmd_score: since-hours only
    captured.clear()

    class FakeStoreScore(FakeStore):
        def fetch_sessions(self, role=None, gap_seconds=600.0, since_epoch=None, until_epoch=None):
            captured["since"] = since_epoch
            return []

    monkeypatch.setattr("sentinel_sequence.store.EventStore", FakeStoreScore)
    args3 = SimpleNamespace(
        role="r",
        db="ignored.duckdb",
        since_hours=24,
        registry=str(tmp_path / "registry"),
    )
    cli.cmd_score(args3)
    assert captured["since"] == pytest.approx(fixed - 24 * 3600)


# =============================================================================
# FR-7 / AC-7 / UAT-7 — markov.top_k heapq.nlargest equivalence
# =============================================================================


def _baseline_top_k(model: MarkovModel, context: tuple, k: int) -> list[tuple[int, float]]:
    """The pre-fix reference algorithm per SPEC.md FR-7: a full descending sort
    of the candidate distribution, tie-stable in insertion order.
    """
    c = model.counts.get(context)
    if not c:
        return []
    ranked = sorted(c.items(), key=lambda kv: kv[1], reverse=True)[:k]
    return [(tok, model.prob(context, tok)) for tok, _ in ranked]


def test_fr7_top_k_matches_baseline_sorted_including_ties():
    model = MarkovModel(order=1, alpha=1.0, vocab_size=10)
    # exact-count ties among tokens 1,2,3 (all count=5); insertion order matters
    model.counts = {(0,): {1: 5, 2: 5, 3: 5, 4: 3, 5: 1}}
    model.context_totals = {(0,): 19}
    model._fitted = True

    for k in (1, 2, 3, 4, 5, 10):
        assert model.top_k((0,), k) == _baseline_top_k(model, (0,), k)


def test_fr7_top_k_matches_baseline_randomized_contexts():
    import random

    rng = random.Random(1234)
    model = MarkovModel(order=1, alpha=0.7, vocab_size=1200)
    contexts = [(i,) for i in range(5)]
    for ctx in contexts:
        counts = {}
        for tok in rng.sample(range(1200), 60):
            # force some exact ties by reusing a small set of count values
            counts[tok] = rng.choice([1, 1, 2, 2, 5, 5, 5, 9])
        model.counts[ctx] = counts
        model.context_totals[ctx] = sum(counts.values())
    model._fitted = True

    for ctx in contexts:
        for k in (1, 3, 7, 25):
            assert model.top_k(ctx, k) == _baseline_top_k(model, ctx, k)


def test_fr7_top_k_empty_context_returns_empty_list():
    model = MarkovModel(order=1, alpha=1.0, vocab_size=5)
    model._fitted = True
    assert model.top_k((99,), 3) == []


def test_fr7_uses_heapq_nlargest_not_full_sort():
    import inspect

    src = inspect.getsource(MarkovModel.top_k)
    assert "heapq" in src and "nlargest" in src, (
        "AC-7 requires MarkovModel.top_k to use heapq.nlargest (or a documented "
        "equivalent partial-selection algorithm), not a full sort"
    )


def test_fr7_top_k_negative_k_raises_value_error():
    # heapq.nlargest(-1, ...) silently returns [], unlike sorted(...)[:-1] which
    # returns all-but-the-last item — top_k rejects negative k explicitly
    # instead of silently diverging from the old slice-based behavior.
    model = MarkovModel(order=1, alpha=1.0, vocab_size=5)
    model._fitted = True
    model.counts[(0,)][1] += 1
    with pytest.raises(ValueError, match="k must be >= 0"):
        model.top_k((0,), -1)


def test_fr7_top_k_zero_k_returns_empty_list():
    model = MarkovModel(order=1, alpha=1.0, vocab_size=5)
    model._fitted = True
    model.counts[(0,)][1] += 1
    assert model.top_k((0,), 0) == []


# =============================================================================
# FR-8 / AC-8 / UAT-8 — registry.load reads each artifact once (TOCTOU close)
# =============================================================================


def _publish_bundle(tmp_path, role="kyc_bot"):
    sessions = data_gen.generate_normal_sessions(40)
    tok = Tokenizer().fit(sessions)
    encoded = [tok.encode_session(s) for s in sessions]
    model = MarkovModel(order=1, alpha=0.5).fit(encoded, tok.vocab_size)
    registry = ModelRegistry(tmp_path / "registry")
    calibration = {"percentile": 99.0, "n_sessions": 10, "median": 0.5, "p99": 2.0}
    version = registry.publish(role, model, tok, threshold=1.23, calibration=calibration)
    return registry, role, version, model, tok, calibration


@pytest.mark.integration
def test_fr8_valid_bundle_loads_identically(tmp_path):
    registry, role, version, model, tok, calibration = _publish_bundle(tmp_path)
    bundle = registry.load(role)

    assert isinstance(bundle, ModelBundle)
    assert bundle.role == role
    assert bundle.version == version
    assert bundle.threshold == pytest.approx(1.23)
    assert bundle.calibration == calibration
    assert bundle.tokenizer.token_to_id == tok.token_to_id
    assert dict(bundle.model.counts) == {k: dict(v) for k, v in model.counts.items()}
    assert bundle.model.order == model.order
    assert bundle.model.alpha == model.alpha
    assert bundle.model.vocab_size == model.vocab_size


@pytest.mark.integration
def test_fr8_corrupted_artifact_raises_registry_error(tmp_path):
    registry, role, version, *_ = _publish_bundle(tmp_path)
    model_json = tmp_path / "registry" / role / version / "model.json"
    data = bytearray(model_json.read_bytes())
    data[0] ^= 0xFF  # flip one byte
    model_json.write_bytes(bytes(data))

    with pytest.raises(RegistryError) as exc:
        registry.load(role)
    msg = str(exc.value).lower()
    assert "corrupt" in msg or "checksum" in msg


@pytest.mark.integration
def test_fr8_each_artifact_read_exactly_once(tmp_path, monkeypatch):
    registry, role, version, *_ = _publish_bundle(tmp_path)

    read_counts: dict[str, int] = defaultdict(int)
    original_read_bytes = Path.read_bytes

    def counting_read_bytes(self):
        read_counts[self.name] += 1
        return original_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", counting_read_bytes)
    registry.load(role)

    assert read_counts["model.json"] == 1, "model.json must be read exactly once (no TOCTOU)"
    assert read_counts["tokenizer.json"] == 1, "tokenizer.json must be read exactly once"


# =============================================================================
# FR-9 / AC-9 / UAT-9 — config.from_dict single unknown-key mechanism
# =============================================================================


def test_fr9_valid_dict_builds_equal_config():
    d = {"order": 1, "alpha": 0.5}
    assert SequenceConfig.from_dict(d) == SequenceConfig(order=1, alpha=0.5)


def test_fr9_unknown_key_raises_valueerror_not_typeerror():
    with pytest.raises(ValueError) as exc:
        SequenceConfig.from_dict({"nope": 1})
    # Per FR-9 / mini-ADR-1: the manual ValueError gate is authoritative, and
    # must fire (not the constructor's TypeError-on-unexpected-kwarg path).
    assert exc.type is ValueError
    assert "nope" in str(exc.value) or "Unknown" in str(exc.value)


def test_fr9_all_known_keys_dict_round_trips():
    full = SequenceConfig().to_dict()
    assert SequenceConfig.from_dict(full) == SequenceConfig()


# =============================================================================
# FR-10 / AC-10 / UAT-10 — degenerate calibration-median handling
# =============================================================================


def test_fr10_zero_median_returns_not_stale_report_no_raise():
    scores = [1.0] * 40
    report = check_drift(scores, calibration_median=0.0)
    assert report.stale is False
    assert "insufficient" in report.reason.lower() or "degenerate" in report.reason.lower()


def test_fr10_near_zero_epsilon_median_returns_not_stale_no_raise():
    scores = [1.0] * 40
    report = check_drift(scores, calibration_median=1e-12)
    assert report.stale is False
    assert "insufficient" in report.reason.lower() or "degenerate" in report.reason.lower()


def test_fr10_degenerate_report_has_no_flagged_inf_nan_signal():
    for median in (0.0, 1e-12, -5.0):
        report = check_drift([1.0] * 40, calibration_median=median)
        assert report.stale is False
        # ratio/recent_median must never be treated as a real (True) staleness
        # signal; either they are finite, or they are an explicit not-stale
        # sentinel (nan) consistent with the "insufficient data" shape.
        if not math.isnan(report.ratio):
            assert math.isfinite(report.ratio)


def test_fr10_normal_positive_median_stale_true():
    report = check_drift([3.0] * 40, calibration_median=1.0)
    assert report.stale is True
    assert report.recent_median == pytest.approx(3.0)
    assert report.ratio == pytest.approx(3.0)


def test_fr10_normal_positive_median_within_variation_not_stale():
    report = check_drift([1.1] * 40, calibration_median=1.0)
    assert report.stale is False
    assert "normal variation" in report.reason.lower()


def test_fr10_insufficient_session_count_unaffected_by_fr10():
    report = check_drift([5.0] * 5, calibration_median=1.0)
    assert report.stale is False
    assert "insufficient data" in report.reason.lower()


# =============================================================================
# NFR-7 cleanup — CLEAN-A/B/C/D
# =============================================================================


def test_clean_a_prob_consistent_with_raw_counts_after_fit():
    """CLEAN-A: whether context_totals is kept as a cache or removed, prob()
    must remain consistent with the raw per-context counts (AC-NFR-7).
    """
    sessions = data_gen.generate_normal_sessions(60)
    tok = Tokenizer().fit(sessions)
    encoded = [tok.encode_session(s) for s in sessions]
    model = MarkovModel(order=1, alpha=0.5).fit(encoded, tok.vocab_size)

    checked = 0
    for ctx, nxt in model.counts.items():
        if not nxt:
            continue
        total_from_counts = sum(nxt.values())
        any_tok = next(iter(nxt))
        expected_p = (nxt[any_tok] + model.alpha) / (
            total_from_counts + model.alpha * model.vocab_size
        )
        assert model.prob(ctx, any_tok) == pytest.approx(expected_p)
        checked += 1
    assert checked > 0, "fixture must exercise at least one context"


def test_clean_b_detector_registry_dir_matches_args_registry_single_construction(tmp_path):
    registry_dir = str(tmp_path / "myregistry")
    args = SimpleNamespace(registry=registry_dir)
    det = cli._detector(args)

    assert isinstance(det.registry, ModelRegistry)
    assert Path(det.registry.root) == Path(registry_dir)
    assert det.cfg.registry_dir == registry_dir


# CLEAN-C (remap still works) is covered by test_fr4_benign_remap_still_works_clean_c.
# CLEAN-D (every column-mapping key validated) is covered by
# test_fr4_clean_d_every_column_key_is_validated.
