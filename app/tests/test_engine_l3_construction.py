"""L3 sequence-layer construction fail-open (design/DESIGN.md §7.1, UAT-1..6).

Primary coverage drives the REAL construction chain (Engine -> L3SequenceLayer
-> ModelRegistry.__init__ -> mkdir) and forces the real mkdir to raise, since
numpy/sentinel_sequence are always importable under UNIT_TEST_CMD (no optional
dependency to skip). Fake-module injection is used only to prove the catch is
`except Exception`, not a narrower tuple — the one case the real filesystem
cannot produce.
"""

from __future__ import annotations

import logging
import sys
import types
from pathlib import Path

import pytest

from sentinel.collector.parsers import parse_flow
from sentinel.detection.engine import Engine
from sentinel.detection.policy import PolicySet
from sentinel.detection.seq_config import SeqLayerConfig
from sentinel.pipeline import Pipeline

POLICY = str(Path(__file__).resolve().parents[1].parent / "policies" / "example.yaml")


def bad_registry_dir(tmp_path: Path) -> str:
    """A path that is an existing regular file, not a directory.

    `Path(p).mkdir(parents=True, exist_ok=True)` raises `FileExistsError` (an
    `OSError` subclass) for this on both POSIX and Windows, deterministically
    — see design/DESIGN.md R5.
    """
    p = tmp_path / "not_a_dir"
    p.write_text("x")
    return str(p)


def good_registry_dir(tmp_path: Path) -> str:
    d = tmp_path / "registry"
    d.mkdir()
    return str(d)


def _fake_l3_module(exc: Exception) -> types.ModuleType:
    mod = types.ModuleType("sentinel.detection.sequence_layer")

    class FakeL3SequenceLayer:
        def __init__(self, *args, **kwargs):
            raise exc

    setattr(mod, "L3SequenceLayer", FakeL3SequenceLayer)  # noqa: B010 - dynamic fake module attr
    return mod


# ---- T1 (UAT-1, AC-1/AC-2) — real filesystem, primary ----------------------
def test_bad_registry_dir_is_fail_open_and_logged(tmp_path, caplog):
    registry_dir = bad_registry_dir(tmp_path)
    with caplog.at_level(logging.WARNING, logger="sentinel.detection.sequence"):
        engine = Engine(
            PolicySet.from_yaml(POLICY),
            seq_config=SeqLayerConfig(enabled=True, registry_dir=registry_dir),
        )
    assert engine._l3 is None
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    msg = warnings[0].getMessage()
    assert registry_dir in msg
    assert "FileExistsError" in msg


# ---- T2 (UAT-2, AC-1) — exception-type coverage, parametrized --------------
@pytest.mark.parametrize("exc", [ImportError("no numpy"), RuntimeError("boom"), ValueError("boom")])
def test_any_exception_during_construction_is_fail_open(monkeypatch, exc):
    monkeypatch.setitem(sys.modules, "sentinel.detection.sequence_layer", _fake_l3_module(exc))
    engine = Engine(
        PolicySet.from_yaml(POLICY),
        seq_config=SeqLayerConfig(enabled=True, registry_dir="models/sequence"),
    )
    assert engine._l3 is None


# ---- T3 (UAT-3, AC-3) — real filesystem, primary ---------------------------
def test_engine_still_evaluates_l1_after_l3_construction_failure(tmp_path):
    engine = Engine(
        PolicySet.from_yaml(POLICY),
        seq_config=SeqLayerConfig(enabled=True, registry_dir=bad_registry_dir(tmp_path)),
    )
    e = parse_flow(
        agent_id="recon-bot",
        session_id="s",
        host="attacker-exfil.example",
        method="POST",
        path="/c",
        request_body="x",
    )
    findings = engine.evaluate(e)
    assert any(f.rule_id == "net.host_not_allowed" for f in findings)
    assert not any(f.rule_id.startswith("sequence.") for f in findings)


# ---- T4 (UAT-4, AC-3) — real filesystem, primary ---------------------------
def test_pipeline_ingest_survives_l3_construction_failure(tmp_path):
    pipe = Pipeline(
        POLICY,
        ":memory:",
        seq_config=SeqLayerConfig(enabled=True, registry_dir=bad_registry_dir(tmp_path)),
    )
    findings = pipe.ingest_flow(
        agent_id="recon-bot",
        session_id="s",
        host="ledger.internal",
        method="GET",
        path="/t",
    )
    assert not any(f.rule_id.startswith("sequence.") for f in findings)


# ---- T5 (UAT-5, AC-4) — real success ---------------------------------------
def test_successful_l3_construction_is_unchanged(tmp_path):
    engine = Engine(
        PolicySet.from_yaml(POLICY),
        seq_config=SeqLayerConfig(enabled=True, registry_dir=good_registry_dir(tmp_path)),
    )
    assert engine._l3 is not None
    e = parse_flow(
        agent_id="recon-bot", session_id="s", host="ledger.internal", method="GET", path="/t"
    )
    engine.evaluate(e)  # must not raise


# ---- T6 (UAT-6, AC-5) — disabled/absent path unchanged ---------------------
def test_no_seq_config_means_l3_disabled_silently(caplog):
    with caplog.at_level(logging.INFO, logger="sentinel.detection.sequence"):
        engine = Engine(PolicySet.from_yaml(POLICY))
    assert engine._l3 is None
    assert not any("L3 sequence layer" in r.getMessage() for r in caplog.records)


def test_explicitly_disabled_seq_config_logs_info(caplog):
    with caplog.at_level(logging.INFO, logger="sentinel.detection.sequence"):
        engine = Engine(PolicySet.from_yaml(POLICY), seq_config=SeqLayerConfig(enabled=False))
    assert engine._l3 is None
    assert any(
        r.levelno == logging.INFO and "L3 sequence layer disabled" in r.getMessage()
        for r in caplog.records
    )
