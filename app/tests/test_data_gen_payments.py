"""Black-box coverage for data_gen_payments.py — the payments_bot_demo
synthetic data generator used by docs/EVAL_PAYMENTS_BOT.md.

Mirrors the data_gen.py coverage convention in
test_sentinel_sequence_coverage.py: ordinary black-box tests against the
module's documented public contract (its own docstring), not FR-traced
bug-fix tests.
"""

from __future__ import annotations

from sentinel_sequence import data_gen_payments as dgp


def test_normal_sessions_shape_and_kinds():
    sessions = dgp.generate_normal_sessions(50, seed=7)
    assert len(sessions) == 50
    for s in sessions:
        assert len(s) >= 1
        for e in s:
            assert set(e.keys()) >= {"kind", "name"}
            assert e["kind"] in {"llm", "tool", "net"}


def test_normal_sessions_deterministic_for_fixed_seed():
    a = dgp.generate_normal_sessions(30, seed=42)
    b = dgp.generate_normal_sessions(30, seed=42)
    assert a == b


def test_normal_templates_vocab_size_matches_docstring():
    # docstring claims 25 distinct (kind, name) actions across the 8 templates
    actions = {(e["kind"], e["name"]) for tmpl in dgp.NORMAL_TEMPLATES for e in tmpl}
    assert len(actions) == 25
    assert len(dgp.NORMAL_TEMPLATES) == 8


def test_attack_sessions_deterministic_for_fixed_seed():
    a = dgp.generate_attack_sessions(10, seed=137)
    b = dgp.generate_attack_sessions(10, seed=137)
    assert a == b


def test_attack_sessions_labels_are_composed_from_known_primitives():
    attacks = dgp.generate_attack_sessions(50, seed=137)
    known = set(dgp._PRIMITIVES)
    for label, session in attacks:
        names = label.split("+")
        assert 1 <= len(names) <= 2
        assert set(names) <= known
        assert names == sorted(names)  # label is documented as sorted, joined
        assert len(session) > 0


def test_attack_sessions_can_compose_two_primitives():
    # n_primitives is 1 with p=0.7, 2 with p=0.3 — 50 samples should surface both
    attacks = dgp.generate_attack_sessions(50, seed=137)
    assert any("+" in label for label, _ in attacks)
    assert any("+" not in label for label, _ in attacks)


def test_burst_loop_primitive_repeats_fetch_invoice():
    rng = dgp.random.Random(1)
    injected = dgp._PRIMITIVES["burst_loop"](rng)
    assert 9 <= len(injected) < 16
    assert all(e == {"kind": "tool", "name": "fetch_invoice"} for e in injected)


def test_exfiltration_burst_primitive_uses_net_egress():
    rng = dgp.random.Random(1)
    injected = dgp._PRIMITIVES["exfiltration_burst"](rng)
    assert 3 <= len(injected) < 7
    assert all(e == {"kind": "net", "name": "egress_new_domain"} for e in injected)


def test_credential_probe_primitive_repeats_verify_2fa():
    rng = dgp.random.Random(1)
    injected = dgp._PRIMITIVES["credential_probe"](rng)
    assert 4 <= len(injected) < 8
    assert all(e == {"kind": "tool", "name": "verify_2fa"} for e in injected)


def test_order_abuse_primitive_transfers_before_validation():
    rng = dgp.random.Random(1)
    injected = dgp._PRIMITIVES["order_abuse"](rng)
    names = [e["name"] for e in injected]
    # documented anomaly: wire transfer happens BEFORE payee/sanctions checks
    assert names.index("initiate_wire_transfer") < names.index("validate_payee")
    assert names.index("initiate_wire_transfer") < names.index("check_sanctions_list")


def test_silent_cancel_replay_primitive_replays_transfer_after_cancel():
    rng = dgp.random.Random(1)
    injected = dgp._PRIMITIVES["silent_cancel_replay"](rng)
    names = [e["name"] for e in injected]
    assert names.count("initiate_wire_transfer") == 2
    assert names.index("cancel_payment") < names.index("initiate_wire_transfer")


def test_perturb_preserves_event_shape():
    rng = dgp.random.Random(3)
    for tmpl in dgp.NORMAL_TEMPLATES:
        perturbed = dgp._perturb(tmpl, rng)
        for e in perturbed:
            assert set(e.keys()) == {"kind", "name"}
