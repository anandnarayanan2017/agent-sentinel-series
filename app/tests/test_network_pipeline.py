"""Pipeline integration tests for the network-visibility collector.

Covers design/DESIGN.md §2.8 (I-8, `Pipeline.ingest_event`) end-to-end through
storage + detection, and the single most important regression guard in this
feature: R-15 (§2.1.1 / DD-12) — adopting the network collector must never
turn an existing hostname-based `allowed_hosts` policy into a HIGH-severity
false-positive storm. UAT-19 (coverage-in-finding) and UAT-23 (ordering
preserved) are both exercised here, per design/DESIGN.md §4.1's file map.
"""

from __future__ import annotations

from pathlib import Path

from sentinel.pipeline import Pipeline
from sentinel.schema.events import ActionType, AgentEvent, Direction

POLICY = str(Path(__file__).resolve().parents[1].parent / "policies" / "example.yaml")


def _network_event(
    *,
    agent_id: str = "recon-bot",
    dst_ip: str,
    dst_port: int,
    host: str | None = None,
    scan_class: str = "top_1000",
    coverage: str = "in nmap's default top-1000 TCP port set",
    net_change: str = "new_open_port",
) -> AgentEvent:
    """Build a network-scan-derived `AgentEvent`, matching the shape
    `collector/network_scan.py`'s `InventoryJob._diff_and_emit` produces:
    `host=None` unless the host map supplies a hostname label (design §2.1.1),
    `attributes["collector"] == "network_scan"`, and a populated `coverage`
    phrase (FR-23/FR-24).
    """
    return AgentEvent(
        agent_id=agent_id,
        session_id="inventory",
        action=ActionType.NETWORK_CALL,
        direction=Direction.LOCAL,
        host=host,
        src_ip=None,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol="tcp",
        mac=None,
        attributes={
            "collector": "network_scan",
            "capture_mode": "inventory",
            "scan_class": scan_class,
            "coverage": coverage,
            "net_change": net_change,
        },
    )


# ---------------------------------------------------------------------------
# ingest_event: end-to-end through store + engine, coverage phrase present
# ---------------------------------------------------------------------------
def test_ingest_event_persists_and_evaluates_network_event():
    """`Pipeline.ingest_event` (design §2.8) stores the event and runs it
    through `Engine.evaluate`, exactly like `ingest_flow` did before the
    refactor (DD-4)."""
    pipe = Pipeline(POLICY, ":memory:")

    # First observation of this (dst_ip, dst_port) pair on this agent: the
    # baseline.new_listening_port guard (`bl.seen_ports` must be non-empty,
    # mirroring the existing baseline.new_host guard) means this first event
    # is learned, not flagged (design §2.9/§2.10) — so drive a second,
    # different port to get a finding to inspect.
    first = _network_event(dst_ip="192.0.2.11", dst_port=22)
    pipe.ingest_event(first)

    second = _network_event(dst_ip="192.0.2.11", dst_port=8080)
    findings = pipe.ingest_event(second)

    port_findings = [f for f in findings if f.rule_id == "baseline.new_listening_port"]
    assert len(port_findings) == 1
    finding = port_findings[0]

    # FR-23/UAT-19: every scan-derived finding states its coverage class.
    assert "top-1000" in finding.explanation

    # FR-28/AC-28: network findings carry non-empty control_refs even with
    # no agent-specific control_refs override (recon-bot's policy DOES have
    # control_refs, so this also exercises the "p.control_refs when a policy
    # exists" branch of design §2.10).
    assert finding.control_refs

    # Persisted through the real store (design §2.7/§2.8) — not merely
    # evaluated in memory.
    stored_events = pipe.store.events_for_agent("recon-bot")
    assert any(e["dst_port"] == 8080 for e in stored_events)
    stored_findings = pipe.store.list_findings()
    assert any(f["rule_id"] == "baseline.new_listening_port" for f in stored_findings)


def test_ingest_event_full_range_coverage_phrase():
    """A full-range-scan-derived finding names the full-range coverage class,
    never the top-1000 wording (FR-24)."""
    pipe = Pipeline(POLICY, ":memory:")

    pipe.ingest_event(
        _network_event(
            dst_ip="192.0.2.12",
            dst_port=22,
            scan_class="full_range",
            coverage="in the full TCP port range (-p-)",
        )
    )
    findings = pipe.ingest_event(
        _network_event(
            dst_ip="192.0.2.12",
            dst_port=9999,
            scan_class="full_range",
            coverage="in the full TCP port range (-p-)",
        )
    )

    port_findings = [f for f in findings if f.rule_id == "baseline.new_listening_port"]
    assert len(port_findings) == 1
    assert "full range" in port_findings[0].explanation or "-p-" in port_findings[0].explanation
    assert "top-1000" not in port_findings[0].explanation


def test_new_listening_port_detected_when_port_is_zero():
    """Regression: `dst_port=0` is a real (if unusual) port value, not
    "absent" -- `AgentBaseline.update`/`is_new_port` must not treat it as
    falsy, or traffic to port 0 is silently never tracked as new."""
    pipe = Pipeline(POLICY, ":memory:")

    first = _network_event(dst_ip="192.0.2.13", dst_port=1)
    pipe.ingest_event(first)

    second = _network_event(dst_ip="192.0.2.13", dst_port=0)
    findings = pipe.ingest_event(second)

    port_findings = [f for f in findings if f.rule_id == "baseline.new_listening_port"]
    assert len(port_findings) == 1
    assert port_findings[0].title.endswith("port 0 on 192.0.2.13")

    # A second observation of the same (dst_ip=0) pair is no longer "new".
    third = _network_event(dst_ip="192.0.2.13", dst_port=0)
    findings_again = pipe.ingest_event(third)
    assert not [f for f in findings_again if f.rule_id == "baseline.new_listening_port"]


def test_live_packets_and_closed_ports_never_create_listening_port_findings():
    pipe = Pipeline(POLICY, ":memory:")
    pipe.ingest_event(_network_event(dst_ip="192.0.2.40", dst_port=22))

    live = _network_event(dst_ip="192.0.2.40", dst_port=8080)
    live.attributes["capture_mode"] = "live"
    closed = _network_event(dst_ip="192.0.2.40", dst_port=8443, net_change="port_closed")

    findings = pipe.ingest_event(live) + pipe.ingest_event(closed)
    assert not [f for f in findings if f.rule_id == "baseline.new_listening_port"]


def test_monitored_host_label_never_triggers_egress_allow_list_rule():
    pipe = Pipeline(POLICY, ":memory:")
    event = _network_event(
        dst_ip="192.0.2.11",
        dst_port=443,
        host="recon-bot.internal",
    )
    event.direction = Direction.INGRESS
    findings = pipe.ingest_event(event)
    assert not [f for f in findings if f.rule_id == "net.host_not_allowed"]


# ---------------------------------------------------------------------------
# L1-before-L2 ordering preserved (UAT-23) — a non-event here, but confirmed
# ---------------------------------------------------------------------------
def test_existing_l1_policy_checks_still_run_before_l2_for_network_events():
    """FR-27/UAT-23: network events traverse the SAME
    `_policy_checks` (L1) -> `_baseline_checks` (L2) flow every other event
    does. There is no L1 network-specific check (design §2.10, C-2) — this
    test confirms the four existing L1 checks still get a chance to run
    first and correctly find nothing to flag for a network-scan event
    (none of their guard fields apply to inventory-shaped events), i.e. this
    traversal is a non-event, exactly as design/DESIGN.md §2.10 predicts.
    """
    pipe = Pipeline(POLICY, ":memory:")

    # host=None (per §2.1.1, real inventory events carry no host) so the
    # net.host_not_allowed L1 check's `if e.host and ...` guard short-circuits
    # -- it runs, finds nothing, and is not bypassed.
    event = _network_event(dst_ip="203.0.113.5", dst_port=443, host=None)
    findings = pipe.ingest_event(event)

    # No L1 finding of any kind (tool/model/bytes/rate checks are all
    # inapplicable to a NETWORK_CALL inventory event; host check is
    # inapplicable because host is None) -- only the L2 baseline path can
    # ever fire for this event shape, and on a first observation even that
    # is suppressed (bl.seen_ports guard).
    assert findings == []


# ---------------------------------------------------------------------------
# R-15 — the load-bearing no-regression assertion (design §2.1.1, §7.1(6),
# §7.2, §10 DoD item 8). THE most important test in this wave.
# ---------------------------------------------------------------------------
def test_r15_hostname_only_allowed_hosts_produces_zero_host_not_allowed_findings():
    """R-15 / C-4 / DD-12: an agent whose `AgentPolicy.allowed_hosts` contains
    ONLY hostnames (never IPs) must see ZERO `net.host_not_allowed` findings
    when network-capture-derived events are ingested -- because real capture
    events carry `host=None` (per §2.1.1, since Sentinel never populates
    `host` from a bare `dst_ip`), and `Engine._policy_checks`'s
    `net.host_not_allowed` check is gated on `if e.host and p.allowed_hosts`
    (engine.py:107) -- a `None` host short-circuits it unconditionally.

    This is the exact regression the design's C-4 fix exists to prevent: the
    rejected round-0 design would have set `host = dst_ip` when no hostname
    was known, which would have made every one of these events a HIGH-severity
    `net.host_not_allowed` finding for `recon-bot` (whose policy.yaml
    `allowed_hosts` -- api.anthropic.com, ledger.internal, reports.internal --
    is hostnames only, never IP literals). This test proves that did NOT
    happen, rather than merely asserting the code looks right.
    """
    pipe = Pipeline(POLICY, ":memory:")  # recon-bot's policy: hostname-only allowed_hosts

    # Drive several network-capture-style events (host=None, as real capture
    # events have per §2.1.1) through `ingest_event`, across several distinct
    # destinations/ports so the L2 new_listening_port check has room to fire
    # too -- the R-15 guard must hold regardless of what else fires.
    capture_events = [
        _network_event(
            dst_ip="192.0.2.20",
            dst_port=443,
            host=None,
            scan_class="top_1000",
            net_change="new_open_port",
        ),
        _network_event(
            dst_ip="192.0.2.21",
            dst_port=22,
            host=None,
            scan_class="top_1000",
            net_change="new_open_port",
        ),
        _network_event(
            dst_ip="192.0.2.22",
            dst_port=3389,
            host=None,
            scan_class="full_range",
            coverage="in the full TCP port range (-p-)",
            net_change="new_open_port",
        ),
        # Re-observe the first address/port pair -- must not newly flag either.
        _network_event(
            dst_ip="192.0.2.20",
            dst_port=443,
            host=None,
            scan_class="top_1000",
            net_change="new_open_port",
        ),
    ]

    all_findings = []
    for event in capture_events:
        all_findings.extend(pipe.ingest_event(event))

    # THE assertion: zero net.host_not_allowed findings, for any event, ever.
    host_not_allowed = [f for f in all_findings if f.rule_id == "net.host_not_allowed"]
    assert host_not_allowed == []

    # Corroborating check: no finding of any kind carries HIGH severity as a
    # side effect of this collector (the L2 network check is LOW/advisory by
    # design, DD-11) -- a HIGH finding here would itself indicate the L1 host
    # check fired, which is precisely what must not happen.
    assert all(f.severity.value != "high" for f in all_findings)

    # And confirm the events were genuinely persisted with host=None (not
    # silently coerced to dst_ip anywhere in the ingest path).
    stored = pipe.store.events_for_agent("recon-bot")
    network_rows = [
        e for e in stored if e.get("dst_ip") in {"192.0.2.20", "192.0.2.21", "192.0.2.22"}
    ]
    assert len(network_rows) == 4
    assert all(row["host"] is None for row in network_rows)
