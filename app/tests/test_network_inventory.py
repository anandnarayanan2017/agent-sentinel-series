"""Inventory-job collector tests (design §4.1; UAT-5, 6, 16, 17, 18, 21, 22).

Covers: argv assertions for both scan classes, diffing logic, per-scan-class
state separation, off-by-default config, and timeout semantics via an
injected `ScanTimeoutError`.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from sentinel.collector.host_map import ReloadableHostMap
from sentinel.collector.network_scan import (
    COVERAGE_PHRASE,
    InMemoryScanState,
    InventoryJob,
    JsonFileScanState,
    ScanOutcome,
    parse_nmap_xml,
)
from sentinel.collector.runner import CompletedRun, ScanTimeoutError, ToolNotAvailableError
from sentinel.collector.scan_config import ScanClass, ScanConfigError, ScanJobConfig

FIXTURES = Path(__file__).parent / "fixtures" / "network"
NMAP_FIX_A = (FIXTURES / "nmap_a.xml").read_bytes()
NMAP_FIX_B = (FIXTURES / "nmap_b.xml").read_bytes()
NMAP_FIX_FULL = (FIXTURES / "nmap_full.xml").read_bytes()
NMAP_FIX_A_DOWN = (FIXTURES / "nmap_a_down.xml").read_bytes()
NMAP_FIX_A_PORT_CLOSED = (FIXTURES / "nmap_a_port_closed.xml").read_bytes()

HOST = "192.0.2.11"


def _write_host_map(tmp_path: Path, hosts: list[dict]) -> Path:
    path = tmp_path / "network_hosts.yaml"
    path.write_text(yaml.safe_dump({"version": 1, "hosts": hosts}), encoding="utf-8")
    return path


@pytest.fixture()
def reloadable_map(tmp_path: Path) -> ReloadableHostMap:
    _write_host_map(tmp_path, [{"address": HOST, "agent_id": "bot-1"}])
    return ReloadableHostMap(tmp_path / "network_hosts.yaml")


class FakeRunner:
    """STUB_RUN -- a fake `SubprocessRunner` for inventory jobs. Records
    every argv it was called with; never execs a real binary."""

    def __init__(self) -> None:
        self.run_calls: list[list[str]] = []
        self._responses: dict[str, bytes] = {}
        self._tool_missing = False
        self._timeout_error: ScanTimeoutError | None = None

    def queue_payload(self, address: str, payload: bytes) -> None:
        self._responses[address] = payload

    def queue_tool_missing(self) -> None:
        self._tool_missing = True

    def queue_timeout(self, argv: list[str], timeout: float, elapsed: float) -> None:
        self._timeout_error = ScanTimeoutError(argv, timeout, elapsed)

    def run(self, argv: list[str], *, timeout: float) -> CompletedRun:
        self.run_calls.append(argv)
        if self._timeout_error is not None:
            raise self._timeout_error
        if self._tool_missing:
            raise ToolNotAvailableError("nmap not found")
        address = argv[-1]
        payload = self._responses.get(address, NMAP_FIX_A)
        return CompletedRun(argv=argv, returncode=0, stdout=payload, stderr=b"")

    def stream(self, argv):  # pragma: no cover - not used by inventory tests
        raise NotImplementedError


def _make_job(
    scan_class: ScanClass,
    reloadable_map: ReloadableHostMap,
    runner: FakeRunner,
    state=None,
    sink=None,
    **config_kwargs,
) -> InventoryJob:
    config = ScanJobConfig(scan_class=scan_class, enabled=True, **config_kwargs)
    return InventoryJob(
        scan_class=scan_class,
        config=config,
        host_map=reloadable_map,
        runner=runner,
        state=state or InMemoryScanState(),
        sink=sink or (lambda e: None),
    )


# ---- UAT-5 / UAT-16: hourly (TOP_1000) argv --------------------------------


def test_top_1000_argv_has_no_port_flag(reloadable_map: ReloadableHostMap) -> None:
    runner = FakeRunner()
    job = _make_job(ScanClass.TOP_1000, reloadable_map, runner)
    argv = job.build_argv(HOST)
    assert "-sT" in argv
    assert "-sV" in argv
    assert not any(a == "-p" or a.startswith("-p") for a in argv)
    assert "-sS" not in argv
    assert "-O" not in argv
    assert "-sn" not in argv
    assert argv[-1] == HOST
    assert "/" not in argv[-1]  # never a CIDR


def test_top_1000_default_cadence_is_hourly() -> None:
    config = ScanJobConfig(scan_class=ScanClass.TOP_1000, enabled=True)
    assert config.interval_seconds == 3600


# ---- UAT-5 / UAT-17: full-range argv and cadence ---------------------------


def test_full_range_argv_has_p_dash(reloadable_map: ReloadableHostMap) -> None:
    runner = FakeRunner()
    job = _make_job(ScanClass.FULL_RANGE, reloadable_map, runner, interval_seconds=86400)
    argv = job.build_argv(HOST)
    assert "-p-" in argv
    assert "-sT" in argv and "-sV" in argv
    assert "-sS" not in argv
    assert "-O" not in argv
    assert "-sn" not in argv


def test_full_range_rejects_sub_daily_cadence_at_load() -> None:
    with pytest.raises(ScanConfigError):
        ScanJobConfig(scan_class=ScanClass.FULL_RANGE, enabled=True, interval_seconds=3600)


def test_jobs_are_independently_enableable(reloadable_map: ReloadableHostMap) -> None:
    """UAT-17 step 2: disabling one job must not affect the other."""
    runner = FakeRunner()
    top_job = InventoryJob(
        scan_class=ScanClass.TOP_1000,
        config=ScanJobConfig(scan_class=ScanClass.TOP_1000, enabled=False),
        host_map=reloadable_map,
        runner=runner,
        state=InMemoryScanState(),
        sink=lambda e: None,
    )
    full_job = InventoryJob(
        scan_class=ScanClass.FULL_RANGE,
        config=ScanJobConfig(scan_class=ScanClass.FULL_RANGE, enabled=True, interval_seconds=86400),
        host_map=reloadable_map,
        runner=runner,
        state=InMemoryScanState(),
        sink=lambda e: None,
    )
    assert (
        top_job.is_due(__import__("datetime").datetime.now(__import__("datetime").timezone.utc))
        is False
    )
    assert (
        full_job.is_due(__import__("datetime").datetime.now(__import__("datetime").timezone.utc))
        is True
    )


# ---- UAT-6: diffing against last-known state -------------------------------


def test_inventory_diffs_against_last_known_state(reloadable_map: ReloadableHostMap) -> None:
    runner = FakeRunner()
    state = InMemoryScanState()
    events_out: list = []
    job = _make_job(ScanClass.TOP_1000, reloadable_map, runner, state=state, sink=events_out.append)

    # Step 1: NMAP_FIX_A -- host appears for the first time.
    runner.queue_payload(HOST, NMAP_FIX_A)
    outcome1, events1 = job.run_once()
    assert outcome1 == ScanOutcome.COMPLETED
    assert len(events1) == 1
    assert events1[0].attributes["net_change"] == "host_appeared"

    job._last_run = None  # force due again for the test's successive-run shape

    # Step 2: NMAP_FIX_B -- one additional open port (8080).
    runner.queue_payload(HOST, NMAP_FIX_B)
    outcome2, events2 = job.run_once()
    assert outcome2 == ScanOutcome.COMPLETED
    new_port_events = [e for e in events2 if e.attributes["net_change"] == "new_open_port"]
    assert len(new_port_events) == 1
    assert new_port_events[0].dst_port == 8080

    job._last_run = None

    # Step 3: re-feed NMAP_FIX_B -- zero events (no change).
    runner.queue_payload(HOST, NMAP_FIX_B)
    outcome3, events3 = job.run_once()
    assert outcome3 == ScanOutcome.COMPLETED
    assert events3 == []

    # All sink-delivered events accumulate in events_out.
    assert len(events_out) == 2  # host_appeared + the one new_open_port


def test_new_host_appearance_emits_event(reloadable_map: ReloadableHostMap) -> None:
    runner = FakeRunner()
    job = _make_job(ScanClass.TOP_1000, reloadable_map, runner)
    runner.queue_payload(HOST, NMAP_FIX_A)
    outcome, events = job.run_once()
    assert outcome == ScanOutcome.COMPLETED
    assert any(e.attributes["net_change"] == "host_appeared" for e in events)


# ---- UAT-18: every scan-derived event carries a distinct scan-class label --


def test_events_carry_distinct_scan_class_labels(reloadable_map: ReloadableHostMap) -> None:
    top_runner = FakeRunner()
    top_runner.queue_payload(HOST, NMAP_FIX_A)
    top_job = _make_job(ScanClass.TOP_1000, reloadable_map, top_runner)
    _, top_events = top_job.run_once()

    full_runner = FakeRunner()
    full_runner.queue_payload(HOST, NMAP_FIX_FULL)
    full_job = _make_job(ScanClass.FULL_RANGE, reloadable_map, full_runner, interval_seconds=86400)
    _, full_events = full_job.run_once()

    assert top_events and full_events
    assert all(e.attributes["scan_class"] == ScanClass.TOP_1000.value for e in top_events)
    assert all(e.attributes["scan_class"] == ScanClass.FULL_RANGE.value for e in full_events)
    assert all(e.attributes["coverage"] == COVERAGE_PHRASE[ScanClass.TOP_1000] for e in top_events)
    assert all(
        e.attributes["coverage"] == COVERAGE_PHRASE[ScanClass.FULL_RANGE] for e in full_events
    )
    assert ScanClass.TOP_1000.value != ScanClass.FULL_RANGE.value


# ---- UAT-21: diff state kept per scan class --------------------------------


def test_diff_state_is_kept_per_scan_class(reloadable_map: ReloadableHostMap) -> None:
    shared_state = InMemoryScanState()

    # Seed FULL_RANGE's own state with a baseline (ports 22/443 only), then a
    # second FULL_RANGE scan reveals port 33445 as a genuine new-open-port
    # diff *within FULL_RANGE's own bucket* (design's emission table: a
    # first-ever scan emits only host_appeared, not per-port events).
    full_runner_1 = FakeRunner()
    full_runner_1.queue_payload(HOST, NMAP_FIX_A)
    full_job_1 = _make_job(
        ScanClass.FULL_RANGE,
        reloadable_map,
        full_runner_1,
        state=shared_state,
        interval_seconds=86400,
    )
    full_job_1.run_once()

    full_runner_2 = FakeRunner()
    full_runner_2.queue_payload(HOST, NMAP_FIX_FULL)
    full_job_2 = _make_job(
        ScanClass.FULL_RANGE,
        reloadable_map,
        full_runner_2,
        state=shared_state,
        interval_seconds=86400,
    )
    _, full_events = full_job_2.run_once()
    assert any(e.dst_port == 33445 for e in full_events)

    top_runner = FakeRunner()
    top_runner.queue_payload(HOST, NMAP_FIX_A)
    top_job = _make_job(ScanClass.TOP_1000, reloadable_map, top_runner, state=shared_state)
    _, top_events = top_job.run_once()

    # The top-1000 run must not report port 33445 as newly closed (it never
    # observed it under its own scan class) nor as newly opened.
    assert not any(e.dst_port == 33445 for e in top_events)
    # It's the top-1000 job's first-ever run for this class -> host_appeared only.
    assert any(e.attributes["net_change"] == "host_appeared" for e in top_events)


def test_diff_state_per_scan_class_reverse_order(reloadable_map: ReloadableHostMap) -> None:
    shared_state = InMemoryScanState()

    top_runner = FakeRunner()
    top_runner.queue_payload(HOST, NMAP_FIX_A)
    top_job = _make_job(ScanClass.TOP_1000, reloadable_map, top_runner, state=shared_state)
    top_job.run_once()

    full_runner = FakeRunner()
    full_runner.queue_payload(HOST, NMAP_FIX_FULL)
    full_job = _make_job(
        ScanClass.FULL_RANGE,
        reloadable_map,
        full_runner,
        state=shared_state,
        interval_seconds=86400,
    )
    _, full_events = full_job.run_once()

    # Ports 22/443 were already seen by top-1000, but FULL_RANGE has its own
    # state bucket, so it's their first observation under FULL_RANGE -- this
    # must appear as host_appeared, not spurious new/closed noise for 22/443
    # specifically mislabeled by the other class.
    net_changes = {e.attributes["net_change"] for e in full_events}
    assert net_changes == {"host_appeared"}


# ---- UAT-22: off by default -------------------------------------------------


def test_disabled_by_default_config(reloadable_map: ReloadableHostMap) -> None:
    runner = FakeRunner()
    config = ScanJobConfig(scan_class=ScanClass.TOP_1000)  # enabled defaults False
    assert config.enabled is False
    job = InventoryJob(
        scan_class=ScanClass.TOP_1000,
        config=config,
        host_map=reloadable_map,
        runner=runner,
        state=InMemoryScanState(),
        sink=lambda e: None,
    )
    outcome, events = job.run_once()
    assert outcome == ScanOutcome.DISABLED
    assert events == []
    assert runner.run_calls == []  # zero real (or fake) nmap invocations


# ---- DD-13 / timeout semantics ----------------------------------------------


def test_timeout_never_parses_partial_output_and_preserves_state(
    reloadable_map: ReloadableHostMap,
) -> None:
    state = InMemoryScanState()
    runner = FakeRunner()
    job = _make_job(ScanClass.TOP_1000, reloadable_map, runner, state=state)

    # First: a clean scan establishes state.
    runner.queue_payload(HOST, NMAP_FIX_A)
    job.run_once()
    prior_state = state.last(HOST, ScanClass.TOP_1000)
    assert prior_state is not None

    # Second: force a timeout.
    job._last_run = None
    argv = job.build_argv(HOST)
    runner.queue_timeout(argv, timeout=600.0, elapsed=605.0)
    outcome, events = job.run_once()

    assert outcome == ScanOutcome.TIMED_OUT
    assert events == []
    assert not any(e.attributes.get("net_change") == "host_unreachable" for e in events)
    # State must be left exactly as it was -- not cleared, not overwritten.
    assert state.last(HOST, ScanClass.TOP_1000) == prior_state


def test_tool_missing_outcome(reloadable_map: ReloadableHostMap) -> None:
    runner = FakeRunner()
    runner.queue_tool_missing()
    job = _make_job(ScanClass.TOP_1000, reloadable_map, runner)
    outcome, events = job.run_once()
    assert outcome == ScanOutcome.TOOL_MISSING
    assert events == []


def test_unmapped_target_set_yields_unmapped_outcome(tmp_path: Path) -> None:
    empty_map_path = _write_host_map(tmp_path, [])
    reloadable = ReloadableHostMap(empty_map_path)
    runner = FakeRunner()
    job = _make_job(ScanClass.TOP_1000, reloadable, runner)
    outcome, events = job.run_once()
    assert outcome == ScanOutcome.UNMAPPED
    assert events == []


# ---- parse_nmap_xml direct tests (DD-9 security posture) -------------------


def test_parse_nmap_xml_extracts_open_ports_only() -> None:
    result = parse_nmap_xml(NMAP_FIX_A, HOST)
    assert result is not None
    assert result.up is True
    ports = {p.port for p in result.ports}
    assert ports == {22, 443}


def test_parse_nmap_xml_rejects_dtd_and_entities_without_raising() -> None:
    hostile_xml = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        b'<nmaprun><host><status state="up"/>'
        b'<address addr="192.0.2.11" addrtype="ipv4"/>'
        b'<ports><port protocol="tcp" portid="22">'
        b'<state state="open"/></port></ports></host></nmaprun>'
    )
    result = parse_nmap_xml(hostile_xml, HOST)
    # DD-9: DTD/entity declarations are refused outright -- never expanded,
    # never resolved, and the parser must never raise out of this function.
    assert result is None


def test_parse_nmap_xml_malformed_returns_none() -> None:
    assert parse_nmap_xml(b"not xml at all <<<", HOST) is None
    assert parse_nmap_xml(b"", HOST) is None


# ---- JsonFileScanState (DD-5 opt-in sidecar) --------------------------------


def test_json_file_scan_state_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "scan_state.json"
    state = JsonFileScanState(path)
    result = parse_nmap_xml(NMAP_FIX_A, HOST)
    assert result is not None
    state.put(HOST, ScanClass.TOP_1000, result)

    reloaded = JsonFileScanState(path)
    fetched = reloaded.last(HOST, ScanClass.TOP_1000)
    assert fetched == result


def test_json_file_scan_state_missing_file_starts_empty(tmp_path: Path) -> None:
    path = tmp_path / "does_not_exist.json"
    state = JsonFileScanState(path)
    assert state.last(HOST, ScanClass.TOP_1000) is None


# ---- Emission rules: port_closed / host_unreachable / failed --------------


def test_port_closed_event_emitted_when_a_port_disappears(
    reloadable_map: ReloadableHostMap,
) -> None:
    runner = FakeRunner()
    state = InMemoryScanState()
    job = _make_job(ScanClass.TOP_1000, reloadable_map, runner, state=state)

    runner.queue_payload(HOST, NMAP_FIX_A)  # ports 22, 443
    job.run_once()
    job._last_run = None

    runner.queue_payload(HOST, NMAP_FIX_A_PORT_CLOSED)  # only port 22 remains
    outcome, events = job.run_once()

    assert outcome == ScanOutcome.COMPLETED
    closed = [e for e in events if e.attributes["net_change"] == "port_closed"]
    assert len(closed) == 1
    assert closed[0].dst_port == 443


def test_host_unreachable_event_emitted_when_host_goes_down(
    reloadable_map: ReloadableHostMap,
) -> None:
    runner = FakeRunner()
    state = InMemoryScanState()
    job = _make_job(ScanClass.TOP_1000, reloadable_map, runner, state=state)

    runner.queue_payload(HOST, NMAP_FIX_A)
    job.run_once()
    job._last_run = None

    runner.queue_payload(HOST, NMAP_FIX_A_DOWN)
    outcome, events = job.run_once()

    assert outcome == ScanOutcome.COMPLETED
    assert len(events) == 1
    assert events[0].attributes["net_change"] == "host_unreachable"


def test_nonzero_returncode_yields_failed_outcome(reloadable_map: ReloadableHostMap) -> None:
    class NonZeroRunner(FakeRunner):
        def run(self, argv, *, timeout):
            return CompletedRun(argv=argv, returncode=1, stdout=b"", stderr=b"nmap: error")

    runner = NonZeroRunner()
    job = _make_job(ScanClass.TOP_1000, reloadable_map, runner)
    outcome, events = job.run_once()
    assert outcome == ScanOutcome.FAILED
    assert events == []


# ---- Code-review regression: batch-level failure must not silently drop a
# ---- successful host's events (MAJOR finding, FR-7 "diff, never dump" /
# ---- NFR-4 fail-safe). ------------------------------------------------------


HOST_OK = "192.0.2.11"
HOST_BAD = "192.0.2.12"


@pytest.fixture()
def two_host_map(tmp_path: Path) -> ReloadableHostMap:
    _write_host_map(
        tmp_path,
        [
            {"address": HOST_OK, "agent_id": "bot-1"},
            {"address": HOST_BAD, "agent_id": "bot-2"},
        ],
    )
    return ReloadableHostMap(tmp_path / "network_hosts.yaml")


class PerAddressFailureRunner(FakeRunner):
    """Like `FakeRunner`, but one specific address always fails with a
    non-zero exit code while every other address is served normally --
    lets a test exercise "one host fails, another succeeds, same batch"
    without touching `runner.py` (out of scope for this fix)."""

    def __init__(self, failing_address: str) -> None:
        super().__init__()
        self._failing_address = failing_address

    def run(self, argv: list[str], *, timeout: float) -> CompletedRun:
        self.run_calls.append(argv)
        address = argv[-1]
        if address == self._failing_address:
            return CompletedRun(argv=argv, returncode=1, stdout=b"", stderr=b"nmap: error")
        payload = self._responses.get(address, NMAP_FIX_A)
        return CompletedRun(argv=argv, returncode=0, stdout=payload, stderr=b"")


def test_successful_host_events_still_reach_sink_when_another_host_fails(
    two_host_map: ReloadableHostMap,
) -> None:
    """MAJOR regression: a multi-host batch where one host fails must not
    cause the successful host's already-diffed events to be silently
    dropped from the sink."""
    state = InMemoryScanState()
    sunk_events: list = []
    runner = PerAddressFailureRunner(failing_address=HOST_BAD)
    job = _make_job(ScanClass.TOP_1000, two_host_map, runner, state=state, sink=sunk_events.append)

    # HOST_OK gets a genuinely new port (8080) relative to its prior baseline,
    # established via a direct state seed so this run's event is unambiguously
    # a "new_open_port", not first-ever "host_appeared".
    baseline = parse_nmap_xml(NMAP_FIX_A, HOST_OK)
    assert baseline is not None
    state.put(HOST_OK, ScanClass.TOP_1000, baseline)
    runner.queue_payload(HOST_OK, NMAP_FIX_B)  # NMAP_FIX_B adds port 8080

    outcome, events = job.run_once()

    # (b) the batch outcome reflects the failure, not COMPLETED.
    assert outcome == ScanOutcome.FAILED

    # (a) the successful host's event reached the sink despite the other
    # host's failure in the very same run_once() call.
    new_port_events = [e for e in sunk_events if e.attributes["net_change"] == "new_open_port"]
    assert len(new_port_events) == 1
    assert new_port_events[0].dst_port == 8080
    assert new_port_events[0].dst_ip == HOST_OK
    # The returned event list mirrors what was sunk for the successful host.
    assert any(e.dst_port == 8080 and e.dst_ip == HOST_OK for e in events)

    # (c) state for HOST_OK genuinely advanced -- exactly once. A second call,
    # with both hosts now succeeding, must not re-emit the same new-port event.
    job._last_run = None
    runner_2 = FakeRunner()
    runner_2.queue_payload(HOST_OK, NMAP_FIX_B)
    runner_2.queue_payload(HOST_BAD, NMAP_FIX_A)
    job._runner = runner_2  # type: ignore[assignment]

    outcome2, events2 = job.run_once()
    assert outcome2 == ScanOutcome.COMPLETED
    assert not any(
        e.dst_ip == HOST_OK and e.attributes["net_change"] == "new_open_port" for e in events2
    )
    # Across BOTH calls, the HOST_OK new-port-8080 event was sunk exactly
    # once -- state genuinely advanced on the first (partially-failed) batch,
    # not zero times (which would repeat Finding 1's bug) and not twice
    # (which would mean the first call's diff state never actually stuck).
    all_new_port_for_host_ok = [
        e
        for e in sunk_events
        if e.dst_ip == HOST_OK and e.attributes["net_change"] == "new_open_port"
    ]
    assert len(all_new_port_for_host_ok) == 1


class PerAddressTimeoutRunner(FakeRunner):
    """Like `PerAddressFailureRunner`, but the failing address times out
    (`ScanTimeoutError`) instead of exiting non-zero."""

    def __init__(self, timeout_address: str) -> None:
        super().__init__()
        self._timeout_address = timeout_address

    def run(self, argv: list[str], *, timeout: float) -> CompletedRun:
        self.run_calls.append(argv)
        address = argv[-1]
        if address == self._timeout_address:
            raise ScanTimeoutError(argv, timeout, timeout + 5.0)
        payload = self._responses.get(address, NMAP_FIX_A)
        return CompletedRun(argv=argv, returncode=0, stdout=payload, stderr=b"")


def test_return_value_includes_earlier_successful_hosts_events_on_later_timeout(
    two_host_map: ReloadableHostMap,
) -> None:
    """Regression: `run_once`'s own docstring promises the return value
    "mirrors exactly what was sunk this cycle" even when a later host in
    the same batch times out. HOST_OK (sorted first) succeeds with a
    genuinely new port and is sunk; HOST_BAD (sorted second) times out and
    short-circuits the loop -- the returned event list must still include
    HOST_OK's event, not silently report an empty list despite it having
    been sunk."""
    state = InMemoryScanState()
    sunk_events: list = []
    runner = PerAddressTimeoutRunner(timeout_address=HOST_BAD)
    job = _make_job(ScanClass.TOP_1000, two_host_map, runner, state=state, sink=sunk_events.append)

    baseline = parse_nmap_xml(NMAP_FIX_A, HOST_OK)
    assert baseline is not None
    state.put(HOST_OK, ScanClass.TOP_1000, baseline)
    runner.queue_payload(HOST_OK, NMAP_FIX_B)

    outcome, events = job.run_once()

    assert outcome == ScanOutcome.TIMED_OUT
    # HOST_OK's event was genuinely sunk...
    assert any(e.dst_port == 8080 and e.dst_ip == HOST_OK for e in sunk_events)
    # ...and the return value must mirror that, per run_once's own docstring.
    assert any(e.dst_port == 8080 and e.dst_ip == HOST_OK for e in events)
