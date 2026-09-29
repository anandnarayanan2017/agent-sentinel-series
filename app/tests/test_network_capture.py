"""Live-capture collector tests (design §4.1; UAT-1, 2, 3, 4, 9).

Covers: tshark argv construction incl. the empty-address-set-raises safety
check, EK-line parsing, hostile/malformed input handling, subprocess
supervision via a fake `SubprocessRunner`, drop-not-placeholder for unmapped
addresses, and `host is None` when no hostname label exists.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest
import yaml

from sentinel.collector.host_map import HostMap, ReloadableHostMap
from sentinel.collector.network_scan import (
    CaptureHealth,
    LiveCaptureSupervisor,
    parse_ek_line,
)
from sentinel.collector.runner import ToolNotAvailableError
from sentinel.collector.scan_config import CaptureConfig
from sentinel.schema.events import ActionType, AgentEvent, Direction

FIXTURES = Path(__file__).parent / "fixtures" / "network"
EK_FIXTURE = (FIXTURES / "tshark_ek_sample.jsonl").read_text(encoding="utf-8")


def _write_host_map(tmp_path: Path, hosts: list[dict]) -> Path:
    path = tmp_path / "network_hosts.yaml"
    path.write_text(yaml.safe_dump({"version": 1, "hosts": hosts}), encoding="utf-8")
    return path


@pytest.fixture()
def map_a(tmp_path: Path) -> HostMap:
    """MAP_A: only addr_A (192.0.2.11) and 192.0.2.12 mapped; 192.0.2.99 is not."""
    path = _write_host_map(
        tmp_path,
        [
            {"address": "192.0.2.11", "agent_id": "bot-1", "mac": "aa:bb:cc:dd:ee:01"},
            {"address": "192.0.2.12", "agent_id": "bot-2", "mac": "aa:bb:cc:dd:ee:02"},
        ],
    )
    return HostMap.from_yaml(path)


@pytest.fixture()
def reloadable_map_a(tmp_path: Path) -> ReloadableHostMap:
    _write_host_map(
        tmp_path,
        [
            {"address": "192.0.2.11", "agent_id": "bot-1", "mac": "aa:bb:cc:dd:ee:01"},
            {"address": "192.0.2.12", "agent_id": "bot-2", "mac": "aa:bb:cc:dd:ee:02"},
        ],
    )
    return ReloadableHostMap(tmp_path / "network_hosts.yaml")


class FakeRunner:
    """STUB_RUN -- a fake `SubprocessRunner`. Never execs a real binary."""

    def __init__(self, lines: list[bytes] | None = None, tool_missing: bool = False) -> None:
        self._lines = lines or []
        self._tool_missing = tool_missing
        self.stream_calls: list[list[str]] = []
        self.run_calls: list[list[str]] = []

    def run(self, argv, *, timeout):  # pragma: no cover - not used by capture tests
        raise NotImplementedError

    def stream(self, argv: list[str]) -> Iterator[bytes]:
        self.stream_calls.append(argv)
        if self._tool_missing:
            raise ToolNotAvailableError("tshark not found")
        for line in self._lines:
            yield line


# ---- UAT-1 step 1: argv construction ---------------------------------------


def test_build_argv_contains_interface_and_ek(reloadable_map_a: ReloadableHostMap) -> None:
    config = CaptureConfig(interface="eth0")
    supervisor = LiveCaptureSupervisor(config, reloadable_map_a, FakeRunner(), sink=lambda e: None)
    argv = supervisor.build_argv()
    assert argv[0] == "tshark"
    assert "-i" in argv and argv[argv.index("-i") + 1] == "eth0"
    assert "-T" in argv and argv[argv.index("-T") + 1] == "ek"
    assert "-f" in argv
    bpf = argv[argv.index("-f") + 1]
    assert "192.0.2.11" in bpf
    assert "192.0.2.12" in bpf


def test_build_argv_raises_on_empty_address_set(tmp_path: Path) -> None:
    """R-4 safety check: an empty allow-list must raise, never silently
    capture everything on the interface (OOS-1)."""
    empty_map_path = _write_host_map(tmp_path, [])
    reloadable = ReloadableHostMap(empty_map_path)
    config = CaptureConfig(interface="eth0")
    supervisor = LiveCaptureSupervisor(config, reloadable, FakeRunner(), sink=lambda e: None)
    with pytest.raises(ValueError):
        supervisor.build_argv()


# ---- UAT-1 steps 2-4: EK line parsing --------------------------------------


def test_parse_ek_line_produces_network_call_events(map_a: HostMap) -> None:
    events: list[AgentEvent] = []
    for line in EK_FIXTURE.splitlines():
        ev = parse_ek_line(line, map_a)
        if ev is not None:
            events.append(ev)

    # 192.0.2.99 record is unmapped and must be dropped (UAT-9), so only the
    # three mapped records survive.
    assert len(events) == 3
    for ev in events:
        assert ev.action == ActionType.NETWORK_CALL

    # TLS/SNI record: dst_port, protocol, mac, and a hostname-shaped `host`.
    tls_ev = next(e for e in events if e.dst_port == 443)
    assert tls_ev.dst_ip == "203.0.113.10"
    assert tls_ev.src_ip == "192.0.2.11"
    assert tls_ev.protocol == "tls"
    assert tls_ev.mac == "aa:bb:cc:dd:ee:01"
    assert tls_ev.host == "example.com"
    assert tls_ev.agent_id == "bot-1"

    # Plain TCP record, no SNI, no hostname label configured -> host is None.
    tcp_ev = next(e for e in events if e.dst_port == 8080)
    assert tcp_ev.protocol == "tcp"
    assert tcp_ev.host is None

    # UDP record from bot-2.
    udp_ev = next(e for e in events if e.dst_port == 53)
    assert udp_ev.protocol == "udp"
    assert udp_ev.agent_id == "bot-2"


def test_host_is_none_when_no_hostname_label_exists(map_a: HostMap) -> None:
    """design §2.1.1 / C-4: host is None, never dst_ip, when no hostname is
    available from capture data or the operator's host map."""
    line = (
        '{"timestamp":"1","layers":{"ip_ip_src":["192.0.2.11"],'
        '"ip_ip_dst":["203.0.113.99"],"tcp_tcp_dstport":["9000"]}}'
    )
    ev = parse_ek_line(line, map_a)
    assert ev is not None
    assert ev.host is None
    assert ev.host != ev.dst_ip


def test_operator_hostname_label_is_not_misused_as_remote_destination(tmp_path: Path) -> None:
    path = _write_host_map(
        tmp_path,
        [{"address": "192.0.2.11", "agent_id": "bot-1", "hostname": "Recon-Bot.example.com"}],
    )
    hm = HostMap.from_yaml(path)
    line = (
        '{"timestamp":"1","layers":{"ip_ip_src":["192.0.2.11"],'
        '"ip_ip_dst":["203.0.113.99"],"tcp_tcp_dstport":["9000"]}}'
    )
    ev = parse_ek_line(line, hm)
    assert ev is not None
    assert ev.host is None
    assert ev.direction == Direction.EGRESS


def test_inbound_packet_is_attributed_as_ingress_and_has_no_egress_host(map_a: HostMap) -> None:
    line = (
        '{"timestamp":"1","layers":{"ip_ip_src":["203.0.113.99"],'
        '"ip_ip_dst":["192.0.2.11"],"tcp_tcp_dstport":["443"],'
        '"tls_tls_handshake_extensions_server_name":["bot-1.example.com"]}}'
    )
    ev = parse_ek_line(line, map_a)
    assert ev is not None
    assert ev.agent_id == "bot-1"
    assert ev.direction == Direction.INGRESS
    assert ev.host is None


# ---- UAT-3: hostile input never raises -------------------------------------


@pytest.mark.parametrize(
    "hostile_line",
    [
        "",
        '{"timestamp": "1", "lay',  # truncated JSON
        '{"foo": "bar"}',  # valid JSON, wrong shape
        b"\xff\xfe\x00invalid-utf8",  # non-UTF-8 byte sequence
    ],
)
def test_parse_ek_line_never_raises_on_hostile_input(map_a: HostMap, hostile_line) -> None:
    result = parse_ek_line(hostile_line, map_a)
    assert result is None


def test_parse_ek_line_index_line_returns_none_without_malformed_flag(map_a: HostMap) -> None:
    index_line = '{"index":{"_index":"packets-2026-08-20","_type":"doc"}}'
    assert parse_ek_line(index_line, map_a) is None


# ---- UAT-9: unmapped address is DROPPED, never placeholdered ---------------


def test_unmapped_address_dropped_never_placeholdered(map_a: HostMap) -> None:
    events = [parse_ek_line(line, map_a) for line in EK_FIXTURE.splitlines()]
    produced = [e for e in events if e is not None]
    agent_ids = {e.agent_id for e in produced}
    assert "unknown" not in agent_ids
    assert "" not in agent_ids
    assert None not in agent_ids
    assert "unmapped" not in agent_ids
    assert "192.0.2.99" not in agent_ids
    assert agent_ids <= {"bot-1", "bot-2"}


def test_supervisor_drop_and_malformed_counts_are_separate(
    reloadable_map_a: ReloadableHostMap,
) -> None:
    lines = EK_FIXTURE.encode("utf-8").splitlines() + [b'{"bad json'] * 2
    runner = FakeRunner(lines=lines)
    events: list[AgentEvent] = []
    supervisor = LiveCaptureSupervisor(
        CaptureConfig(interface="eth0", enabled=True), reloadable_map_a, runner, sink=events.append
    )
    health = supervisor.run_once()

    assert health == CaptureHealth.EXITED  # stream exhausted -> subprocess exited (FR-5)
    assert len(events) == 3
    assert supervisor.drop_count == 1  # exactly the one unmapped (192.0.2.99) record
    assert supervisor.malformed_count == 2  # the two injected bad-JSON lines


# ---- UAT-4: subprocess failure is visible, not silently healthy ------------


def test_tool_missing_surfaces_as_tool_missing_health(reloadable_map_a: ReloadableHostMap) -> None:
    runner = FakeRunner(tool_missing=True)
    supervisor = LiveCaptureSupervisor(
        CaptureConfig(interface="eth0", enabled=True), reloadable_map_a, runner, sink=lambda e: None
    )
    health = supervisor.run_once()
    assert health == CaptureHealth.TOOL_MISSING
    assert health != CaptureHealth.CAPTURING


def test_stream_exhaustion_is_exited_not_capturing(reloadable_map_a: ReloadableHostMap) -> None:
    """An unexpected subprocess exit must never silently read as healthy
    capture (FR-5, AC-5)."""
    runner = FakeRunner(lines=[])
    supervisor = LiveCaptureSupervisor(
        CaptureConfig(interface="eth0", enabled=True), reloadable_map_a, runner, sink=lambda e: None
    )
    assert supervisor.health == CaptureHealth.NOT_STARTED
    health = supervisor.run_once()
    assert health == CaptureHealth.EXITED
    assert supervisor.health == CaptureHealth.EXITED


def test_no_real_subprocess_is_ever_spawned(reloadable_map_a: ReloadableHostMap) -> None:
    """Zero real executions -- STUB_RUN records calls instead of exec'ing."""
    runner = FakeRunner(lines=EK_FIXTURE.encode("utf-8").splitlines())
    supervisor = LiveCaptureSupervisor(
        CaptureConfig(interface="eth0", enabled=True), reloadable_map_a, runner, sink=lambda e: None
    )
    supervisor.run_once()
    assert len(runner.stream_calls) == 1
    assert runner.stream_calls[0][0] == "tshark"


def test_disabled_capture_never_invokes_tshark(reloadable_map_a: ReloadableHostMap) -> None:
    runner = FakeRunner(lines=EK_FIXTURE.encode("utf-8").splitlines())
    supervisor = LiveCaptureSupervisor(
        CaptureConfig(interface="eth0", enabled=False),
        reloadable_map_a,
        runner,
        sink=lambda e: None,
    )
    assert supervisor.run_once() == CaptureHealth.NOT_STARTED
    assert runner.stream_calls == []
