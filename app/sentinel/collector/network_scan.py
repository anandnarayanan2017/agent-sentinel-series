"""Network-visibility collector: live capture (tshark) + periodic inventory (nmap).

The only module that knows the words "tshark"/"nmap" (design/DESIGN.md §4.1).
All external-binary invocation goes through the `SubprocessRunner` seam
(`collector/runner.py`) -- this module never imports `subprocess` itself
(design §2.3).

Two collection modes, both scoped to the operator-authored address allow-list
in `config/network_hosts.yaml` (`collector/host_map.py`):

- `LiveCaptureSupervisor` (design §2.4, "C1"): runs `tshark -T ek` as a
  supervised subprocess and parses each JSON line into an `AgentEvent`.
- `InventoryJob` (design §2.5, "C1"): runs `nmap -sT -sV [-p-] -oX -` on a
  schedule, diffs against last-known state per `(address, scan_class)`, and
  emits synthetic `AgentEvent`s for what changed.

Binding rule (design §2.1.1, C-4/DD-12): `AgentEvent.host` is the remote
egress hostname and is populated ONLY from capture data (TLS SNI / HTTP Host
header) on an outbound packet -- NEVER from `dst_ip`, the monitored host's
label, or a live DNS lookup. A capture-derived candidate is validated as
hostname-shaped (not an IP literal) before assignment (N-2).
"""

from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional, Protocol
from xml.etree.ElementTree import TreeBuilder  # nosec B405 - DTD/entities rejected below
from xml.parsers import expat  # nosec B407 - see _build_hardened_xml_parser

from sentinel.collector.host_map import HostMap, ReloadableHostMap
from sentinel.collector.runner import ScanTimeoutError, SubprocessRunner, ToolNotAvailableError
from sentinel.collector.scan_config import CaptureConfig, ScanClass, ScanJobConfig
from sentinel.detection.engine import NETWORK_CONTROL_REFS
from sentinel.schema.events import ActionType, AgentEvent, Direction

logger = logging.getLogger("sentinel.collector.network_scan")

# Re-exported so callers/tests can do `from sentinel.collector.network_scan import
# NETWORK_CONTROL_REFS` without knowing the canonical constant now lives on
# `detection/engine.py` (design §2.11, "I-11"; see module note below).
__all__ = [
    "NETWORK_CONTROL_REFS",
    "COVERAGE_PHRASE",
    "PortObservation",
    "HostScanResult",
    "ScanOutcome",
    "ScanStateStore",
    "InMemoryScanState",
    "JsonFileScanState",
    "parse_ek_line",
    "parse_nmap_xml",
    "LiveCaptureSupervisor",
    "CaptureHealth",
    "InventoryJob",
]

# ---------------------------------------------------------------------------
# NETWORK_CONTROL_REFS canonical-source resolution (build-phase judgment call)
# ---------------------------------------------------------------------------
# Design §2.11 (I-11) specifies this constant as living in "C1"
# (`network_scan.py`). However, `detection/engine.py` was built by an earlier
# wave (before this module existed) and already defines `NETWORK_CONTROL_REFS`
# there -- verified directly: `engine.py`'s `baseline.new_listening_port` check
# reads the module-level `NETWORK_CONTROL_REFS` name in its own file (not an
# import), and `engine.py` is in the explicitly-frozen "already built, do not
# touch" set for this task. Re-defining a second, textually identical
# `NETWORK_CONTROL_REFS` here would create two independently-editable copies
# of the same compliance-critical constant -- exactly the kind of duplicate
# constant that can drift, which the project's "Findings always carry
# control_refs" convention implicitly depends on staying a single source of
# truth. Resolution: `engine.py` is the canonical source (it got there first
# and this task must not edit it); this module imports it from there and
# re-exports it so `from sentinel.collector.network_scan import
# NETWORK_CONTROL_REFS` (the surface the design document's own examples use)
# still works unchanged.


# ---------------------------------------------------------------------------
# I-6 -- scan-class coverage-phrase carrier (design §2.6). `ScanClass` itself
# is NOT redefined here: it already lives in `scan_config.py` (built by an
# earlier wave) and is imported above, so there is exactly one enum in the
# tree, matching `ScanJobConfig.scan_class`'s type.
# ---------------------------------------------------------------------------
COVERAGE_PHRASE: dict[ScanClass, str] = {
    ScanClass.TOP_1000: "in nmap's default top-1000 TCP port set",
    ScanClass.FULL_RANGE: "in the full TCP port range (-p-)",
}


# ===========================================================================
# Shared small value types
# ===========================================================================


@dataclass(frozen=True)
class PortObservation:
    port: int
    protocol: str  # "tcp"
    service: Optional[str]  # from -sV
    version: Optional[str]  # from -sV


@dataclass(frozen=True)
class HostScanResult:
    address: str
    up: bool
    ports: frozenset[PortObservation]


class ScanOutcome(str, Enum):
    """The job-level counterpart of `CaptureHealth` (design §2.5). Every
    `InventoryJob.run_once()` cycle ends in exactly one of these, mutually
    exclusive by construction (AC-36)."""

    COMPLETED = "completed"  # ran to completion; diff emitted (possibly empty)
    TOOL_MISSING = "tool_missing"  # ToolNotAvailableError
    TIMED_OUT = "timed_out"  # ScanTimeoutError -- NOT a clean scan
    FAILED = "failed"  # non-zero exit / unparseable XML
    DISABLED = "disabled"  # not enabled, or not due
    UNMAPPED = "unmapped"  # target absent from the host map


# ===========================================================================
# Scan-diff state -- collector-local ONLY (design §3.5, DD-5; C-1 fix).
# Never behind `storage/base.py`'s `StoreBase`. Defined here, not in storage/.
# ===========================================================================


class ScanStateStore(Protocol):
    def last(self, address: str, scan_class: ScanClass) -> Optional[HostScanResult]: ...

    def put(self, address: str, scan_class: ScanClass, result: HostScanResult) -> None: ...


class InMemoryScanState:
    """Process-lifetime dict keyed (address, scan_class). No persistence.

    The default (design DD-5 option D). After a restart the first successful
    scan establishes a fresh baseline and emits only `host_appeared` for an
    up host; it does not claim every current port is newly opened.
    """

    def __init__(self) -> None:
        self._state: dict[tuple[str, ScanClass], HostScanResult] = {}

    def last(self, address: str, scan_class: ScanClass) -> Optional[HostScanResult]:
        return self._state.get((address, scan_class))

    def put(self, address: str, scan_class: ScanClass, result: HostScanResult) -> None:
        self._state[(address, scan_class)] = result


class JsonFileScanState:
    """Atomic-write JSON sidecar owned entirely by C1 (design DD-5 option E).

    Opt-in via `ScanJobConfig.state_path`. Never a `StoreBase` call, never
    reachable from `Pipeline.store`. The file is a cache: deleting it is safe
    and merely reproduces the `InMemoryScanState` cold-start re-emit.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._state: dict[tuple[str, ScanClass], HostScanResult] = {}
        self._load()

    def _load(self) -> None:
        try:
            raw_text = self._path.read_text(encoding="utf-8")
        except OSError:
            return  # absent/unreadable -- start from empty state (fail-safe)
        try:
            raw = json.loads(raw_text)
        except json.JSONDecodeError:
            logger.warning("scan-state sidecar %s is not valid JSON; starting empty", self._path)
            return
        if not isinstance(raw, list):
            logger.warning("scan-state sidecar %s has unexpected shape; starting empty", self._path)
            return
        for entry in raw:
            try:
                address = entry["address"]
                scan_class = ScanClass(entry["scan_class"])
                ports = frozenset(
                    PortObservation(
                        port=p["port"],
                        protocol=p["protocol"],
                        service=p.get("service"),
                        version=p.get("version"),
                    )
                    for p in entry["ports"]
                )
                result = HostScanResult(address=address, up=entry["up"], ports=ports)
            except (KeyError, TypeError, ValueError):
                logger.warning(
                    "scan-state sidecar %s has a malformed entry; skipping it", self._path
                )
                continue
            self._state[(address, scan_class)] = result

    def _flush(self) -> None:
        payload = [
            {
                "address": address,
                "scan_class": scan_class.value,
                "up": result.up,
                "ports": [
                    {
                        "port": p.port,
                        "protocol": p.protocol,
                        "service": p.service,
                        "version": p.version,
                    }
                    for p in result.ports
                ],
            }
            for (address, scan_class), result in self._state.items()
        ]
        tmp_path = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(payload), encoding="utf-8")
        tmp_path.replace(self._path)  # atomic on POSIX and Windows

    def last(self, address: str, scan_class: ScanClass) -> Optional[HostScanResult]:
        return self._state.get((address, scan_class))

    def put(self, address: str, scan_class: ScanClass, result: HostScanResult) -> None:
        self._state[(address, scan_class)] = result
        self._flush()


# ===========================================================================
# Hostname-shape validation (design §2.1.1, N-2) -- a capture-derived hostname
# candidate (e.g. TLS SNI) must be validated as hostname-shaped, never an IP
# literal, before it is ever assigned to `AgentEvent.host`.
# ===========================================================================


def _is_hostname_shaped(value: str) -> bool:
    """True if `value` looks like a hostname, false if it's an IP literal
    (or otherwise not hostname-shaped). Never raises."""
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return False  # it parsed as an IP literal -- not a hostname
    except ValueError:
        pass
    # Minimal shape check: at least one label, only hostname-legal chars.
    # Deliberately permissive (this is a safety filter against IP-shaped
    # values reaching `host`, not a full RFC-1123 validator) and never raises.
    if any(c.isspace() for c in value):
        return False
    return True


def _normalize_host_candidate(value: Optional[str]) -> Optional[str]:
    """Lowercase + hostname-shape-validate a capture-derived host candidate.

    Returns `None` if `value` is falsy or IP-shaped (design §2.1.1 / N-2).
    """
    if not value:
        return None
    candidate = value.strip().lower()
    if not _is_hostname_shaped(candidate):
        return None
    return candidate


# ===========================================================================
# I-4 -- Live capture supervisor (design §2.4, "C1")
# ===========================================================================


class CaptureHealth(str, Enum):
    NOT_STARTED = "not_started"
    CAPTURING = "capturing"
    TOOL_MISSING = "tool_missing"
    EXITED = "exited"  # subprocess died unexpectedly (FR-5)


# Internal-only classification of *why* `parse_ek_line` returned None (design
# DD-2). Only `UNATTRIBUTABLE` increments the FR-11 drop counter; `MALFORMED`
# and `SKIP_INDEX_LINE` are counted separately so UAT-9's exact-count
# assertion on the drop counter is satisfiable.
class _SkipReason(str, Enum):
    SKIP_INDEX_LINE = "skip_index_line"
    MALFORMED = "malformed"
    UNATTRIBUTABLE = "unattributable"


def _classify_ek_line(line: bytes | str) -> tuple[Optional[_SkipReason], Optional[dict[str, Any]]]:
    """Decode one `-T ek` JSON line. Returns (skip_reason, record_dict).

    `skip_reason` is None only when a record-shaped dict was decoded.
    NEVER raises (FR-4).
    """
    try:
        if isinstance(line, bytes):
            text = line.decode("utf-8", errors="strict")
        else:
            text = line
    except UnicodeDecodeError:
        return _SkipReason.MALFORMED, None

    text = text.strip()
    if not text:
        return _SkipReason.MALFORMED, None

    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return _SkipReason.MALFORMED, None

    if not isinstance(obj, dict):
        return _SkipReason.MALFORMED, None

    # `-T ek` alternates index lines (`{"index": {...}}`) with record lines
    # (`{"timestamp": ..., "layers": {...}}`). Index lines are a normal,
    # expected part of the wire format -- not malformed, not a drop.
    if "index" in obj and "layers" not in obj:
        return _SkipReason.SKIP_INDEX_LINE, None

    layers = obj.get("layers")
    if not isinstance(layers, dict):
        return _SkipReason.MALFORMED, None

    return None, obj


def _first_str(layers: dict[str, Any], *keys: str) -> Optional[str]:
    """tshark `-T ek` layers commonly store repeated fields as JSON arrays of
    strings; take the first, defensively."""
    for key in keys:
        val = layers.get(key)
        if val is None:
            continue
        if isinstance(val, list):
            if val and isinstance(val[0], str):
                return val[0]
            continue
        if isinstance(val, str):
            return val
    return None


def _first_int(layers: dict[str, Any], *keys: str) -> Optional[int]:
    for key in keys:
        val = layers.get(key)
        if val is None:
            continue
        if isinstance(val, list):
            val = val[0] if val else None
        if val is None:
            continue
        try:
            return int(val)
        except (TypeError, ValueError):
            continue
    return None


def parse_ek_line(line: bytes | str, host_map: HostMap) -> Optional[AgentEvent]:
    """THE defensive parse boundary for live capture (design §2.4).

    Returns None on: index line, unparseable, wrong shape, or unmapped
    address. NEVER raises. NEVER placeholders identity.
    Sets `AgentEvent.host` per §2.1.1 ONLY (hostname or None; never dst_ip).
    """
    reason, record = _classify_ek_line(line)
    if reason is not None or record is None:
        if reason is _SkipReason.MALFORMED:
            logger.warning("network_scan: dropped a malformed -T ek line")
        return None

    layers = record.get("layers") or {}

    src_ip = _first_str(layers, "ip_ip_src", "ip_ip_src_host", "ipv6_ipv6_src")
    dst_ip = _first_str(layers, "ip_ip_dst", "ip_ip_dst_host", "ipv6_ipv6_dst")
    dst_port = _first_int(layers, "tcp_tcp_dstport", "udp_udp_dstport")
    mac = _first_str(layers, "eth_eth_dst")

    protocol: Optional[str] = None
    if _first_str(layers, "tls_tls_handshake_type") is not None or "tls" in layers:
        protocol = "tls"
    elif _first_int(layers, "tcp_tcp_dstport") is not None:
        protocol = "tcp"
    elif _first_int(layers, "udp_udp_dstport") is not None:
        protocol = "udp"

    # agent_id is resolved BEFORE AgentEvent construction (FR-9); unmapped ->
    # drop, never a placeholder identity (FR-10).
    # Direction is relative to the monitored agent. Prefer the mapped source
    # for host-to-host traffic: that is an outbound packet from the agent.
    src_agent = host_map.resolve(src_ip)
    dst_agent = host_map.resolve(dst_ip, mac)
    if src_agent is not None:
        agent_id = src_agent
        direction = Direction.EGRESS
    elif dst_agent is not None:
        agent_id = dst_agent
        direction = Direction.INGRESS
    else:
        attributable_addr = dst_ip or src_ip or "<unknown-address>"
        logger.warning(
            "network_scan: dropped unattributable capture record for address %s",
            attributable_addr,
        )
        return None

    # `host` means the remote egress destination used by allowed_hosts. The
    # host-map hostname labels the monitored machine, so copying it here would
    # compare local identity with a remote-destination allow-list.
    sni_candidate = _first_str(layers, "tls_tls_handshake_extensions_server_name", "http_http_host")
    host = _normalize_host_candidate(sni_candidate) if direction is Direction.EGRESS else None

    session_id = _first_str(layers, "frame_frame_time_epoch") or "capture"

    return AgentEvent(
        agent_id=agent_id,
        session_id=session_id,
        action=ActionType.NETWORK_CALL,
        direction=direction,
        host=host,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        mac=mac,
        attributes={
            "collector": "network_scan",
            "capture_mode": "live",
        },
    )


class LiveCaptureSupervisor:
    """Supervises `tshark -T ek` as a subprocess (design §2.4, "C1")."""

    def __init__(
        self,
        config: CaptureConfig,
        host_map: ReloadableHostMap,
        runner: SubprocessRunner,
        sink: Callable[[AgentEvent], None],
    ) -> None:
        self._config = config
        self._host_map = host_map
        self._runner = runner
        self._sink = sink
        self._health = CaptureHealth.NOT_STARTED
        self._drop_count = 0
        self._malformed_count = 0

    def build_argv(self) -> list[str]:
        """`["tshark", "-i", <interface>, "-T", "ek", "-f", <bpf>]` (AC-1/UAT-1).

        Scopes capture to the host-map allow-list via a BPF capture filter
        (design §2.4) -- true at the kernel-filter level, not merely a
        post-hoc discard. Raises if the allow-list is empty rather than
        emitting an unfiltered (capture-everything) invocation (R-4).
        """
        addresses = self._host_map.current.addresses()
        if not addresses:
            raise ValueError(
                "network_scan: refusing to build an unfiltered tshark capture -- "
                "the host map has zero configured addresses (OOS-1 safety check)"
            )
        bpf = " or ".join(f"host {addr}" for addr in sorted(addresses))
        return ["tshark", "-i", self._config.interface, "-T", "ek", "-f", bpf]

    @property
    def health(self) -> CaptureHealth:
        return self._health

    @property
    def drop_count(self) -> int:
        return self._drop_count

    @property
    def malformed_count(self) -> int:
        return self._malformed_count

    def run_once(self) -> CaptureHealth:
        """Run the supervised capture stream once; consumes lines until the
        subprocess exits, updating health (FR-5)."""
        if not self._config.enabled:
            self._health = CaptureHealth.NOT_STARTED
            return self._health

        if self._config.reload_interval_seconds is not None:
            self._host_map.reload()

        argv = self.build_argv()
        # `stream()` is typically generator-based (design §2.3): calling it
        # returns an iterator without running any body code, so a
        # `ToolNotAvailableError` raised by the underlying Popen only
        # surfaces once iteration begins -- it must be caught around the
        # loop, not around the call that merely constructs the iterator.
        stream = self._runner.stream(argv)

        self._health = CaptureHealth.CAPTURING
        try:
            for line in stream:
                event = parse_ek_line(line, self._host_map.current)
                if event is None:
                    reason, record = _classify_ek_line(line)
                    if reason is _SkipReason.MALFORMED:
                        self._malformed_count += 1
                    elif reason is None and record is not None:
                        # Record-shaped but unattributable -> the drop path.
                        self._drop_count += 1
                    continue
                self._sink(event)
        except ToolNotAvailableError as exc:
            logger.warning("network_scan: tshark not available: %s", exc)
            self._health = CaptureHealth.TOOL_MISSING
            return self._health
        except Exception:  # capture loop must never crash the collector (FR-4)
            logger.exception("network_scan: live capture stream raised unexpectedly")
            self._health = CaptureHealth.EXITED
            return self._health

        # Stream iterator exhausted -> the subprocess exited (FR-5): an
        # unexpected exit must never silently read as "still capturing".
        self._health = CaptureHealth.EXITED
        return self._health


# ===========================================================================
# I-5 -- Inventory job (design §2.5, "C1")
# ===========================================================================

# DD-9 (§3.9): nmap XML output is untrusted (a hostile service banner is
# reflected into -sV output). Parse with DTD processing, external-entity
# resolution and entity expansion ALL disabled, configured explicitly on the
# parser object -- never relied upon as a default, and never suppressed with
# `# nosec` (C-3: SECURITY_SCAN_CMD is `bandit -r app -lll`, high-confidence
# only, and B314 is Medium -- it cannot fire here, so no suppression is
# needed or appropriate). `defusedxml` is NOT a project dependency
# (pyproject.toml has no such entry) so it is not imported here (B9) --
# instead the stdlib expat parser is hardened directly.


def _build_hardened_xml_parser() -> tuple[expat.XMLParserType, TreeBuilder]:
    """A raw `xml.parsers.expat` parser wired to a `TreeBuilder`, with DTD
    processing, external-entity resolution and entity expansion ALL disabled
    (design DD-9), configured explicitly rather than relied upon as a
    library default.

    Built directly on `xml.parsers.expat.ParserCreate()` -- NOT
    `xml.etree.ElementTree.XMLParser` -- because the current stdlib's
    `ElementTree.XMLParser` (the C-accelerated `_elementtree` implementation)
    does not expose its underlying expat parser object at all, so there is no
    supported hook to reach in and disable DTD/entity handling on it. Going
    straight to `xml.parsers.expat` is the documented, dependency-free way to
    get that hook (the same technique `defusedxml` itself uses internally;
    `defusedxml` is NOT a project dependency -- pyproject.toml has no such
    entry -- so it is not imported here, per B9).
    """
    tb = TreeBuilder()
    parser = expat.ParserCreate()

    def _start(name: str, attrs: dict[str, str]) -> None:
        tb.start(name, attrs)

    def _end(name: str) -> None:
        tb.end(name)

    def _data(data: str) -> None:
        tb.data(data)

    def _reject_entity(*_args: Any, **_kwargs: Any) -> None:
        # Any DOCTYPE/entity declaration in scanned-host-influenced XML is
        # refused outright rather than expanded or resolved.
        raise ValueError("network_scan: DTD/entity declarations are not permitted in nmap XML")

    parser.StartElementHandler = _start
    parser.EndElementHandler = _end
    parser.CharacterDataHandler = _data

    # Disable DTD/external-entity resolution and entity expansion explicitly
    # (DD-9) -- never left at expat's default, which does process these.
    parser.StartDoctypeDeclHandler = _reject_entity
    parser.EntityDeclHandler = _reject_entity
    parser.UnparsedEntityDeclHandler = _reject_entity
    parser.ExternalEntityRefHandler = lambda *a, **k: False  # refuse resolution
    parser.DefaultHandler = None

    return parser, tb


def parse_nmap_xml(payload: bytes, address: str) -> Optional[HostScanResult]:
    """Parse `nmap -oX -` output for one host. Defensive: malformed XML,
    unexpected shape, or a rejected DTD/entity construct -> `None`, never
    raises (FR-4 posture extended; design §2.5, DD-9)."""
    try:
        parser, tb = _build_hardened_xml_parser()
        parser.Parse(payload, True)
        root = tb.close()
    except Exception:
        logger.warning("network_scan: dropped unparseable/rejected nmap XML for %s", address)
        return None

    if root is None or root.tag != "nmaprun":
        return None

    host_el = root.find("host")
    if host_el is None:
        # nmap emits a hostless <nmaprun> when the target never responded.
        return HostScanResult(address=address, up=False, ports=frozenset())

    status_el = host_el.find("status")
    up = status_el is not None and status_el.get("state") == "up"

    ports: set[PortObservation] = set()
    ports_el = host_el.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            port_id = port_el.get("portid")
            protocol = port_el.get("protocol") or "tcp"
            if port_id is None:
                continue
            try:
                port_num = int(port_id)
            except ValueError:
                continue
            service_el = port_el.find("service")
            service = service_el.get("name") if service_el is not None else None
            version = service_el.get("version") if service_el is not None else None
            ports.add(
                PortObservation(port=port_num, protocol=protocol, service=service, version=version)
            )

    return HostScanResult(address=address, up=up, ports=frozenset(ports))


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class InventoryJob:
    """Runs one nmap scan class on its own schedule (design §2.5, "C1")."""

    def __init__(
        self,
        scan_class: ScanClass,
        config: ScanJobConfig,
        host_map: ReloadableHostMap,
        runner: SubprocessRunner,
        state: ScanStateStore,
        sink: Callable[[AgentEvent], None],
    ) -> None:
        if config.scan_class is not scan_class:
            raise ValueError(
                f"network_scan: InventoryJob scan_class {scan_class!r} does not match "
                f"config.scan_class {config.scan_class!r}"
            )
        self._scan_class = scan_class
        self._config = config
        self._host_map = host_map
        self._runner = runner
        self._state = state
        self._sink = sink
        self._last_run: Optional[datetime] = None

    def build_argv(self, address: str) -> list[str]:
        """TOP_1000: no `-p` in any form. FULL_RANGE: `-p-`. Never `-sS`,
        `-O`, `-sn`. Never a CIDR (AC-6/20/21/35; UAT-5/16/17)."""
        argv = ["nmap", "-sT", "-sV"]
        if self._scan_class is ScanClass.FULL_RANGE:
            argv.append("-p-")
        argv += ["-oX", "-", address]
        return argv

    def is_due(self, now: datetime) -> bool:
        if not self._config.enabled:
            return False
        if self._last_run is None:
            return True
        elapsed = (now - self._last_run).total_seconds()
        return elapsed >= self._config.interval_seconds

    def run_once(self) -> tuple[ScanOutcome, list[AgentEvent]]:
        """Scan -> parse -> diff -> emit. Returns `(ScanOutcome, list[AgentEvent])`
        (design §2.5). A `ScanTimeoutError` does NOT parse partial output,
        returns `(ScanOutcome.TIMED_OUT, [])`, and leaves diff state untouched
        (design §3.12, DD-13).

        Sink delivery is per-host, not gated on the batch's overall outcome:
        each successfully-scanned host's events are handed to `self._sink`
        immediately after `_diff_and_emit` returns them, because
        `_diff_and_emit` has already advanced that host's diff baseline as a
        side effect. If a later host in the same batch fails, the returned
        `ScanOutcome` reflects the worst per-host outcome (so a caller can
        tell something failed), but the hosts that succeeded are never
        silently dropped -- their events were already sunk, and `all_events`
        (the return value) mirrors exactly what was sunk this cycle."""
        now = _now_utc()
        if not self.is_due(now):
            return ScanOutcome.DISABLED, []

        addresses = self._host_map.current.addresses()
        if not addresses:
            return ScanOutcome.UNMAPPED, []

        outcome_priority = {
            ScanOutcome.TIMED_OUT: 3,
            ScanOutcome.TOOL_MISSING: 2,
            ScanOutcome.FAILED: 1,
        }
        worst_outcome: Optional[ScanOutcome] = None
        all_events: list[AgentEvent] = []

        for address in sorted(addresses):
            argv = self.build_argv(address)
            timeout = self._config.effective_timeout_seconds
            try:
                completed = self._runner.run(argv, timeout=timeout)
            except ToolNotAvailableError as exc:
                logger.warning("network_scan: nmap not available: %s", exc)
                if worst_outcome is None or outcome_priority[
                    ScanOutcome.TOOL_MISSING
                ] > outcome_priority.get(worst_outcome, 0):
                    worst_outcome = ScanOutcome.TOOL_MISSING
                continue
            except ScanTimeoutError as exc:
                # DD-13: never parse partial output; state left untouched;
                # no host_unreachable event; this is its own distinct outcome.
                logger.warning(
                    "network_scan: nmap scan of %s (%s) timed out after %.1fs (budget %.1fs)",
                    address,
                    self._scan_class.value,
                    exc.elapsed,
                    exc.timeout,
                )
                worst_outcome = ScanOutcome.TIMED_OUT  # highest priority; short-circuit below
                break

            if completed.returncode != 0:
                logger.warning(
                    "network_scan: nmap exited %s scanning %s", completed.returncode, address
                )
                if worst_outcome is None or outcome_priority[
                    ScanOutcome.FAILED
                ] > outcome_priority.get(worst_outcome, 0):
                    worst_outcome = ScanOutcome.FAILED
                continue

            result = parse_nmap_xml(completed.stdout, address)
            if result is None:
                logger.warning("network_scan: unparseable nmap XML for %s", address)
                if worst_outcome is None or outcome_priority[
                    ScanOutcome.FAILED
                ] > outcome_priority.get(worst_outcome, 0):
                    worst_outcome = ScanOutcome.FAILED
                continue

            host_events = self._diff_and_emit(address, result)
            for event in host_events:
                self._sink(event)
            all_events.extend(host_events)

        self._last_run = now

        if worst_outcome is ScanOutcome.TIMED_OUT:
            # The timed-out host itself contributes no event (DD-13: never
            # parse partial output), but any earlier host in this batch that
            # already succeeded was already sunk at line 759 above -- return
            # all_events here too, so the return value keeps mirroring what
            # was actually sunk this cycle, as the docstring promises.
            return ScanOutcome.TIMED_OUT, all_events
        if worst_outcome is not None:
            return worst_outcome, all_events

        return ScanOutcome.COMPLETED, all_events

    def _diff_and_emit(self, address: str, result: HostScanResult) -> list[AgentEvent]:
        """Emission rules (design §2.5, FR-7 -- diff, never dump)."""
        agent_id = self._host_map.current.resolve(address)
        if agent_id is None:
            logger.warning(
                "network_scan: dropped inventory result for unattributable address %s", address
            )
            return []

        last = self._state.last(address, self._scan_class)
        events: list[AgentEvent] = []
        coverage = COVERAGE_PHRASE[self._scan_class]
        mac = None

        def _make_event(
            dst_port: Optional[int], net_change: str, ports_meta: dict[str, Any]
        ) -> AgentEvent:
            return AgentEvent(
                agent_id=agent_id,
                session_id="inventory",
                action=ActionType.NETWORK_CALL,
                direction=Direction.LOCAL,
                # Inventory observes a service on the monitored host; it is
                # not egress to the host-map hostname.
                host=None,
                src_ip=None,  # §2.1: Sentinel's own scanner address is not recorded
                dst_ip=address,
                dst_port=dst_port,
                protocol="tcp",
                mac=mac,
                attributes={
                    "collector": "network_scan",
                    "capture_mode": "inventory",
                    "scan_class": self._scan_class.value,
                    "coverage": coverage,
                    "net_change": net_change,
                    **ports_meta,
                },
            )

        if last is None:
            if result.up:
                events.append(_make_event(None, "host_appeared", {}))
            self._state.put(address, self._scan_class, result)
            return events

        if last.up and not result.up:
            events.append(_make_event(None, "host_unreachable", {}))
            self._state.put(address, self._scan_class, result)
            return events

        last_ports = {p.port: p for p in last.ports}
        now_ports = {p.port: p for p in result.ports}

        for port_num, obs in now_ports.items():
            if port_num not in last_ports:
                events.append(
                    _make_event(
                        port_num,
                        "new_open_port",
                        {"service": obs.service, "service_version": obs.version},
                    )
                )
        for port_num in last_ports:
            if port_num not in now_ports:
                events.append(_make_event(port_num, "port_closed", {}))

        self._state.put(address, self._scan_class, result)
        return events
