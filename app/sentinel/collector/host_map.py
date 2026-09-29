"""Address -> agent_id attribution for the network-visibility collector.

This is the reverse-direction lookup the network collector needs (address ->
agent_id), which is structurally different from `AgentPolicy.allowed_hosts`
(agent_id -> permitted hosts, consumed only after an event already carries an
`agent_id`). It is deliberately its own module, outside `detection/`, so it
can never be confused with or cross-loaded by `PolicySet`/`AgentPolicy`
(spec FR-8, FR-9, OOS-3).

`config/network_hosts.yaml` is NOT a policy file and is never read by
`PolicySet`. See design/DESIGN.md §2.2.

Binding rule (design §2.1.1): `hostname_for()` NEVER falls back to the raw
address. An address with no `hostname:` label yields `None`, which is the
safe default consumed by `AgentEvent.host` -- never a synthesised or
IP-shaped placeholder.
"""

from __future__ import annotations

import logging
import os
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


class HostMapError(Exception):
    """Base error for host-map loading and validation failures."""


class HostMapParseError(HostMapError):
    """The file is not valid YAML, is not a mapping, or has a bad version."""


class HostMapValidationError(HostMapError):
    """An entry is missing a required field or has a malformed shape."""


class HostMapDuplicateError(HostMapValidationError):
    """The same address maps to two different agent_ids."""


_SUPPORTED_VERSION = 1


@dataclass(frozen=True)
class HostEntry:
    """One address -> agent_id attribution record."""

    address: str
    agent_id: str
    mac: Optional[str] = None
    hostname: Optional[str] = None  # design §2.1.1 -- the only sanctioned host source
    description: str = ""


def _normalize_mac(mac: Optional[str]) -> Optional[str]:
    if mac is None:
        return None
    return mac.strip().lower()


class HostMap:
    """Immutable address/MAC -> agent_id and -> hostname lookup.

    Construct only via `from_yaml`. Never mutated after construction --
    `ReloadableHostMap` builds a brand-new `HostMap` on reload and swaps the
    reference only on success (design §2.2).
    """

    def __init__(self, entries: list[HostEntry]) -> None:
        self._by_address: dict[str, HostEntry] = {}
        self._by_mac: dict[str, HostEntry] = {}
        for entry in entries:
            self._by_address[entry.address] = entry
            norm_mac = _normalize_mac(entry.mac)
            if norm_mac:
                self._by_mac[norm_mac] = entry

    @classmethod
    def from_yaml(cls, path: str | Path) -> "HostMap":
        """Load and validate a `network_hosts.yaml` file.

        Raises a `HostMapError` subclass on any problem; never returns a
        partial mapping (FR-12, AC-12).
        """
        p = Path(path)
        try:
            raw_text = p.read_text(encoding="utf-8")
        except OSError as exc:
            raise HostMapParseError(f"Could not read host map file {p}: {exc}") from exc

        try:
            data = yaml.safe_load(raw_text)
        except yaml.YAMLError as exc:
            raise HostMapParseError(f"Invalid YAML in {p}: {exc}") from exc

        if not isinstance(data, dict):
            raise HostMapParseError(f"{p}: top-level document must be a mapping")

        version = data.get("version")
        if version != _SUPPORTED_VERSION:
            raise HostMapParseError(
                f"{p}: unsupported or missing 'version' (expected {_SUPPORTED_VERSION}, "
                f"got {version!r})"
            )

        raw_hosts = data.get("hosts")
        if raw_hosts is None:
            raise HostMapParseError(f"{p}: missing required 'hosts' key")
        if not isinstance(raw_hosts, list):
            raise HostMapParseError(f"{p}: 'hosts' must be a list")

        entries: list[HostEntry] = []
        seen_addresses: dict[str, str] = {}  # address -> agent_id, for duplicate detection
        for idx, raw_entry in enumerate(raw_hosts):
            if not isinstance(raw_entry, dict):
                raise HostMapValidationError(f"{p}: hosts[{idx}] is not a mapping")

            address = raw_entry.get("address")
            if not address or not isinstance(address, str):
                raise HostMapValidationError(f"{p}: hosts[{idx}] is missing a required 'address'")
            address = address.strip()
            try:
                # This value becomes one nmap target and one BPF `host` clause.
                # A CIDR, range, or hostname would widen that authorization.
                address = str(ipaddress.ip_address(address))
            except ValueError as exc:
                raise HostMapValidationError(
                    f"{p}: hosts[{idx}].address must be one IPv4 or IPv6 literal, got {address!r}"
                ) from exc

            agent_id = raw_entry.get("agent_id")
            if not agent_id or not isinstance(agent_id, str):
                raise HostMapValidationError(f"{p}: hosts[{idx}] is missing a required 'agent_id'")

            mac = raw_entry.get("mac")
            hostname = raw_entry.get("hostname")
            description = raw_entry.get("description", "")

            if address in seen_addresses and seen_addresses[address] != agent_id:
                raise HostMapDuplicateError(
                    f"{p}: address {address!r} maps to two different agent_ids "
                    f"({seen_addresses[address]!r} and {agent_id!r})"
                )
            seen_addresses[address] = agent_id

            entries.append(
                HostEntry(
                    address=address,
                    agent_id=agent_id,
                    mac=mac,
                    hostname=hostname,
                    description=description if isinstance(description, str) else "",
                )
            )

        return cls(entries)

    def resolve(self, address: Optional[str], mac: Optional[str] = None) -> Optional[str]:
        """Reverse lookup: address/MAC -> agent_id, or None if unattributable.

        NEVER raises. `None` means the caller MUST drop the record (FR-10) --
        never ingest under a placeholder or synthesised identity.
        """
        if address is not None:
            entry = self._by_address.get(address)
            if entry is not None:
                return entry.agent_id
        norm_mac = _normalize_mac(mac)
        if norm_mac is not None:
            entry = self._by_mac.get(norm_mac)
            if entry is not None:
                return entry.agent_id
        return None

    def hostname_for(self, address: Optional[str], mac: Optional[str] = None) -> Optional[str]:
        """Label lookup for `AgentEvent.host` (design §2.1.1).

        Returns `None` when the address/MAC is unmapped OR when the matched
        entry has no `hostname:` label. NEVER raises, and NEVER falls back to
        returning the raw address -- an unmapped or label-less host is
        represented as `None`, not as an IP-shaped placeholder.
        """
        entry: Optional[HostEntry] = None
        if address is not None:
            entry = self._by_address.get(address)
        if entry is None:
            norm_mac = _normalize_mac(mac)
            if norm_mac is not None:
                entry = self._by_mac.get(norm_mac)
        if entry is None:
            return None
        return entry.hostname

    def addresses(self) -> frozenset[str]:
        """The capture/scan allow-list (design AS-5)."""
        return frozenset(self._by_address.keys())

    def __len__(self) -> int:
        return len(self._by_address)


class ReloadableHostMap:
    """Wraps a `HostMap` with FR-13 last-good-wins reload semantics.

    Reload is explicit-call, mtime-gated, and never empties the mapping on
    failure (design §2.2, DD-3). The default posture is restart-only: nothing
    calls `reload()` unless the operator's configuration opts into interval
    polling -- this class just makes that safe when it happens.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        # Initial load MAY raise -- there is no "previous good" to fall back to yet.
        self._current = HostMap.from_yaml(self._path)
        self._mtime = self._safe_mtime()

    def _safe_mtime(self) -> Optional[float]:
        try:
            return os.stat(self._path).st_mtime
        except OSError:
            return None

    def reload(self) -> bool:
        """Re-read the host map file if it changed.

        Returns True on a successful reload (or when the file is unchanged --
        a no-op is not a failure), False on failure. NEVER raises, and NEVER
        empties the current mapping: a new `HostMap` is built in full before
        the reference is swapped, so a failed reload structurally cannot leave
        `current` in a partial or empty state.
        """
        new_mtime = self._safe_mtime()
        if new_mtime is not None and new_mtime == self._mtime:
            return True  # unchanged; nothing to do; not a failure
        try:
            new_map = HostMap.from_yaml(self._path)
        except HostMapError as exc:
            logger.warning("host map reload failed for %s: %s", self._path, exc)
            return False
        self._current = new_map
        self._mtime = new_mtime
        return True

    @property
    def current(self) -> HostMap:
        return self._current
