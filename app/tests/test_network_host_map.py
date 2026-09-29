"""Tests for `sentinel.collector.host_map` (UAT-7, UAT-10, UAT-11).

Covers: loader validation (well-formed load, invalid YAML, missing address,
missing agent_id, duplicate-address-different-agent), same-address-same-agent
idempotence, failed-reload preservation of the previously-loaded mapping, and
`hostname_for()` returning `None` -- never the raw address -- both when
unmapped and when the entry has no `hostname:` label.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from sentinel.collector.host_map import (
    HostMap,
    HostMapDuplicateError,
    HostMapError,
    HostMapParseError,
    HostMapValidationError,
    ReloadableHostMap,
)

ADDR_A = "192.0.2.11"
ADDR_B = "192.0.2.12"


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _rewrite_with_new_mtime(path: Path, text: str) -> None:
    """Overwrite `path` and force a distinct mtime.

    `ReloadableHostMap.reload()` is mtime-gated (DD-3), and some filesystems
    have mtime resolution coarser than this test suite's write speed. Forcing
    a bump keeps these tests about reload *behavior*, not clock granularity.
    """
    _write(path, text)
    time.sleep(0.01)
    os.utime(path, None)


WELL_FORMED = f"""
version: 1
hosts:
  - address: "{ADDR_A}"
    agent_id: "bot-1"
    mac: "aa:bb:cc:dd:ee:01"
    hostname: "bot-1.example.com"
    description: "recon-bot host"
  - address: "{ADDR_B}"
    agent_id: "bot-2"
"""


# ---- UAT-7: structurally separate from AgentPolicy -------------------------


def test_host_map_module_is_not_under_detection():
    """UAT-7 step 4: the mapping loader lives outside detection/policy.py."""
    import sentinel.collector.host_map as host_map_module

    assert "detection" not in host_map_module.__name__
    assert host_map_module.__name__ == "sentinel.collector.host_map"


def test_host_map_file_shape_differs_from_policy_shape(tmp_path: Path):
    """The file format is `version`/`hosts`, not `agents:` -> AgentPolicy list."""
    p = _write(tmp_path / "network_hosts.yaml", WELL_FORMED)
    hm = HostMap.from_yaml(p)
    assert isinstance(hm, HostMap)
    assert hm.addresses() == frozenset({ADDR_A, ADDR_B})


# ---- UAT-10: loader validation ---------------------------------------------


def test_loads_well_formed_file(tmp_path: Path):
    p = _write(tmp_path / "network_hosts.yaml", WELL_FORMED)
    hm = HostMap.from_yaml(p)
    assert len(hm) == 2
    assert hm.resolve(ADDR_A) == "bot-1"
    assert hm.resolve(ADDR_B) == "bot-2"


def test_resolve_by_mac_when_no_address_hit(tmp_path: Path):
    p = _write(tmp_path / "network_hosts.yaml", WELL_FORMED)
    hm = HostMap.from_yaml(p)
    assert hm.resolve(None, mac="AA:BB:CC:DD:EE:01") == "bot-1"


def test_resolve_unmapped_address_returns_none_never_raises(tmp_path: Path):
    p = _write(tmp_path / "network_hosts.yaml", WELL_FORMED)
    hm = HostMap.from_yaml(p)
    assert hm.resolve("203.0.113.99") is None
    assert hm.resolve(None) is None


def test_invalid_yaml_raises_typed_error(tmp_path: Path):
    p = _write(tmp_path / "bad.yaml", "hosts: [this is not: valid: yaml: at all")
    with pytest.raises(HostMapParseError):
        HostMap.from_yaml(p)


def test_missing_version_raises(tmp_path: Path):
    p = _write(tmp_path / "bad.yaml", f'hosts:\n  - address: "{ADDR_A}"\n    agent_id: "bot-1"\n')
    with pytest.raises(HostMapParseError):
        HostMap.from_yaml(p)


def test_non_mapping_top_level_raises(tmp_path: Path):
    p = _write(tmp_path / "bad.yaml", "- just\n- a\n- list\n")
    with pytest.raises(HostMapParseError):
        HostMap.from_yaml(p)


def test_missing_hosts_key_raises(tmp_path: Path):
    p = _write(tmp_path / "bad.yaml", "version: 1\n")
    with pytest.raises(HostMapParseError):
        HostMap.from_yaml(p)


def test_entry_missing_address_raises(tmp_path: Path):
    p = _write(tmp_path / "bad.yaml", 'version: 1\nhosts:\n  - agent_id: "bot-1"\n')
    with pytest.raises(HostMapValidationError):
        HostMap.from_yaml(p)


def test_entry_missing_agent_id_raises(tmp_path: Path):
    p = _write(tmp_path / "bad.yaml", f'version: 1\nhosts:\n  - address: "{ADDR_A}"\n')
    with pytest.raises(HostMapValidationError):
        HostMap.from_yaml(p)


@pytest.mark.parametrize("address", ["192.0.2.0/24", "192.0.2.1-192.0.2.8", "agent.local"])
def test_address_must_be_one_ip_literal(tmp_path: Path, address: str):
    p = _write(
        tmp_path / "bad.yaml",
        f'version: 1\nhosts:\n  - address: "{address}"\n    agent_id: "bot-1"\n',
    )
    with pytest.raises(HostMapValidationError, match="one IPv4 or IPv6 literal"):
        HostMap.from_yaml(p)


def test_duplicate_address_different_agent_id_raises(tmp_path: Path):
    """AC-12(c): same address, two different agent_ids => error, not last-one-wins."""
    text = f"""
version: 1
hosts:
  - address: "{ADDR_A}"
    agent_id: "bot-1"
  - address: "{ADDR_A}"
    agent_id: "bot-2"
"""
    p = _write(tmp_path / "dup.yaml", text)
    with pytest.raises(HostMapDuplicateError):
        HostMap.from_yaml(p)


def test_duplicate_address_same_agent_id_is_idempotent_and_allowed(tmp_path: Path):
    """JC-7: duplicate address with the SAME agent_id is harmless, not an error."""
    text = f"""
version: 1
hosts:
  - address: "{ADDR_A}"
    agent_id: "bot-1"
  - address: "{ADDR_A}"
    agent_id: "bot-1"
"""
    p = _write(tmp_path / "dup_same.yaml", text)
    hm = HostMap.from_yaml(p)
    assert hm.resolve(ADDR_A) == "bot-1"
    assert len(hm) == 1


def test_file_not_found_raises_typed_error(tmp_path: Path):
    with pytest.raises(HostMapError):
        HostMap.from_yaml(tmp_path / "does_not_exist.yaml")


# ---- hostname_for(): never falls back to the address -----------------------


def test_hostname_for_returns_label_when_present(tmp_path: Path):
    p = _write(tmp_path / "network_hosts.yaml", WELL_FORMED)
    hm = HostMap.from_yaml(p)
    assert hm.hostname_for(ADDR_A) == "bot-1.example.com"


def test_hostname_for_returns_none_when_entry_has_no_hostname_label(tmp_path: Path):
    """ADDR_B has no `hostname:` in the fixture -- must be None, never ADDR_B itself."""
    p = _write(tmp_path / "network_hosts.yaml", WELL_FORMED)
    hm = HostMap.from_yaml(p)
    result = hm.hostname_for(ADDR_B)
    assert result is None
    assert result != ADDR_B


def test_hostname_for_returns_none_when_address_unmapped(tmp_path: Path):
    """Never falls back to the raw address for a completely unmapped address."""
    p = _write(tmp_path / "network_hosts.yaml", WELL_FORMED)
    hm = HostMap.from_yaml(p)
    unmapped = "203.0.113.55"
    result = hm.hostname_for(unmapped)
    assert result is None
    assert result != unmapped


def test_hostname_for_matches_same_entry_as_resolve(tmp_path: Path):
    """resolve() and hostname_for() must use identical matching order (design §2.2)."""
    p = _write(tmp_path / "network_hosts.yaml", WELL_FORMED)
    hm = HostMap.from_yaml(p)
    assert hm.resolve(ADDR_A) == "bot-1"
    assert hm.hostname_for(ADDR_A) == "bot-1.example.com"


# ---- UAT-11: failed reload preserves the previous mapping ------------------


def test_reloadable_host_map_initial_load(tmp_path: Path):
    p = _write(tmp_path / "network_hosts.yaml", WELL_FORMED)
    rhm = ReloadableHostMap(p)
    assert rhm.current.resolve(ADDR_A) == "bot-1"


def test_reloadable_host_map_initial_load_may_raise(tmp_path: Path):
    p = _write(tmp_path / "bad.yaml", "not: [valid")
    with pytest.raises(HostMapError):
        ReloadableHostMap(p)


def test_failed_reload_preserves_previous_mapping(tmp_path: Path):
    """UAT-11: a reload pointed at an invalid file must not empty the mapping."""
    p = _write(tmp_path / "network_hosts.yaml", WELL_FORMED)
    rhm = ReloadableHostMap(p)
    assert rhm.current.resolve(ADDR_A) == "bot-1"

    # Corrupt the file in place, then trigger a reload.
    _rewrite_with_new_mtime(p, "not: [valid yaml at all")
    ok = rhm.reload()

    assert ok is False
    # The previously-loaded mapping remains in effect -- not dropped, not empty.
    assert rhm.current.resolve(ADDR_A) == "bot-1"
    assert len(rhm.current) == 2


def test_reload_never_raises_on_bad_file(tmp_path: Path):
    p = _write(tmp_path / "network_hosts.yaml", WELL_FORMED)
    rhm = ReloadableHostMap(p)
    _rewrite_with_new_mtime(p, "hosts: not-even-a-list")
    # Must not raise.
    result = rhm.reload()
    assert result is False


def test_successful_reload_swaps_to_new_mapping(tmp_path: Path):
    p = _write(tmp_path / "network_hosts.yaml", WELL_FORMED)
    rhm = ReloadableHostMap(p)
    assert rhm.current.resolve(ADDR_B) == "bot-2"

    updated = f"""
version: 1
hosts:
  - address: "{ADDR_A}"
    agent_id: "bot-1"
"""
    _rewrite_with_new_mtime(p, updated)

    ok = rhm.reload()
    assert ok is True
    assert rhm.current.resolve(ADDR_A) == "bot-1"
    assert rhm.current.resolve(ADDR_B) is None


def test_reload_is_noop_when_file_unchanged(tmp_path: Path):
    p = _write(tmp_path / "network_hosts.yaml", WELL_FORMED)
    rhm = ReloadableHostMap(p)
    ok = rhm.reload()
    assert ok is True
    assert rhm.current.resolve(ADDR_A) == "bot-1"


# ---- Committed template: config/network_hosts.example.yaml (BLOCKER fix) ---
# Loads the actual committed file (not a copy or an inline fixture) through
# the real loader, so this test fails the moment the example and the loader
# drift out of sync (AC-12, FR-8, FR-12; docs/NETWORK_COLLECTOR.md).


def test_committed_example_host_map_loads_via_real_loader():
    repo_root = Path(__file__).resolve().parents[2]
    example_path = repo_root / "config" / "network_hosts.example.yaml"
    assert example_path.is_file(), f"missing committed template: {example_path}"

    hm = HostMap.from_yaml(example_path)

    # At least 2-3 entries, matching the finding's requirement.
    assert len(hm) >= 3

    # At least one entry WITH a hostname label and one WITHOUT (§2.1.1).
    addresses = hm.addresses()
    with_hostname = [a for a in addresses if hm.hostname_for(a) is not None]
    without_hostname = [a for a in addresses if hm.hostname_for(a) is None]
    assert with_hostname, "example file must include at least one hostname: entry"
    assert without_hostname, "example file must include at least one entry with no hostname:"

    # Only RFC 5737 / RFC 2606 documentation addresses -- never a routable
    # production-shaped host.
    for addr in addresses:
        assert addr.startswith(("192.0.2.", "203.0.113.")), (
            f"example host map must use only RFC 5737 documentation addresses, got {addr!r}"
        )
