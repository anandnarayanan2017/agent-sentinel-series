"""nmap XML is attacker-influenced (a scanned host shapes it): DTDs and
entities must be rejected, never resolved or expanded."""

from pathlib import Path

import pytest

from sentinel.collector.network_scan import HostScanResult, parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures" / "network"

HOSTILE = {
    "xxe_file": b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
    b"<nmaprun><host>&x;</host></nmaprun>",
    "billion_laughs": b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa">'
    b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>'
    b"<nmaprun><host>&c;</host></nmaprun>",
    "external_dtd": b'<?xml version="1.0"?><!DOCTYPE nmaprun SYSTEM "http://127.0.0.1:1/x.dtd">'
    b"<nmaprun/>",
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_hostile_xml_is_rejected(name):
    assert parse_nmap_xml(HOSTILE[name], "203.0.113.10") is None


def test_real_nmap_output_still_parses():
    payload = (FIXTURES / "nmap_a.xml").read_bytes()
    assert isinstance(parse_nmap_xml(payload, "203.0.113.10"), HostScanResult)
