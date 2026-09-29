# 0008 — nmap/tshark as a network-visibility collector

**Date**: 2026-08-13
**Status**: Accepted (2026-08-20)
**Deciders**: Agent Sentinel team

## Context

Every existing collector (`collector/proxy.py`, the Envoy tap from ADR 0005,
the Phase 2 SDK wrappers from ADR 0002) sees only HTTP(S) traffic that an
agent chooses to route through them. That is a structural blind spot: an
agent process that is prompt-injected or otherwise compromised into opening
a raw TCP/UDP socket, spinning up a listener, or exfiltrating over a non-HTTP
channel is invisible to the pipeline end to end. There is currently no
network-level visibility into what an agent's own host actually exposes or
talks to outside the HTTP layer, and no device/asset inventory of any kind
exists in the schema, detection, or storage layers.

A manual investigation (this session, human-driven, against a home network —
not an agent host) validated that `nmap` (service/version/full-port scanning)
and `tshark` (live packet capture, SYN/ACK/RST-level ground truth) can
together answer two questions an HTTP-only collector structurally cannot:
what is listening on a host, and what did it actually send/receive on the
wire, independent of any application-layer cooperation.

This ADR is scoped narrowly: it decides *whether and how* to bring this
capability into the product, not to build a general-purpose network scanner.
By design, Agent Sentinel is an agent/M2M-identity observability and policy-detection layer
— network visibility only has product value where it is scoped to hosts that
*are* agent or M2M identities, not arbitrary devices on a LAN.

## Decision

Add a new collector, `collector/network_scan.py`, that runs two distinct
capture modes against a configured allow-list of agent/M2M host addresses
(never a full subnet sweep):

1. **Live capture mode** (tshark): runs `tshark -i <if> -T ek` as a
   supervised subprocess scoped to the configured host list, parses each
   flow into a new optional-fields extension of `AgentEvent`
   (`src_ip`, `dst_ip`, `dst_port`, `protocol`, `mac`), tagged
   `action=ActionType.NETWORK_CALL`.
2. **Periodic inventory mode** (nmap): scheduled `-sT -sV` scans (TCP
   connect, not raw SYN — see Alternatives) against the same allow-list,
   diffed against last-known state, emitting synthetic events for new open
   ports or newly-appeared hosts on the allow-list's subnet.

Both modes attribute events to `agent_id` via a static **address→agent_id**
lookup table, supplied as new standalone configuration (e.g.
`config/network_hosts.yaml`), resolved by the collector *before* any
`AgentEvent` is constructed — never by inferring identity from network
behavior. Traffic from addresses not in that table is dropped at the
collector, not ingested under a placeholder identity.

This is deliberately **not** a new field on `AgentPolicy`. `AgentPolicy` is
keyed by `agent_id` and its existing `allowed_hosts` field is a forward
lookup (agent → permitted hostnames) used *after* an event already carries
an `agent_id`, checked in `Engine._policy_checks`
(`detection/policy.py:20-25`). The network collector's problem is the
opposite direction: resolve `agent_id` *from* an address, before an
`AgentEvent` — and therefore an `agent_id` — exists at all. A prior draft
of this ADR conflated the two; they are structurally different lookups and
must not share a config field. The new table is consulted once, at
collector ingest time, to populate `AgentEvent.agent_id`; `allowed_hosts`
is then checked as normal, unchanged, once the event reaches the engine.

## Alternatives considered

| Option | Rejected because |
|---|---|
| Full subnet/LAN scanning (scan everything reachable) | Out of product scope — Sentinel is agent/M2M-identity-centric by design, not a general network security scanner; would misrepresent what the tool is for and create noise from devices with no agent relationship |
| Raw SYN scan (`nmap -sS`) for the inventory mode | Requires raw sockets / elevated privileges (Npcap admin mode on Windows, `CAP_NET_RAW` on Linux) for a marginal speed gain over `-sT`; TCP connect scan proved reliable and privilege-free during manual testing, `-sS` did not (see Consequences) |
| eBPF host-level socket monitoring | Same rejection as ADR 0005's eBPF row — platform-specific, no WSL2 support, kernel ≥5.8 requirement; also a materially larger engineering lift than shelling out to two existing tools |
| Passive-only (tshark, no nmap) | Live capture alone answers "what happened" but not "what's listening right now" — periodic inventory is the only way to catch a newly-opened port between traffic bursts |
| Infer agent identity from traffic patterns (ML/heuristic host fingerprinting) | Violates ADR 0001 (rules-first, statistics secondary and never sole detector); host→agent_id must be an explicit, auditable mapping an operator configured, not an inferred guess |

## Consequences

**Positive**:
- Closes a real, demonstrated gap: non-HTTP egress and unexpected listening
  services on an agent's host are invisible to every existing collector.
- Reuses the existing pipeline unchanged — new collector, same
  `AgentEvent` → `policy.py` → `baseline.py` → `Finding` flow every other
  collector uses. No new detection paradigm.
- `control_refs` needs no schema change (already free-form strings); new
  network-security control references (e.g. DORA Art. 9) slot in the same
  way existing ones do.
- Extends `docs/COMPLIANCE.md` into a control family (network security)
  that is currently unaddressed.

**Negative / trade-offs**:
- New optional fields on `AgentEvent` touch a schema every existing
  collector and consumer depends on — must be strictly additive and
  defaulted, verified against every current parser in `parsers.py`.
- **Both storage backends write `AgentEvent` rows as fixed positional
  inserts** — `storage/store.py:70` (`INSERT OR REPLACE INTO events
  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, 14 columns) and the equivalent in
  `storage/pg_store.py`. Adding the five new optional fields to the
  pydantic model alone does **not** persist them — they would silently be
  dropped on write. DuckDB's `CREATE TABLE IF NOT EXISTS`
  (`storage/store.py:29`) will not retroactively add columns to an
  existing database file either. This collector therefore requires a
  storage migration (both a new `events` column set and a DuckDB
  `ALTER TABLE`/rebuild path for existing deployments) as an explicit,
  in-scope work item — not a side effect of the schema change.
- The port range for periodic inventory mode must be decided explicitly,
  not left implicit: nmap's default (`-sT -sV` with no `-p` flag) scans
  only the top 1000 ports in minutes, while a full `-p-` sweep takes on
  the order of 30+ minutes per host (observed in manual testing) but is
  the only way to catch a newly-opened port outside the top 1000. v1
  scope is the **top-1000 default**, run hourly; a full-range sweep is a
  separate, explicitly slower job run at most daily, and the two must be
  labeled distinctly in any finding or compliance claim ("port scanned"
  is not the same coverage claim as "in nmap's default top-1000 set").
- `nmap -O` (OS fingerprinting) combined with a full port range
  (`-p-`) was found during manual testing to fail silently — exits in
  under a second reporting "0 hosts up" against a host confirmed reachable
  by every other method. Root cause not isolated. OS fingerprinting is
  therefore **out of scope for v1**; if added later, needs its own
  investigation, run as a separate, smaller-scope scan rather than
  combined with `-p-`.
- Raw ARP-based host discovery (`nmap -sn`) was found unreliable in the
  tested environment (Npcap capture of ARP replies failed even from an
  elevated shell) — inventory mode must use OS-level reachability
  (ICMP/TCP-connect) for host-liveness checks, not nmap's own `-sn`.
- tshark/nmap must be present on whatever host runs the collector — an
  operational dependency the HTTP-proxy collectors do not have.
- Running periodic port scans against production agent hosts, even
  narrowly scoped, is itself traffic an operator must authorize — this is
  not a passive-only capability like the HTTP tap.
**Neutral**:
- Existing collectors (SDK wrappers, Envoy tap, mitmproxy) are unaffected;
  this is purely additive.
- Dashboard changes (a network-inventory table alongside the existing
  findings table) reuse the existing `FindingsTable` pattern in
  `dashboard/index.html` — no new UI paradigm.

## Phase relevance

Not yet assigned to a phase. Recommend framing as a Phase 4+ capability
(after Phase 3's Envoy egress proxy, per ADR 0005) since it depends on
having a stable, configured set of agent/M2M host identities to scope the
allow-list against — a prerequisite that earlier phases establish.

## Follow-ups

- Gate 1 spec for the network collector (see `spec/SPEC.md` once produced)
  defines exact acceptance criteria and UAT for v1 scope (live capture +
  periodic inventory, no OS fingerprinting, allow-list only), and must
  include the storage migration for the five new `AgentEvent` columns as
  an explicit acceptance criterion, not an implementation detail assumed
  away by the schema change alone.
- Revisit `nmap -O` failure as a separate investigation if OS
  fingerprinting becomes a real requirement.

## Revision history

- 2026-08-13 (original): host→agent_id attribution described as
  "mirroring `allowed_hosts`"; storage persistence and the top-1000-vs-
  full-port scan distinction were not addressed.
- 2026-08-13 (revised, same day): corrected the identity-attribution
  design — address→agent_id is a standalone lookup table consulted at
  ingest time, structurally distinct from `AgentPolicy.allowed_hosts`.
  Added the storage-migration requirement (both stores use fixed
  positional inserts against fixed-column tables; new fields silently
  would not persist without it). Resolved the port-range ambiguity
  between the decision text and the timing rationale in Consequences.
  Found during Gate 1 spec review, before any implementation
  began — the two-gate model working as intended.
