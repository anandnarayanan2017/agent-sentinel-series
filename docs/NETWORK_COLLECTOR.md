# Network-visibility collector — operator guide

`app/sentinel/collector/network_scan.py` gives Agent Sentinel network-level
visibility into agent/M2M hosts, in two modes:

- **Live capture** — `tshark` runs as a supervised subprocess, scoped to a
  configured host allow-list, and turns each decoded packet record into a normalized
  `AgentEvent`.
- **Periodic inventory** — `nmap` runs on a schedule against the same
  allow-list, and the collector diffs each scan against the last-known state
  for that host to emit "new port", "port closed" and "host appeared /
  unreachable" events — never a raw dump of every scan result.

Both modes are **off by default** and both require an explicit,
operator-authored address→identity mapping before either can run at all.
See `design/DESIGN.md` for the full design; this document is the operator-facing
summary of what you need to know to run it safely.

## Binary dependency and absent-binary behavior

Unlike the HTTP-proxy collectors (`collector/proxy.py`), this collector
depends on two **external binaries** that must be installed on the collector
host: `tshark` (Wireshark's CLI capture tool) and `nmap`. Neither is a Python
package — no `pip install` adds them, and `pyproject.toml` declares no new
dependency for this feature.

If either binary is absent, not executable, or the path is misconfigured, the
collector does **not** silently report a clean/empty result. It surfaces a
distinct, observable "tool not available" condition:

- Live capture: `CaptureHealth.TOOL_MISSING`, logged at WARNING.
- Inventory: `ScanOutcome.TOOL_MISSING`, logged at WARNING, with the prior
  scan-diff state left untouched.

A missing tool and "scan ran, found nothing" are structurally different
values in this codebase (`ToolNotAvailableError` is a distinct exception type
from a completed, zero-finding run) — an operator can always tell "we didn't
look" from "we looked and it was quiet."

## Scan-authorization statement

**Enabling live mode authorizes passive observation of matching packets on
the selected interface. Enabling inventory authorizes active nmap probes to
the allow-listed hosts.** Both affect a real environment and remain explicit
operator decisions, never something an agent session or CI job turns on.

- Both `CaptureConfig.enabled` and `ScanJobConfig.enabled` default to
  `False`. With no operator configuration at all, **zero** `tshark`/`nmap`
  invocations occur — this is a config *absence*, not merely a default
  value that happens to be off.
- Turning either on requires **two separate, positive acts**: authoring
  `config/network_hosts.yaml` (below) *and* setting `enabled: true` in the
  relevant job's configuration. There is no single flag that turns on
  scanning against hosts you haven't explicitly listed.
- The loader accepts one IPv4 or IPv6 literal per entry and rejects CIDRs,
  ranges, and hostnames. Inventory never scans a target absent from that list.

## The address→identity mapping (`config/network_hosts.yaml`)

Both modes require a host-map file mapping network addresses to `agent_id`
values, loaded by `app/sentinel/collector/host_map.py`. This is **not** a
policy file — it is never read by `PolicySet`/`AgentPolicy`, and it never
appears under `policies/`. It answers a different question ("which agent
identity owns this address?") than `policies/*.yaml` answers ("what is this
agent identity allowed to do?").

- The real, operator-authored file is `config/network_hosts.yaml` and is
  **gitignored** — it typically names real internal or production hosts.
- A committed template, `config/network_hosts.example.yaml`, documents the
  expected shape (`version`, a `hosts` list of `address`/`agent_id`, with
  optional `mac`, `hostname`, and `description` fields).
- An address not present in the mapping is **dropped**, never ingested under
  a placeholder or synthesized identity. Live-capture drops are counted and
  logged; inventory attribution failures are logged. Logs include the address,
  never payload content.

### Reload mechanism

The host map is loaded once at collector start. Reload is **explicit-call,
mtime-gated, and operator-configurable** — not signal-based (SIGHUP doesn't
exist on Windows, which this repo develops and tests on) and not a
filesystem watcher (no new dependency).

- **Default: restart-only.** `reload_interval_seconds` is `None` unless you
  set it, so out-of-the-box behavior is the simplest one: change the file,
  restart the collector.
- **Opt-in: interval polling.** Set a `reload_interval_seconds` on
  `CaptureConfig`/the job config to have the collector re-check the file's
  mtime and reload it periodically without a restart.
- **A failed reload never empties the mapping.** A new `HostMap` is built
  from the file in full before the reference is swapped — if that build
  fails (bad YAML, missing fields, a duplicate address mapped to two
  different agents), the previous good mapping stays in effect and a
  WARNING is logged. A typo in the file degrades to "still using the old
  map," never to "attributing nothing."

## `AgentEvent.host` — the rule, and the egress-allow-list gap it leaves open

**`AgentEvent.host` means the remote egress hostname.** It is populated only
for an outbound packet when TLS SNI or an HTTP `Host` header supplies a
hostname-shaped value. It is never a bare IP, the monitored machine's
`hostname:` label, or a live DNS result. Inbound packets and outbound packets
without a captured hostname carry `host=None`.

This matters operationally because `AgentPolicy.allowed_hosts` is an
exact-match **hostname** allow-list. If this collector ever populated `host`
from a raw IP literal, any agent with an existing hostname-based
`allowed_hosts` policy would see a HIGH-severity `net.host_not_allowed`
finding on **every captured outbound packet** — a false-positive storm
that would also bury genuine egress violations in noise. This collector is
built so that adopting it changes nothing about an existing agent's
detection behavior: a `None` host is inert everywhere it's consumed.

**The consequence, stated as a known limitation, not hidden as a design
detail:** egress allow-list evaluation (`allowed_hosts`) is **not extended
to raw IP-level packet capture** in this release. If an outbound packet has
no captured hostname, the check has nothing safe to compare. The packet can
still be recorded with `dst_ip`/`dst_port`, but live capture does not feed the
new-listening-port rule; that rule consumes only inventory
`net_change=new_open_port` events. Closing the IP-policy gap would mean adding
IP-aware matching to `AgentPolicy` — a real design decision this release
deliberately defers to a future ADR, rather than approximating today by
mismatching an IP against a hostname list.

The optional host-map `hostname:` labels the monitored machine for operator
context. It does not authorize or synthesize the remote egress hostname.

## Observable states

**Live capture** (`CaptureHealth`): `not_started`, `capturing`,
`tool_missing`, `exited` (the tshark subprocess died unexpectedly — this is
distinct from "not started" and from "tool missing," so a silent capture
death is never mistaken for a quiet network).

**Periodic inventory** (`ScanOutcome`), one per scan cycle, mutually
exclusive: `completed` (ran to completion; diff emitted, possibly empty),
`tool_missing`, `timed_out` (see below — **not** a clean scan), `failed`
(non-zero exit or unparseable XML), `disabled` (not enabled, or not due
yet), `unmapped` (no allow-listed hosts configured).

## Coverage claims — read this before trusting a "no findings" result

There are **two, separately-scheduled, separately-labeled** inventory scan
classes, and a claim from one must never be read as the other:

- **Top-1000 scan** — `nmap`'s default TCP port set (no `-p` flag at all),
  run **hourly**.
- **Full-range scan** — the full TCP port range (`-p-`), run **at most
  daily**, as a completely separate job with its own enable/disable and its
  own cadence. There is no configuration value that makes the hourly job
  emit `-p-`, and a sub-daily full-range cadence is rejected at load.

Every scan-derived event and finding carries a machine-readable scan-class
label and a human-readable coverage phrase (`"in nmap's default top-1000 TCP
port set"` or `"in the full TCP port range (-p-)"`). **A quiet top-1000
result is coverage of 1,000 common ports, not a "no open ports" or "clean
host" claim** — see `docs/COMPLIANCE.md`'s "Network security" section for
the compliance-facing version of this rule.

## Severity posture: a new port is LOW/advisory, not HIGH/policy

A newly-observed listening port surfaces as `baseline.new_listening_port` at
`Severity.LOW`, as an **advisory** finding — not as a HIGH-severity policy
violation. This repo's rules-first convention reserves a HIGH verdict for a
deterministic policy clause an operator authored (e.g. `allowed_hosts`,
`allowed_tools`). No `allowed_ports`-style field exists on `AgentPolicy` in
this release, so there is no clause a "disallowed port" check could cite —
and a LOW advisory finding, fully explainable with control references
attached, is the honest representation of what the system actually knows. A
future release that wants a HIGH/policy-enforced verdict for ports would need
a new `AgentPolicy` field and its own design review.

## Cold-start behavior and the optional scan-state sidecar

Scan-diff state (which ports were seen last time, per host and per scan
class) is **collector-local**, never stored in the events database.

- **Default: in-process only.** State lives in a plain dict for the life of
  the process. After restart, the first successful scan establishes a new
  baseline and emits `host_appeared` for an up host; it does not claim that
  every currently open port is newly opened. Changes relative to the
  pre-restart baseline cannot be detected without persisted state.
- **Opt-in: a JSON sidecar file.** Set a `state_path` on the relevant scan
  job's config to preserve scan-diff history between restarts and avoid a
  fresh cold-start baseline. The sidecar is a cache, not a source of truth:
  deleting it is operationally safe but discards comparison history and
  reproduces the cold-start baseline behavior on the next run.

## Timeout budget

Each scan invocation (one `nmap` process against one address) has a
configurable timeout, defaulting to 600s for the top-1000 job and 5400s (90
minutes) for the full-range job — deliberately generous, since manual
testing observed full-range scans taking 30+ minutes per host and that
figure is not a guaranteed upper bound. Configuration validation rejects a
timeout that isn't strictly less than the job's own cadence interval, so a
hung scan can never still be running when the next cycle is due.

**A timed-out scan is never treated as a clean result.** On timeout the
child process is terminated and reaped (no orphaned `nmap` process keeps
scanning), partial output is discarded unparsed (a truncated XML document
would look like a shrunken port list and could trigger spurious
"port closed" events), the job reports `ScanOutcome.TIMED_OUT` with an empty
event list, and the previous scan-diff state for that host is left exactly
as it was. No coverage claim is made for a timed-out cycle.

## Dashboard display limit

The dashboard's Network Inventory panel derives its rows from the same
`/events?limit=100` fetch every other panel uses — there is no separate
endpoint. This means the panel shows, at most, the same recent-events window
the rest of the dashboard shows; it is a **display** limitation, not data
loss (everything is still persisted to the events store and queryable
directly).

## Rollback — a one-way door

The storage migration that adds the five network-visibility columns
(`src_ip`, `dst_ip`, `dst_port`, `protocol`, `mac`) to the `events` table is
**not safely reversible** on either backend: rolling back to pre-migration
code against an already-migrated database will fail loudly (a
column-count/binder error) rather than silently writing misaligned data,
because both backends' inserts name their columns explicitly. If you need to
roll back application code after this migration has run, keep the
network-aware storage code, or plan a deliberate column-drop — don't assume
old code "just works" against a migrated database.
