# Compliance mapping

This is the document that turns a "cool repo" into a procurement conversation.
Each Agent Sentinel capability is mapped to the obligation it helps evidence.

> Not legal advice. References are indicative and must be validated against the
> current consolidated texts and your own regulatory scoping.

## Mapping

| Capability | What it produces | DORA | EU AI Act | CSSF |
|---|---|---|---|---|
| Normalized event log from configured collectors | Best-effort-redacted, bounded records of observed LLM/tool/network activity; the API audit trail over them is hash-chained and verifiable (see below) | Art. 9 (protection), Art. 10 (detection) | Art. 12 for high-risk AI systems in scope (automatic logging/record-keeping) | 20/750 ICT risk mgmt, subject to entity scope |
| Policy-as-code per agent | Documented control envelope per machine identity | Art. 6 (ICT risk framework) | Art. 14 (human oversight design) | 20/750 governance |
| Anomaly / deviation detection | Behavioral detection of abnormal agent activity | Art. 10 (anomalous activities detection) | Art. 15 (accuracy/robustness monitoring) | 22/806 outsourcing oversight |
| Explainable findings + evidence chain | Reviewable incident evidence | Art. 17 (incident management) | Art. 12 + Art. 13 (transparency) | incident notification expectations |
| Severity + rationale | Triage/classification of ICT-related incidents | Art. 18 (classification) | — | incident classification |
| Control references on findings | Audit traceability to obligations | Art. 5 (governance) | Art. 17 (quality mgmt system) | audit/inspection readiness |

## How findings carry this through

Every `Finding` includes a `control_refs` list populated from the agent's
policy. When the reconciliation-bot policy declares:

```yaml
control_refs:
  - "DORA Art.10 (anomaly detection)"
  - "EU AI Act Art.12 (logging)"
  - "CSSF 20/750 (ICT risk)"
```

then every alert that agent generates is automatically tagged with those
references — so an auditor sees, per incident, exactly which obligation the
detection supports.

## Network security (network-visibility collector)

The network-visibility collector (`app/sentinel/collector/network_scan.py`;
see `docs/NETWORK_COLLECTOR.md` for operator setup) adds two additional
signal sources: live traffic capture and periodic port inventory, both
scoped to an operator-authored allow-list of agent/M2M hosts.

| Capability | What it produces | DORA | EU AI Act | CSSF |
|---|---|---|---|---|
| Live traffic capture (`tshark`), allow-list-scoped | Egress metadata record (src/dst IP, port, protocol) per agent identity | Art. 9 (protection), Art. 10 (detection) | Art. 12 (logging/record-keeping) | 20/750 ICT risk mgmt |
| Periodic port inventory (`nmap`), two labeled scan classes | First-appearance / new-open-port / closed-port advisory events, each tagged with its scan class | Art. 9 (protection), Art. 10 (detection) | Art. 15 (accuracy, robustness and cybersecurity) | 22/806 outsourcing oversight |
| First-seen-listening-port finding (`baseline.new_listening_port`) | Explainable, evidence-backed advisory finding naming the port, host, and scan coverage | Art. 9, Art. 10 | Art. 15 | ICT risk mgmt |

**Every coverage claim below is scan-class-qualified — never an unqualified
"port scanned" or "network monitored" statement.** This collector runs two
separately-scheduled inventory jobs, and a finding or report that doesn't say
which one produced it is a compliance-claim bug, not a stylistic choice:

- **Top-1000 scan** — nmap's default TCP port set, run **hourly**. A finding
  or dashboard row from this job states its coverage as *"in nmap's default
  top-1000 TCP port set"*. This is coverage of the most common 1,000 TCP
  ports, **not** full-port coverage — a top-1000 result finding nothing must
  never be read or reported as "no open ports" without that qualification.
- **Full-range scan** — the full TCP port range (`-p-`), run **at most
  daily**, as its own separately-configured, separately-enabled job. A
  finding or dashboard row from this job states its coverage as *"in the
  full TCP port range (-p-)"*.
- The two scan classes maintain **independent diff state per host**: a port
  first observed by one class is never reported as newly opened or closed by
  the other, so a compliance reader can trust that a "new port" claim
  reflects a real change within that scan's own coverage, not an artifact of
  comparing two different sweeps.

**Severity posture — stated plainly so a compliance reader is not
misled.** A newly-observed listening port surfaces as a **LOW-severity
advisory finding** (`baseline.new_listening_port`), not a HIGH-severity
policy violation. This is a deliberate design choice, not an oversight: under
this repo's rules-first convention, a HIGH verdict rests on a deterministic
policy clause an operator authored and can point to in a change review (see
`policies/*.yaml`'s `allowed_hosts`/`allowed_tools`/etc.). No such
operator-authored port policy exists yet — `AgentPolicy` deliberately has no
`allowed_ports` field in this release — so a newly-open port is reported as
exactly what the system knows: a first-seen fact worth review, with full
evidence and control references attached, but not a confirmed policy breach.
Escalating this to a HIGH/policy-enforced verdict is a known, tracked future
capability (it would require a new `AgentPolicy` field and its own design
review), not a gap silently left unaddressed.

**Known limitation.** Egress allow-list detection (`allowed_hosts`) is not
extended to bare IP addresses in this release: capture-derived events
populate `host` only from a genuine hostname such as TLS SNI or HTTP Host.
IP-only traffic remains visible as network metadata but is outside this
hostname rule; the engine does not treat the monitored machine's label as a
remote destination. This is documented in `docs/NETWORK_COLLECTOR.md`.

## Suggested evidence exports (roadmap)

- Per-agent control coverage report (which obligations have active policy).
- Time-bounded incident pack (events + findings + evidence) for a regulator.


## Audit-trail integrity — what "tamper-evident" means here

Each `audit_log` entry stores a SHA-256 of the request payload **and** the hash
of the preceding entry, forming a chain (ADR-0010,
`app/sentinel/storage/audit_chain.py`). Editing, deleting or reordering any
record breaks every link after it, and `GET /audit-log/verify` walks the chain
and names the first record where it stops reconciling.

Stated precisely, because the distinction matters to an assessor:

- **Detected** — modification of a stored record, removal of a record, or
  reordering, by anyone who cannot recompute the whole chain forward.
- **Not detected by the chain alone** — an attacker with sustained database
  write access who rewrites every subsequent row. Closing that requires
  anchoring the chain head outside the database: periodic export of
  `last_hash` to append-only storage (Log Analytics archive tier, an
  object-lock bucket, or a notarisation service). This is a **deployment
  control the operator owns**, not something the application provides.
- **Unverified, and reported as such** — rows written before the chain existed
  carry NULL hashes. `verify_chain` reports the first such row as a break
  rather than passing over it. History that was never hashed must never read
  as verified.

Reviewer attribution carries the same posture: a review decision is attributed
to the authenticated Entra ID principal (`oid`), never to a name supplied in
the request body (CR-22). Reading the audit trail requires `sentinel.admin`,
which is a different role from the `sentinel.write` a collector uses and the
`sentinel.approver` a reviewer uses — ingesting, approving, and reading the
trail are three separate authorities (CR-20).


## Payload evidence and personal data

Sentinel keeps a bounded fragment of each captured payload so a finding can
show its context. That fragment is the most sensitive data in the system.

At the collector edge (`app/sentinel/collector/redact.py`) every fragment is
**scrubbed before it is truncated** — structured identifiers (payment cards,
IBANs, email addresses, phone numbers, long national-ID digit runs, bearer
tokens, provider API keys, AWS keys, JWTs) are replaced with a
`[REDACTED:kind]` marker that names what was removed without storing it. The
marker preserves the analyst's signal (*a card number was present*) while
keeping the value out of storage, the dashboard and the SIEM export.

Scrub-then-truncate is the deliberate order: truncating first would crop a
secret out of the *preview* while leaving it in the payload the scrubber never
saw.

**Stated limitation.** This is pattern-based scrubbing. It handles structured
identifiers reliably and **free-text personal data not at all** — a customer's
name written in prose will survive. It reduces exposure; it is not a guarantee,
and it is not a substitute for deciding whether regulated data should transit
an agent at all. Deployments handling special-category data under GDPR Art. 9
should treat the evidence store as in-scope personal data: apply retention
limits, restrict `sentinel.read` accordingly, and consider disabling payload
previews entirely.
