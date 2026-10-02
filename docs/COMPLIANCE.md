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
