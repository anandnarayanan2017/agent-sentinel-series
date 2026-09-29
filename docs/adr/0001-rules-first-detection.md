# ADR-0001: Rules-first (policy-as-code) detection, statistics second

**Status:** Accepted
**Date:** 2026-06-10
**Deciders:** Founder / sole IC

## Context

The product detects misbehaving AI agents in fintech. Two detection philosophies
compete: (A) learn "normal" with ML and flag anomalies, or (B) declare allowed
behavior explicitly and flag violations. Fintech buyers (risk, compliance,
security) must be able to audit and defend every alert to a regulator.

## Decision

Make deterministic **policy-as-code** the primary detector. Statistical
baselining is a secondary, lower-severity signal that adds context but never
fires high-severity alerts on its own.

## Options Considered

### Option A: ML-first anomaly detection
| Dimension | Assessment |
|-----------|------------|
| Complexity | High (training, drift, tuning) |
| Auditability | Low (opaque scores) |
| Time to value | Slow (needs data + tuning) |
| Solo-IC fit | Poor |

**Pros:** catches unknown-unknowns; demo-friendly.
**Cons:** false positives; hard to explain to an auditor; cold-start problem.

### Option B: Rules-first policy-as-code
| Dimension | Assessment |
|-----------|------------|
| Complexity | Low |
| Auditability | High (human-readable YAML clause) |
| Time to value | Immediate |
| Solo-IC fit | Strong |

**Pros:** every alert maps to a readable clause and a control reference;
deterministic; trivially testable.
**Cons:** only catches what you declare; requires defining policy per agent.

## Trade-off Analysis

The cold-start and explainability problems of ML are fatal in a regulated sale,
where "why did this fire?" must have a one-line answer. Rules give that for free
and let a solo IC ship something testable in week 4. Anomaly detection is kept as
a complementary low-severity layer to surface novelty without owning decisions.

## Consequences

- Easier: audits, explanations, tests, demos, compliance mapping.
- Harder: detecting genuinely novel attacks not covered by any clause.
- Revisit: introduce ML scoring as an additive signal once there is real traffic
  data and a labeled feedback loop, never as the sole basis for a high-severity
  finding.

## Action Items

1. [x] Implement deterministic policy engine (`detection/policy.py`, `engine.py`).
2. [x] Implement statistical baseline as secondary signal (`detection/baseline.py`).
3. [ ] Add labeled-feedback capture before considering ML scoring (post-launch).
