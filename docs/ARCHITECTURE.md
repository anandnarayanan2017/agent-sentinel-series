# Agent Sentinel — Architecture

Agent Sentinel is an explainable flight recorder and behavioral firewall for AI agents and machine-to-machine identities. The architecture is deliberately **rules-first**: deterministic policy is the authoritative detection layer; statistical and sequence analytics add context but do not silently become enforcement authority.


## 1. System context

```mermaid
flowchart LR
    subgraph Agents["AI agents / M2M identities"]
        A1["Reconciliation bot"]
        A2["KYC assistant"]
        A3["Payments copilot"]
    end

    subgraph Capture["Collector front-ends"]
        P["Egress proxy"]
        S["SDK wrappers"]
        N["Network visibility\ntshark / scoped nmap"]
        E["eBPF probe\nfuture"]
    end

    subgraph Sentinel["Agent Sentinel"]
        API["FastAPI ingest/query API"]
        PA["Parsers + normalization"]
        EV["AgentEvent"]
        DET["Detection engine"]
        EXP["Explainability"]
        ST["Storage"]
    end

    subgraph Consumers["Security operations"]
        D["Dashboard"]
        SIEM["SIEM / alerting"]
        AN["Analyst / CISO"]
    end

    A1 & A2 & A3 -->|"LLM / MCP / tool / egress"| P
    A1 & A2 & A3 --> S
    A1 & A2 & A3 -.-> N
    A1 & A2 & A3 -.-> E
    P & S & N --> API
    E -.-> API
    API --> PA --> EV --> DET --> EXP
    EV --> ST
    EXP --> ST
    ST --> API
    API --> D & SIEM
    D --> AN
```

Solid paths represent current architectural capabilities; dashed paths are optional/future visibility mechanisms. Every collector converges on the same normalized event contract.

## 2. Container / logical architecture

```mermaid
flowchart TB
    subgraph CapturePlane[Capture plane]
        PROXY[mitmproxy addon]
        SDK[Azure OpenAI / Anthropic wrappers]
        NET[Network collector]
    end

    subgraph ServicePlane[Service plane]
        API[FastAPI]
        PIPE[Pipeline]
        PARSER[Parsers]
        ENGINE[Detection Engine]
        POLICY[L1 Policy-as-code]
        BASE[L2 Statistical baseline]
        SEQ[L3 Sequence analytics]
        EXPLAIN[Explainability]
        EXPORT[Alerting / SIEM exporters]
    end

    subgraph DataPlane[Data plane]
        STORE[StoreBase]
        DUCK[(DuckDB)]
        PG[(Postgres / TimescaleDB)]
        AUDIT[(Audit records)]
        APPROVAL[(Approval workflow)]
        POLICIES[(Versioned YAML policies)]
    end

    subgraph Experience[Experience plane]
        DASH[React dashboard]
        SOC[SOC / reviewer]
    end

    PROXY & SDK & NET --> API --> PIPE --> PARSER --> ENGINE
    ENGINE --> POLICY
    ENGINE --> BASE
    ENGINE --> SEQ
    POLICY & BASE & SEQ --> EXPLAIN
    PIPE --> STORE
    EXPLAIN --> STORE
    STORE --> DUCK & PG
    PG --> AUDIT & APPROVAL
    POLICIES --> POLICY
    API --> EXPORT
    API --> DASH --> SOC
```

## 3. Detection pipeline

```mermaid
sequenceDiagram
    participant C as Collector
    participant P as Pipeline
    participant Parse as Parser
    participant Store
    participant Eng as Engine
    participant Pol as L1 Policy
    participant Base as L2 Baseline
    participant Seq as L3 Sequence
    participant Exp as Explainer

    C->>P: captured activity
    P->>Parse: parse + normalize
    Parse-->>P: AgentEvent
    P->>Store: persist event
    P->>Eng: evaluate(event)
    Eng->>Pol: deterministic checks
    Pol-->>Eng: violations / clauses
    Eng->>Base: statistical deviation
    Base-->>Eng: anomaly context
    opt SENTINEL_SEQ_ENABLED
        Eng->>Seq: sequence evaluation
        Seq-->>Eng: advisory context
    end
    Eng->>Exp: structured reason + evidence
    Exp-->>Eng: Finding
    Eng->>Store: persist finding
    Eng-->>P: findings
```

The trust order is **L1 deterministic policy → L2 statistical context → optional L3 sequence context**. L3 is feature-flagged, advisory-only and must not create an independent deny path.

## 4. Trust-boundary architecture

```mermaid
flowchart LR
    subgraph T0[TB0 — externally influenced]
        AG[Agent]
        LLM[LLM response]
        MCP[MCP / tool output]
        REMOTE[Remote services]
    end

    subgraph T1[TB1 — capture]
        COL[Collectors]
    end

    subgraph T2[TB2 — normalization]
        VAL[Schema validation]
        EVENT[Typed AgentEvent]
    end

    subgraph T3[TB3 — decision]
        POLICY[Deterministic policy]
        ANALYTICS[Advisory analytics]
        EXPLAIN[Evidence-based explanation]
    end

    subgraph T4[TB4 — persistence / access]
        STORE[(Storage)]
        API[Authenticated API]
        AUDIT[(Audit)]
    end

    AG --> COL
    LLM & MCP & REMOTE --> COL
    COL --> VAL --> EVENT
    EVENT --> POLICY & ANALYTICS
    POLICY & ANALYTICS --> EXPLAIN
    EVENT & EXPLAIN --> STORE --> API --> AUDIT
```

**Security invariant:** external/model/tool content is data. It cannot acquire policy authority merely because it appears in a captured payload.

## 5. Data model

```mermaid
classDiagram
    class AgentEvent {
        +event_id
        +ts
        +agent_id
        +session_id
        +ActionType action
        +host
        +method
        +path
        +model
        +tool_name
        +bytes_out
        +bytes_in
        +attributes
        +Evidence[] evidence
    }
    class Finding {
        +finding_id
        +rule_id
        +Severity severity
        +explanation
        +policy_clause
        +severity_rationale
        +event_ids[]
        +Evidence[] evidence
        +control_refs[]
    }
    class Evidence {
        +key
        +value
        +redacted
    }
    class AgentPolicy {
        +agent_id
        +allowed_hosts[]
        +allowed_tools[]
        +allowed_models[]
        +max_tool_calls_per_session
        +max_bytes_out_per_call
        +control_refs[]
    }

    AgentEvent "1" --> "*" Evidence
    Finding "1" --> "*" Evidence
    Finding "*" --> "1..*" AgentEvent : event_ids
    AgentPolicy ..> Finding : evaluated by policy engine
```

## 6. Storage architecture

```mermaid
flowchart TB
    PIPE[Pipeline / API] --> STORE[StoreBase]
    STORE -->|embedded default| DUCK[(DuckDB)]
    STORE -->|DATABASE_URL| PG[(Postgres / TimescaleDB)]
    DUCK --> DEV[Dev / demo]
    PG --> PROD[Production]
    PG --> AUDIT[Tamper-evident audit]
    PG --> APPROVAL[HIGH / CRITICAL review workflow]

    ENGINE[Engine] --> STATE[(In-process counters / baselines / L3 buffers)]
    STATE -. scale-out prerequisite .-> SHARED[(Future shared runtime state)]
```

DuckDB intentionally provides a reduced-function local mode. Deployments requiring retained audit trails or review workflows require the production Postgres backend. Current behavioral counters/baselines/session buffers are per-process; multi-replica consistency therefore requires shared runtime state before horizontal scaling is considered authoritative.

### Backend capability matrix

| Capability | DuckDB (default, embedded) | Postgres/TimescaleDB |
|---|---|---|
| Events + findings | ✅ | ✅ |
| Aggregate stats | ✅ | ✅ |
| Hash-chained audit log | ❌ refuses (501) | ✅ |
| Audit chain verification | ❌ refuses (501) | ✅ |
| Approval workflow (HIGH/CRITICAL review) | ❌ refuses (501) | ✅ |

"Reduced-function" means these surfaces **raise** on DuckDB
(`AuditNotSupportedError` / `ApprovalsNotSupportedError`, both
`NotImplementedError` subclasses), and the API maps that to **501 Not
Implemented** with the remedy in the message.

They were previously silent no-ops returning success, which is not the same
thing as safe: `POST /approvals/{id}` answered `200 {"msg": "recorded"}` having
recorded nothing, and `GET /audit-log` returned an empty list indistinguishable
from "no activity" — on the backend the quickstart actually runs. A backend that
cannot record a compliance decision must refuse it, and name the remedy (CR-18).

### Runtime state and concurrency

`Pipeline` holds two locks rather than one. The engine's in-memory state
(volume counters, baselines, L3 session buffers) is shared across Starlette's
threadpool and always needs serializing. Storage writes are serialized *only*
on a backend that declares `StoreBase.thread_safe = False` — the embedded
DuckDB connection. On PostgreSQL, whose pooled per-thread connections are
already safe, storage writes run concurrently. A single lock around both
previously capped ingest throughput at one flow at a time on every backend
(CR-19).

The shared lock is an `RLock`: `engine.evaluate()` reads the store through
`BaselineStore.get()`, so on DuckDB the store lock is re-entered by the same
thread.

## 7. Deployment topology

```mermaid
flowchart TB
    subgraph Workloads[Workload network]
        AG[Agent workloads]
        SDK[SDK interceptor]
        PX[Egress proxy]
    end

    subgraph SentinelZone[Sentinel application zone]
        GW[Ingress / gateway]
        API[Sentinel API]
        WORK[Detection workers]
        EXP[Explainability]
        OUT[SIEM / alert exporters]
    end

    subgraph DataZone[Data zone]
        PG[(Postgres / TimescaleDB)]
        POL[(Policy repository)]
        AUD[(Audit trail)]
    end

    subgraph Ops[Operations zone]
        UI[Dashboard]
        SOC[SOC / security reviewer]
    end

    AG --> SDK --> GW
    AG --> PX --> GW
    GW --> API --> WORK
    WORK --> POL
    WORK --> EXP
    WORK & EXP --> PG
    PG --> AUD
    API --> OUT
    API --> UI --> SOC
```

## 8. Network collector boundary

```mermaid
flowchart LR
    SCOPE[Authorized target scope] --> ADAPTER[Typed collector adapter]
    ADAPTER --> TSHARK[tshark capture]
    ADAPTER --> NMAP[scoped nmap discovery]
    TSHARK & NMAP --> NORMALIZE[Normalized evidence]
    NORMALIZE --> PIPE[Sentinel pipeline]

    DENY["No arbitrary shell / command-string interface"] -. invariant .-> ADAPTER
```

Active discovery is not a generic execution facility. Target scope, arguments, duration and resource use must be bounded independently of any agent/model request.

## 9. Architectural decisions and trade-offs

| Decision | Choice | Trade-off / rationale |
|---|---|---|
| Primary detection | Deterministic policy-as-code | Strong auditability and predictable behavior; requires explicit policy lifecycle. |
| Secondary detection | Statistical baseline | Adds behavioral context without replacing policy authority. |
| Sequence detection | Optional advisory L3 | Better multi-step context; feature flag and fail-open behavior limit operational coupling. |
| Capture | Proxy + SDK wrappers | Proxy reduces agent changes; wrappers reduce infrastructure changes. Both normalize to one schema. |
| Event contract | `AgentEvent` | Collector independence and stable downstream semantics. |
| Explanation | Deterministic from evidence | Audit-friendly; less free-form than generative explanation. |
| Local storage | DuckDB | Simple single-node operation; intentionally lacks production audit/approval semantics. |
| Production storage | Postgres/TimescaleDB | Multi-writer durability and workflow support at greater operational cost. |
| Network visibility | Bounded collector adapters | Useful visibility without turning Sentinel into an arbitrary remote shell. |

## 10. Architecture principles

1. **Rules first, models second.** Deterministic policy is the authoritative detection mechanism.
2. **Normalize once.** All collectors converge on a typed, transport-independent event contract.
3. **Evidence is the source of truth.** Explanations and compliance mappings derive from structured evidence.
4. **Treat observed content as untrusted data.** LLM/tool/network strings never become instructions to Sentinel.
5. **Separate observation from execution.** Network visibility adapters expose narrow capabilities, not arbitrary shell access.
6. **Make degraded modes explicit.** DuckDB and optional analytics have intentionally different guarantees from the production stack.
7. **Do not hide distributed-state limitations.** Scale-out requires shared state for counters, baselines and session-aware analytics.
8. **Prefer auditable failure behavior.** Optional analytics may fail open for ingestion; authoritative schema/policy/security controls must remain explicit and observable.

See [`docs/adr/0001-rules-first-detection.md`](adr/0001-rules-first-detection.md).
