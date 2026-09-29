# Publication traceability: plain English → design → code → proof

<a id="publication-traceability"></a>

This matrix is the public contract for the series. A claim is **current** only
when the linked implementation and regression test exist. Items marked
**roadmap** are not implemented and must not be described as current behavior.
Relative links deliberately resolve against the branch or commit being read,
so the article, diagram, code, and tests stay on the same repository version.

| Part | LinkedIn post | Technical design / diagram | Current implementation | Regression proof | Status boundary |
|---|---|---|---|---|---|
| 1 | [Flight recorder](linkedin/01-why-agents-need-a-flight-recorder.md) | [System context](technical-details/01-why-agents-need-a-flight-recorder.md#c4-level-1--system-context) | [`Pipeline.ingest_event`](../../app/sentinel/pipeline.py), [`Engine.evaluate`](../../app/sentinel/detection/engine.py) | [`test_pipeline.py`](../../app/tests/test_pipeline.py) | Detection and evidence; no pre-action blocking |
| 2 | [Real model calls](linkedin/02-simulation-to-real-models.md) | [Phase 2 flow](technical-details/02-simulation-to-real-models.md#phase-2--real-cloud-models) | [Azure wrapper](../../app/sentinel/collector/azure_openai.py), [Anthropic wrapper](../../app/sentinel/collector/anthropic_sdk.py), [reporter](../../app/sentinel/collector/sdk_base.py), [redaction](../../app/sentinel/collector/redaction.py) | [`test_collector_contracts.py`](../../app/tests/test_collector_contracts.py) | Wrapped methods only; fail-open delivery can create a visible log gap |
| 3 | [Rules first](linkedin/03-rules-first-statistics-second.md) | [Decision flow](technical-details/03-rules-first-statistics-second.md#policy-decision-tree) | [`Engine`](../../app/sentinel/detection/engine.py), [`PolicySet`](../../app/sentinel/detection/policy.py), [sequence layer](../../app/sentinel/detection/sequence_layer.py) | [`test_engine_l3_construction.py`](../../app/tests/test_engine_l3_construction.py), [`test_sequence_layer.py`](../../app/tests/test_sequence_layer.py) | All layers produce findings; none deny the action |
| 4 | [Enterprise foundation](linkedin/04-enterprise-foundation.md) | [Enterprise architecture](technical-details/04-enterprise-foundation.md#phase-3-enterprise-architecture) | [auth](../../app/sentinel/api/auth.py), [audit](../../app/sentinel/api/audit.py), [PostgreSQL store](../../app/sentinel/storage/pg_store.py) | [`test_auth.py`](../../app/tests/test_auth.py), [`test_audit_middleware.py`](../../app/tests/test_audit_middleware.py), [`test_api_main.py`](../../app/tests/test_api_main.py) | API auth exists; built-in dashboard token acquisition is roadmap |
| 5 | [SOC export](linkedin/05-soc-and-whats-next.md) | [SOC architecture](technical-details/05-soc-and-whats-next.md#soc-integration-architecture) | [Log Analytics](../../app/sentinel/siem/log_analytics.py), [webhooks](../../app/sentinel/alerting/webhook.py) | [`test_siem_log_analytics.py`](../../app/tests/test_siem_log_analytics.py), [`test_alerting_webhook.py`](../../app/tests/test_alerting_webhook.py) | Detect, explain, export now; enforce and hash chain are roadmap |
| 6 | [HTTP blind spot](linkedin/06-the-blind-spot-every-agent-firewall-has.md) | [Two views](technical-details/06-the-blind-spot-every-agent-firewall-has.md#two-very-different-views-of-the-same-host) | [proxy](../../app/sentinel/collector/proxy.py), [network collector](../../app/sentinel/collector/network_scan.py) | [`test_network_capture.py`](../../app/tests/test_network_capture.py) | Visibility covers configured collectors, never every process action |
| 7 | [Scoped visibility](linkedin/07-visibility-without-a-blank-check.md) | [Attribution flow](technical-details/07-visibility-without-a-blank-check.md#what-happens-to-an-address-that-isnt-mapped) | [host map](../../app/sentinel/collector/host_map.py), [scan config](../../app/sentinel/collector/scan_config.py) | [`test_network_host_map.py`](../../app/tests/test_network_host_map.py), [`test_network_capture.py`](../../app/tests/test_network_capture.py) | One IP literal per entry; both modes off by default |
| 8 | [Explainable port finding](linkedin/08-from-open-port-to-explainable-finding.md) | [Scan-to-finding sequence](technical-details/08-from-open-port-to-explainable-finding.md#scan--parse--diff--event--finding) | [`InventoryJob`](../../app/sentinel/collector/network_scan.py), [`baseline.new_listening_port`](../../app/sentinel/detection/engine.py) | [`test_network_inventory.py`](../../app/tests/test_network_inventory.py), [`test_network_pipeline.py`](../../app/tests/test_network_pipeline.py) | Only inventory `new_open_port`; full range means TCP 1–65535 |
| 9 | [False-positive regression](linkedin/09-built-to-fail-safe-not-fail-quiet.md) | [Correct host semantics](technical-details/09-built-to-fail-safe-not-fail-quiet.md#the-fix-is-structural-not-a-patch) | [`parse_ek_line`](../../app/sentinel/collector/network_scan.py), [`net.host_not_allowed`](../../app/sentinel/detection/engine.py) | [`test_network_pipeline.py`](../../app/tests/test_network_pipeline.py), [`test_network_capture.py`](../../app/tests/test_network_capture.py) | Host-map labels identify the monitored machine; they are not remote destinations |
| 10 | [Known limits](linkedin/10-what-this-doesnt-do-yet.md) | [Enablement state](technical-details/10-what-this-doesnt-do-yet.md#gap-two-shipped-tested-and-off) | [capture supervisor](../../app/sentinel/collector/network_scan.py), [policy schema](../../app/sentinel/detection/policy.py) | [`test_network_capture.py`](../../app/tests/test_network_capture.py), [`test_network_spec_fidelity_audit.py`](../../app/tests/test_network_spec_fidelity_audit.py) | No IP/CIDR egress policy and no network-layer enforcement |

## Regulatory scope

Control references are navigation aids, not a certification or a legal
conclusion. DORA applicability depends on entity and deployment scope. The EU
AI Act Article 12 logging obligation applies to high-risk AI systems in scope.
For Luxembourg, DORA overlaps changed the applicability of CSSF Circulars
20/750 and 22/806; use the amended circulars and current CSSF guidance.

- [DORA — Regulation (EU) 2022/2554](https://eur-lex.europa.eu/eli/reg/2022/2554/oj/eng)
- [EU AI Act — Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng)
- [CSSF update on DORA overlap and Circulars 20/750, 22/806 and 25/882](https://www.cssf.lu/en/2025/04/updates-of-several-cssf-circulars-related-to-ict-risk-management-and-use-of-ict-third-parties-ict-outsourcing/)
