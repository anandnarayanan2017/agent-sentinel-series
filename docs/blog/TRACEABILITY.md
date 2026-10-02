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

## Regulatory scope

Control references are navigation aids, not a certification or a legal
conclusion. DORA applicability depends on entity and deployment scope. The EU
AI Act Article 12 logging obligation applies to high-risk AI systems in scope.
For Luxembourg, DORA overlaps changed the applicability of CSSF Circulars
20/750 and 22/806; use the amended circulars and current CSSF guidance.

- [DORA — Regulation (EU) 2022/2554](https://eur-lex.europa.eu/eli/reg/2022/2554/oj/eng)
- [EU AI Act — Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng)
- [CSSF update on DORA overlap and Circulars 20/750, 22/806 and 25/882](https://www.cssf.lu/en/2025/04/updates-of-several-cssf-circulars-related-to-ict-risk-management-and-use-of-ict-third-parties-ict-outsourcing/)
