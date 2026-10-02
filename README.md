# Agent Sentinel (blog companion)

Code, tests, and write-ups for the 10-part **Agent Sentinel** series: an
explainable runtime observability and policy-detection layer for AI agents in
regulated environments.

```text
Detect. Explain. Export.   (Enforce is roadmap)
```

Start at [`docs/blog/README.md`](docs/blog/README.md): each part has a
plain-English LinkedIn post, a technical write-up, the code it cites, and its tests.
Parts are published weekly, one per Tuesday; later parts are marked "coming soon" there.

## Layout

| Path | What it holds |
|---|---|
| `docs/blog/` | LinkedIn posts (plain English), technical write-ups, images, traceability matrix |
| `app/sentinel/` | Collectors, detection engine, explainer, storage, API, SIEM export |
| `app/sentinel_sequence/` | The optional sequence-anomaly model (advisory only, off by default) |
| `app/tests/` | Regression tests the traceability matrix points at |
| `policies/` | Example policy files |
| `docs/` | Architecture, compliance mapping, ADR-0001 |
| `examples/`, `dashboard/`, `start_phase2.sh` | Demo agents and the CISO dashboard the posts mention |

## Run the tests

```bash
python -m venv .venv && . .venv/bin/activate
pip install pydantic duckdb pyyaml fastapi uvicorn numpy pytest httpx psycopg2-binary
python -m pytest -q -m "not integration"
```

Expected: 386 passed with `pip install -e ".[auth,postgres]"` (the 8 JWT tests skip without `python-jose`).
Check the write-ups' links with `python scripts/check_links.py`.
