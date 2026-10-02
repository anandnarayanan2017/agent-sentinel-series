"""DuckDB `Store` reads run on API worker threads, outside the Pipeline's write
lock. They used to share one connection, so parallel `/stats`, `/findings` and
`/events` calls interleaved result sets and `stats()` intermittently raised."""

from concurrent.futures import ThreadPoolExecutor

from sentinel.schema.events import ActionType, AgentEvent, Finding, Severity
from sentinel.storage.store import Store


def test_parallel_reads_do_not_interfere():
    store = Store(":memory:")
    for i in range(40):
        e = AgentEvent(agent_id=f"a{i % 4}", session_id="s", action=ActionType.NETWORK_CALL, host=f"h{i}")
        store.insert_event(e)
        store.insert_finding(
            Finding(agent_id=e.agent_id, session_id="s", rule_id="r", title="t", severity=Severity.HIGH)
        )

    calls = [store.stats, lambda: store.list_findings(500), lambda: store.list_events(500)] * 100
    with ThreadPoolExecutor(16) as pool:
        results = list(pool.map(lambda f: f(), calls))

    stats = [r for r in results if isinstance(r, dict)]
    assert stats and all(s["total_events"] == 40 and s["total_findings"] == 40 for s in stats)
    assert all(len(r) == 40 for r in results if isinstance(r, list))
