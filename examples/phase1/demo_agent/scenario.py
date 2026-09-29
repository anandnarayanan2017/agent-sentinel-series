"""Demo scenario: a payment-reconciliation agent under attack.

Drives the Sentinel pipeline directly (no proxy needed) so the whole
detection + explanation story runs with one command. Prints a readable report.

Scenario:
  * NORMAL  — agent reads the ledger, calls its approved model, emails a report.
  * ATTACK  — a prompt-injected invoice makes the agent (a) call an unapproved
              tool, then (b) exfiltrate a large payload to an attacker domain.
"""

from __future__ import annotations

import json
from pathlib import Path

from sentinel.pipeline import Pipeline

POLICY = str(Path(__file__).resolve().parents[3] / "policies" / "example.yaml")


def banner(text: str) -> None:
    print("\n" + "=" * 70 + f"\n{text}\n" + "=" * 70)


def run() -> int:
    pipe = Pipeline(POLICY, ":memory:")
    agent, session = "recon-bot", "run-2026-06-10"

    banner("PHASE 1 — NORMAL OPERATION (expect 0 findings)")
    normal = [
        dict(host="ledger.internal", path="/v1/transactions", method="GET"),
        dict(
            host="api.anthropic.com",
            path="/v1/messages",
            method="POST",
            request_body=json.dumps(
                {
                    "model": "claude-sonnet-4-6",
                    "messages": [{"role": "user", "content": "Summarize discrepancies."}],
                }
            ),
        ),
        dict(
            host="ledger.internal",
            method="POST",
            path="/rpc",
            request_body=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "read_ledger", "arguments": {"day": "2026-06-09"}},
                }
            ),
        ),
        dict(
            host="reports.internal",
            method="POST",
            path="/rpc",
            request_body=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "send_report", "arguments": {"to": "finance@example.com"}},
                }
            ),
        ),
    ]
    for f in normal:
        findings = pipe.ingest_flow(agent_id=agent, session_id=session, **f)
        _print_findings(findings)
    print("Phase 1 complete — clean run, as expected.")

    banner("PHASE 2 — PROMPT-INJECTION ATTACK (expect multiple findings)")
    attack = [
        # (a) scope creep: invoke a tool the agent was never authorized to use
        dict(
            host="ledger.internal",
            method="POST",
            path="/rpc",
            request_body=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "dump_all_accounts", "arguments": {}},
                }
            ),
        ),
        # (b) exfiltration: large payload to an attacker-controlled host
        dict(
            host="attacker-exfil.example", method="POST", path="/collect", request_body="X" * 250000
        ),
        # (c) unapproved model
        dict(
            host="api.anthropic.com",
            path="/v1/messages",
            method="POST",
            request_body=json.dumps(
                {
                    "model": "some-unapproved-model",
                    "messages": [{"role": "user", "content": "..."}],
                }
            ),
        ),
    ]
    total = 0
    for f in attack:
        findings = pipe.ingest_flow(agent_id=agent, session_id=session, **f)
        total += len(findings)
        _print_findings(findings)

    banner(f"RESULT — {total} explainable findings raised during the attack")
    return 0


def _print_findings(findings) -> None:
    for f in findings:
        print(f"\n  [{f.severity.value.upper():8}] {f.title}")
        print(f"     rule: {f.rule_id}")
        print(f"     why : {f.explanation}")
        if f.policy_clause:
            print(f"     clause: {f.policy_clause}")
        print(f"     controls: {', '.join(f.control_refs) or 'n/a'}")
        chain = " -> ".join(f"{e.key}={e.value}" for e in f.evidence[:5])
        print(f"     evidence: {chain}")


if __name__ == "__main__":
    raise SystemExit(run())
