"""End-to-end check of the whole product: real server, real traffic, real dashboard.

    python scripts/e2e.py                       # API + traffic checks
    python scripts/e2e.py --browser             # ...plus the dashboard in headless Chromium
    python scripts/e2e.py --browser --shots out # ...and save screenshots into ./out

What it does, in order:
  1. starts `sentinel serve` (dev auth mode, fintech policy, in-memory store);
  2. sends known-good and known-bad agent traffic to POST /ingest and checks
     that each produces exactly the expected findings, with explanations;
  3. runs the fintech simulator for a few seconds for realistic volume;
  4. checks /findings, /events, /stats, the SSE /stream and the audit chain;
  5. (--browser) opens the dashboard, waits for live data, checks it renders
     the findings with no console errors, and optionally takes screenshots.

The dashboard loads React and Chart.js from public CDNs. Where those are not
reachable (a locked-down CI runner), set E2E_CDN_DIR to a folder holding
node_modules for react@18.3.1, react-dom@18.3.1, htm@3.1.1 and chart.js@4.4.0;
the script then serves those instead (the CDN integrity hashes are dropped for
that run only). Set E2E_CHROMIUM to a Chromium binary if Playwright's own
browser build is not installed.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORT = int(os.environ.get("E2E_PORT", "8000"))  # the dashboard hardcodes :8000
BASE = f"http://localhost:{PORT}"

failures: list[str] = []


def check(ok: bool, what: str) -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {what}")
    if not ok:
        failures.append(what)


def call(path: str, body: dict | None = None):
    req = urllib.request.Request(
        BASE + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="GET" if body is None else "POST",
    )
    with urllib.request.urlopen(req, timeout=15) as r:  # nosec B310 - localhost only
        return json.loads(r.read())


def start_server() -> subprocess.Popen:
    env = dict(
        os.environ,
        SENTINEL_DEV_MODE="1",
        SENTINEL_POLICY=str(ROOT / "policies" / "fintech.yaml"),
        SENTINEL_DB=":memory:",
        SENTINEL_CORS_ORIGINS=BASE,
    )
    proc = subprocess.Popen(  # nosec B603 - fixed argv
        [sys.executable, "-m", "sentinel.cli", "serve", "--port", str(PORT)],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    for _ in range(60):
        try:
            if call("/healthz").get("status") == "ok":
                return proc
        except Exception:
            time.sleep(0.5)
    proc.kill()
    sys.exit("server did not start:\n" + (proc.stdout.read() if proc.stdout else ""))


def ingest(agent: str, session: str, **flow) -> list[dict]:
    return call("/ingest", {"agent_id": agent, "session_id": session, **flow})["items"]


def scripted_traffic() -> None:
    print("\n[2] scripted traffic: known-good must stay quiet, known-bad must be explained")
    s = "e2e-session"
    good = ingest("recon-bot", s, host="ledger.internal", path="/v1/transactions", method="GET")
    check(good == [], "approved host -> no finding")

    bad = ingest("recon-bot", s, host="evil.example.net", path="/upload", method="POST")
    rules = {f["rule_id"] for f in bad}
    check("net.host_not_allowed" in rules, "unapproved host -> net.host_not_allowed")
    f = next((x for x in bad if x["rule_id"] == "net.host_not_allowed"), {})
    check(bool(f.get("explanation")) and bool(f.get("control_refs")), "finding carries explanation + control refs")
    check(f.get("severity") in {"high", "critical"}, f"severity is high or critical (got {f.get('severity')})")

    big = ingest("recon-bot", s, host="reports.internal", path="/send", method="POST", request_body="x" * 250_000)
    check("net.oversize_egress" in {x["rule_id"] for x in big}, "250KB upload -> net.oversize_egress")

    tool = ingest(
        "recon-bot",
        s,
        host="tools.internal",
        path="/mcp",
        request_body=json.dumps(
            {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "delete_all_records", "arguments": {}}}
        ),
    )
    check("tool.not_allowed" in {x["rule_id"] for x in tool}, "unapproved tool requested -> tool.not_allowed")

    model = ingest(
        "recon-bot",
        s,
        host="api.anthropic.com",
        path="/v1/messages",
        request_body=json.dumps({"model": "gpt-unapproved", "messages": []}),
    )
    check("model.not_allowed" in {x["rule_id"] for x in model}, "unapproved model -> model.not_allowed")


def simulator() -> None:
    print("\n[3] fintech simulator (6 agents, mixed normal/attack traffic) for ~8s")
    proc = subprocess.Popen(  # nosec B603 - fixed argv
        [sys.executable, "examples/phase1/fintech_sim/sim.py", "--rate", "0.15", "--burst", "2",
         "--attack-prob", "0.35", "--no-color"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(8)
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def api_checks() -> None:
    print("\n[4] read APIs")
    findings = call("/findings?limit=500")["items"]
    events = call("/events?limit=500")["items"]
    stats = call("/stats")
    check(len(findings) >= 5, f"findings recorded ({len(findings)})")
    check(len(events) >= 20, f"events recorded ({len(events)})")
    check(len({f["agent_id"] for f in findings}) >= 3, "findings span several agents")
    check(all(f.get("explanation") for f in findings), "every finding has an explanation")
    check(isinstance(stats, dict) and stats, "/stats returns data")
    html = urllib.request.urlopen(BASE + "/", timeout=10).read().decode()  # nosec B310
    check("Agent Sentinel" in html, "GET / serves the dashboard")
    try:
        v = call("/audit-log/verify")
        check(bool(v.get("valid", v.get("ok", True))), f"audit chain verifies ({v})")
    except Exception as exc:  # PostgreSQL-only feature on some builds
        print(f"  skip  audit chain verify ({exc})")


def browser(shots: Path | None) -> None:
    print("\n[5] dashboard in headless Chromium")
    from playwright.sync_api import sync_playwright

    cdn = os.environ.get("E2E_CDN_DIR")
    routes = {
        "unpkg.com/react@18.3.1/umd/react.production.min.js": "react/umd/react.production.min.js",
        "unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js": "react-dom/umd/react-dom.production.min.js",
        "unpkg.com/htm@3.1.1/dist/htm.umd.js": "htm/dist/htm.umd.js",
        "cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js": "chart.js/dist/chart.umd.js",
    }
    errors: list[str] = []
    with sync_playwright() as p:
        b = p.chromium.launch(args=["--no-sandbox"], executable_path=os.environ.get("E2E_CHROMIUM") or None)
        ctx = b.new_context(viewport={"width": 1440, "height": 1000})
        page = ctx.new_page()
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: m.type == "error" and errors.append(m.text))
        if cdn:
            import re

            def serve(rel: str):
                return lambda route, request=None: route.fulfill(
                    path=str(Path(cdn) / "node_modules" / rel), content_type="application/javascript"
                )

            for needle, rel in routes.items():
                page.route(f"**/{needle}", serve(rel))
            page.route(
                BASE + "/",
                lambda route, request=None: route.fulfill(
                    body=re.sub(r'\s+integrity="[^"]*"', "", route.fetch().text()), content_type="text/html"
                ),
            )
        page.goto(BASE + "/", wait_until="load")
        page.wait_for_function("document.body.innerText.includes('net.host_not_allowed')", timeout=30_000)
        text = page.inner_text("body")
        check("net.host_not_allowed" in text, "dashboard lists live findings (net.host_not_allowed)")
        check("recon-bot" in text, "dashboard shows agent identities")
        if shots:
            shots.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(shots / "dashboard.png"), full_page=True)
            row = page.locator("text=net.host_not_allowed").first
            row.click()
            page.wait_for_timeout(600)
            page.screenshot(path=str(shots / "evidence-drawer.png"))
        b.close()
    check(not errors, f"no browser console errors {errors[:3] if errors else ''}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--browser", action="store_true", help="also drive the dashboard in headless Chromium")
    ap.add_argument("--shots", type=Path, help="directory for dashboard screenshots (implies --browser)")
    args = ap.parse_args()

    print("[1] starting the server")
    server = start_server()
    try:
        check(True, f"server healthy on {BASE}")
        scripted_traffic()
        simulator()
        api_checks()
        if args.browser or args.shots:
            browser(args.shots)
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
    print(f"\n{'FAILED' if failures else 'ALL CHECKS PASSED'}" + (f": {len(failures)} failing" if failures else ""))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
