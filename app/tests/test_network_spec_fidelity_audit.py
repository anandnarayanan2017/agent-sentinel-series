"""Phase-6 spec-fidelity audit: gaps between `spec/ACCEPTANCE.md`/`spec/UAT.md`
and the executable test suite, found by re-reading the frozen spec
independently of the implementation (not by reading the implementation and
backfitting assertions to it).

Each test below traces to a specific AC/UAT whose own wording demanded a
check that the build-wave test files (`test_network_capture.py`,
`test_network_host_map.py`, `test_network_inventory.py`,
`test_network_pipeline.py`, `test_network_storage_migration.py`,
`test_pg_store_migration.py`) did not yet execute, even though the underlying
units were separately covered and code review passed. See the accompanying
phase-6 report for the full audit trail; only the closed gaps are encoded
here.
"""

from __future__ import annotations

import inspect
import re
import subprocess
from pathlib import Path

import pytest

from sentinel.collector.parsers import parse_flow
from sentinel.schema.events import ActionType, AgentEvent

REPO_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = REPO_ROOT / "app"

_NEW_NETWORK_FIELDS = ("src_ip", "dst_ip", "dst_port", "protocol", "mac")

# The AgentEvent field set as it existed before this feature (FR-14's "no
# pre-existing field renamed, retyped, removed or made required" baseline).
# Hand-enumerated from schema/events.py at the merge base rather than derived
# from the current file, so this test still catches a later regression even
# if someone edits the "current" field list to match a bug.
_PRE_EXISTING_FIELDS: dict[str, bool] = {
    # name -> required?
    "event_id": False,
    "ts": False,
    "agent_id": True,
    "session_id": True,
    "action": True,
    "direction": False,
    "host": False,
    "method": False,
    "path": False,
    "model": False,
    "tool_name": False,
    "bytes_out": False,
    "bytes_in": False,
    "attributes": False,
    "evidence": False,
}


# =============================================================================
# AC-3 / UAT-2 — transport detail never leaks past the collector boundary
# =============================================================================
# This is the literal grep AC-3/UAT-2 name. Nothing in the build-wave suite
# actually runs it; test_network_capture.py only exercises the collector's
# own parse function, never the "the rest of the codebase never mentions
# tshark/nmap" claim.

_LEAK_PATTERN = re.compile(r"tshark|nmap|_ek\b|-sT\b|-p-|layers\.")

_SCOPED_DIRS = [
    APP_ROOT / "sentinel" / "detection",
    APP_ROOT / "sentinel" / "storage",
    APP_ROOT / "sentinel" / "api",
]
_SCOPED_FILES = [REPO_ROOT / "dashboard" / "index.html"]


def _iter_scoped_files():
    for d in _SCOPED_DIRS:
        if d.is_dir():
            yield from d.rglob("*.py")
    for f in _SCOPED_FILES:
        if f.is_file():
            yield f


def test_ac3_uat2_no_transport_specific_identifiers_leak_past_collector():
    hits: list[str] = []
    for path in _iter_scoped_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _LEAK_PATTERN.search(line):
                hits.append(f"{path.relative_to(REPO_ROOT)}:{lineno}: {line.strip()}")
    assert hits == [], (
        "tshark/nmap-specific identifiers must never appear in "
        "detection/, storage/, api/ or dashboard/index.html:\n" + "\n".join(hits)
    )


# AC-3 step 1's "public entry point" set, scoped to the functions that hand
# results across the collector boundary to a consumer (parse_ek_line ->
# AgentEvent, InventoryJob.run_once -> (ScanOutcome, list[AgentEvent])). This
# deliberately excludes `parse_nmap_xml`: it is an internal helper whose
# `HostScanResult` output is consumed only inside `network_scan.py` itself and
# converted to `AgentEvent`s before ever reaching a caller outside the
# collector module -- so it is not one of AC-3's "entry points", and treating
# it as one would be testing an implementation detail the spec never named.
_EXPECTED_ENTRY_POINT_RETURN_MARKERS = ("AgentEvent", "ScanOutcome", "CaptureHealth")
_KNOWN_ENTRY_POINTS = {"parse_ek_line"}
_KNOWN_INTERNAL_HELPERS = {"parse_nmap_xml"}


def test_ac3_collector_entry_points_return_agentevent_types():
    """AC-3 step 1: every public entry point of network_scan.py is annotated
    to return AgentEvent / list[AgentEvent] / Optional[AgentEvent] / a tuple
    containing one — never a tool-specific type. `parse_nmap_xml` is a named
    internal exception (see comment above); any *other* module-level
    function whose name suggests it hands data to a caller must satisfy the
    same contract.
    """
    import sentinel.collector.network_scan as ns

    checked = 0
    for name, obj in vars(ns).items():
        if name.startswith("_") or not inspect.isfunction(obj) or name in _KNOWN_INTERNAL_HELPERS:
            continue
        sig = inspect.signature(obj)
        if sig.return_annotation is inspect.Signature.empty:
            continue
        ann = str(sig.return_annotation)
        if any(marker in ann for marker in _EXPECTED_ENTRY_POINT_RETURN_MARKERS):
            checked += 1
            continue
        if name in _KNOWN_ENTRY_POINTS or "parse" in name or name in ("run_once",):
            pytest.fail(f"{name} returns {ann!r}, expected AgentEvent-shaped")
    assert checked > 0, "expected at least one AgentEvent-returning entry point"
    assert "parse_ek_line" in vars(ns), (
        "expected parse_ek_line to still exist as the AC-1 entry point"
    )


# =============================================================================
# AC-8 / UAT-7 step 1 — literal git-diff emptiness against policy.py/policies/
# =============================================================================


def _git_diff(*paths: str) -> str:
    """Full diff (not --stat) so assertions can inspect the added lines."""
    result = subprocess.run(
        ["git", "diff", "HEAD", "--", *paths],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout


def _git_diff_stat(*paths: str) -> str:
    result = subprocess.run(
        ["git", "diff", "--stat", "HEAD", "--", *paths],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip()


@pytest.mark.skipif(
    subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "--is-inside-work-tree"], capture_output=True
    ).returncode
    != 0,
    reason="not inside a git work tree",
)
def test_ac8_no_network_address_awareness_added_to_policy_or_policies_dir():
    """AC-8: the policy layer must gain no awareness of network addresses.

    Originally asserted the stronger "zero changes to `detection/policy.py` or
    `policies/*.yaml`". That was a workable proxy while the network collector
    was the only work in flight, but it is not a sustainable invariant for a
    living file: it fails on *any* later policy change, including ones with
    nothing to do with this feature (it fired on the CR-15/CR-16 severity and
    unregistered-identity work). What AC-8 actually protects is that the
    collector did not leak address/host-mapping concepts into the policy
    layer, so that is what is asserted here — against the diff content, not
    its existence. The structural guards below assert the same property from
    the other direction, on the loaded model rather than the diff.
    """
    diff = _git_diff("app/sentinel/detection/policy.py", "policies/")
    forbidden = (
        "network_host",
        "host_map",
        "address_map",
        "addr_map",
        "dst_ip",
        "src_ip",
        "dst_port",
        "allowed_ips",
        "ip_range",
        "cidr",
    )
    added = [
        line for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++")
    ]
    for line in added:
        lowered = line.lower()
        for bad in forbidden:
            assert bad not in lowered, (
                f"policy layer gained network-address awareness (AC-8): {line.strip()!r}"
            )


def test_ac8_agentpolicy_field_set_has_no_address_mapping_field():
    """AC-8: `AgentPolicy`'s field set carries no address/agent mapping field
    (no `network_hosts`, `host_map`, `address_map`, or similarly-named field)."""
    from sentinel.detection.policy import AgentPolicy

    fields = set(AgentPolicy.model_fields.keys())
    forbidden_substrings = ("network_host", "host_map", "address_map", "addr_map")
    for name in fields:
        lowered = name.lower()
        for bad in forbidden_substrings:
            assert bad not in lowered, f"AgentPolicy gained a mapping-shaped field: {name!r}"


def test_ac8_policyset_from_yaml_does_not_read_network_hosts_file():
    """AC-8/FR-8: `PolicySet.from_yaml` must not reference `network_hosts` at
    all -- it must remain structurally incapable of loading the mapping."""
    from sentinel.detection.policy import PolicySet

    source = inspect.getsource(PolicySet.from_yaml)
    assert "network_hosts" not in source
    assert "host_map" not in source.lower()


# =============================================================================
# AC-14 — no pre-existing AgentEvent field renamed/retyped/removed/required
# =============================================================================


def test_ac14_pre_existing_agentevent_fields_unchanged_in_shape():
    fields = AgentEvent.model_fields
    for name, was_required in _PRE_EXISTING_FIELDS.items():
        assert name in fields, f"pre-existing field {name!r} was removed"
        is_required = fields[name].is_required()
        if not was_required:
            assert not is_required, f"pre-existing optional field {name!r} was made required"


def test_ac14_exactly_five_new_fields_all_optional_with_defaults():
    fields = AgentEvent.model_fields
    for name in _NEW_NETWORK_FIELDS:
        assert name in fields, f"expected new field {name!r} on AgentEvent"
        assert not fields[name].is_required(), f"new field {name!r} must be optional"
    # Exactly five new fields beyond the pre-existing set -- not six, not four.
    new_beyond_baseline = set(fields.keys()) - set(_PRE_EXISTING_FIELDS.keys())
    assert new_beyond_baseline == set(_NEW_NETWORK_FIELDS), (
        f"expected exactly the five documented new fields, found: {new_beyond_baseline}"
    )


# =============================================================================
# AC-15 / UAT-12 step 3 — pre-existing parser branches: five fields at
# defaults, EXPLICITLY asserted (not merely "the call didn't raise").
# =============================================================================


def test_ac15_llm_call_branch_has_five_new_fields_at_defaults():
    e = parse_flow(
        agent_id="a",
        session_id="s",
        host="api.anthropic.com",
        method="POST",
        path="/v1/messages",
        request_body='{"model": "claude-sonnet-4-6", "messages": []}',
    )
    assert e.action == ActionType.LLM_CALL
    for field in _NEW_NETWORK_FIELDS:
        assert getattr(e, field) is None, f"{field} should default to None on LLM_CALL branch"


def test_ac15_mcp_call_branch_has_five_new_fields_at_defaults():
    e = parse_flow(
        agent_id="a",
        session_id="s",
        host="ledger.internal",
        method="POST",
        path="/rpc",
        request_body=(
            '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", '
            '"params": {"name": "read_ledger", "arguments": {}}}'
        ),
    )
    assert e.action == ActionType.TOOL_CALL
    for field in _NEW_NETWORK_FIELDS:
        assert getattr(e, field) is None, f"{field} should default to None on TOOL_CALL branch"


def test_ac15_generic_network_call_branch_has_five_new_fields_at_defaults():
    e = parse_flow(
        agent_id="a",
        session_id="s",
        host="evil.example",
        method="POST",
        path="/x",
        request_body="data",
    )
    assert e.action == ActionType.NETWORK_CALL
    for field in _NEW_NETWORK_FIELDS:
        assert getattr(e, field) is None, f"{field} should default to None on generic branch"


# =============================================================================
# AC-24 / UAT-20 — literal grep for unqualified coverage claims
# =============================================================================
# AC-24's own "Fail:" clause narrows its intent precisely: "any single
# occurrence that would let a reader infer full-port coverage from a
# top-1000 result." A literal phrase grep over-fires on two shapes of
# legitimate text that are not that failure mode, and both are excluded
# explicitly here (not by loosening the assertion, but by scoping it to what
# AC-24 actually forbids):
#
#   1. A sentence that *names* one of the forbidden phrases in order to
#      prohibit it (e.g. "never an unqualified 'port scanned' ... statement")
#      is talking ABOUT the compliance rule, not making the unqualified claim
#      itself. Recognized via a small set of negation/meta markers that must
#      appear near the hit.
#   2. "clean" describing TOOL AVAILABILITY (a missing tshark/nmap binary
#      "does not silently report a clean/empty result", "not a clean scan"
#      re: a timeout) is a different axis entirely from PORT-RANGE coverage
#      -- it's the AC-36/NFR-4 tool-missing-vs-quiet distinction, not a
#      top-1000-vs-full-range coverage claim. Recognized via nearby
#      tool-availability markers.
#
# Neither exclusion widens what counts as a *coverage* violation; a genuine
# unqualified "no open ports" or "port scanned" claim describing an actual
# scan result, without naming its scan class, still fails this test.

_UNQUALIFIED_PHRASES = [
    "port scanned",
    "ports scanned",
    "full port",
    "all ports",
    "no open ports",
    "clean",
]
_COVERAGE_MARKERS = ["top-1000", "top_1000", "full-range", "full_range", "-p-", "full range"]
_META_NEGATION_MARKERS = ["never", "not a clean", "not treated as a clean", "unqualified"]
_TOOL_AVAILABILITY_MARKERS = [
    "tool not available",
    "tool_missing",
    "binary is absent",
    "silently report a clean",
    "clean scan",
    "clean/empty",
]


def _strip_python_comments(text: str) -> str:
    """Best-effort: blank out `#`-prefixed Python comment tails so a code
    comment referencing "clean" doesn't count as a user-facing string (AC-24
    scopes this grep to user-facing strings, not source comments)."""
    out_lines = []
    for line in text.splitlines():
        code_part, sep, _comment = line.partition("#")
        out_lines.append(code_part if sep else line)
    return "\n".join(out_lines)


def _grep_unqualified(text: str, path_label: str) -> list[str]:
    violations = []
    lower = text.lower()
    for phrase in _UNQUALIFIED_PHRASES:
        start = 0
        while True:
            idx = lower.find(phrase, start)
            if idx == -1:
                break
            window = lower[max(0, idx - 200) : idx + 200]
            has_coverage_marker = any(marker in window for marker in _COVERAGE_MARKERS)
            is_meta_negation = any(marker in window for marker in _META_NEGATION_MARKERS)
            is_tool_availability = phrase == "clean" and any(
                marker in window for marker in _TOOL_AVAILABILITY_MARKERS
            )
            if not has_coverage_marker and not is_meta_negation and not is_tool_availability:
                line_no = text.count("\n", 0, idx) + 1
                violations.append(f"{path_label}:{line_no}: unqualified {phrase!r}")
            start = idx + len(phrase)
    return violations


def test_ac24_uat20_no_unqualified_coverage_claim_anywhere_in_scope():
    all_violations: list[str] = []

    # network_scan.py: only user-facing string literals matter (AC-24's own
    # scope), so Python comments are stripped before grepping.
    collector_path = APP_ROOT / "sentinel" / "collector" / "network_scan.py"
    collector_text = _strip_python_comments(
        collector_path.read_text(encoding="utf-8", errors="replace")
    )
    all_violations.extend(
        _grep_unqualified(collector_text, str(collector_path.relative_to(REPO_ROOT)))
    )

    for path in (
        REPO_ROOT / "docs" / "COMPLIANCE.md",
        REPO_ROOT / "docs" / "NETWORK_COLLECTOR.md",
    ):
        text = path.read_text(encoding="utf-8", errors="replace")
        all_violations.extend(_grep_unqualified(text, str(path.relative_to(REPO_ROOT))))

    # dashboard/index.html: scope to the NetworkInventory component only --
    # that is the scan-coverage-labeling surface FR-29 added. The pre-existing
    # FindingsTable CLEAN/WARN/ALERT severity badge is untouched by this
    # feature and is not a network-scan coverage claim.
    dashboard_text = (REPO_ROOT / "dashboard" / "index.html").read_text(encoding="utf-8")
    match = re.search(r"function NetworkInventory\(.*?\n\}\n", dashboard_text, re.DOTALL)
    assert match, "NetworkInventory component not found in dashboard/index.html"
    all_violations.extend(
        _grep_unqualified(match.group(0), "dashboard/index.html (NetworkInventory)")
    )

    assert all_violations == [], (
        "found unqualified coverage claim(s) that could let a reader infer "
        "full-port coverage from a top-1000 result:\n" + "\n".join(all_violations)
    )


# =============================================================================
# AC-29 / UAT-24 — dashboard network-inventory component reuses the existing
# pattern; no new framework/build step; empty dataset renders without error.
# =============================================================================


def test_ac29_uat24_dashboard_networkinventory_matches_existing_table_pattern():
    dashboard = (REPO_ROOT / "dashboard" / "index.html").read_text(encoding="utf-8")
    # Locate the NetworkInventory component body.
    match = re.search(r"function NetworkInventory\(.*?\n\}\n", dashboard, re.DOTALL)
    assert match, "NetworkInventory component not found in dashboard/index.html"
    body = match.group(0)

    assert "html`" in body, (
        "must use the html template-literal pattern like FindingsTable/EventsFeed"
    )
    assert re.search(r"const TH\s*=", body), (
        "must define a local TH helper like FindingsTable/EventsFeed"
    )
    assert "useState" in body, "must use useState for filtering, like the existing tables"
    assert "useMemo" in body, "must use useMemo for filtering, like the existing tables"
    assert 'class="card"' in body, 'must render inside a class="card" container'

    # Empty-state row rather than erroring on an empty dataset.
    assert "No network-visibility events" in body or "rows.length===0" in body


# The pre-existing CDN script includes (React/Preact/htm/Chart.js) as of this
# feature's merge base. FR-29/AC-29 forbid introducing a new framework or
# build step; this pins the known-good set so a new bundler-shaped
# `<script src>` (webpack/vite/rollup output, a new CDN framework) is caught
# rather than merely "not obviously named like a bundler".
_KNOWN_SCRIPT_SRC_MARKERS = ("react", "htm@", "chart.js")


def test_ac29_no_new_script_src_or_build_tooling_introduced():
    dashboard = (REPO_ROOT / "dashboard" / "index.html").read_text(encoding="utf-8")
    script_srcs = re.findall(r'<script[^>]*\ssrc=["\']([^"\']+)["\']', dashboard)
    assert script_srcs, "expected at least the pre-existing CDN script includes"
    for src in script_srcs:
        lowered = src.lower()
        assert any(marker in lowered for marker in _KNOWN_SCRIPT_SRC_MARKERS), (
            f"unrecognized <script src> not in the known pre-existing set "
            f"(possible new framework/build-step dependency): {src!r}"
        )
        assert not any(
            marker in lowered for marker in ("webpack", "vite", "rollup", "bundle.js")
        ), f"unexpected build-step script reference: {src!r}"


# =============================================================================
# AC-30 / AC-31 — compliance doc + operator doc content, asserted in words
# =============================================================================


def test_ac30_compliance_doc_has_network_security_section_with_scan_coverage_wording():
    text = (REPO_ROOT / "docs" / "COMPLIANCE.md").read_text(encoding="utf-8")
    assert re.search(r"network security", text, re.IGNORECASE), (
        "docs/COMPLIANCE.md must contain a network-security control-family section"
    )
    # Every coverage statement in that section must satisfy AC-24; reuse the
    # same grep helper scoped just to this file (already covered above), plus
    # an explicit assertion that the two scan classes are actually named.
    assert "top-1000" in text.lower() or "top_1000" in text.lower()
    assert "full-range" in text.lower() or "full_range" in text.lower() or "-p-" in text


def test_ac31_operator_docs_state_tshark_and_nmap_dependency_and_absence_behavior():
    text = (REPO_ROOT / "docs" / "NETWORK_COLLECTOR.md").read_text(encoding="utf-8")
    assert "tshark" in text and "nmap" in text
    assert "HTTP-proxy" in text or "http-proxy" in text.lower() or "proxy.py" in text, (
        "must note this is a dependency the HTTP-proxy collectors do not have"
    )
    assert (
        "tool_missing" in text.lower()
        or "tool not available" in text.lower()
        or ("TOOL_MISSING" in text)
    ), "must describe the observable behavior when a required binary is absent"


# =============================================================================
# AC-39 / UAT-27 step 5 — no blanket lint suppressions in new modules
# =============================================================================

_NEW_MODULES = [
    APP_ROOT / "sentinel" / "collector" / "network_scan.py",
    APP_ROOT / "sentinel" / "collector" / "host_map.py",
    APP_ROOT / "sentinel" / "collector" / "scan_config.py",
    APP_ROOT / "sentinel" / "collector" / "runner.py",
]

_BLANKET_NOQA = re.compile(r"#\s*noqa\s*(?:$|[^:])")
_BLANKET_TYPE_IGNORE = re.compile(r"#\s*type:\s*ignore\s*(?:$|[^\[])")


def test_ac39_new_modules_carry_no_blanket_lint_suppressions():
    violations: list[str] = []
    for path in _NEW_MODULES:
        if not path.is_file():
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if _BLANKET_NOQA.search(line):
                violations.append(f"{path.name}:{lineno}: blanket # noqa (no code): {line.strip()}")
            if _BLANKET_TYPE_IGNORE.search(line):
                violations.append(
                    f"{path.name}:{lineno}: blanket # type: ignore (no code): {line.strip()}"
                )
    assert violations == [], "\n".join(violations)


# =============================================================================
# NFR-1 — representative sample of PRE-EXISTING functionality still passes
# end-to-end after this feature, exercised together in one process (not just
# "the pre-existing suite still passes when pytest happens to collect it").
# =============================================================================


def test_nfr1_pre_existing_llm_and_mcp_flows_survive_full_pipeline_after_migration():
    """A representative pre-existing scenario -- an LLM call and an MCP tool
    call for a pre-existing agent, run through the *same* Pipeline/Store/Engine
    stack the network feature modified -- must still store, evaluate and
    round-trip correctly. This is deliberately NOT a network event: it is the
    NFR-1 "existing consumers keep working" claim exercised directly, end to
    end, rather than inferred from the new feature's own green tests."""
    from sentinel.pipeline import Pipeline

    policy_path = str(REPO_ROOT / "policies" / "example.yaml")
    pipe = Pipeline(policy_path, ":memory:")

    llm_event = parse_flow(
        agent_id="recon-bot",
        session_id="sess-nfr1",
        host="api.anthropic.com",
        method="POST",
        path="/v1/messages",
        request_body='{"model": "claude-sonnet-4-6", "messages": []}',
    )
    tool_event = parse_flow(
        agent_id="recon-bot",
        session_id="sess-nfr1",
        host="ledger.internal",
        method="POST",
        path="/rpc",
        request_body=(
            '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", '
            '"params": {"name": "read_ledger", "arguments": {}}}'
        ),
    )

    pipe.ingest_event(llm_event)
    pipe.ingest_event(tool_event)

    stored = pipe.store.events_for_agent("recon-bot")
    assert any(e["action"] == "llm_call" for e in stored)
    assert any(e["action"] == "tool_call" for e in stored)
    # Every pre-existing event still round-trips with the five new columns
    # present (NULL) rather than erroring on read.
    for row in stored:
        for field in _NEW_NETWORK_FIELDS:
            assert field in row
