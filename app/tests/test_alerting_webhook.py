"""Webhook alerter tests (app/sentinel/alerting/webhook.py).

`urllib.request.urlopen` is never invoked against a real endpoint: the
severity-threshold gate (`_should_alert`), the per-target fail-open dispatch
(`fire`), and the URL-scheme guard added to `_post` are exercised directly,
monkeypatching only at those documented seams.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

import sentinel.alerting.webhook as webhook
from sentinel.schema.events import Evidence, Finding, Severity


def _finding(severity: Severity = Severity.HIGH, **overrides) -> Finding:
    defaults: dict[str, Any] = dict(
        agent_id="recon-bot",
        session_id="s1",
        rule_id="R-1",
        title="Suspicious egress",
        severity=severity,
        explanation="host not seen before",
        control_refs=["DORA-Art.25"],
        evidence=[Evidence(key="host", value="evil.example.com")],
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---- _should_alert(): severity threshold ------------------------------------


@pytest.mark.parametrize(
    "severity, threshold, expected",
    [
        (Severity.CRITICAL, "high", True),
        (Severity.HIGH, "high", True),
        (Severity.MEDIUM, "high", False),
        (Severity.LOW, "high", False),
        (Severity.INFO, "high", False),
        (Severity.MEDIUM, "medium", True),
        (Severity.LOW, "medium", False),
        (Severity.LOW, "low", True),
        (Severity.INFO, "low", False),
    ],
)
def test_should_alert_respects_configured_severity_threshold(
    monkeypatch, severity, threshold, expected
):
    monkeypatch.setattr(webhook, "_THRESHOLD", threshold)
    assert webhook._should_alert(_finding(severity)) is expected


# ---- fire(): fail-open, per-target isolation --------------------------------


def _configure_all_targets(monkeypatch):
    monkeypatch.setattr(webhook, "_THRESHOLD", "high")
    monkeypatch.setattr(webhook, "_TEAMS_WEBHOOK", "https://example.test/teams")
    monkeypatch.setattr(webhook, "_PAGERDUTY_KEY", "pd-key")
    monkeypatch.setattr(webhook, "_SLACK_WEBHOOK", "https://example.test/slack")


def test_fire_below_threshold_posts_to_nothing(monkeypatch):
    _configure_all_targets(monkeypatch)
    post = MagicMock()
    monkeypatch.setattr(webhook, "_post", post)

    webhook.fire(_finding(Severity.LOW))

    post.assert_not_called()


def test_fire_dispatches_to_every_configured_target_when_above_threshold(monkeypatch):
    _configure_all_targets(monkeypatch)
    post = MagicMock()
    monkeypatch.setattr(webhook, "_post", post)

    webhook.fire(_finding(Severity.CRITICAL))

    assert post.call_count == 3


def test_fire_skips_unconfigured_targets(monkeypatch):
    monkeypatch.setattr(webhook, "_THRESHOLD", "high")
    monkeypatch.setattr(webhook, "_TEAMS_WEBHOOK", "")
    monkeypatch.setattr(webhook, "_PAGERDUTY_KEY", "")
    monkeypatch.setattr(webhook, "_SLACK_WEBHOOK", "https://example.test/slack")
    post = MagicMock()
    monkeypatch.setattr(webhook, "_post", post)

    webhook.fire(_finding(Severity.CRITICAL))

    assert post.call_count == 1


def test_fire_one_target_failing_does_not_block_the_others(monkeypatch, capsys):
    _configure_all_targets(monkeypatch)

    def _post_side_effect(url, payload, headers=None):
        if "teams" in url:
            raise RuntimeError("teams webhook down")
        # pagerduty / slack succeed

    monkeypatch.setattr(webhook, "_post", _post_side_effect)

    webhook.fire(_finding(Severity.CRITICAL))  # must not raise

    err = capsys.readouterr().err
    assert "delivery failures" in err
    assert "teams" in err


def test_fire_all_targets_failing_still_does_not_raise(monkeypatch, capsys):
    _configure_all_targets(monkeypatch)
    monkeypatch.setattr(webhook, "_post", MagicMock(side_effect=RuntimeError("network down")))

    webhook.fire(_finding(Severity.CRITICAL))  # must not raise

    err = capsys.readouterr().err
    assert "teams" in err and "pagerduty" in err and "slack" in err


# ---- _post(): non-http(s) scheme guard ---------------------------------------


def test_post_rejects_file_scheme_url():
    with pytest.raises(ValueError, match="non-http"):
        webhook._post("file:///etc/passwd", {"x": 1})


@pytest.mark.parametrize(
    "scheme_url",
    ["ftp://example.test/x", "javascript:alert(1)", "data:text/plain,x", "gopher://x"],
)
def test_post_rejects_other_non_http_schemes(scheme_url):
    with pytest.raises(ValueError):
        webhook._post(scheme_url, {"x": 1})


def test_post_allows_https_and_invokes_urlopen_with_a_post_request(monkeypatch):
    urlopen = MagicMock()
    monkeypatch.setattr(webhook.urllib.request, "urlopen", urlopen)

    webhook._post("https://example.test/hook", {"x": 1})

    assert urlopen.call_count == 1
    request = urlopen.call_args[0][0]
    assert request.full_url == "https://example.test/hook"
    assert request.get_method() == "POST"


def test_post_allows_plain_http(monkeypatch):
    urlopen = MagicMock()
    monkeypatch.setattr(webhook.urllib.request, "urlopen", urlopen)

    webhook._post("http://example.test/hook", {"x": 1})

    assert urlopen.call_count == 1


# ---- per-target payload shape -----------------------------------------------


def test_alert_teams_payload_carries_control_refs_and_evidence_fingerprint(monkeypatch):
    monkeypatch.setattr(webhook, "_TEAMS_WEBHOOK", "https://example.test/teams")
    captured = {}

    def _capture(url, payload, headers=None):
        captured["url"] = url
        captured["payload"] = payload

    monkeypatch.setattr(webhook, "_post", _capture)

    f = _finding(Severity.CRITICAL)
    webhook._alert_teams(f)

    assert captured["url"] == "https://example.test/teams"
    facts = {fact["name"]: fact["value"] for fact in captured["payload"]["sections"][0]["facts"]}
    assert facts["Controls"] == "DORA-Art.25"
    assert facts["Finding ID"] == f.finding_id
    assert facts["Evidence SHA"] == webhook._evidence_fingerprint(f)


def test_alert_pagerduty_posts_to_fixed_events_endpoint_with_routing_key(monkeypatch):
    monkeypatch.setattr(webhook, "_PAGERDUTY_KEY", "pd-routing-key")
    captured = {}

    def _capture(url, payload, headers=None):
        captured["url"] = url
        captured["payload"] = payload

    monkeypatch.setattr(webhook, "_post", _capture)

    f = _finding(Severity.HIGH)
    webhook._alert_pagerduty(f)

    assert captured["url"] == "https://events.pagerduty.com/v2/enqueue"
    assert captured["payload"]["routing_key"] == "pd-routing-key"
    assert captured["payload"]["dedup_key"] == f.finding_id
    assert captured["payload"]["payload"]["severity"] == "error"  # high -> "error" mapping


def test_alert_slack_payload_includes_agent_and_evidence_fingerprint(monkeypatch):
    monkeypatch.setattr(webhook, "_SLACK_WEBHOOK", "https://example.test/slack")
    captured = {}

    def _capture(url, payload, headers=None):
        captured["url"] = url
        captured["payload"] = payload

    monkeypatch.setattr(webhook, "_post", _capture)

    f = _finding(Severity.CRITICAL)
    webhook._alert_slack(f)

    assert captured["url"] == "https://example.test/slack"
    fields = {fld["title"]: fld["value"] for fld in captured["payload"]["attachments"][0]["fields"]}
    assert fields["Agent"] == "recon-bot"
    assert fields["Evidence SHA"] == webhook._evidence_fingerprint(f)
