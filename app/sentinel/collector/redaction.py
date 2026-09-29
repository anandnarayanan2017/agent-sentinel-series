"""Best-effort edge redaction for collector telemetry.

No regex can prove that arbitrary free text contains no sensitive data. This
module removes common credential and identifier shapes, and recursively
replaces values under sensitive JSON keys, before collectors send telemetry.

Two complementary strategies, because neither is sufficient alone:

- **Structural** — values under a sensitive *key* are replaced whatever they
  look like. This catches `{"password": "hunter2"}`, where the value has no
  recognisable shape at all.
- **Pattern** — recognisable *shapes* are replaced wherever they appear,
  including inside free text and under innocuous keys. This catches a card
  number pasted into a prompt.

Callers must redact BEFORE truncating (see `parsers._preview`): truncating
first crops a secret out of the preview while leaving it in the text the
redactor never saw.

Stated limitation, because `docs/COMPLIANCE.md` relies on it being stated:
this handles structured identifiers and sensitive keys, and free-text personal
data not at all — a customer's name written in prose survives. It reduces
exposure; it is not a guarantee.
"""

from __future__ import annotations

import json
import re
from typing import Any

_SENSITIVE_KEYS = re.compile(
    r"(?:authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|password|passwd|passphrase|private[_-]?key|"
    r"credit[_-]?card|card[_-]?number|iban|account[_-]?number|"
    r"ssn|national[_-]?id|tax[_-]?id|date[_-]?of[_-]?birth|dob)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+")

#: Order matters: more specific shapes run before broader ones, so a card
#: number is not partially consumed by a looser rule.
_TEXT_PATTERNS = (
    # Provider API keys. The inner hyphen is load-bearing — real keys look
    # like `sk-proj-AbC…`, and a pattern stopping at the first hyphen leaves
    # the secret intact.
    re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{12,}"),
    # AWS access key ids.
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{12,}\b"),
    # JWTs (three base64url segments).
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    # IBANs, with or without the conventional four-character grouping.
    re.compile(r"\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\b"),
    re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    # Payment cards, including space- and hyphen-separated.
    re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"),
    # International phone numbers.
    re.compile(r"(?<![\w.])\+\d[\d\s().-]{7,}\d(?![\w.])"),
)

# Deliberately NOT a rule: a bare run of 9+ digits. It would redact epoch
# timestamps, byte counts and row counts — destroying the explainability this
# evidence exists to provide. Account and national-ID numbers are covered
# structurally by `_SENSITIVE_KEYS` instead, which is where they actually
# appear in tool arguments.


def _redact_patterns(text: str) -> str:
    text = _BEARER.sub(r"\1[REDACTED]", text)
    for pattern in _TEXT_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _SENSITIVE_KEYS.search(str(key)) else _redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, str):
        return _redact_patterns(value)
    return value


def redact_text(text: str | None) -> str:
    """Redact a JSON document or plain text without ever raising.

    Accepts `None` because that is what the collectors actually hand it:
    `mitmproxy`'s `flow.request.get_text(strict=False)` returns `None` for a
    body it cannot decode. Without this, `None` fell through to
    `_redact_patterns(str(None))` and the literal string "None" was stored as
    the evidence preview for every binary payload. An absent body has no
    preview, so the answer is an empty string.

    The exception net is deliberately broad on BOTH legs. `json.loads` raises
    more than JSONDecodeError on hostile input — a 10,000-digit number trips
    CPython's integer-string conversion limit with a bare ValueError, and deep
    nesting raises RecursionError — and re-serialising can fail on values
    `default=str` cannot reach. A monitoring tool must never crash on the
    traffic it is monitoring, so any failure degrades to pattern-only
    redaction of the raw text rather than propagating.
    """
    if text is None:
        return ""
    try:
        value = json.loads(text)
    except Exception:  # noqa: BLE001 — see docstring; must never raise
        return _redact_patterns(str(text))
    try:
        return json.dumps(_redact_value(value), separators=(",", ":"), default=str)
    except Exception:  # noqa: BLE001 — same contract on the way back out
        return _redact_patterns(str(text))
