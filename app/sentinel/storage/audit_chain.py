"""Hash-chaining for the audit trail — what makes it *evidently* tamper-evident.

Storing a SHA-256 of each request payload binds that payload to that row: replay
a mutated body and the hash no longer matches. That is a real property, and it
is all the audit trail used to have. It is NOT tamper-evidence of the *log*:
nothing linked one row to the next, so anyone able to write to the database
could rewrite a row and its payload hash together, consistently, leaving
nothing to detect (CR-17).

This module closes that gap. Each entry carries the hash of its predecessor, so
the log is a chain: altering, deleting or reordering any row breaks every link
after it, and `verify_chain` names the first row where the break occurs.

Deliberately pure and backend-agnostic — no database imports — so the property
is unit-testable without a live PostgreSQL instance, and so a second backend
can adopt the same chain without reimplementing the rules.

What this does and does not give you
------------------------------------
It detects tampering by anyone who cannot recompute the whole chain forward
from the altered row. It does NOT by itself stop an attacker with write access
from rewriting every subsequent row: for that, the chain head must be anchored
somewhere the database cannot reach — periodic export of `last_hash` to
append-only storage (Log Analytics archive tier, object-lock bucket, a
notarisation service). `docs/COMPLIANCE.md` states that boundary; this module
is the half that belongs in the application.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Optional

#: The chain's anchor. A fixed, well-known value so the very first entry has a
#: real predecessor hash to commit to rather than a NULL that could be forged.
GENESIS_HASH = "0" * 64

#: Fields committed to by the chain, in this exact order. Adding a field here
#: changes every subsequent hash, so it is an append-only list in practice —
#: extend at the end and version the chain if a break is ever required.
CHAINED_FIELDS: tuple[str, ...] = (
    "ts",
    "endpoint",
    "method",
    "agent_id",
    "source_ip",
    "payload_hash",
    "status_code",
    "duration_ms",
    "user_id",
)


def canonical_entry(entry: dict[str, Any]) -> str:
    """Serialize an audit entry deterministically.

    `sort_keys` is not enough on its own: the caller's dict may carry extra
    keys, and `datetime` values are not JSON-serializable. Projecting onto
    CHAINED_FIELDS and stringifying through `default=str` makes the same
    logical entry hash identically on every machine and Python version.
    """
    projected = {k: entry.get(k) for k in CHAINED_FIELDS}
    return json.dumps(projected, sort_keys=True, default=str, separators=(",", ":"))


def entry_hash(prev_hash: str, entry: dict[str, Any]) -> str:
    """Hash one audit entry as a link committing to its predecessor."""
    material = f"{prev_hash}\n{canonical_entry(entry)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def verify_chain(rows: Iterable[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Walk `rows` oldest-first and return the first broken link, or None.

    A row breaks the chain when its stored `prev_hash` does not match the
    previous row's `entry_hash` (a row was deleted, inserted or reordered), or
    when its own `entry_hash` does not match a recomputation from its stored
    content (the row's fields were edited).

    The return value is a dict describing the break — `index`, `audit_id`,
    `reason`, `expected`, `found` — rather than a bare bool, because an
    auditor's next question is always *which* record and *how*.
    """
    prev = GENESIS_HASH
    for index, row in enumerate(rows):
        stored_prev = row.get("prev_hash")
        if stored_prev != prev:
            # Distinguish the two ways this happens, because the operator's
            # next action differs. At index 0 the log does not begin at the
            # genesis hash, which means entries that once existed are gone
            # (a TRUNCATE or a row delete at the head) or the chain head was
            # carried over from a previous log. Anywhere else, a row in the
            # middle was removed, inserted or reordered.
            if index == 0:
                reason = (
                    "first entry does not chain from the genesis hash — records "
                    "before it were removed, or the chain head was carried over "
                    "from a previous log"
                )
            else:
                reason = "prev_hash does not match the preceding entry"
            return {
                "index": index,
                "audit_id": str(row.get("audit_id", "")),
                "reason": reason,
                "expected": prev,
                "found": stored_prev,
            }
        recomputed = entry_hash(prev, row)
        stored = row.get("entry_hash")
        if stored != recomputed:
            return {
                "index": index,
                "audit_id": str(row.get("audit_id", "")),
                "reason": "entry_hash does not match this entry's content",
                "expected": recomputed,
                "found": stored,
            }
        prev = recomputed
    return None
