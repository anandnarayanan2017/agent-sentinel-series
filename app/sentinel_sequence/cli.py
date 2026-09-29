"""CLI for the sequence-detection subsystem.

python -m sentinel_sequence.cli train --role kyc_bot --db events.duckdb
python -m sentinel_sequence.cli score --role kyc_bot --db events.duckdb --since-hours 24
python -m sentinel_sequence.cli drift --role kyc_bot --db events.duckdb
python -m sentinel_sequence.cli demo          # synthetic end-to-end (no DB needed)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time

from .config import SequenceConfig
from .detector import SequenceDetector
from .drift import check_drift
from .scoring import score_session


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _epoch_hours_ago(hours: float | None) -> float | None:
    """Epoch seconds for 'N hours ago', or None when hours is falsy.
    Single source of truth for cmd_train / cmd_score window math."""
    return time.time() - hours * 3600 if hours else None


def _detector(args) -> SequenceDetector:
    return SequenceDetector(SequenceConfig(registry_dir=args.registry))


def cmd_train(args) -> int:
    from .store import EventStore

    since = _epoch_hours_ago(args.since_hours)
    until = _epoch_hours_ago(args.until_hours)
    if args.since_epoch is not None:
        since = args.since_epoch
    if args.until_epoch is not None:
        until = args.until_epoch
    with EventStore(args.db) as store:
        sessions = store.fetch_sessions(role=args.role, since_epoch=since, until_epoch=until)
    det = _detector(args)
    info = det.train_and_publish(args.role, sessions)
    info["training_window"] = {
        "since_epoch": since,
        "until_epoch": until,
        "n_sessions": len(sessions),
    }
    print(json.dumps(info, indent=2))
    return 0


def cmd_score(args) -> int:
    from .store import EventStore

    since = _epoch_hours_ago(args.since_hours)
    with EventStore(args.db) as store:
        sessions = store.fetch_sessions(role=args.role, since_epoch=since)
    det = _detector(args)
    flagged = 0
    for s in sessions:
        finding = det.score(args.role, s)
        if finding["type"] == "sequence_anomaly":
            flagged += 1
            print(json.dumps(finding, indent=2))
    print(f"# scored {len(sessions)} sessions, flagged {flagged}", file=sys.stderr)
    return 0


def cmd_drift(args) -> int:
    from .store import EventStore

    det = _detector(args)
    bundle = det.registry.load(args.role)
    since = time.time() - args.window_days * 86400
    with EventStore(args.db) as store:
        sessions = store.fetch_sessions(role=args.role, since_epoch=since)
    scores = [
        score_session(
            bundle.model, bundle.tokenizer, bundle.tokenizer.encode_session(s)
        ).topk_surprise
        for s in sessions
    ]
    report = check_drift(scores, bundle.calibration["median"])
    print(json.dumps({"stale": report.stale, "evidence": report.to_evidence()}, indent=2))
    return 0


def cmd_demo(args) -> int:
    """Synthetic end-to-end: train, publish, score attacks — no DB required."""
    from .data_gen import generate_attack_sessions, generate_normal_sessions

    det = _detector(args)
    info = det.train_and_publish("kyc_bot_demo", generate_normal_sessions(600))
    print(json.dumps(info, indent=2))
    hits = 0
    attacks = generate_attack_sessions(5)
    for atk_type, session in attacks:
        finding = det.score("kyc_bot_demo", session)
        ok = finding["type"] == "sequence_anomaly"
        hits += ok
        print(f"{atk_type:24s} -> {finding['type']:20s} severity={finding['severity']}")
    print(f"# {hits}/{len(attacks)} attack sessions flagged", file=sys.stderr)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sentinel-sequence")
    p.add_argument("--registry", default="models/sequence")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("train")
    t.add_argument("--role", required=True)
    t.add_argument("--db", required=True)
    t.add_argument(
        "--since-hours",
        type=float,
        default=None,
        help="train only on events newer than N hours ago",
    )
    t.add_argument(
        "--until-hours",
        type=float,
        default=None,
        help="train only on events older than N hours ago",
    )
    t.add_argument("--since-epoch", type=float, default=None)
    t.add_argument(
        "--until-epoch",
        type=float,
        default=None,
        help="IMPORTANT: bound training to a vetted clean window; "
        "training on unvetted data that contains attacks "
        "teaches the model that attacks are normal",
    )
    t.set_defaults(fn=cmd_train)

    s = sub.add_parser("score")
    s.add_argument("--role", required=True)
    s.add_argument("--db", required=True)
    s.add_argument("--since-hours", type=float, default=24.0)
    s.set_defaults(fn=cmd_score)

    d = sub.add_parser("drift")
    d.add_argument("--role", required=True)
    d.add_argument("--db", required=True)
    d.add_argument("--window-days", type=int, default=7)
    d.set_defaults(fn=cmd_drift)

    demo = sub.add_parser("demo")
    demo.set_defaults(fn=cmd_demo)

    args = p.parse_args(argv)
    _setup_logging(args.verbose)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
