"""Command-line entrypoint: `sentinel serve | demo | ingest-file`."""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel")
    sub = parser.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", help="run the collector/query API")
    # Loopback by default so a local demo is never reachable from the network.
    # Inside a container, pass `--host 0.0.0.0` explicitly; auth is enforced
    # separately (api/auth.py) and is not a function of bind address.
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)

    sub.add_parser("demo", help="run the built-in attack demo")

    sub.add_parser("version", help="print version")

    args = parser.parse_args(argv)

    if args.cmd == "serve":
        import uvicorn

        uvicorn.run("sentinel.api.main:app", host=args.host, port=args.port)
        return 0

    if args.cmd == "demo":
        import importlib.util
        from pathlib import Path

        scenario = (
            Path(__file__).resolve().parents[2] / "examples" / "phase1" / "demo_agent" / "scenario.py"
        )
        spec = importlib.util.spec_from_file_location("sentinel_demo_scenario", scenario)
        if spec is None or spec.loader is None:
            print(f"demo scenario not found at {scenario}", file=sys.stderr)
            return 1
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return int(module.run())

    if args.cmd == "version":
        from sentinel import __version__

        print(json.dumps({"version": __version__}))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
