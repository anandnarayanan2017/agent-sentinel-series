"""`sentinel serve` must bind to loopback unless told otherwise."""

from unittest import mock

from sentinel.cli import main


def test_serve_defaults_to_loopback():
    with mock.patch("uvicorn.run") as run:
        assert main(["serve"]) == 0
    assert run.call_args.kwargs["host"] == "127.0.0.1"
