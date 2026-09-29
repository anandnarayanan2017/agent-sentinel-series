"""`sentinel demo` must run the documented attack scenario end to end."""

from sentinel.cli import main


def test_demo_runs_and_raises_findings(capsys):
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "net.host_not_allowed" in out
    assert "net.oversize_egress" in out
    assert "model.not_allowed" in out
