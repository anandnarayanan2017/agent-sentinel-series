"""Subprocess runner seam for the network-visibility collector.

The single point every external-binary invocation (tshark, nmap) passes
through, so that "the real binaries are never exec'd in tests" (NFR-8, AC-38,
UAT-27) is verifiable at *one* place rather than by auditing every call site.

This module is the ONLY place `subprocess` is imported anywhere in the
network-visibility collector feature (design §2.3; DoD item 6). Tests inject
a stub implementing `SubprocessRunner` instead of `RealSubprocessRunner`.
"""

from __future__ import annotations

import subprocess  # the one sanctioned import site for this feature (design §2.3)
import time
from dataclasses import dataclass
from typing import Iterator, Protocol


class ToolNotAvailableError(RuntimeError):
    """Binary absent or not executable. DISTINCT from a non-zero exit."""


class ScanTimeoutError(RuntimeError):
    """The subprocess exceeded its timeout budget and was terminated.

    DISTINCT from a completed run, from a non-zero exit, and from an absent
    binary. Carries argv, the timeout that was applied, and the elapsed
    seconds -- never partial stdout as if it were a result (design §2.3, DD-13).
    """

    def __init__(self, argv: list[str], timeout: float, elapsed: float) -> None:
        self.argv = argv
        self.timeout = timeout
        self.elapsed = elapsed
        super().__init__(
            f"subprocess timed out after {elapsed:.1f}s (budget {timeout:.1f}s): {argv!r}"
        )


@dataclass(frozen=True)
class CompletedRun:
    """A process that ran to completion (any returncode)."""

    argv: list[str]
    returncode: int
    stdout: bytes
    stderr: bytes


class SubprocessRunner(Protocol):
    """The test-double point (design §2.3, C4)."""

    def run(self, argv: list[str], *, timeout: float) -> CompletedRun:
        """Run `argv` to completion or raise.

        Returns ONLY on a process that ran to completion (any returncode).
        Raises `ToolNotAvailableError` if the binary is absent/not executable.
        Raises `ScanTimeoutError` if `timeout` elapses.
        """
        ...

    def stream(self, argv: list[str]) -> Iterator[bytes]:
        """Line iterator over a long-running process's stdout (for tshark)."""
        ...


# Grace period between SIGTERM and SIGKILL when a run times out (DD-13: the
# child must be terminated AND reaped -- an unsupervised long scan is exactly
# the unauthorized-traffic risk R-7 covers).
_KILL_GRACE_SECONDS = 5.0


class RealSubprocessRunner:
    """Executes real subprocesses. The only class that ever exec's a real binary.

    `argv` is always a list; `shell=False` always. No value derived from
    config or from tool output is ever interpolated into a shell command
    (design §2.3 -- the mcp-governance "tool results are untrusted" posture
    applied to subprocess I/O).
    """

    def run(self, argv: list[str], *, timeout: float) -> CompletedRun:
        start = time.monotonic()
        try:
            # argv is always a list; shell=False always (design §2.3).
            proc = subprocess.Popen(
                argv,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise ToolNotAvailableError(f"binary not found for argv {argv!r}: {exc}") from exc
        except PermissionError as exc:
            raise ToolNotAvailableError(f"binary not executable for argv {argv!r}: {exc}") from exc

        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._terminate_and_reap(proc)
            elapsed = time.monotonic() - start
            # Partial stdout is truncated/misleading output (design §2.3) --
            # never collected, never returned as if it were a result.
            raise ScanTimeoutError(argv, timeout, elapsed) from None

        return CompletedRun(
            argv=argv,
            returncode=proc.returncode,
            stdout=stdout,
            stderr=stderr,
        )

    def stream(self, argv: list[str]) -> Iterator[bytes]:
        try:
            # argv is always a list; shell=False always (design §2.3).
            proc = subprocess.Popen(
                argv,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise ToolNotAvailableError(f"binary not found for argv {argv!r}: {exc}") from exc
        except PermissionError as exc:
            raise ToolNotAvailableError(f"binary not executable for argv {argv!r}: {exc}") from exc

        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                yield line
        finally:
            self._terminate_and_reap(proc)

    @staticmethod
    def _terminate_and_reap(proc: "subprocess.Popen[bytes]") -> None:
        """Terminate, escalate to kill after a grace period, and reap.

        Ensures no orphaned nmap/tshark process keeps running after the
        caller has given up on it (design §2.3, DD-13, R-7).
        """
        if proc.poll() is not None:
            return  # already exited
        proc.terminate()
        try:
            proc.wait(timeout=_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
