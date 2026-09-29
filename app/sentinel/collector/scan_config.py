"""Capture/scan-job configuration and cadence validation.

Kept separate from `host_map.py` so "who may I capture/scan" (identity
attribution) and "how often do I capture/scan" (cadence, timeouts,
enablement) can never be conflated in a single loader (design §4.1, C3).

Off-by-default throughout (FR-26, DD-8): with no operator configuration,
`CaptureConfig.enabled` and `ScanJobConfig.enabled` are both `False`, so
adopting this collector issues zero tshark/nmap invocations until an operator
makes two positive acts -- authoring a host map and setting `enabled: true`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ScanConfigError(ValueError):
    """A `CaptureConfig`/`ScanJobConfig` failed cadence or timeout validation."""


class ScanClass(str, Enum):
    """FR-20/FR-21: the two, separately-scheduled, separately-labeled scans."""

    TOP_1000 = "top_1000"  # nmap default port set, hourly
    FULL_RANGE = "full_range"  # nmap -p-, at most daily


# FR-21 / AC-21: a FULL_RANGE job configured more frequently than this is
# rejected at load. TOP_1000 has no such floor -- hourly is its intended
# cadence and there is no faster/slower alternate path for it in this design.
_FULL_RANGE_MIN_INTERVAL_SECONDS = 86400

# DD-13 (§3.12): class-differentiated default timeouts, deliberately generous
# since ADR-0008's ~30+ min/host observation for `-p-` is explicitly not a
# guarantee (AS-6).
DEFAULT_TIMEOUT_SECONDS: dict[ScanClass, float] = {
    ScanClass.TOP_1000: 600.0,
    ScanClass.FULL_RANGE: 5400.0,
}

# FR-20: the hourly job's intended default cadence.
DEFAULT_TOP_1000_INTERVAL_SECONDS = 3600


@dataclass(frozen=True)
class CaptureConfig:
    """Live-capture (tshark) supervisor configuration (design §2.4)."""

    interface: str
    enabled: bool = False  # FR-26 posture: off unless configured
    reload_interval_seconds: Optional[int] = None  # None => restart-only (DD-3)

    def __post_init__(self) -> None:
        if self.reload_interval_seconds is not None and self.reload_interval_seconds <= 0:
            raise ScanConfigError(
                "reload_interval_seconds must be a positive number of seconds, "
                f"got {self.reload_interval_seconds!r}"
            )


@dataclass(frozen=True)
class ScanJobConfig:
    """Periodic inventory (nmap) job configuration (design §2.5, §3.8, DD-13).

    Validated at construction time (`__post_init__`), never lazily, so a
    misconfigured cadence or timeout is a load-time error rather than a
    silently-wrong scan schedule.
    """

    scan_class: ScanClass
    enabled: bool = False  # FR-26 / DD-8 posture: off unless configured
    interval_seconds: int = DEFAULT_TOP_1000_INTERVAL_SECONDS
    timeout_seconds: Optional[float] = None  # None => class default (DEFAULT_TIMEOUT_SECONDS)
    state_path: Optional[str] = None  # DD-5 opt-in JSON sidecar path; None => in-memory only

    def __post_init__(self) -> None:
        if self.interval_seconds <= 0:
            raise ScanConfigError(
                f"interval_seconds must be positive, got {self.interval_seconds!r}"
            )

        if self.scan_class is ScanClass.FULL_RANGE and (
            self.interval_seconds < _FULL_RANGE_MIN_INTERVAL_SECONDS
        ):
            raise ScanConfigError(
                "FULL_RANGE scan interval must be at least "
                f"{_FULL_RANGE_MIN_INTERVAL_SECONDS} seconds (once per day), "
                f"got {self.interval_seconds!r}"
            )

        timeout = self.effective_timeout_seconds
        if timeout <= 0:
            raise ScanConfigError(f"timeout_seconds must be positive, got {timeout!r}")

        # DD-13: timeout must be strictly less than the cadence interval, so a
        # hung scan cannot still be running when the next cycle is due --
        # overlapping nmap processes against the same host would be
        # unauthorized extra traffic (R-7).
        if timeout >= self.interval_seconds:
            raise ScanConfigError(
                f"timeout_seconds ({timeout!r}) must be strictly less than "
                f"interval_seconds ({self.interval_seconds!r})"
            )

    @property
    def effective_timeout_seconds(self) -> float:
        """The configured timeout, or the class default if unset."""
        if self.timeout_seconds is not None:
            return self.timeout_seconds
        return DEFAULT_TIMEOUT_SECONDS[self.scan_class]
