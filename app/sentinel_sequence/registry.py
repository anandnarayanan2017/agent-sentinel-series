"""Versioned, per-role model registry.

Layout on disk:

    <registry_dir>/
        <role>/
            v0001/
                model.json          # MarkovModel blob
                tokenizer.json      # frozen vocab
                meta.json           # metadata + calibration + sha256 checksums
            v0002/...
            LATEST                  # text file containing e.g. "v0002"

Guarantees:
- Atomic publish: artifacts are written to a temp dir and renamed into place;
  LATEST is updated last. Readers never observe a half-written version.
- Integrity: meta.json stores sha256 of model.json and tokenizer.json,
  verified on load. A corrupted artifact raises RegistryError, it does not
  silently misscore.
- Calibration travels with the model: the operating threshold and the
  calibration score distribution snapshot are stored in meta.json, so
  scoring anywhere reproduces the same decisions.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .markov import MarkovModel
from .tokenizer import Tokenizer

logger = logging.getLogger("sentinel.sequence.registry")

_ROLE_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


class RegistryError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class ModelBundle:
    role: str
    version: str
    model: MarkovModel
    tokenizer: Tokenizer
    threshold: float
    calibration: dict  # {"percentile":..., "n_sessions":..., "median":..., "p99":...}
    trained_at: str

    @property
    def meta(self) -> dict:
        return {
            "role": self.role,
            "version": self.version,
            "threshold": self.threshold,
            "calibration": self.calibration,
            "trained_at": self.trained_at,
        }


class ModelRegistry:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    # -- helpers -------------------------------------------------------------
    def _role_dir(self, role: str) -> Path:
        if not _ROLE_RE.match(role):
            raise RegistryError(f"Invalid role name: {role!r}")
        return self.root / role

    def _next_version(self, role: str) -> str:
        d = self._role_dir(role)
        existing = sorted(p.name for p in d.glob("v[0-9][0-9][0-9][0-9]"))
        n = int(existing[-1][1:]) + 1 if existing else 1
        return f"v{n:04d}"

    # -- publish ---------------------------------------------------------------
    def publish(
        self,
        role: str,
        model: MarkovModel,
        tokenizer: Tokenizer,
        threshold: float,
        calibration: dict,
    ) -> str:
        """Atomically publish a new model version for a role. Returns version."""
        role_dir = self._role_dir(role)
        role_dir.mkdir(parents=True, exist_ok=True)
        version = self._next_version(role)

        tmp = Path(tempfile.mkdtemp(dir=role_dir, prefix=".staging-"))
        try:
            model.save(tmp / "model.json")
            (tmp / "tokenizer.json").write_text(json.dumps(tokenizer.to_dict()))
            meta = {
                "role": role,
                "version": version,
                "threshold": float(threshold),
                "calibration": calibration,
                "trained_at": datetime.now(timezone.utc).isoformat(),
                "checksums": {
                    "model.json": _sha256(tmp / "model.json"),
                    "tokenizer.json": _sha256(tmp / "tokenizer.json"),
                },
                "schema_version": 1,
            }
            (tmp / "meta.json").write_text(json.dumps(meta, indent=2))
            final = role_dir / version
            os.rename(tmp, final)  # atomic on same filesystem
        except Exception:
            shutil.rmtree(tmp, ignore_errors=True)
            raise

        latest_tmp = role_dir / ".LATEST.tmp"
        latest_tmp.write_text(version)
        os.replace(latest_tmp, role_dir / "LATEST")  # atomic pointer swap
        logger.info("published %s/%s (threshold=%.4f)", role, version, threshold)
        return version

    # -- load ------------------------------------------------------------------
    def load(self, role: str, version: str | None = None) -> ModelBundle:
        role_dir = self._role_dir(role)
        if version is None:
            latest = role_dir / "LATEST"
            if not latest.exists():
                raise RegistryError(f"No published model for role {role!r}")
            version = latest.read_text().strip()
        vdir = role_dir / version
        meta_path = vdir / "meta.json"
        if not meta_path.exists():
            raise RegistryError(f"Missing version {role}/{version}")
        meta = json.loads(meta_path.read_text())

        buffers: dict[str, bytes] = {}
        for fname, expected in meta.get("checksums", {}).items():
            data = (vdir / fname).read_bytes()
            if hashlib.sha256(data).hexdigest() != expected:
                raise RegistryError(
                    f"Checksum mismatch for {role}/{version}/{fname}: artifact corrupted"
                )
            buffers[fname] = data

        def _bytes(fname: str) -> bytes:
            return buffers[fname] if fname in buffers else (vdir / fname).read_bytes()

        model = MarkovModel._from_blob(json.loads(_bytes("model.json").decode("utf-8")))
        tokenizer = Tokenizer.from_dict(json.loads(_bytes("tokenizer.json").decode("utf-8")))
        return ModelBundle(
            role=role,
            version=version,
            model=model,
            tokenizer=tokenizer,
            threshold=float(meta["threshold"]),
            calibration=meta["calibration"],
            trained_at=meta["trained_at"],
        )

    def list_versions(self, role: str) -> list[str]:
        d = self._role_dir(role)
        return sorted(p.name for p in d.glob("v[0-9][0-9][0-9][0-9]")) if d.exists() else []

    def list_roles(self) -> list[str]:
        return sorted(p.name for p in self.root.iterdir() if p.is_dir())
