"""Model artifact storage with integrity verification.

Bundles are serialised with joblib (pickle). Unpickling an attacker-controlled
file executes code, so an artifact is only ever loaded after its SHA-256
matches the checksum recorded in the registry database at training time.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import joblib

from app.ml.models.bundle import ModelBundle


class ArtifactIntegrityError(RuntimeError):
    """Raised when an artifact's checksum does not match the registry."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save_bundle(bundle: ModelBundle, directory: Path, name: str, version: int) -> tuple[Path, str]:
    """Atomically write `<name>-v<version>.joblib` plus a JSON manifest; return (path, sha256)."""
    directory.mkdir(parents=True, exist_ok=True)
    final = directory / f"{name}-v{version}.joblib"
    if final.exists():
        # Never overwrite an existing version — versions are immutable.
        raise FileExistsError(f"artifact already exists: {final.name}")
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    os.close(fd)
    try:
        joblib.dump(bundle, tmp, compress=3)
        os.replace(tmp, final)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    checksum = sha256_file(final)
    manifest: dict[str, Any] = {
        "name": name,
        "version": version,
        "sha256": checksum,
        "feature_version": bundle.feature_version,
        "members": [m.name for m in bundle.members],
        "known_families": bundle.known_families,
        "thresholds": {"anomalous": bundle.threshold_anomalous, "unknown": bundle.threshold_unknown},
    }
    (directory / f"{name}-v{version}.manifest.json").write_text(json.dumps(manifest, indent=2))
    return final, checksum


def load_bundle(path: Path, expected_sha256: str) -> ModelBundle:
    if not path.is_file():
        raise ArtifactIntegrityError(f"artifact missing: {path.name}")
    actual = sha256_file(path)
    if actual != expected_sha256:
        raise ArtifactIntegrityError(f"checksum mismatch for {path.name}: refusing to load")
    bundle = joblib.load(path)  # nosec B301 - checksum verified against the registry above
    if not isinstance(bundle, ModelBundle):
        raise ArtifactIntegrityError(f"{path.name} is not a ModelBundle")
    return bundle
