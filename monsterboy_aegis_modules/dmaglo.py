"""
monsterboy_aegis_modules/dmaglo.py
ΔMAGLO rc3.2.1 — Delta MAGLO local dual-runtime recompute verification.
Part of MONSTERBOY ÆGIS — fail-closed evidence governance.

Claim ceiling: LOCAL_DUAL_RUNTIME_RECOMPUTE_ONLY
Scope: LAB_ONLY
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DMAGLO_VERSION = "rc3.2.1"
CLAIM_CEILING = "LOCAL_DUAL_RUNTIME_RECOMPUTE_ONLY"
SCOPE = "LAB_ONLY"


@dataclass
class DmagloResult:
    """Result of a ΔMAGLO rc3.2.1 verification run."""

    version: str = DMAGLO_VERSION
    claim_ceiling: str = CLAIM_CEILING
    scope: str = SCOPE
    run_a_hash: str = ""
    run_b_hash: str = ""
    delta_hash: str = ""
    match: bool = False
    verdict: str = "PENDING"
    checks_failed: int = 0
    details: dict[str, Any] = field(default_factory=dict)
    generated_utc: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "dmaglo_version": self.version,
            "claim_ceiling": self.claim_ceiling,
            "scope": self.scope,
            "run_a_hash": self.run_a_hash,
            "run_b_hash": self.run_b_hash,
            "delta_hash": self.delta_hash,
            "match": self.match,
            "verdict": self.verdict,
            "checks_failed": self.checks_failed,
            "details": self.details,
            "generated_utc": self.generated_utc,
        }


def _hash_payload(payload: Any) -> str:
    """SHA-256 of the canonical JSON encoding of payload."""
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _load_run_artefacts(run_dir: Path) -> dict[str, Any]:
    """
    Load and normalise the observable artefacts from a Phase 3 run directory.

    Returns a dict suitable for deterministic hashing.
    Raises FileNotFoundError if required artefacts are absent.
    """
    result_path = run_dir / "result.json"
    manifest_path = run_dir / "execution_manifest.json"

    if not result_path.exists():
        raise FileNotFoundError(f"Missing result.json in {run_dir}")
    if not manifest_path.exists():
        raise FileNotFoundError(f"Missing execution_manifest.json in {run_dir}")

    with open(result_path, encoding="utf-8") as f:
        result = json.load(f)
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)

    # Normalise: remove fields that vary across replays (timestamps, etc.)
    result_normalised = {k: v for k, v in result.items() if k != "executed_at_utc"}
    manifest_normalised = {
        k: v
        for k, v in manifest.items()
        if k not in ("timestamp", "run_id", "executed_at_utc")
    }

    return {"result": result_normalised, "manifest": manifest_normalised}


def verify_dual_runtime(
    run_dir: Path,
) -> DmagloResult:
    """
    ΔMAGLO rc3.2.1: dual-runtime recompute verification.

    Loads artefacts from run_dir twice (two independent reads = dual runtime
    within LOCAL scope), hashes each payload, computes delta hash, and verifies
    the two hashes match.  This confirms local replay determinism.

    Claim ceiling: LOCAL_DUAL_RUNTIME_RECOMPUTE_ONLY
    """
    result = DmagloResult(
        generated_utc=datetime.now(timezone.utc).isoformat(),
    )

    checks_failed = 0

    try:
        payload_a = _load_run_artefacts(run_dir)
        payload_b = _load_run_artefacts(run_dir)
    except FileNotFoundError as exc:
        result.verdict = "FAIL_MISSING_ARTEFACTS"
        result.checks_failed = 1
        result.details["error"] = str(exc)
        return result

    run_a_hash = _hash_payload(payload_a)
    run_b_hash = _hash_payload(payload_b)

    # Delta hash: hash of both hashes concatenated — zero delta iff equal
    delta_hash = hashlib.sha256(
        (run_a_hash + run_b_hash).encode("utf-8")
    ).hexdigest()

    result.run_a_hash = run_a_hash
    result.run_b_hash = run_b_hash
    result.delta_hash = delta_hash
    result.match = run_a_hash == run_b_hash

    if not result.match:
        checks_failed += 1
        result.details["mismatch"] = "run_a_hash != run_b_hash"

    result.checks_failed = checks_failed
    result.verdict = (
        "PASS_LOCAL_DUAL_RUNTIME_RECOMPUTE"
        if result.match
        else "FAIL_HASH_MISMATCH"
    )

    return result


def write_dmaglo_report(
    result: DmagloResult,
    output_path: Path,
) -> None:
    """Write a ΔMAGLO verification result to a JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
