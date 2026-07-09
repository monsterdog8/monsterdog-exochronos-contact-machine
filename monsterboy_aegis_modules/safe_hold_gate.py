"""
monsterboy_aegis_modules/safe_hold_gate.py
Production gate, lane ceilings, and SAFE_HOLD structured logic.
Part of MONSTERBOY ÆGIS — fail-closed evidence governance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Ceiling(str, Enum):
    """Lane ceiling levels, ordered from most restrictive to least."""

    LOCKED = "LOCKED"
    QUARANTINE_HOLD = "QUARANTINE_HOLD"
    UX_SYMBOLIC_ONLY = "UX_SYMBOLIC_ONLY"
    LOCAL_BOUNDED = "LOCAL_BOUNDED"
    LAB_ONLY = "LAB_ONLY"
    ARCH_BOUNDED = "ARCH_BOUNDED"
    CONF_DEMO_COMPLETE = "CONF_DEMO_COMPLETE"
    PARTIALLY_PUBLISHABLE = "PARTIALLY_PUBLISHABLE"
    PRODUCTION_READY = "PRODUCTION_READY"


# Default lane ceilings per the canonical report
DEFAULT_LANE_CEILINGS: dict[str, Ceiling] = {
    "global": Ceiling.LAB_ONLY,
    "CORE": Ceiling.LOCAL_BOUNDED,
    "SUPPORT": Ceiling.CONF_DEMO_COMPLETE,
    "LAB": Ceiling.LAB_ONLY,
    "ARCHITECTURE": Ceiling.ARCH_BOUNDED,
    "WORLD": Ceiling.UX_SYMBOLIC_ONLY,
    "PRODUCTION": Ceiling.LOCKED,
    "QUARANTINE": Ceiling.QUARANTINE_HOLD,
}

# Production X-01A required artefacts
PRODUCTION_REQUIRED_ARTEFACTS = [
    "x01a_ledger_production_SCHEMA_ALIGNED.jsonl",
    "stdout_stderr_production_SCHEMA_ALIGNED.txt",
    "raw_ledger_gate_PRODUCTION_result.json",
    "sha256sum_production_SCHEMA_ALIGNED.txt",
]


@dataclass
class GateResult:
    """Result of a production gate check."""

    verdict: str
    ceiling: Ceiling
    missing_artefacts: list[str] = field(default_factory=list)
    present_artefacts: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


def check_production_gate(artefact_dir: str | Path) -> GateResult:
    """
    Check whether the production X-01A gate can be passed.

    Scans artefact_dir for the four required production artefacts.
    All must be present and non-empty.
    """
    artefact_dir = Path(artefact_dir)
    missing = []
    present = []

    for name in PRODUCTION_REQUIRED_ARTEFACTS:
        path = artefact_dir / name
        if path.exists() and path.stat().st_size > 0:
            present.append(name)
        else:
            missing.append(name)

    if not missing:
        return GateResult(
            verdict="PASS_PRODUCTION_GATE",
            ceiling=Ceiling.PARTIALLY_PUBLISHABLE,
            missing_artefacts=[],
            present_artefacts=present,
        )

    return GateResult(
        verdict="LOCKED_FAIL_CLOSED",
        ceiling=Ceiling.LOCKED,
        missing_artefacts=missing,
        present_artefacts=present,
        details={
            "cause": "Required production artefacts missing or empty",
            "total_required": len(PRODUCTION_REQUIRED_ARTEFACTS),
            "total_present": len(present),
        },
    )


def apply_safe_hold(
    lane_ceilings: dict[str, Ceiling] | None = None,
) -> dict[str, Any]:
    """
    Apply SAFE_HOLD logic: block overclaim, advance sub-scope,
    do not glorify the blockage.

    Returns a structured SAFE_HOLD state dict.
    """
    if lane_ceilings is None:
        lane_ceilings = dict(DEFAULT_LANE_CEILINGS)

    production_locked = lane_ceilings.get("PRODUCTION") == Ceiling.LOCKED
    global_ceiling = lane_ceilings.get("global", Ceiling.LAB_ONLY)

    return {
        "safe_hold_active": True,
        "production_locked": production_locked,
        "global_ceiling": global_ceiling.value,
        "lane_ceilings": {k: v.value for k, v in lane_ceilings.items()},
        "forbidden_claims": [
            "No production claim",
            "No external validation claim",
            "No scientific validation claim",
            "No consciousness claim",
            "No global-superiority claim",
        ],
        "allowed_actions": [
            "Continue LAB_ONLY exploitation",
            "Advance sub-scope non-production",
            "Generate local evidence bundles",
        ],
    }


def get_lane_ceiling(lane: str) -> Ceiling:
    """Get the ceiling for a specific lane."""
    return DEFAULT_LANE_CEILINGS.get(lane, Ceiling.LOCKED)
