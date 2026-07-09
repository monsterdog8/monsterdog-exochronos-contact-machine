"""
monsterboy_aegis_modules/sync_config.py
Local configuration synthesis for MONSTERBOY ÆGIS.
Part of MONSTERBOY ÆGIS — fail-closed evidence governance.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def build_sync_config(
    *,
    verdict: str = "PARTIAL_PASS_LOCAL_BUNDLE__PRODUCTION_LOCKED",
    global_ceiling: str = "LAB_ONLY",
    production_gate: str = "LOCKED",
    cycle: int = 10,
) -> dict[str, Any]:
    """
    Build a unified sync configuration for the ÆGIS framework.

    Returns a structured config dict suitable for JSON serialization.
    """
    return {
        "framework": "MONSTERBOY_AEGIS",
        "version": "X-01",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "AUDIT / VERIFY / ARCHITECTURE / BUNDLE / EXECUTION_LOCALE",
        "verdict": verdict,
        "cycle": cycle,
        "ceilings": {
            "global": global_ceiling,
            "CORE": "LOCAL_BOUNDED",
            "SUPPORT": "CONF_DEMO_COMPLETE",
            "LAB": "LAB_ONLY",
            "ARCHITECTURE": "ARCH_BOUNDED",
            "WORLD": "UX_SYMBOLIC_ONLY",
            "PRODUCTION": production_gate,
            "QUARANTINE": "QUARANTINE_HOLD",
        },
        "counter_hypotheses": {
            "CH1_insufficient_data": "active_for_PRODUCTION",
            "CH2_overinterpretation": "controlled_by_LAB_ONLY_ceiling",
            "CH3_inadequate_framework": "discriminated_by_lane_separation",
            "CH4_false_signal": "active_quarantine_hold",
            "CH5_alternative_explanation": "not_testable_without_external",
        },
        "proof_limits": [
            "Python compilation != full execution",
            "ZIP extraction != semantic validation",
            "Local benchmark != external truth",
            "Self-test X-01A negative != production",
            "Canonical report validated != scientific validation",
            "Local hash != external proof",
        ],
        "forbidden_claims": [
            "production",
            "external",
            "scientific",
            "independent",
            "oracle",
            "consciousness",
            "global-superiority",
        ],
        "safe_hold": {
            "active": True,
            "block_overclaim": True,
            "advance_subscope": True,
            "glorify_blockage": False,
        },
        "synchronization": {
            "verdict_global": "BLOQUE_FAIL_CLOSED",
            "promotion_ceiling": "LAB_ONLY",
            "scientific_validation": "NOT_SUPPORTED",
            "A-1": "UNLOCKED",
            "A-2": "PARTIAL",
            "A-3": "LOCKED",
        },
        "next_action": (
            "Provide four raw production X-01A artefacts from HTTPS 28/28 run, "
            "then pass raw_ledger_gate_PRODUCTION_result.json."
        ),
    }


def write_sync_config(
    output_path: str | Path,
    **kwargs: Any,
) -> dict[str, Any]:
    """Build and write sync config to a JSON file."""
    config = build_sync_config(**kwargs)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    return config
