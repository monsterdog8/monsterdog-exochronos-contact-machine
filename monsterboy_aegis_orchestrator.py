#!/usr/bin/env python3
"""
monsterboy_aegis_orchestrator.py
CLI orchestrator for MONSTERBOY ÆGIS — fail-closed evidence governance.

Usage:
    python monsterboy_aegis_orchestrator.py [--target-dir DIR] [--output-dir DIR]

Runs the full audit pipeline:
  1. Compile-check all Python files
  2. Parse all JSON files
  3. Check production gate
  4. Apply SAFE_HOLD
  5. Generate manifest
  6. Write sync config
  7. Produce final verdict
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent))

from monsterboy_aegis_modules.audit import (
    aggregate_results,
    batch_compile_check,
    batch_parse_json,
)
from monsterboy_aegis_modules.manifest import generate_manifest
from monsterboy_aegis_modules.safe_hold_gate import (
    apply_safe_hold,
    check_production_gate,
)
from monsterboy_aegis_modules.sync_config import build_sync_config


def run_orchestrator(
    target_dir: Path,
    output_dir: Path,
) -> dict:
    """Execute the full ÆGIS audit pipeline."""
    output_dir.mkdir(parents=True, exist_ok=True)
    results = {}

    # 1. Compile-check Python
    print("[1/6] Compile-checking Python files...")
    py_check = batch_compile_check(target_dir)
    results["python_compile"] = {
        "total": py_check["total"],
        "pass": py_check["pass"],
        "fail": py_check["fail"],
        "status": "PASS_LOCAL" if py_check["fail"] == 0 else "PARTIAL",
    }

    # 2. Parse JSON
    print("[2/6] Parsing JSON files...")
    json_check = batch_parse_json(target_dir)
    results["json_parse"] = {
        "total": json_check["total"],
        "valid": json_check["valid"],
        "invalid": json_check["invalid"],
        "status": "PASS_LOCAL" if json_check["invalid"] == 0 else "PARTIAL",
    }

    # 3. Production gate
    print("[3/6] Checking production gate...")
    gate = check_production_gate(target_dir)
    results["production_gate"] = {
        "verdict": gate.verdict,
        "ceiling": gate.ceiling.value,
        "missing": gate.missing_artefacts,
        "present": gate.present_artefacts,
    }

    # 4. SAFE_HOLD
    print("[4/6] Applying SAFE_HOLD...")
    safe_hold = apply_safe_hold()
    results["safe_hold"] = safe_hold

    # 5. Manifest
    print("[5/6] Generating manifest...")
    manifest_csv = output_dir / "SHA256_MANIFEST.csv"
    manifest_json = output_dir / "SHA256_MANIFEST.json"
    entries = generate_manifest(
        target_dir,
        output_csv=manifest_csv,
        output_json=manifest_json,
    )
    results["manifest"] = {
        "total_files": len(entries),
        "csv_path": str(manifest_csv),
        "json_path": str(manifest_json),
    }

    # 6. Sync config
    print("[6/6] Writing sync config...")
    config = build_sync_config()
    config_path = output_dir / "UNIFIED_SYNC_CONFIG.json"
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    results["sync_config_path"] = str(config_path)

    # Aggregate
    agg = aggregate_results(
        {"status": results["python_compile"]["status"]},
        {"status": results["json_parse"]["status"]},
        {"status": "FAIL" if gate.missing_artefacts else "PASS_LOCAL"},
    )

    production_locked = bool(gate.missing_artefacts)
    if production_locked:
        final_verdict = "PARTIAL_PASS_LOCAL_BUNDLE__PRODUCTION_LOCKED"
    else:
        final_verdict = "PASS_PRODUCTION_GATE"

    report = {
        "framework": "MONSTERBOY_AEGIS",
        "version": "X-01",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "verdict": final_verdict,
        "global_ceiling": "LAB_ONLY" if production_locked else "PARTIALLY_PUBLISHABLE",
        "production_gate": "LOCKED" if production_locked else "UNLOCKED",
        "aggregate": agg,
        "checks": results,
    }

    # Write canonical report JSON
    report_path = output_dir / "REPORT_FINAL_CANONICAL.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\nVerdict: {final_verdict}")
    print(f"Global ceiling: {report['global_ceiling']}")
    print(f"Report written to: {report_path}")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MONSTERBOY ÆGIS Orchestrator — fail-closed evidence governance"
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=Path("."),
        help="Directory to audit (default: current directory)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("aegis_output"),
        help="Directory for output artefacts (default: aegis_output)",
    )
    args = parser.parse_args()

    report = run_orchestrator(args.target_dir, args.output_dir)
    sys.exit(0 if "PASS" in report["verdict"] else 1)


if __name__ == "__main__":
    main()
