"""
tests/test_phase3_replay.py
Phase 3 Replay + ΔMAGLO rc3.2.1 Verification Test Suite
Part of MONSTERBOY ÆGIS — fail-closed evidence governance.

Validates:
- Phase 3 run artefacts are present and parseable
- ΔMAGLO rc3.2.1 dual-runtime recompute passes (checks_failed == 0)
- Orchestrator pipeline produces PASS_LOCAL status for Python/JSON checks
- Claim ceilings are respected (no overclaim)
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

# Allow import from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from monsterboy_aegis_modules.audit import (
    batch_compile_check,
    batch_parse_json,
)
from monsterboy_aegis_modules.dmaglo import (
    CLAIM_CEILING,
    DMAGLO_VERSION,
    SCOPE,
    DmagloResult,
    verify_dual_runtime,
    write_dmaglo_report,
)
from monsterboy_aegis_modules.safe_hold_gate import (
    Ceiling,
    apply_safe_hold,
    check_production_gate,
    get_lane_ceiling,
)
from monsterboy_aegis_modules.sync_config import build_sync_config

REPO_ROOT = Path(__file__).resolve().parent.parent
PHASE3_RUN_DIR = REPO_ROOT / "real_contact_logs" / "run_20260708_235812"


# ---------------------------------------------------------------------------
# Phase 3 artefact presence
# ---------------------------------------------------------------------------


class TestPhase3Artefacts:
    def test_run_directory_exists(self):
        assert PHASE3_RUN_DIR.exists(), f"Phase 3 run dir missing: {PHASE3_RUN_DIR}"

    def test_result_json_present_and_valid(self):
        path = PHASE3_RUN_DIR / "result.json"
        assert path.exists(), "result.json missing"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["phase"] == 3
        assert data["mode"] == "FAIL_CLOSED"
        assert data["status"] == "OBSERVED_LOCAL_EXECUTION"

    def test_execution_manifest_present_and_valid(self):
        path = PHASE3_RUN_DIR / "execution_manifest.json"
        assert path.exists(), "execution_manifest.json missing"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "mode" in data
        assert data["mode"] == "FAIL_CLOSED"
        assert "artifacts" in data

    def test_stdout_log_present(self):
        path = PHASE3_RUN_DIR / "stdout.log"
        assert path.exists(), "stdout.log missing"

    def test_environment_json_present_and_valid(self):
        path = PHASE3_RUN_DIR / "environment.json"
        assert path.exists(), "environment.json missing"
        json.loads(path.read_text(encoding="utf-8"))

    def test_claim_ceiling_structural_local_only(self):
        """Phase 3 result must not overclaim beyond STRUCTURAL_LOCAL_ONLY."""
        path = PHASE3_RUN_DIR / "result.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["claim_ceiling"] == "STRUCTURAL_LOCAL_ONLY"
        assert data["local_only_until_replay"] is True
        assert data["observables_only"] is True


# ---------------------------------------------------------------------------
# ΔMAGLO rc3.2.1 verification
# ---------------------------------------------------------------------------


class TestDmagloRc321:
    def test_version_constant(self):
        assert DMAGLO_VERSION == "rc3.2.1"

    def test_claim_ceiling_constant(self):
        assert CLAIM_CEILING == "LOCAL_DUAL_RUNTIME_RECOMPUTE_ONLY"

    def test_scope_constant(self):
        assert SCOPE == "LAB_ONLY"

    def test_dual_runtime_recompute_passes(self):
        """Core ΔMAGLO test: dual-runtime recompute must pass with checks_failed=0."""
        result = verify_dual_runtime(PHASE3_RUN_DIR)
        assert result.checks_failed == 0, (
            f"checks_failed={result.checks_failed}, verdict={result.verdict}, "
            f"details={result.details}"
        )
        assert result.verdict == "PASS_LOCAL_DUAL_RUNTIME_RECOMPUTE"
        assert result.match is True
        assert result.run_a_hash == result.run_b_hash
        assert result.run_a_hash != ""

    def test_delta_hash_present(self):
        import hashlib
        result = verify_dual_runtime(PHASE3_RUN_DIR)
        assert result.delta_hash != ""
        assert len(result.delta_hash) == 64  # SHA-256 hex
        # When both runs match, delta_hash is SHA-256(hash_a + hash_a) — the
        # zero-delta sentinel.  Assert explicitly so the invariant is documented.
        expected_zero_delta = hashlib.sha256(
            (result.run_a_hash + result.run_a_hash).encode("utf-8")
        ).hexdigest()
        assert result.delta_hash == expected_zero_delta, (
            "delta_hash does not equal zero-delta sentinel; artefacts may be unstable"
        )

    def test_result_to_dict_keys(self):
        result = verify_dual_runtime(PHASE3_RUN_DIR)
        d = result.to_dict()
        required_keys = {
            "dmaglo_version",
            "claim_ceiling",
            "scope",
            "run_a_hash",
            "run_b_hash",
            "delta_hash",
            "match",
            "verdict",
            "checks_failed",
            "generated_utc",
        }
        assert required_keys.issubset(set(d.keys()))

    def test_write_dmaglo_report(self, tmp_path):
        result = verify_dual_runtime(PHASE3_RUN_DIR)
        out = tmp_path / "dmaglo_report.json"
        write_dmaglo_report(result, out)
        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["checks_failed"] == 0
        assert data["verdict"] == "PASS_LOCAL_DUAL_RUNTIME_RECOMPUTE"

    def test_fail_on_missing_run_dir(self, tmp_path):
        result = verify_dual_runtime(tmp_path / "nonexistent")
        assert result.verdict == "FAIL_MISSING_ARTEFACTS"
        assert result.checks_failed == 1

    def test_fail_on_empty_run_dir(self, tmp_path):
        result = verify_dual_runtime(tmp_path)
        assert result.verdict == "FAIL_MISSING_ARTEFACTS"
        assert result.checks_failed == 1


# ---------------------------------------------------------------------------
# Audit module
# ---------------------------------------------------------------------------


class TestAuditModule:
    def test_python_compile_check_passes(self):
        result = batch_compile_check(REPO_ROOT)
        assert result["fail"] == 0, (
            f"{result['fail']} Python file(s) failed compile check: "
            + str([r for r in result["results"] if r["status"] == "FAIL"])
        )

    def test_json_parse_passes(self):
        result = batch_parse_json(REPO_ROOT)
        assert result["invalid"] == 0, (
            f"{result['invalid']} JSON file(s) failed parse: "
            + str([r for r in result["results"] if r["status"] == "FAIL"])
        )


# ---------------------------------------------------------------------------
# Safe-hold gate
# ---------------------------------------------------------------------------


class TestSafeHoldGate:
    def test_production_gate_locked_without_artefacts(self):
        gate = check_production_gate(REPO_ROOT)
        assert gate.verdict == "LOCKED_FAIL_CLOSED"
        assert gate.ceiling == Ceiling.LOCKED
        assert len(gate.missing_artefacts) > 0

    def test_apply_safe_hold_structure(self):
        sh = apply_safe_hold()
        assert sh["safe_hold_active"] is True
        assert sh["production_locked"] is True
        assert sh["global_ceiling"] == "LAB_ONLY"
        assert "forbidden_claims" in sh
        assert "allowed_actions" in sh

    def test_global_ceiling_is_lab_only(self):
        assert get_lane_ceiling("global") == Ceiling.LAB_ONLY

    def test_production_ceiling_is_locked(self):
        assert get_lane_ceiling("PRODUCTION") == Ceiling.LOCKED


# ---------------------------------------------------------------------------
# Sync config
# ---------------------------------------------------------------------------


class TestSyncConfig:
    def test_build_sync_config_structure(self):
        cfg = build_sync_config()
        assert cfg["framework"] == "MONSTERBOY_AEGIS"
        assert cfg["ceilings"]["global"] == "LAB_ONLY"
        assert cfg["ceilings"]["PRODUCTION"] == "LOCKED"
        assert cfg["safe_hold"]["active"] is True
        assert cfg["safe_hold"]["block_overclaim"] is True

    def test_no_forbidden_claims_in_verdict(self):
        cfg = build_sync_config()
        verdict = cfg["verdict"]
        # The verdict must not claim production success, external, scientific,
        # or consciousness validity — it may reference PRODUCTION in a LOCKED context
        overclaim_terms = [
            "PRODUCTION_READY",
            "EXTERNAL_VALIDATED",
            "SCIENTIFIC_VALIDATED",
            "CONSCIOUSNESS",
            "GLOBAL_SUPERIORITY",
        ]
        verdict_upper = verdict.upper()
        for term in overclaim_terms:
            assert term not in verdict_upper, (
                f"Overclaim term '{term}' found in verdict '{verdict}'"
            )
