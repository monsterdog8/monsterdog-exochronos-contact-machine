"""
monsterboy_aegis_modules/audit.py
Python compilation checks, JSON/JSONL parsing, and aggregation utilities.
Part of MONSTERBOY ÆGIS — fail-closed evidence governance.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any
import hashlib

CHUNK_SIZE = 8192


def compile_check_python(filepath: str | Path) -> dict[str, Any]:
    """
    Check whether a Python file compiles without syntax errors.

    Returns {"path": ..., "status": "PASS"|"FAIL", "error": ...}.
    """
    filepath = Path(filepath)
    try:
        source = filepath.read_text(encoding="utf-8")
        ast.parse(source, filename=str(filepath))
        return {"path": str(filepath), "status": "PASS", "error": None}
    except SyntaxError as exc:
        return {
            "path": str(filepath),
            "status": "FAIL",
            "error": f"SyntaxError at line {exc.lineno}: {exc.msg}",
        }
    except Exception as exc:
        return {
            "path": str(filepath),
            "status": "FAIL",
            "error": f"{type(exc).__name__}: {exc}",
        }


def batch_compile_check(root_dir: str | Path) -> dict[str, Any]:
    """
    Compile-check all .py files under root_dir.

    Returns {"total": N, "pass": N, "fail": N, "results": [...]}.
    """
    root = Path(root_dir)
    results = []
    for py_file in sorted(root.rglob("*.py")):
        results.append(compile_check_python(py_file))

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    return {
        "total": len(results),
        "pass": passed,
        "fail": failed,
        "results": results,
    }


def parse_json_file(filepath: str | Path) -> dict[str, Any]:
    """
    Attempt to parse a JSON file.

    Returns {"path": ..., "status": "PASS"|"FAIL", "error": ...}.
    """
    filepath = Path(filepath)
    try:
        with open(filepath, encoding="utf-8") as f:
            json.load(f)
        return {"path": str(filepath), "status": "PASS", "error": None}
    except json.JSONDecodeError as exc:
        return {"path": str(filepath), "status": "FAIL", "error": str(exc)}
    except Exception as exc:
        return {
            "path": str(filepath),
            "status": "FAIL",
            "error": f"{type(exc).__name__}: {exc}",
        }


def batch_parse_json(root_dir: str | Path) -> dict[str, Any]:
    """
    Parse all .json files under root_dir.

    Returns {"total": N, "valid": N, "invalid": N, "results": [...]}.
    """
    root = Path(root_dir)
    results = []
    for json_file in sorted(root.rglob("*.json")):
        results.append(parse_json_file(json_file))

    valid = sum(1 for r in results if r["status"] == "PASS")
    invalid = sum(1 for r in results if r["status"] == "FAIL")
    return {
        "total": len(results),
        "valid": valid,
        "invalid": invalid,
        "results": results,
    }


def parse_jsonl_file(filepath: str | Path) -> dict[str, Any]:
    """
    Parse a JSONL file (one JSON object per line).

    Returns {"path": ..., "total_lines": N, "valid": N, "invalid": N,
             "invalid_lines": [...]}.
    """
    filepath = Path(filepath)
    total = 0
    valid = 0
    invalid_lines: list[int] = []

    try:
        with open(filepath, encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    json.loads(line)
                    valid += 1
                except json.JSONDecodeError:
                    invalid_lines.append(i)
    except Exception as exc:
        return {
            "path": str(filepath),
            "status": "FAIL",
            "error": f"{type(exc).__name__}: {exc}",
        }

    return {
        "path": str(filepath),
        "total_lines": total,
        "valid": valid,
        "invalid": total - valid,
        "invalid_lines": invalid_lines,
        "status": "PASS" if not invalid_lines else "PARTIAL",
    }


def aggregate_results(*check_results: dict[str, Any]) -> dict[str, Any]:
    """
    Aggregate multiple check results into a single summary.

    Each input should have at minimum a "status" or "verdict" field.
    """
    statuses = []
    for r in check_results:
        s = r.get("status") or r.get("verdict", "UNKNOWN")
        statuses.append(s)

    all_pass = all(s == "PASS" or s == "PASS_LOCAL" for s in statuses)
    any_fail = any("FAIL" in s for s in statuses)

    if all_pass:
        verdict = "PASS_LOCAL"
    elif any_fail:
        verdict = "PARTIAL"
    else:
        verdict = "PARTIAL"

    return {
        "verdict": verdict,
        "total_checks": len(check_results),
        "statuses": statuses,
    }


def sha256_file(filepath: str | Path) -> str:
    """
    Compute a lowercase SHA-256 hex digest via chunked reads.

    Uses chunked reads to handle large files efficiently and to match the
    lowercase output format emitted by sha256sum.
    """
    digest = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_replay_artifacts(
    run_dir: str | Path,
    hash_file: str | Path,
) -> dict[str, Any]:
    """
    Verify replay artifacts using two local runtimes:
    shell-produced sha256sum output and Python hashlib recomputation.

    Returns a dict with:
      - status: str - Either "PASS_LOCAL_ONLY" or "FAIL_CLOSED"
      - checks_passed: number of successful checks
      - checks_failed: number of failed checks
      - checks: ordered list of {"name": ..., "status": ...} entries
    """
    run_dir = Path(run_dir)
    hash_file = Path(hash_file)
    required = [
        "stdout.log",
        "environment.json",
        "result.json",
        "execution_manifest.json",
    ]
    checks: list[dict[str, str]] = []

    if not hash_file.is_file():
        return {
            "status": "FAIL_CLOSED",
            "checks_passed": 0,
            "checks_failed": 1,
            "checks": [{"name": "hash_file_exists", "status": "FAIL"}],
        }

    shell_hashes: dict[str, str] = {}
    try:
        for line in hash_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                # Store both raw and resolved paths to support verification
                # with both relative and absolute run_dir arguments.
                shell_hashes[str(Path(parts[1]))] = parts[0]
                shell_hashes[str(Path(parts[1]).resolve())] = parts[0]
    except OSError:
        return {
            "status": "FAIL_CLOSED",
            "checks_passed": 0,
            "checks_failed": 1,
            "checks": [{"name": "hash_file_readable", "status": "FAIL"}],
        }

    manifest_path = run_dir / "execution_manifest.json"
    manifest_hashes: dict[str, str] = {}
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest_hashes = {
                entry["file"]: entry["sha256"]
                for entry in manifest.get("artifacts", [])
                if "file" in entry and "sha256" in entry
            }
        except (OSError, json.JSONDecodeError):
            checks.append({"name": "execution_manifest_json_valid", "status": "FAIL"})

    for name in required:
        path = run_dir / name
        relpath = str(path)
        if not path.is_file():
            checks.append({"name": f"{name}_exists", "status": "FAIL"})
            continue

        checks.append({"name": f"{name}_exists", "status": "PASS"})
        python_hash = sha256_file(path)
        shell_hash = shell_hashes.get(relpath) or shell_hashes.get(str(path.resolve()))
        checks.append(
            {
                "name": f"{name}_shell_python_match",
                "status": "PASS" if shell_hash == python_hash else "FAIL",
            }
        )

        if name != "execution_manifest.json":
            manifest_hash = manifest_hashes.get(name)
            checks.append(
                {
                    "name": f"{name}_manifest_match",
                    "status": "PASS" if manifest_hash == python_hash else "FAIL",
                }
            )

    checks_passed = sum(1 for check in checks if check["status"] == "PASS")
    checks_failed = sum(1 for check in checks if check["status"] == "FAIL")
    return {
        "status": "PASS_LOCAL_ONLY" if checks_failed == 0 else "FAIL_CLOSED",
        "checks_passed": checks_passed,
        "checks_failed": checks_failed,
        "checks": checks,
    }
