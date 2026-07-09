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
