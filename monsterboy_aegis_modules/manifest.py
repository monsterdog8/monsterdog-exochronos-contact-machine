"""
monsterboy_aegis_modules/manifest.py
Safe ZIP extraction, SHA-256 manifest generation (CSV/JSON).
Part of MONSTERBOY ÆGIS — fail-closed evidence governance.
"""

import csv
import hashlib
import json
import os
import zipfile
from pathlib import Path
from typing import Any


def sha256_file(filepath: str | Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_extract_zip(
    zip_path: str | Path,
    dest_dir: str | Path,
    *,
    max_members: int = 10000,
    max_total_bytes: int = 500_000_000,
) -> dict[str, Any]:
    """
    Extract a ZIP archive safely with path-traversal protection.

    Returns a dict with extraction metadata:
      - zip_path, dest_dir, members, total_bytes, status
    """
    zip_path = Path(zip_path)
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    resolved_dest = dest_dir.resolve()

    result: dict[str, Any] = {
        "zip_path": str(zip_path),
        "dest_dir": str(dest_dir),
        "members": 0,
        "total_bytes": 0,
        "status": "PENDING",
    }

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            infos = zf.infolist()
            if len(infos) > max_members:
                result["status"] = "FAIL_TOO_MANY_MEMBERS"
                return result

            total = sum(i.file_size for i in infos)
            if total > max_total_bytes:
                result["status"] = "FAIL_TOO_LARGE"
                result["total_bytes"] = total
                return result

            for info in infos:
                target = (dest_dir / info.filename).resolve()
                if not str(target).startswith(str(resolved_dest)):
                    result["status"] = "FAIL_PATH_TRAVERSAL"
                    result["blocked_path"] = info.filename
                    return result

            zf.extractall(dest_dir)
            result["members"] = len(infos)
            result["total_bytes"] = total
            result["status"] = "PASS_LOCAL"
    except zipfile.BadZipFile:
        result["status"] = "FAIL_BAD_ZIP"
    except Exception as exc:
        result["status"] = f"FAIL_EXCEPTION: {type(exc).__name__}"

    return result


def generate_manifest(
    root_dir: str | Path,
    output_csv: str | Path | None = None,
    output_json: str | Path | None = None,
) -> list[dict[str, str]]:
    """
    Walk root_dir and produce a SHA-256 manifest of all files.

    Returns list of {"path": ..., "sha256": ..., "size": ...} dicts.
    Optionally writes CSV and/or JSON manifests.
    """
    root = Path(root_dir)
    entries: list[dict[str, str]] = []

    for fpath in sorted(root.rglob("*")):
        if fpath.is_file():
            stat = fpath.stat()
            entries.append(
                {
                    "path": str(fpath.relative_to(root)),
                    "sha256": sha256_file(fpath),
                    "size": str(stat.st_size),
                }
            )

    if output_csv:
        with open(output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["path", "sha256", "size"])
            writer.writeheader()
            writer.writerows(entries)

    if output_json:
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2, ensure_ascii=False)

    return entries
