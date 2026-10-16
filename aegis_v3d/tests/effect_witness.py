#!/usr/bin/env python3
"""Témoin d'effet AEGIS V3D — processus séparé, UID distinct, AUCUN canal API.

Oracle d'effet unique : ouverture/lecture OS du répertoire de marqueurs, SHA-256
des octets, validation du contenu canonique (`content_digest`), comparaison aux
attentes passées en CLI. Écrit un rapport JSON dans un répertoire qui n'appartient
ni au PEP ni à l'agent. Ne croit jamais un code HTTP ni un message du PEP.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from typing import Any, Dict, List


def canonical_hash(obj: dict) -> str:
    c_str = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(c_str.encode("utf-8")).hexdigest()


def parse_expect(raw: str) -> Dict[str, str]:
    # format : filename|permit_id|nonce|action|resource
    parts = raw.split("|")
    if len(parts) != 5:
        raise SystemExit(f"bad --expect format: {raw!r}")
    return {
        "filename": parts[0],
        "permit_id": parts[1],
        "nonce": parts[2],
        "action": parts[3],
        "resource": parts[4],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--effect-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--expect", action="append", default=[])
    ap.add_argument("--expect-absent", action="append", default=[],
                    help="fichiers qui ne doivent PAS exister")
    ap.add_argument("--chain-floor", default=None,
                    help="fichier contenant la tête de chaîne attendue (anti-rollback)")
    args = ap.parse_args()

    expected = [parse_expect(e) for e in args.expect]
    expected_names = {e["filename"] for e in expected}

    files: List[Dict[str, Any]] = []
    names_seen: List[str] = []
    try:
        names_seen = sorted(os.listdir(args.effect_dir))
    except OSError as exc:
        print(json.dumps({"error": f"LIST_FAILED: {exc}"}))
        return 3

    for name in names_seen:
        path = os.path.join(args.effect_dir, name)
        entry: Dict[str, Any] = {"filename": name}
        try:
            st = os.stat(path)
            with open(path, "rb") as f:
                blob = f.read()
        except OSError as exc:
            entry["read_error"] = repr(exc)
            files.append(entry)
            continue
        entry["size"] = st.st_size
        entry["inode"] = st.st_ino
        entry["mtime_ns"] = st.st_mtime_ns
        entry["sha256"] = hashlib.sha256(blob).hexdigest()
        try:
            content = json.loads(blob.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            entry["parse_error"] = repr(exc)
            files.append(entry)
            continue
        fields = {k: v for k, v in content.items() if k != "content_digest"}
        entry["content"] = content
        entry["content_digest_valid"] = content.get("content_digest") == canonical_hash(fields)
        exp = next((e for e in expected if e["filename"] == name), None)
        if exp is not None:
            entry["matches_expected"] = all(
                content.get(k) == exp[k]
                for k in ("permit_id", "nonce", "action", "resource")
            )
        files.append(entry)

    absent_results = {n: (n not in names_seen) for n in args.expect_absent}

    floor_note = None
    if args.chain_floor is not None:
        try:
            with open(args.chain_floor, "r", encoding="utf-8") as f:
                floor_note = f.read().strip()
        except OSError as exc:
            floor_note = f"UNREADABLE:{exc}"

    witness_confirmed = []
    for e in expected:
        match = next((f for f in files if f.get("filename") == e["filename"]), None)
        ok = (
            match is not None
            and match.get("content_digest_valid") is True
            and match.get("matches_expected") is True
        )
        witness_confirmed.append({"filename": e["filename"], "confirmed": ok})

    report = {
        "witness_uid": os.getuid(),
        "witness_euid": os.geteuid(),
        "observed_at_unix": time.time(),
        "effect_dir": os.path.realpath(args.effect_dir),
        "listing": names_seen,
        "files": files,
        "expected": expected,
        "expected_absent_ok": absent_results,
        "witness_confirmed": witness_confirmed,
        "chain_floor": floor_note,
        "oracle": "OS_OPEN_READ_SHA256",
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(json.dumps({"written": args.out, "confirmed": witness_confirmed, "absent_ok": absent_results}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
