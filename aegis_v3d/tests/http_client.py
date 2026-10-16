#!/usr/bin/env python3
"""Client HTTP minimal pour l'UID non fiable `aegis_agent` (loopback uniquement).

Usage : http_client.py --url URL --json REQ.json --out OUT.json [--timeout N]
Sortie : {"status_code": int|null, "body": ..., "error": ...} (JSON).
"""

from __future__ import annotations

import argparse
import json

import httpx


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--json", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--get", action="store_true")
    args = ap.parse_args()

    out = {}
    try:
        if args.get:
            r = httpx.get(args.url, timeout=args.timeout)
        else:
            with open(args.json, "r", encoding="utf-8") as f:
                payload = json.load(f)
            r = httpx.post(args.url, json=payload, timeout=args.timeout)
        try:
            body = r.json()
        except Exception:  # noqa: BLE001
            body = {"_raw": r.text[:500]}
        out = {"status_code": r.status_code, "body": body}
    except Exception as exc:  # noqa: BLE001
        out = {"status_code": None, "body": None, "error": repr(exc)}

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)
        f.write("\n")
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
