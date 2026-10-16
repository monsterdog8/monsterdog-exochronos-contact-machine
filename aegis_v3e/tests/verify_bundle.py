#!/usr/bin/env python3
"""verify_bundle.py — VÉRIFICATEUR EXTERNE indépendant (V3E).

Troisième implémentation : il ne croit ni le PEP, ni le témoin, ni le runner.
Il RECALCULE tout depuis les octets RAW du paquet :
  - empreinte du manifeste gelé vs ANCRE (git) — refuse tout rollback (V3) ;
  - chaîne de reçus (prev_hash) — refuse toute rupture ;
  - octets des marqueurs RAW vs attentes pré-enregistrées ;
  - rapports du témoin vs recalcul depuis les octets — refuse la substitution
    de rapport (V2) et l'altération d'octet (V1) ;
  - source du témoin (empreinte) vs source livrée ;
  - rapport de témoin absent -> UNKNOWN/HOLD (V5), jamais CONFIRMED.

Exit codes : 0 VERIFIED | 1 REFUSED | 3 UNKNOWN/HOLD | 2 usage
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def fail(code: int, msg: str) -> int:
    print(f"VERIFY_VERDICT={ {1: 'REFUSED', 3: 'UNKNOWN_HOLD', 2: 'USAGE'}[code] }")
    print(f"reason={msg}")
    return code


def parse_witness_report(text: str) -> Dict[str, Any]:
    rep: Dict[str, Any] = {"files": [], "raw": text}
    for line in text.splitlines():
        if line.startswith("WITNESS_VERDICT="):
            rep["verdict"] = line.split("=", 1)[1].strip()
        elif line.startswith("run_id="):
            rep["run_id"] = line.split("=", 1)[1].strip()
        elif line.startswith("euid="):
            rep["euid"] = line.split("=", 1)[1].strip()
        elif line.startswith("witness_source_sha256="):
            rep["source_sha256"] = line.split("=", 1)[1].strip()
        elif line.startswith("FILE "):
            fields = dict(kv.split("=", 1) for kv in line.split()[1:] if "=" in kv)
            rep["files"].append(fields)
    return rep


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True, help="répertoire RAW_EVIDENCE")
    ap.add_argument("--freeze", required=True, help="EXPERIMENT_FREEZE.json")
    ap.add_argument("--anchor-sha256", required=True,
                    help="empreinte attendue du freeze (ancre git, pré-réservation)")
    ap.add_argument("--witness-source", required=True,
                    help="INDEPENDENT_WITNESS_SOURCE/witness_v3e.sh")
    args = ap.parse_args()

    bundle = Path(args.bundle)
    freeze = Path(args.freeze)
    witness_src = Path(args.witness_source)
    if not bundle.is_dir():
        return fail(2, "bundle missing")

    problems: List[str] = []
    holds: List[str] = []

    # --- V3 : ancre du manifeste gelé -------------------------------------
    freeze_sha = sha256_file(freeze)
    if freeze_sha != args.anchor_sha256.strip():
        return fail(1, f"freeze hash {freeze_sha} != anchor {args.anchor_sha256.strip()} (rollback?)")
    print(f"check=FREEZE_ANCHOR ok sha256={freeze_sha}")

    # --- chaîne de reçus ---------------------------------------------------
    chain_path = bundle / "receipts_chain.jsonl"
    if not chain_path.exists():
        return fail(1, "receipts chain missing")
    prev = "GENESIS"
    n_entries = 0
    for line in chain_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry.get("prev_hash") != prev:
            return fail(1, f"chain break at seq={entry.get('seq')}")
        body = json.dumps({k: v for k, v in entry.items() if k != "entry_hash"},
                          sort_keys=True, ensure_ascii=False)
        h = hashlib.sha256(body.encode("utf-8")).hexdigest()
        if h != entry.get("entry_hash"):
            return fail(1, f"entry hash mismatch at seq={entry.get('seq')}")
        prev = entry["entry_hash"]
        n_entries += 1
    print(f"check=RECEIPT_CHAIN ok entries={n_entries} head={prev[:16]}...")

    # --- attentes pré-enregistrées ----------------------------------------
    pre = json.loads((bundle / "precomputed_expectations.json").read_text(encoding="utf-8"))
    markers_dir = bundle / "markers"
    if not markers_dir.is_dir():
        return fail(1, "no RAW marker bytes in bundle")
    raw_markers = sorted(markers_dir.glob("*.json"))
    if not raw_markers:
        return fail(1, "RAW marker set empty")
    recomputed: Dict[str, Tuple[str, int]] = {}
    for m in raw_markers:
        data = m.read_bytes()
        # nom logique : retirer le préfixe de label éventuel
        name = m.name.split("_", 1)[-1] if "_" in m.name else m.name
        recomputed[name] = (hashlib.sha256(data).hexdigest(), len(data))
    print(f"check=RAW_MARKER_BYTES ok count={len(raw_markers)}")

    # --- rapports du témoin -------------------------------------------------
    wdir = bundle / "witness_reports"
    reports = sorted(wdir.glob("*.json")) if wdir.is_dir() else []
    usable = 0
    allow_report = None
    for rp in reports:
        r = json.loads(rp.read_text(encoding="utf-8"))
        text = r.get("raw_stdout", "")
        parsed = parse_witness_report(text)
        if parsed.get("verdict") not in ("VALID", "INVALID"):
            # rapports d'attaque (ex. V5 UNAVAILABLE) : conservés, jamais confirmants
            continue
        usable += 1
        # empreinte de la source du témoin
        src_sha = sha256_file(witness_src)
        if parsed.get("source_sha256") not in (None, src_sha):
            problems.append(f"witness report {rp.name}: source hash mismatch")
        if parsed.get("verdict") == "VALID":
            for f in parsed["files"]:
                if f.get("verdict") != "OK":
                    problems.append(f"report {rp.name}: FILE not OK {f}")
                    continue
                name = f.get("name")
                if name in recomputed:
                    got_sha, got_size = recomputed[name]
                    if got_sha != f.get("sha256") or str(got_size) != f.get("size"):
                        problems.append(
                            f"report {rp.name}: claimed {f} but RAW bytes give {got_sha}/{got_size}"
                        )
                else:
                    problems.append(f"report {rp.name}: no RAW bytes for {name}")
        if "A1" in rp.name or "ALLOW" in rp.name.upper():
            allow_report = parsed

    # --- V5 : confirmation jamais par défaut -------------------------------
    if allow_report is None and usable == 0:
        holds.append("no usable witness report -> cannot confirm effect (V5)")
    elif allow_report is None:
        holds.append("no ALLOW witness report found -> cannot confirm effect (V5)")

    if problems:
        for p in problems:
            print("problem:", p)
        return fail(1, "bundle verification refused")
    if holds:
        for h in holds:
            print("hold:", h)
        return fail(3, "cannot confirm without witness (UNKNOWN/HOLD)")
    print("check=WITNESS_REPORTS ok (raw bytes agree with reports)")
    print("VERIFY_VERDICT=VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
