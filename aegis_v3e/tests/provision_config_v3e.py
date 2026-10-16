#!/usr/bin/env python3
"""Provisionnement V3E : clé Ed25519 de test, pin, politique v3e.

Écrit `tests/keys/signer_*_test_only.*` côté admin (gitignoré, jamais dans RAW)
et installe la config dans /tmp/aegis_v3e_sandbox/config en root:root 0644.
Exécuté APRÈS tests/setup_sandbox_v3e.sh (journalisé via sudo -n).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

HERE = Path(__file__).resolve().parent
V3E = HERE.parent
CONFIG = Path("/tmp/aegis_v3e_sandbox/config")
STAGE = Path("/tmp/aegis_v3e_stage")

POLICY_VERSION = "v3e.1.0"
AUDIENCE = "monsterdog.pep.v3e.local"
ISSUER = "monsterdog.core.v3e"
FIXED_NOW = "1760650000.0"  # horloge figée : marqueurs pré-calculables


def main() -> int:
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    fp = hashlib.sha256(pub_raw).hexdigest()

    keys = HERE / "keys"
    keys.mkdir(exist_ok=True)
    (keys / "signer_private_test_only.pem").write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (keys / "signer_public_raw_test_only.bin").write_bytes(pub_raw)

    policy = {
        "policy_version": POLICY_VERSION,
        "audience": AUDIENCE,
        "trust_root_fingerprint": fp,
        "allowed_issuers": [ISSUER],
        "allowlist": [
            {
                "subject": "agent-alpha",
                "action": "marker.create",
                "resource": "effect/marker-P-*.json",
            },
        ],
        "max_ttl_seconds": 300,
        "max_issued_at_skew_seconds": 60,
    }

    STAGE.mkdir(exist_ok=True)
    (STAGE / "pep_policy_v3e.json").write_text(
        json.dumps(policy, indent=2) + "\n", encoding="utf-8"
    )
    (STAGE / "pep_public.key").write_bytes(pub_raw)
    (STAGE / "trust_root.pin").write_text(fp + "\n", encoding="utf-8")

    def run_priv(desc: str, cmd: list) -> None:
        import datetime
        p = subprocess.run(cmd, capture_output=True, text=True)
        entry = {
            "ts_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "desc": desc,
            "cmdline": " ".join(cmd),
            "stdout": p.stdout[:4000],
            "stderr": p.stderr[:4000],
            "exit_code": p.returncode,
        }
        journal = V3E / "PROVISION_JOURNAL.jsonl"
        with open(journal, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        print(f"[JOURNAL] rc={p.returncode} {desc}")
        if p.returncode != 0:
            raise SystemExit(f"priv command failed: {desc}")

    run_priv("cp policy+key+pin into sandbox config",
             ["sudo", "-n", "cp",
              str(STAGE / "pep_policy_v3e.json"), str(STAGE / "pep_public.key"),
              str(STAGE / "trust_root.pin"), str(CONFIG) + "/"])
    run_priv("chown root:root config files",
             ["sudo", "-n", "chown", "root:root",
              str(CONFIG / "pep_policy_v3e.json"), str(CONFIG / "pep_public.key"),
              str(CONFIG / "trust_root.pin")])
    run_priv("chmod 644 config files",
             ["sudo", "-n", "chmod", "644",
              str(CONFIG / "pep_policy_v3e.json"), str(CONFIG / "pep_public.key"),
              str(CONFIG / "trust_root.pin")])
    # copie de commodité pour le harnais admin (hors RAW ; clé privée exclue)
    (V3E / "results_stage").mkdir(exist_ok=True)
    (V3E / "results_stage" / "fingerprint.txt").write_text(fp + "\n", encoding="utf-8")
    print("fingerprint:", fp)
    print("policy_version:", POLICY_VERSION)
    print("fixed_now:", FIXED_NOW)
    print("provisioned OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
