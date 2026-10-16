#!/usr/bin/env python3
"""Provisionnement admin : clé Ed25519 de test, pin, politique V3D.

Génère `tests/keys/signer_*_test_only.*` (forge, admin uniquement) et installe
la config dans /tmp/aegis_v3d_sandbox/config en root:root 0644 (jamais
inscriptible par aegis_pep ni aegis_agent). Rejouable via tests/setup_sandbox.sh.
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
CONFIG = Path("/tmp/aegis_v3d_sandbox/config")
STAGE = Path("/tmp/aegis_v3d_stage")


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
        "policy_version": "v3d.1.0",
        "audience": "monsterdog.pep.v3d.local",
        "trust_root_fingerprint": fp,
        "allowed_issuers": ["monsterdog.core.v3d"],
        "allowlist": [
            {"subject": "agent-alpha", "action": "marker.create", "resource": "effect/marker-P-*.json"},
            {"subject": "agent-alpha", "action": "report.read", "resource": "reports/*"},
            {"subject": "agent-alpha", "action": "email.send", "resource": "outbox/digest"},
            {"subject": "agent-beta", "action": "report.read", "resource": "reports/public/*"},
        ],
        "max_ttl_seconds": 300,
        "max_issued_at_skew_seconds": 60,
    }

    STAGE.mkdir(exist_ok=True)
    (STAGE / "pep_policy_v3d.json").write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
    (STAGE / "pep_public.key").write_bytes(pub_raw)
    (STAGE / "trust_root.pin").write_text(fp + "\n", encoding="utf-8")

    subprocess.run(
        ["sudo", "cp",
         str(STAGE / "pep_policy_v3d.json"), str(STAGE / "pep_public.key"),
         str(STAGE / "trust_root.pin"), str(CONFIG) + "/"],
        check=True,
    )
    subprocess.run(
        ["sudo", "chown", "root:root",
         str(CONFIG / "pep_policy_v3d.json"), str(CONFIG / "pep_public.key"),
         str(CONFIG / "trust_root.pin")],
        check=True,
    )
    subprocess.run(
        ["sudo", "chmod", "644",
         str(CONFIG / "pep_policy_v3d.json"), str(CONFIG / "pep_public.key"),
         str(CONFIG / "trust_root.pin")],
        check=True,
    )
    print("fingerprint:", fp)
    print("provisioned OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
