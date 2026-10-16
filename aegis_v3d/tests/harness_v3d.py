"""Harnais du bac AEGIS V3D — rôles OS séparés, loopback uniquement.

Rôles (THREAT_MODEL.md §1/§4) :
  - orchestrateur admin : ce processus (uid user, sudo) — hors menace ;
  - PEP          : sudo -u aegis_pep   (uvicorn pep_v3d_effect:app) ;
  - client       : sudo -u aegis_agent (tests/http_client.py) ;
  - témoin       : sudo -u aegis_witness (tests/effect_witness.py).
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

HERE = Path(__file__).resolve().parent
AEGIS_V3D_DIR = HERE.parent
REPO = AEGIS_V3D_DIR.parent
V3C_DIR = REPO / "aegis_v3c"
VENV_PY = "/home/user/.venv-aegis/bin/python"

SANDBOX = Path("/tmp/aegis_v3d_sandbox")
CONFIG = SANDBOX / "config"
EFFECT = SANDBOX / "effect"
STATE = SANDBOX / "state"
WITNESS = SANDBOX / "witness"
LOGS = SANDBOX / "logs"
REQ = SANDBOX / "req"
AGENT_OUT = SANDBOX / "agent_out"

DEFAULT_ISSUER = "monsterdog.core.v3d"
DEFAULT_AUDIENCE = "monsterdog.pep.v3d.local"
DEFAULT_POLICY_VERSION = "v3d.1.0"

_signer: Optional[ed25519.Ed25519PrivateKey] = None


# ---------------------------------------------------------------------------
# Identités et sandbox
# ---------------------------------------------------------------------------


def ensure_sandbox_dirs() -> None:
    # le dossier racine du bac est root-owned : création via sudo
    subprocess.run(["sudo", "mkdir", "-p", str(REQ), str(AGENT_OUT)], check=True)
    # REQ : écriture orchestrateur (admin), lecture agent. AGENT_OUT : écriture agent.
    subprocess.run(["sudo", "chown", "user:user", str(REQ)], check=True)
    subprocess.run(["sudo", "chmod", "755", str(REQ)], check=True)
    subprocess.run(["sudo", "chown", "aegis_agent:aegis_agent", str(AGENT_OUT)], check=True)
    subprocess.run(["sudo", "chmod", "700", str(AGENT_OUT)], check=True)


def reset_runtime_state() -> None:
    """Réinitialise les artefacts RUNTIME (registre + marqueurs) entre deux suites.

    Les noms de fixtures sont figés par THREAT_MODEL.md ; un registre persistant
    rendrait la 2e exécution non reproductible (permit_id UNIQUE). Les sources,
    la config root-owned et les journaux de preuve ne sont jamais touchés.
    """
    subprocess.run(
        [
            "sudo", "-u", "aegis_pep", "sh", "-c",
            "rm -f /tmp/aegis_v3d_sandbox/state/pep_ledger.db "
            "/tmp/aegis_v3d_sandbox/state/pep_ledger.db-wal "
            "/tmp/aegis_v3d_sandbox/state/pep_ledger.db-shm "
            "/tmp/aegis_v3d_sandbox/effect/marker-*.json",
        ],
        check=True,
    )


def load_signer() -> ed25519.Ed25519PrivateKey:
    global _signer
    if _signer is None:
        pem = (HERE / "keys" / "signer_private_test_only.pem").read_bytes()
        _signer = serialization.load_pem_private_key(pem, password=None)
    return _signer


def legit_pub_raw() -> bytes:
    return (HERE / "keys" / "signer_public_raw_test_only.bin").read_bytes()


def fingerprint(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Forge de permis (identique au canon V3C)
# ---------------------------------------------------------------------------


def canonical_hash(obj: dict) -> str:
    c_str = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(c_str.encode("utf-8")).hexdigest()


def make_request(subject: str, action: str, resource: str) -> Dict[str, str]:
    return {"subject": subject, "action": action, "resource": resource}


def forge_permit(
    priv: Optional[ed25519.Ed25519PrivateKey] = None,
    *,
    permit_id: str,
    nonce: str,
    orig_request: Dict[str, Any],
    issued_at: float,
    expires_at: float,
    issuer: str = DEFAULT_ISSUER,
    audience: str = DEFAULT_AUDIENCE,
    policy_version: Optional[str] = DEFAULT_POLICY_VERSION,
    subject: Optional[str] = None,
    action: Optional[str] = None,
    resource: Optional[str] = None,
    extra_fields: Optional[Dict[str, Any]] = None,
    request_hash: Optional[str] = None,
) -> Dict[str, Any]:
    priv = priv or load_signer()
    body: Dict[str, Any] = {
        "permit_id": permit_id,
        "issuer": issuer,
        "subject": subject if subject is not None else orig_request["subject"],
        "action": action if action is not None else orig_request["action"],
        "resource": resource if resource is not None else orig_request["resource"],
        "audience": audience,
        "policy_version": policy_version,
        "nonce": nonce,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "request_hash": request_hash
        if request_hash is not None
        else canonical_hash(orig_request),
    }
    if extra_fields:
        body.update(extra_fields)
    sig = priv.sign(canonical_hash(body).encode("utf-8")).hex()
    return {**body, "signature": sig}


# ---------------------------------------------------------------------------
# Serveur PEP sous UID aegis_pep
# ---------------------------------------------------------------------------


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServerHandle:
    def __init__(
        self,
        env_overrides: Optional[Dict[str, str]] = None,
        name: str = "S_V3D",
    ) -> None:
        self.env_overrides = dict(env_overrides or {})
        self.name = name
        self.port = free_port()
        self.proc: Optional[subprocess.Popen] = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self, wait_s: float = 25.0) -> None:
        env_pairs = {
            "AEGIS_POLICY_PATH": str(CONFIG / "pep_policy_v3d.json"),
            "AEGIS_KEY_PATH": str(CONFIG / "pep_public.key"),
            "AEGIS_PIN_PATH": str(CONFIG / "trust_root.pin"),
            "AEGIS_DB_PATH": str(STATE / "pep_ledger.db"),
            "AEGIS_EFFECT_DIR": str(EFFECT),
            "AEGIS_REAL_ACTIONS": "marker.create",
            "AEGIS_EXPECT_CONFIG_UID": "0",
            "AEGIS_TEST_MODE": "1",
            "PYTHONPATH": str(AEGIS_V3D_DIR),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        env_pairs.update(self.env_overrides)
        env_args = [f"{k}={v}" for k, v in sorted(env_pairs.items())]
        log_out = LOGS / f"{self.name}.out"
        log_err = LOGS / f"{self.name}.err"
        inner = (
            f"exec {VENV_PY} -m uvicorn pep_v3d_effect:app"
            f" --host 127.0.0.1 --port {self.port} --log-level warning"
            f" >> {log_out} 2>> {log_err}"
        )
        cmd = [
            "sudo", "-u", "aegis_pep",
            "env", *env_args,
            "sh", "-c", inner,
        ]
        self.proc = subprocess.Popen(
            cmd,
            cwd=str(AEGIS_V3D_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + wait_s
        last_err = ""
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.name}: died rc={self.proc.returncode} ({last_err})")
            try:
                r = httpx.get(self.base_url + "/v1/health", timeout=1.0)
                if r.status_code == 200:
                    return
                last_err = f"health={r.status_code}"
            except Exception as exc:  # noqa: BLE001
                last_err = repr(exc)
            time.sleep(0.05)
        raise RuntimeError(f"{self.name}: health timeout ({last_err})")

    def stop(self) -> Optional[int]:
        if self.proc is None:
            return None
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        rc = self.proc.returncode
        self.proc = None
        return rc

    def restart(self) -> None:
        self.stop()
        self.start()

    def health(self) -> Dict[str, Any]:
        return httpx.get(self.base_url + "/v1/health", timeout=5.0).json()


# ---------------------------------------------------------------------------
# Appels client sous UID aegis_agent (jamais d'API de confiance côté témoin)
# ---------------------------------------------------------------------------


def agent_post(base_url: str, payload: Dict[str, Any], tag: str) -> Dict[str, Any]:
    req_path = REQ / f"req_{tag}.json"
    out_path = AGENT_OUT / f"out_{tag}.json"
    req_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    subprocess.run(["sudo", "rm", "-f", str(out_path)], check=False)
    cmd = [
        "sudo", "-u", "aegis_agent",
        VENV_PY, str(HERE / "http_client.py"),
        "--url", base_url + "/v1/execute",
        "--json", str(req_path),
        "--out", str(out_path),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    exists = subprocess.run(
        ["sudo", "test", "-f", str(out_path)], capture_output=True
    ).returncode == 0
    if not exists:
        return {"status_code": None, "body": None, "error": f"no out rc={proc.returncode}"}
    raw = subprocess.run(
        ["sudo", "cat", str(out_path)], capture_output=True, text=True, check=True
    ).stdout
    return json.loads(raw)


def agent_exec(code: str) -> Dict[str, Any]:
    """Exécute du code Python sous l'UID non fiable. Retourne {rc, stdout, stderr}."""
    proc = subprocess.run(
        ["sudo", "-u", "aegis_agent", VENV_PY, "-c", code],
        capture_output=True, text=True, timeout=60,
    )
    return {"rc": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip()}


# ---------------------------------------------------------------------------
# Témoin sous UID aegis_witness
# ---------------------------------------------------------------------------


def run_witness(
    tag: str,
    expect: Optional[List[Dict[str, str]]] = None,
    expect_absent: Optional[List[str]] = None,
    chain_floor: Optional[str] = None,
) -> Dict[str, Any]:
    out_path = WITNESS / f"witness_{tag}.json"
    subprocess.run(["sudo", "rm", "-f", str(out_path)], check=False)
    cmd = [
        "sudo", "-u", "aegis_witness",
        VENV_PY, str(HERE / "effect_witness.py"),
        "--effect-dir", str(EFFECT),
        "--out", str(out_path),
    ]
    for e in expect or []:
        cmd += ["--expect", "|".join([e["filename"], e["permit_id"], e["nonce"], e["action"], e["resource"]])]
    for n in expect_absent or []:
        cmd += ["--expect-absent", n]
    if chain_floor is not None:
        floor_file = WITNESS / f"floor_{tag}.txt"
        subprocess.run(
            ["sudo", "tee", str(floor_file)], input=chain_floor + "\n",
            capture_output=True, text=True, check=True,
        )
        subprocess.run(["sudo", "chown", "aegis_witness:aegis_witness", str(floor_file)], check=True)
        cmd += ["--chain-floor", str(floor_file)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    exists = subprocess.run(
        ["sudo", "test", "-f", str(out_path)], capture_output=True
    ).returncode == 0
    if not exists:
        return {"error": f"witness failed rc={proc.returncode}", "stderr": proc.stderr[-500:]}
    return json.loads(
        subprocess.run(["sudo", "cat", str(out_path)], capture_output=True, text=True, check=True).stdout
    )


# ---------------------------------------------------------------------------
# Inspection registre (admin, lecture hors processus PEP)
# ---------------------------------------------------------------------------


def db_query(sql: str, params: Tuple = ()) -> List[Tuple]:
    proc = subprocess.run(
        ["sudo", "-u", "aegis_pep", VENV_PY, "-c",
         "import sqlite3,sys,json;"
         "conn=sqlite3.connect(sys.argv[1]);"
         "rows=conn.execute(sys.argv[2], json.loads(sys.argv[3])).fetchall();"
         "print(json.dumps(rows))",
         str(STATE / "pep_ledger.db"), sql, json.dumps(list(params))],
        capture_output=True, text=True, check=True,
    )
    return [tuple(r) for r in json.loads(proc.stdout)]


def events_for_nonce(nonce: str) -> List[str]:
    return [r[0] for r in db_query(
        "SELECT event_type FROM events WHERE nonce = ? ORDER BY event_id", (nonce,)
    )]


def status_for_nonce(nonce: str) -> Optional[str]:
    rows = db_query("SELECT status FROM consumed_permits WHERE nonce = ?", (nonce,))
    return rows[0][0] if rows else None


def chain_head() -> Optional[str]:
    rows = db_query("SELECT chain_digest FROM consumed_permits ORDER BY rowid DESC LIMIT 1")
    return rows[0][0] if rows else None


def effect_listing() -> List[str]:
    proc = subprocess.run(
        ["sudo", "-u", "aegis_agent", VENV_PY, "-c",
         "import os;print('\\n'.join(sorted(os.listdir(%r))))" % str(EFFECT)],
        capture_output=True, text=True, check=True,
    )
    names = [n for n in proc.stdout.splitlines() if n]
    return names
