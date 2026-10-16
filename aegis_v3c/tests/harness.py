"""Harnais du banc AEGIS V3C — clés, forge de permis, serveur local, workers.

LOCAL_ONLY : loopback 127.0.0.1 uniquement, aucune cible OS réelle, aucun réseau
externe. Toute la mécanique de test est explicite : aucun PASS n'est déclaré sans
observation brute associée.
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

AEGIS_DIR = Path(__file__).resolve().parents[1]
if str(AEGIS_DIR) not in sys.path:
    sys.path.insert(0, str(AEGIS_DIR))

import pep_v3c_pinned as pep_mod  # noqa: E402

VENV_PY = sys.executable
DEFAULT_ISSUER = "monsterdog.core.v3c"
DEFAULT_AUDIENCE = "monsterdog.pep.v3c.local"
DEFAULT_POLICY_VERSION = "v3c.1.0"


# ---------------------------------------------------------------------------
# Clés
# ---------------------------------------------------------------------------


def gen_keypair() -> Tuple[ed25519.Ed25519PrivateKey, bytes]:
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return priv, pub_raw


def fingerprint(pub_raw: bytes) -> str:
    return hashlib.sha256(pub_raw).hexdigest()


# ---------------------------------------------------------------------------
# Forge de permis
# ---------------------------------------------------------------------------


def canonical_hash(obj: dict) -> str:
    return pep_mod.canonical_hash(obj)


def make_request(subject: str, action: str, resource: str) -> Dict[str, str]:
    return {"subject": subject, "action": action, "resource": resource}


def forge_permit(
    priv: ed25519.Ed25519PrivateKey,
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
    """Construit un permis et le signe (corps canonique sans `signature`)."""
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


def sign_body(priv: ed25519.Ed25519PrivateKey, body: Dict[str, Any]) -> str:
    return priv.sign(canonical_hash(body).encode("utf-8")).hex()


# ---------------------------------------------------------------------------
# Espace de travail du banc
# ---------------------------------------------------------------------------


def setup_workspace(
    workspace: Path,
    pub_raw: bytes,
    policy_extra: Optional[Dict[str, Any]] = None,
) -> Path:
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "pep_public.key").write_bytes(pub_raw)
    fp = fingerprint(pub_raw)
    (workspace / "trust_root.pin").write_text(fp + "\n", encoding="utf-8")

    policy: Dict[str, Any] = {
        "policy_version": DEFAULT_POLICY_VERSION,
        "audience": DEFAULT_AUDIENCE,
        "trust_root_fingerprint": fp,
        "allowed_issuers": [DEFAULT_ISSUER],
        "allowlist": [
            {"subject": "agent-alpha", "action": "report.read", "resource": "reports/*"},
            {"subject": "agent-alpha", "action": "email.send", "resource": "outbox/digest"},
            {"subject": "agent-beta", "action": "report.read", "resource": "reports/public/*"},
        ],
        "max_ttl_seconds": 300,
        "max_issued_at_skew_seconds": 60,
    }
    if policy_extra:
        policy.update(policy_extra)
    (workspace / "pep_policy_v3c.json").write_text(
        json.dumps(policy, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return workspace


def workspace_env(workspace: Path, **overrides: str) -> Dict[str, str]:
    env = {
        "AEGIS_POLICY_PATH": str(workspace / "pep_policy_v3c.json"),
        "AEGIS_KEY_PATH": str(workspace / "pep_public.key"),
        "AEGIS_PIN_PATH": str(workspace / "trust_root.pin"),
        "AEGIS_DB_PATH": str(workspace / "pep_ledger.db"),
    }
    env.update(overrides)
    return env


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Serveur uvicorn local (loopback)
# ---------------------------------------------------------------------------


class ServerHandle:
    def __init__(
        self,
        workspace: Path,
        env_overrides: Optional[Dict[str, str]] = None,
        name: str = "S",
    ) -> None:
        self.workspace = workspace
        self.env_overrides = dict(env_overrides or {})
        self.name = name
        self.port = free_port()
        self.proc: Optional[subprocess.Popen] = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self, wait_s: float = 25.0) -> None:
        env = os.environ.copy()
        env.update(workspace_env(self.workspace))
        env.update(self.env_overrides)
        self.proc = subprocess.Popen(
            [
                VENV_PY,
                "-m",
                "uvicorn",
                "pep_v3c_pinned:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--log-level",
                "warning",
            ],
            cwd=str(AEGIS_DIR),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.time() + wait_s
        last_err = ""
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"{self.name}: uvicorn died rc={self.proc.returncode} ({last_err})"
                )
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
        r = httpx.get(self.base_url + "/v1/health", timeout=5.0)
        return r.json()

    def execute(self, orig_request: Dict[str, Any], permit: Dict[str, Any]) -> httpx.Response:
        return httpx.post(
            self.base_url + "/v1/execute",
            json={"original_request": orig_request, "permit": permit},
            timeout=30.0,
        )


# ---------------------------------------------------------------------------
# Inspection SQLite (témoins externes au processus PEP)
# ---------------------------------------------------------------------------


def db_rows(workspace: Path) -> Dict[str, List[Tuple]]:
    db = workspace if workspace.suffix == ".db" else workspace / "pep_ledger.db"
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        cur = conn.cursor()
        consumed = cur.execute(
            "SELECT nonce, permit_id, subject, action, resource, consumed_at, status"
            " FROM consumed_permits ORDER BY consumed_at, nonce"
        ).fetchall()
        events = cur.execute(
            "SELECT event_id, ts, nonce, permit_id, event_type, detail"
            " FROM events ORDER BY event_id"
        ).fetchall()
        effects = cur.execute(
            "SELECT nonce, permit_id, effect_mode, effect_at FROM effect_journal"
            " ORDER BY effect_at"
        ).fetchall()
        return {"consumed": consumed, "events": events, "effects": effects}
    finally:
        conn.close()


def events_for_nonce(workspace: Path, nonce: str) -> List[str]:
    return [e[4] for e in db_rows(workspace)["events"] if e[2] == nonce]


# ---------------------------------------------------------------------------
# Concurrence multi-processus
# ---------------------------------------------------------------------------

WORKER_SOURCE = '''\
import json, sys, time
from pathlib import Path
import httpx

go_file, out_file, payload_file, url = sys.argv[1:5]
payload = json.loads(Path(payload_file).read_text(encoding="utf-8"))
while not Path(go_file).exists():
    time.sleep(0.001)
t0 = time.time()
try:
    r = httpx.post(url + "/v1/execute", json=payload, timeout=60.0)
    out = {"status_code": r.status_code, "body": r.json()}
except Exception as exc:  # noqa: BLE001
    out = {"error": repr(exc)}
Path(out_file).write_text(json.dumps({"elapsed": time.time() - t0, **out}))
'''


def concurrent_execute(
    workspace: Path,
    base_url: str,
    orig_request: Dict[str, Any],
    permit: Dict[str, Any],
    n_workers: int,
    tag: str,
) -> List[Dict[str, Any]]:
    """n_workers interpréteurs Python distincts envoient le même permis en simultané."""
    run_dir = workspace / f"concurrency_{tag}"
    run_dir.mkdir(parents=True, exist_ok=True)
    worker_py = run_dir / "worker.py"
    worker_py.write_text(WORKER_SOURCE, encoding="utf-8")
    payload_file = run_dir / "payload.json"
    payload_file.write_text(
        json.dumps({"original_request": orig_request, "permit": permit}), encoding="utf-8"
    )
    go_file = run_dir / "go.flag"
    if go_file.exists():
        go_file.unlink()

    procs = []
    for i in range(n_workers):
        out_file = run_dir / f"out_{i}.json"
        if out_file.exists():
            out_file.unlink()
        p = subprocess.Popen(
            [
                VENV_PY,
                str(worker_py),
                str(go_file),
                str(out_file),
                str(payload_file),
                base_url,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        procs.append((p, out_file))

    time.sleep(0.4)  # laisse les workers s'installer sur la barrière
    go_file.write_text("go\n", encoding="utf-8")

    results: List[Dict[str, Any]] = []
    for p, out_file in procs:
        p.wait(timeout=90)
        if out_file.exists():
            results.append(json.loads(out_file.read_text(encoding="utf-8")))
        else:
            results.append({"error": f"no output file rc={p.returncode}"})
    return results
