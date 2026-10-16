"""Harnais du bac AEGIS V3E — rôles OS séparés, loopback uniquement.

Rôles (V3E_THREAT_MODEL.md §2) :
  - orchestrateur admin : ce processus (uid user) — hors menace, journalise ;
  - PEP          : sudo -n -u aegis_pep   (uvicorn pep_v3e_effect:app) ;
  - client       : sudo -n -u aegis_agent (tests/http_client_v3e.py) ;
  - témoin       : sudo -n -u aegis_witness (INDEPENDENT_WITNESS_SOURCE/witness_v3e.sh).
Chaque commande sudo est journalisée (cmdline/stdout/stderr/exit) dans
RAW_EVIDENCE/privileged_journal.jsonl. Jamais d'API de confiance côté témoin.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

HERE = Path(__file__).resolve().parent
V3E_DIR = HERE.parent
REPO = V3E_DIR.parent
RAW = V3E_DIR / "RAW_EVIDENCE"

SANDBOX = Path("/tmp/aegis_v3e_sandbox")
CONFIG = SANDBOX / "config"
EFFECT = SANDBOX / "effect"
STATE = SANDBOX / "state"
WITNESS = SANDBOX / "witness"
LOGS = SANDBOX / "logs"
REQ = SANDBOX / "req"
AGENT_OUT = SANDBOX / "agent_out"
APP = SANDBOX / "app"
PYLIBS = SANDBOX / "pylibs"

PY = "/usr/bin/python3"
RUN_ENV_PYTHONPATH = f"{PYLIBS}:{APP}"

ISSUER = "monsterdog.core.v3e"
AUDIENCE = "monsterdog.pep.v3e.local"
POLICY_VERSION = "v3e.1.0"
FIXED_NOW = "1760650000.0"

_signer: Optional[ed25519.Ed25519PrivateKey] = None


# ---------------------------------------------------------------------------
# Journal des commandes privilégiées (sudo) — exigence d'autorisation
# ---------------------------------------------------------------------------

def journal_priv(desc: str, cmd: List[str], stdout: str, stderr: str, rc: int) -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "desc": desc,
        "cmdline": " ".join(cmd),
        "stdout": stdout[:4000],
        "stderr": stderr[:4000],
        "exit_code": rc,
    }
    with open(RAW / "privileged_journal.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def run_priv(desc: str, cmd: List[str], check: bool = False) -> subprocess.CompletedProcess:
    """Exécute une commande (sudo -n préfixé si absent) et la journalise."""
    full = cmd if cmd[0] == "sudo" else ["sudo", "-n"] + cmd
    p = subprocess.run(full, capture_output=True, text=True)
    journal_priv(desc, full, p.stdout, p.stderr, p.returncode)
    if check and p.returncode != 0:
        raise RuntimeError(f"run_priv failed rc={p.returncode}: {desc} :: {p.stderr[:300]}")
    return p


# ---------------------------------------------------------------------------
# Canon et permis (identique au canon V3C/V3D)
# ---------------------------------------------------------------------------

def load_signer() -> ed25519.Ed25519PrivateKey:
    global _signer
    if _signer is None:
        pem = (HERE / "keys" / "signer_private_test_only.pem").read_bytes()
        _signer = serialization.load_pem_private_key(pem, password=None)
    return _signer


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
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    policy_version: Optional[str] = POLICY_VERSION,
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


def expected_marker_blob(
    permit_id: str,
    nonce: str,
    subject: str,
    action: str,
    resource: str,
    policy_version: str,
    materialized_at: str,
) -> bytes:
    """Sérialisation exacte du marqueur (pré-calcul, horloge figée)."""
    fields = {
        "permit_id": permit_id,
        "nonce": nonce,
        "subject": subject,
        "action": action,
        "resource": resource,
        "policy_version": policy_version,
        "materialized_at": materialized_at,
    }
    record = dict(fields)
    record["content_digest"] = canonical_hash(fields)
    return (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


# ---------------------------------------------------------------------------
# Serveur PEP sous UID aegis_pep
# ---------------------------------------------------------------------------

def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServerHandle:
    def __init__(self, env_overrides: Optional[Dict[str, str]] = None, name: str = "S_V3E") -> None:
        self.env_overrides = dict(env_overrides or {})
        self.name = name
        self.port = free_port()
        self.proc: Optional[subprocess.Popen] = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self, wait_s: float = 25.0) -> None:
        env_pairs = {
            "AEGIS_POLICY_PATH": str(CONFIG / "pep_policy_v3e.json"),
            "AEGIS_KEY_PATH": str(CONFIG / "pep_public.key"),
            "AEGIS_PIN_PATH": str(CONFIG / "trust_root.pin"),
            "AEGIS_DB_PATH": str(STATE / "pep_ledger.db"),
            "AEGIS_EFFECT_DIR": str(EFFECT),
            "AEGIS_REAL_ACTIONS": "marker.create",
            "AEGIS_EXPECT_CONFIG_UID": "0",
            "AEGIS_TEST_MODE": "1",
            "AEGIS_FIXED_NOW": FIXED_NOW,
            "PYTHONPATH": RUN_ENV_PYTHONPATH,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        env_pairs.update(self.env_overrides)
        env_args = [f"{k}={v}" for k, v in sorted(env_pairs.items())]
        log_out = LOGS / f"{self.name}.out"
        log_err = LOGS / f"{self.name}.err"
        inner = (
            f"exec {PY} -m uvicorn pep_v3e_effect:app"
            f" --host 127.0.0.1 --port {self.port} --log-level warning"
            f" >> {log_out} 2>> {log_err}"
        )
        cmd = ["sudo", "-n", "-u", "aegis_pep", "env", *env_args, "sh", "-c", inner]
        self.proc = subprocess.Popen(
            cmd, cwd=str(APP), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        journal_priv(f"start server {self.name} (uid aegis_pep)", cmd, "", "", -1)
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
# Client agent (UID aegis_agent) et témoin indépendant (UID aegis_witness)
# ---------------------------------------------------------------------------

def ensure_run_dirs() -> None:
    REQ.mkdir(parents=True, exist_ok=True)
    RAW.mkdir(parents=True, exist_ok=True)


def agent_post(base_url: str, payload: Dict[str, Any], tag: str) -> Dict[str, Any]:
    ensure_run_dirs()
    req_path = REQ / f"req_{tag}.json"
    out_path = AGENT_OUT / f"out_{tag}.json"  # dossier writable par aegis_agent
    req_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    run_priv(f"rm stale agent out {tag}", ["rm", "-f", str(out_path)])
    cmd = [
        "sudo", "-n", "-u", "aegis_agent",
        "env", f"PYTHONPATH={RUN_ENV_PYTHONPATH}",
        PY, str(APP / "http_client_v3e.py"),
        "--url", f"{base_url}/v1/execute",
        "--json", str(req_path),
        "--out", str(out_path),
    ]
    p = subprocess.run(cmd, capture_output=True, text=True)
    journal_priv(f"agent_post {tag} (uid aegis_agent)", cmd, p.stdout, p.stderr, p.returncode)
    if out_path.exists():
        return json.loads(out_path.read_text(encoding="utf-8"))
    return {"status_code": None, "body": None, "error": f"no out file rc={p.returncode}"}


def agent_get(base_url: str, tag: str, path: str = "/v1/health") -> Dict[str, Any]:
    ensure_run_dirs()
    out_path = AGENT_OUT / f"out_{tag}.json"
    cmd = [
        "sudo", "-n", "-u", "aegis_agent",
        "env", f"PYTHONPATH={RUN_ENV_PYTHONPATH}",
        PY, str(APP / "http_client_v3e.py"),
        "--url", f"{base_url}{path}", "--get",
        "--out", str(out_path),
    ]
    p = subprocess.run(cmd, capture_output=True, text=True)
    journal_priv(f"agent_get {tag} (uid aegis_agent)", cmd, p.stdout, p.stderr, p.returncode)
    if out_path.exists():
        return json.loads(out_path.read_text(encoding="utf-8"))
    return {"status_code": None, "body": None, "error": f"no out file rc={p.returncode}"}


def witness_run(
    assertion_rows: List[Tuple[str, int, str]],
    run_id: str,
    effect_dir: Path = EFFECT,
    tag: str = "w",
) -> Dict[str, Any]:
    """Témoin indépendant POSIX sh — seul oracle d'effet."""
    ensure_run_dirs()
    assert_path = REQ / f"assert_{tag}.tsv"
    lines = ["# sha256\tsize\tfile_name"]
    for sha, size, name in assertion_rows:
        lines.append(f"{sha}\t{size}\t{name}")
    assert_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    cmd = [
        "sudo", "-n", "-u", "aegis_witness",
        "sh", str(APP / "witness_v3e.sh"),
        str(effect_dir), str(assert_path), run_id,
    ]
    p = subprocess.run(cmd, capture_output=True, text=True)
    journal_priv(f"witness_run {run_id} (uid aegis_witness)", cmd, p.stdout, p.stderr, p.returncode)
    report = {
        "run_id": run_id,
        "tag": tag,
        "exit_code": p.returncode,
        "raw_stdout": p.stdout,
        "raw_stderr": p.stderr,
    }
    verdict_line = ""
    for line in p.stdout.splitlines():
        if line.startswith("WITNESS_VERDICT="):
            verdict_line = line.split("=", 1)[1]
    report["verdict"] = verdict_line or ("UNAVAILABLE" if p.returncode == 3 else "UNKNOWN")
    out = RAW / "witness_reports" / f"{run_id}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return report


def ls_ln(target: Path) -> str:
    p = subprocess.run(["ls", "-ln", str(target)], capture_output=True, text=True)
    return p.stdout


def db_snapshot(label: str) -> Dict[str, Any]:
    """Instantané SQLite via UID aegis_pep (seul lecteur légitime du registre)."""
    code = (
        "import sqlite3,json\n"
        "con=sqlite3.connect('/tmp/aegis_v3e_sandbox/state/pep_ledger.db')\n"
        "cur=con.cursor()\n"
        "names=[r[0] for r in cur.execute(\"select name from sqlite_master where type='table'\")]\n"
        "rows={}\n"
        "for t in sorted(names):\n"
        "    try:\n"
        "        cols=[d[1] for d in cur.execute('pragma table_info('+t+')')]\n"
        "        rows[t]={'columns':cols,'rows':[list(r) for r in cur.execute('select * from '+t)]}\n"
        "    except Exception as e:\n"
        "        rows[t]={'error':repr(e)}\n"
        "print(json.dumps(rows))\n"
    )
    cmd = ["sudo", "-n", "-u", "aegis_pep", "env", f"PYTHONPATH={RUN_ENV_PYTHONPATH}",
           PY, "-c", code]
    p = subprocess.run(cmd, capture_output=True, text=True)
    journal_priv(f"db_snapshot {label} (uid aegis_pep)", cmd, p.stdout[:2000], p.stderr, p.returncode)
    snap: Dict[str, Any] = {"exit_code": p.returncode, "stderr": p.stderr[:500]}
    try:
        snap["rows"] = json.loads(p.stdout)
    except Exception:  # noqa: BLE001
        snap["rows"] = None
        snap["stdout_head"] = p.stdout[:500]
    out = RAW / "db_states" / f"{label}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(snap, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return snap


def capture_marker_bytes(name: str, label: str) -> Dict[str, Any]:
    """Copie EXACTE des octets du marqueur dans RAW_EVIDENCE (preuve portable)."""
    src = EFFECT / name
    dst_dir = RAW / "markers"
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / f"{label}_{name}"
    if not src.exists():
        return {"present": False}
    data = src.read_bytes()
    dst.write_bytes(data)
    return {
        "present": True,
        "raw_copy": str(dst.relative_to(V3E_DIR)),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }
