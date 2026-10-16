"""MONSTERDOG AEGIS — PEP V3D (mission AEGIS_V3D_REAL_EFFECT_WITNESS_004).

Lignée : `aegis_v3c/pep_v3c_pinned.py` (préservé sans modification) + correctifs
NEMESIS N01–N05 + actionneur d'effet réel borné.

N01 — enveloppe wrapper fermée : `ExecuteRequest` avec `extra="forbid"` ;
      tout champ JSON externe supplémentaire (ex. `system_eval`) => 422.
N02 — identité d'opération : `permit_id` UNIQUE dans le registre ; deux permis
      signés partageant le même `permit_id` (nonces distincts) => 403
      PERMIT_ID_REUSED. L'idempotence métier est portée par permit_id, le
      rejeu transport par nonce.
N03 — révocation : empreinte SHA-256 de la politique re-vérifiée à CHAQUE
      requête (checkpoint par requête) ; changement => rechargement atomique ;
      politique invalide => 503 fail-closed. Contrat : révocation effective au
      plus tard à la requête suivante.
N04 — bootstrap de confiance : la concordance clé/pin/politique est conservée,
      renforcée par un contrôle des permissions de config (refus si mode
      groupe/autre-écriture, UID attendu optionnel) ; la protection réelle des
      fichiers est OS (ACL/propriétaire) — voir THREAT_MODEL.md §1, §5.
N05 — anti-rollback : registre 0700/0600 propriétaire du PEP (prévention dans
      le périmètre agent non privilégié) + chaînage `chain_digest`
      (sha256(prev || row)) permettant la DÉTECTION d'un rollback privilégié
      face à une tête de chaîne détenue hors du PEP.

Effet réel unique et borné : `marker.create` => création exclusive
(`O_CREAT|O_EXCL`) d'un fichier marqueur dans le répertoire d'effet configuré,
contenu canonique auto-intégré (`content_digest`), fsync. Toute autre action
conserve la sémantique simulée V3C (`EFFECT_SIMULATED`). `EFFECT_CONFIRMED`
n'est JAMAIS produit par ce module : la confirmation exige le témoin séparé
(`tests/effect_witness.py`, UID distinct), qui n'écoute aucune API.

Frontières de confiance (inchangées) :
    SIGNATURE_VALID != SIGNER_AUTHORIZED
    PERMIT_CONSUMED  != EFFECT_COMPLETED
    HTTP_200         != EFFECT_PROOF
    DB_MATERIALIZED  != OS_EFFECT_PROOF (le témoin tranche)
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import sqlite3
import stat as stat_mod
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

# ---------------------------------------------------------------------------
# Constantes d'enveloppe (identiques à V3C — compatibilité de banc)
# ---------------------------------------------------------------------------

PERMIT_REQUIRED_FIELDS = frozenset(
    {
        "permit_id",
        "issuer",
        "subject",
        "action",
        "resource",
        "audience",
        "policy_version",
        "nonce",
        "issued_at",
        "expires_at",
        "request_hash",
        "signature",
    }
)
REQUEST_REQUIRED_FIELDS = frozenset({"subject", "action", "resource"})

HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_SIG_RE = re.compile(r"^[0-9a-fA-F]{128}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
PERMIT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
RESOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")

MAX_TTL_SECONDS_LIMIT = 86400.0
MAX_SKEW_SECONDS_LIMIT = 3600.0

CODE_PERMIT_SCHEMA = "PERMIT_SCHEMA_VIOLATION"
CODE_REQUEST_SCHEMA = "REQUEST_SCHEMA_VIOLATION"
CODE_FIELD_TYPE = "INVALID_FIELD_TYPE"
CODE_FIELD_FORMAT = "INVALID_FIELD_FORMAT"
CODE_FIELD_VALUE = "INVALID_FIELD_VALUE"
CODE_TRUST_UNAVAILABLE = "PEP_TRUST_ROOT_UNAVAILABLE"
CODE_TRUST_PIN_MISMATCH = "PEP_TRUST_ROOT_PIN_MISMATCH"
CODE_POLICY_PIN_MISMATCH = "PEP_POLICY_PIN_MISMATCH"
CODE_POLICY_INVALID = "PEP_POLICY_INVALID"
CODE_CONFIG_INSECURE = "PEP_CONFIG_INSECURE_PERMISSIONS"
CODE_BAD_SIGNATURE = "INVALID_SIGNATURE"
CODE_EXPIRED = "PERMIT_EXPIRED"
CODE_FUTURE_ISSUED_AT = "FUTURE_ISSUED_AT"
CODE_TTL_EXCEEDED = "TTL_EXCEEDED"
CODE_TEMPORAL_INCONSISTENCY = "TEMPORAL_INCONSISTENCY"
CODE_WRONG_AUDIENCE = "WRONG_AUDIENCE"
CODE_ISSUER_FORBIDDEN = "ISSUER_FORBIDDEN"
CODE_POLICY_VERSION = "POLICY_VERSION_MISMATCH"
CODE_REQUEST_TAMPERED = "REQUEST_TAMPERED"
CODE_ACTION_FORBIDDEN = "ACTION_FORBIDDEN"
CODE_SUBJECT_FORBIDDEN = "SUBJECT_FORBIDDEN"
CODE_RESOURCE_FORBIDDEN = "RESOURCE_FORBIDDEN"
CODE_EFFECT_PATH_FORBIDDEN = "EFFECT_PATH_FORBIDDEN"
CODE_NONCE_REUSED = "NONCE_REUSED"
CODE_PERMIT_ID_REUSED = "PERMIT_ID_REUSED"
CODE_INTERNAL = "INTERNAL_ERROR"
CODE_EFFECT_UNCONFIRMED = "EFFECT_UNCONFIRMED"

EVENT_PERMIT_CONSUMED = "PERMIT_CONSUMED"
EVENT_ACTION_ATTEMPTED = "ACTION_ATTEMPTED"
EVENT_EFFECT_SIMULATED = "EFFECT_SIMULATED"
EVENT_EFFECT_MATERIALIZED = "EFFECT_MATERIALIZED"
EVENT_EFFECT_CONFIRMED = "EFFECT_CONFIRMED"  # vocabulaire réservé au témoin
EVENT_EFFECT_UNKNOWN = "EFFECT_UNKNOWN"
EVENT_POLICY_RELOADED = "POLICY_RELOADED"

EFFECT_MODE_SIM = "SIMULATED_LOCAL_ONLY"
EFFECT_MODE_REAL = "MATERIALIZED_LOCAL"

STATUS_SIM = "EFFECT_SIMULATED"
STATUS_MATERIALIZED = "EFFECT_MATERIALIZED"


def _reject(status: int, code: str, **extra: Any) -> HTTPException:
    detail: Dict[str, Any] = {"code": code}
    detail.update(extra)
    return HTTPException(status_code=status, detail=detail)


def canonical_hash(obj: dict) -> str:
    c_str = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(c_str.encode("utf-8")).hexdigest()


def _sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _now() -> float:
    if os.environ.get("AEGIS_TEST_MODE") == "1":
        fixed = os.environ.get("AEGIS_FIXED_NOW")
        if fixed is not None:
            try:
                return float(fixed)
            except ValueError:
                pass
    return time.time()


def _fault_inject(point: str) -> None:
    if os.environ.get("AEGIS_TEST_MODE") == "1":
        if os.environ.get("AEGIS_FAULT_INJECT") == point:
            code = 73
            raw = os.environ.get("AEGIS_FAULT_EXIT_CODE")
            if raw is not None:
                try:
                    code = int(raw)
                except ValueError:
                    pass
            os._exit(code)


# ---------------------------------------------------------------------------
# Politique (identique à V3C + checkpoint de révocation)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AllowRule:
    subject: str
    action: str
    resource: str


@dataclass(frozen=True)
class Policy:
    policy_version: str
    audience: str
    trust_root_fingerprint: str
    allowed_issuers: Tuple[str, ...]
    allowlist: Tuple[AllowRule, ...]
    max_ttl_seconds: float
    max_issued_at_skew_seconds: float


POLICY_REQUIRED_FIELDS = frozenset(
    {
        "policy_version",
        "audience",
        "trust_root_fingerprint",
        "allowed_issuers",
        "allowlist",
        "max_ttl_seconds",
        "max_issued_at_skew_seconds",
    }
)


def load_policy(path: str) -> Policy:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError as exc:
        raise ValueError(CODE_POLICY_INVALID + ":MISSING_FILE") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(CODE_POLICY_INVALID + ":UNREADABLE") from exc

    if not isinstance(raw, dict):
        raise ValueError(CODE_POLICY_INVALID + ":NOT_AN_OBJECT")
    if set(raw.keys()) != set(POLICY_REQUIRED_FIELDS):
        raise ValueError(CODE_POLICY_INVALID + ":SCHEMA_MISMATCH")

    pv = raw["policy_version"]
    aud = raw["audience"]
    fp = raw["trust_root_fingerprint"]
    issuers = raw["allowed_issuers"]
    allowlist = raw["allowlist"]
    ttl = raw["max_ttl_seconds"]
    skew = raw["max_issued_at_skew_seconds"]

    if not isinstance(pv, str) or not TOKEN_RE.fullmatch(pv):
        raise ValueError(CODE_POLICY_INVALID + ":POLICY_VERSION")
    if not isinstance(aud, str) or not TOKEN_RE.fullmatch(aud):
        raise ValueError(CODE_POLICY_INVALID + ":AUDIENCE")
    if not isinstance(fp, str) or not HEX_SHA256_RE.fullmatch(fp):
        raise ValueError(CODE_POLICY_INVALID + ":TRUST_ROOT_FINGERPRINT")
    if not isinstance(issuers, list) or not issuers:
        raise ValueError(CODE_POLICY_INVALID + ":ALLOWED_ISSUERS")
    if any(not isinstance(i, str) or not TOKEN_RE.fullmatch(i) for i in issuers):
        raise ValueError(CODE_POLICY_INVALID + ":ALLOWED_ISSUERS")
    if not _is_number(ttl) or not (0 < float(ttl) <= MAX_TTL_SECONDS_LIMIT):
        raise ValueError(CODE_POLICY_INVALID + ":MAX_TTL")
    if not _is_number(skew) or not (0 <= float(skew) <= MAX_SKEW_SECONDS_LIMIT):
        raise ValueError(CODE_POLICY_INVALID + ":MAX_SKEW")
    if not isinstance(allowlist, list) or not allowlist:
        raise ValueError(CODE_POLICY_INVALID + ":ALLOWLIST")

    rules: List[AllowRule] = []
    for entry in allowlist:
        if not isinstance(entry, dict) or set(entry.keys()) != {"subject", "action", "resource"}:
            raise ValueError(CODE_POLICY_INVALID + ":ALLOWLIST_ENTRY")
        s, a, r = entry["subject"], entry["action"], entry["resource"]
        if not isinstance(s, str) or not TOKEN_RE.fullmatch(s) or s == "*":
            raise ValueError(CODE_POLICY_INVALID + ":ALLOWLIST_SUBJECT")
        if not isinstance(a, str) or not TOKEN_RE.fullmatch(a) or a == "*":
            raise ValueError(CODE_POLICY_INVALID + ":ALLOWLIST_ACTION")
        if not isinstance(r, str) or not r or len(r) > 256:
            raise ValueError(CODE_POLICY_INVALID + ":ALLOWLIST_RESOURCE")
        rules.append(AllowRule(subject=s, action=a, resource=r))

    return Policy(
        policy_version=pv,
        audience=aud,
        trust_root_fingerprint=fp,
        allowed_issuers=tuple(dict.fromkeys(issuers)),
        allowlist=tuple(rules),
        max_ttl_seconds=float(ttl),
        max_issued_at_skew_seconds=float(skew),
    )


# ---------------------------------------------------------------------------
# Racine de confiance épinglée + durcissement des permissions de config
# ---------------------------------------------------------------------------


@dataclass
class TrustState:
    ok: bool
    code: str
    fingerprint: Optional[str] = None


def _config_permissions_ok(path: str) -> Tuple[bool, str]:
    """Refuse une config insécure : écriture groupe/autre => fail-closed."""
    try:
        st = os.stat(path)
    except OSError:
        return True, ""  # absence gérée par l'appelant
    if st.st_mode & (stat_mod.S_IWGRP | stat_mod.S_IWOTH):
        return False, CODE_CONFIG_INSECURE
    expect_uid = os.environ.get("AEGIS_EXPECT_CONFIG_UID")
    if expect_uid is not None:
        try:
            if st.st_uid != int(expect_uid):
                return False, CODE_CONFIG_INSECURE
        except ValueError:
            return False, CODE_CONFIG_INSECURE
    return True, ""


def load_trust(
    key_path: str,
    policy: Optional[Policy],
    pin_path: str,
    pin_env: Optional[str],
) -> Tuple[TrustState, Optional[ed25519.Ed25519PublicKey]]:
    if policy is None:
        return TrustState(ok=False, code=CODE_POLICY_INVALID), None

    for p in (key_path, pin_path):
        ok, code = _config_permissions_ok(p)
        if not ok:
            return TrustState(ok=False, code=code), None

    expected = (pin_env or "").strip()
    if not expected:
        try:
            with open(pin_path, "r", encoding="utf-8") as f:
                expected = f.read().strip()
        except OSError:
            expected = ""
    if not expected:
        return TrustState(ok=False, code=CODE_TRUST_UNAVAILABLE), None
    if not HEX_SHA256_RE.fullmatch(expected):
        return TrustState(ok=False, code=CODE_TRUST_PIN_MISMATCH), None

    try:
        with open(key_path, "rb") as f:
            raw = f.read()
    except OSError:
        return TrustState(ok=False, code=CODE_TRUST_UNAVAILABLE), None

    if len(raw) != 32:
        return TrustState(ok=False, code=CODE_TRUST_UNAVAILABLE), None
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(raw)
    except Exception:
        return TrustState(ok=False, code=CODE_TRUST_UNAVAILABLE), None

    fingerprint = _sha256_hex(raw)
    if fingerprint != expected:
        return TrustState(ok=False, code=CODE_TRUST_PIN_MISMATCH), None
    if policy.trust_root_fingerprint != fingerprint:
        return TrustState(ok=False, code=CODE_POLICY_PIN_MISMATCH), None

    return TrustState(ok=True, code="OK", fingerprint=fingerprint), pub


# ---------------------------------------------------------------------------
# Registre transactionnel : nonce PK + permit_id UNIQUE + chaîne anti-rollback
# ---------------------------------------------------------------------------


class NonceReused(Exception):
    pass


class PermitIdReused(Exception):
    pass


class Ledger:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0, isolation_level="IMMEDIATE")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=15000")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS consumed_permits (
                    nonce TEXT PRIMARY KEY,
                    permit_id TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    consumed_at REAL NOT NULL,
                    status TEXT NOT NULL,
                    chain_digest TEXT NOT NULL DEFAULT '',
                    UNIQUE(permit_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    nonce TEXT,
                    permit_id TEXT,
                    event_type TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT ''
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS effect_journal (
                    nonce TEXT PRIMARY KEY,
                    permit_id TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    effect_mode TEXT NOT NULL,
                    effect_at REAL NOT NULL
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _row_canonical(
        nonce: str, permit_id: str, subject: str, action: str, resource: str, ts: float
    ) -> str:
        payload = {
            "nonce": nonce,
            "permit_id": permit_id,
            "subject": subject,
            "action": action,
            "resource": resource,
            "consumed_at": repr(ts),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def consume(
        self,
        nonce: str,
        permit_id: str,
        subject: str,
        action: str,
        resource: str,
        ts: float,
    ) -> str:
        """Consomme le nonce (PK) et lie l'opération (permit_id UNIQUE).

        Retourne le `chain_digest` de la ligne. AT_MOST_ONCE : après COMMIT,
        le nonce est brûlé même en cas de mort du processus.
        """
        conn = self._connect()
        try:
            cur = conn.cursor()
            # Priorité de diagnostic : le rejeu de nonce est annoncé NONCE_REUSED
            # même si permit_id est également en doublon (compat T21).
            if cur.execute(
                "SELECT 1 FROM consumed_permits WHERE nonce = ?", (nonce,)
            ).fetchone():
                raise NonceReused()
            if cur.execute(
                "SELECT 1 FROM consumed_permits WHERE permit_id = ?", (permit_id,)
            ).fetchone():
                raise PermitIdReused()
            prev = cur.execute(
                "SELECT chain_digest FROM consumed_permits ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
            prev_digest = prev[0] if prev else "GENESIS"
            chain = _sha256_hex(
                (
                    prev_digest
                    + self._row_canonical(nonce, permit_id, subject, action, resource, ts)
                ).encode("utf-8")
            )
            try:
                cur.execute(
                    "INSERT INTO consumed_permits"
                    " (nonce, permit_id, subject, action, resource, consumed_at, status, chain_digest)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (nonce, permit_id, subject, action, resource, ts, "PENDING", chain),
                )
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                msg = str(exc)
                if "permit_id" in msg:
                    raise PermitIdReused() from exc
                raise NonceReused() from exc
            cur.execute(
                "INSERT INTO events (ts, nonce, permit_id, event_type, detail)"
                " VALUES (?, ?, ?, ?, ?)",
                (ts, nonce, permit_id, EVENT_PERMIT_CONSUMED, "status=PENDING"),
            )
            conn.commit()
            return chain
        finally:
            conn.close()

    def add_event(
        self, ts: float, nonce: str, permit_id: str, event_type: str, detail: str = ""
    ) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO events (ts, nonce, permit_id, event_type, detail)"
                " VALUES (?, ?, ?, ?, ?)",
                (ts, nonce, permit_id, event_type, detail),
            )
            conn.commit()
        finally:
            conn.close()

    def record_simulated_effect(
        self, ts: float, nonce: str, permit_id: str, subject: str, action: str, resource: str
    ) -> None:
        """Chemin simulé V3C conservé à l'identique (compatibilité de banc)."""
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO effect_journal"
                " (nonce, permit_id, subject, action, resource, effect_mode, effect_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (nonce, permit_id, subject, action, resource, EFFECT_MODE_SIM, ts),
            )
            cur.execute(
                "INSERT INTO events (ts, nonce, permit_id, event_type, detail)"
                " VALUES (?, ?, ?, ?, ?)",
                (ts, nonce, permit_id, EVENT_EFFECT_SIMULATED, "effect_mode=" + EFFECT_MODE_SIM),
            )
            cur.execute(
                "UPDATE consumed_permits SET status = ? WHERE nonce = ?", (STATUS_SIM, nonce)
            )
            conn.commit()
        finally:
            conn.close()

    def record_materialized_effect(
        self, ts: float, nonce: str, permit_id: str, subject: str, action: str, resource: str
    ) -> None:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO effect_journal"
                " (nonce, permit_id, subject, action, resource, effect_mode, effect_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (nonce, permit_id, subject, action, resource, EFFECT_MODE_REAL, ts),
            )
            cur.execute(
                "INSERT INTO events (ts, nonce, permit_id, event_type, detail)"
                " VALUES (?, ?, ?, ?, ?)",
                (ts, nonce, permit_id, EVENT_EFFECT_MATERIALIZED, "effect_mode=" + EFFECT_MODE_REAL),
            )
            cur.execute(
                "UPDATE consumed_permits SET status = ? WHERE nonce = ?",
                (STATUS_MATERIALIZED, nonce),
            )
            conn.commit()
        finally:
            conn.close()

    def mark_effect_unknown(self, ts: float, nonce: str, permit_id: str) -> None:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO events (ts, nonce, permit_id, event_type, detail)"
                " VALUES (?, ?, ?, ?, ?)",
                (ts, nonce, permit_id, EVENT_EFFECT_UNKNOWN, "effect_mode=" + EFFECT_MODE_REAL),
            )
            cur.execute(
                "UPDATE consumed_permits SET status = 'EFFECT_UNKNOWN' WHERE nonce = ?",
                (nonce,),
            )
            conn.commit()
        finally:
            conn.close()

    def chain_head(self) -> Optional[str]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT chain_digest FROM consumed_permits ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
            return row[0] if row else None
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Actionneur d'effet réel borné
# ---------------------------------------------------------------------------


class EffectError(Exception):
    pass


def materialize_marker(
    effect_dir: str,
    permit_id: str,
    nonce: str,
    subject: str,
    action: str,
    resource: str,
    ts: float,
    policy_version: str,
) -> Dict[str, Any]:
    """Création exclusive du marqueur. Jamais en dehors de effect_dir."""
    fname = "marker-" + permit_id + ".json"
    expected_resource = "effect/" + fname
    if resource != expected_resource:
        raise EffectError(CODE_EFFECT_PATH_FORBIDDEN)

    root = os.path.realpath(effect_dir)
    path = os.path.realpath(os.path.join(root, fname))
    if os.path.dirname(path) != root or os.path.basename(path) != fname:
        raise EffectError(CODE_EFFECT_PATH_FORBIDDEN)

    fields: Dict[str, Any] = {
        "permit_id": permit_id,
        "nonce": nonce,
        "subject": subject,
        "action": action,
        "resource": resource,
        "policy_version": policy_version,
        "materialized_at": repr(ts),
    }
    record = dict(fields)
    record["content_digest"] = canonical_hash(fields)
    blob = (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode(
        "utf-8"
    )

    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError as exc:
        raise EffectError(CODE_EFFECT_UNCONFIRMED) from exc
    try:
        os.write(fd, blob)
        os.fsync(fd)
    finally:
        os.close(fd)
    # V3E (V3D-004 corrective) : synchroniser aussi le répertoire parent.
    # fsync(file) != fsync(dir) ; les deux sont faits. Ceci ne démontre PAS la
    # durabilité après coupure d'alimentation (POWER_LOSS_DURABILITY=NOT_EXECUTED).
    try:
        dfd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass
    return {"path": path, "filename": fname, "sha256": _sha256_hex(blob), "bytes": len(blob)}


# ---------------------------------------------------------------------------
# Application PEP
# ---------------------------------------------------------------------------


class ExecuteRequest(BaseModel):
    # N01 : enveloppe wrapper fermée — aucun champ JSON externe toléré.
    model_config = ConfigDict(extra="forbid")

    original_request: dict
    permit: dict


class PEP:
    def __init__(
        self,
        policy_path: str,
        key_path: str,
        pin_path: str,
        db_path: str,
        pin_env: Optional[str] = None,
        effect_dir: Optional[str] = None,
        real_actions: Optional[Tuple[str, ...]] = None,
    ) -> None:
        self.db_path = db_path
        self.policy_path = policy_path
        self.key_path = key_path
        self.pin_path = pin_path

        ok, code = _config_permissions_ok(policy_path)
        self.policy: Optional[Policy] = None
        self.policy_error: Optional[str] = None
        self.policy_fp: Optional[str] = None
        if not ok:
            self.policy_error = code
        else:
            try:
                self.policy = load_policy(policy_path)
                self.policy_fp = self._file_fingerprint(policy_path)
            except ValueError as exc:
                self.policy_error = str(exc)

        self.trust, self.public_key = load_trust(
            key_path, self.policy, pin_path, pin_env
        )
        self.ledger = Ledger(db_path)

        self.effect_dir = effect_dir or os.environ.get("AEGIS_EFFECT_DIR") or os.path.join(
            os.path.dirname(os.path.abspath(db_path)) or ".", "effect_markers"
        )
        raw_real = real_actions or tuple(
            a.strip()
            for a in os.environ.get("AEGIS_REAL_ACTIONS", "marker.create").split(",")
            if a.strip()
        )
        self.real_actions = tuple(raw_real)

    @staticmethod
    def _file_fingerprint(path: str) -> Optional[str]:
        try:
            with open(path, "rb") as f:
                return _sha256_hex(f.read())
        except OSError:
            return None

    def _policy_checkpoint(self) -> None:
        """N03 : re-vérification de l'empreinte de politique à chaque requête."""
        ok, code = _config_permissions_ok(self.policy_path)
        if not ok:
            self.policy = None
            self.policy_error = code
            return
        fp = self._file_fingerprint(self.policy_path)
        if fp is None:
            self.policy = None
            self.policy_error = CODE_POLICY_INVALID + ":MISSING_FILE"
            return
        if fp == self.policy_fp and self.policy is not None:
            return
        try:
            new_policy = load_policy(self.policy_path)
        except ValueError as exc:
            self.policy = None
            self.policy_error = str(exc)
            self.policy_fp = fp
            return
        self.policy = new_policy
        self.policy_fp = fp
        self.policy_error = None
        # Concordance de pin re-vérifiée après rechargement.
        if new_policy.trust_root_fingerprint != self.trust.fingerprint:
            self.trust = TrustState(ok=False, code=CODE_POLICY_PIN_MISMATCH)
            self.public_key = None

    def _require_trust(self) -> None:
        if self.policy is None or self.public_key is None or not self.trust.ok:
            code = self.trust.code if self.trust.code != "OK" else CODE_TRUST_UNAVAILABLE
            if self.policy_error:
                code = self.policy_error
            raise _reject(503, code)

    @staticmethod
    def _validate_request_shape(orig_req: Any) -> Dict[str, Any]:
        if not isinstance(orig_req, dict):
            raise _reject(400, CODE_REQUEST_SCHEMA, expected=sorted(REQUEST_REQUIRED_FIELDS))
        if set(orig_req.keys()) != set(REQUEST_REQUIRED_FIELDS):
            raise _reject(400, CODE_REQUEST_SCHEMA, expected=sorted(REQUEST_REQUIRED_FIELDS))
        for fname in ("subject", "action", "resource"):
            v = orig_req[fname]
            if not isinstance(v, str):
                raise _reject(400, CODE_FIELD_TYPE, field=fname)
        if not TOKEN_RE.fullmatch(orig_req["subject"]):
            raise _reject(400, CODE_FIELD_FORMAT, field="subject")
        if not TOKEN_RE.fullmatch(orig_req["action"]):
            raise _reject(400, CODE_FIELD_FORMAT, field="action")
        res = orig_req["resource"]
        if not RESOURCE_RE.fullmatch(res) or ".." in res.split("/"):
            raise _reject(400, CODE_FIELD_FORMAT, field="resource")
        return orig_req

    @staticmethod
    def _validate_permit_shape(permit: Any) -> Dict[str, Any]:
        if not isinstance(permit, dict):
            raise _reject(400, CODE_PERMIT_SCHEMA, expected=sorted(PERMIT_REQUIRED_FIELDS))
        if set(permit.keys()) != set(PERMIT_REQUIRED_FIELDS):
            raise _reject(400, CODE_PERMIT_SCHEMA, expected=sorted(PERMIT_REQUIRED_FIELDS))

        for fname in (
            "permit_id",
            "issuer",
            "subject",
            "action",
            "resource",
            "audience",
            "policy_version",
            "nonce",
        ):
            if not isinstance(permit[fname], str):
                raise _reject(400, CODE_FIELD_TYPE, field=fname)

        if not PERMIT_ID_RE.fullmatch(permit["permit_id"]):
            raise _reject(400, CODE_FIELD_FORMAT, field="permit_id")
        if not TOKEN_RE.fullmatch(permit["issuer"]):
            raise _reject(400, CODE_FIELD_FORMAT, field="issuer")
        if not TOKEN_RE.fullmatch(permit["subject"]):
            raise _reject(400, CODE_FIELD_FORMAT, field="subject")
        if not TOKEN_RE.fullmatch(permit["action"]):
            raise _reject(400, CODE_FIELD_FORMAT, field="action")
        if not RESOURCE_RE.fullmatch(permit["resource"]) or ".." in permit["resource"].split("/"):
            raise _reject(400, CODE_FIELD_FORMAT, field="resource")
        if not TOKEN_RE.fullmatch(permit["audience"]):
            raise _reject(400, CODE_FIELD_FORMAT, field="audience")
        if not TOKEN_RE.fullmatch(permit["policy_version"]):
            raise _reject(400, CODE_FIELD_FORMAT, field="policy_version")
        if not NONCE_RE.fullmatch(permit["nonce"]):
            raise _reject(400, CODE_FIELD_FORMAT, field="nonce")

        for fname in ("issued_at", "expires_at"):
            if not _is_number(permit[fname]):
                raise _reject(400, CODE_FIELD_TYPE, field=fname)
            if not (0.0 <= float(permit[fname]) <= 4102444800.0):
                raise _reject(400, CODE_FIELD_VALUE, field=fname)

        rh = permit["request_hash"]
        if not isinstance(rh, str) or not HEX_SHA256_RE.fullmatch(rh):
            raise _reject(400, CODE_FIELD_FORMAT, field="request_hash")

        sig = permit["signature"]
        if not isinstance(sig, str) or not HEX_SIG_RE.fullmatch(sig):
            raise _reject(400, CODE_FIELD_FORMAT, field="signature")

        return permit

    def execute(self, orig_req: Any, permit: Any) -> Dict[str, Any]:
        """Pipeline fail-closed. Gates dans l'ordre de la spec V3C/V3D :

        (0) checkpoint politique -> (1) schéma/types -> (2) racine épinglée ->
        (3) signature -> (4) temps -> (5) identité -> (6) intégrité requête ->
        (7) politique -> (8) consommation transactionnelle (nonce + permit_id) ->
        (9) tentative -> (10) effet (réel ou simulé). Aucune consommation avant
        (1)-(7) : pas de burn-on-tamper.
        """
        self._policy_checkpoint()
        self._require_trust()
        policy = self.policy
        assert policy is not None

        orig = self._validate_request_shape(orig_req)
        permit = self._validate_permit_shape(permit)

        signature_hex = permit["signature"]
        body = {k: v for k, v in permit.items() if k != "signature"}

        try:
            signature = bytes.fromhex(signature_hex)
            self.public_key.verify(signature, canonical_hash(body).encode("utf-8"))
        except (ValueError, InvalidSignature):
            raise _reject(403, CODE_BAD_SIGNATURE)

        now = _now()
        issued_at = float(body["issued_at"])
        expires_at = float(body["expires_at"])

        if expires_at <= issued_at:
            raise _reject(403, CODE_TEMPORAL_INCONSISTENCY)
        if now >= expires_at:
            raise _reject(403, CODE_EXPIRED)
        if issued_at > now + policy.max_issued_at_skew_seconds:
            raise _reject(403, CODE_FUTURE_ISSUED_AT)
        if (expires_at - issued_at) > policy.max_ttl_seconds:
            raise _reject(403, CODE_TTL_EXCEEDED)

        if body["audience"] != policy.audience:
            raise _reject(403, CODE_WRONG_AUDIENCE)
        if body["policy_version"] != policy.policy_version:
            raise _reject(403, CODE_POLICY_VERSION)
        if body["issuer"] not in policy.allowed_issuers:
            raise _reject(403, CODE_ISSUER_FORBIDDEN)

        if body["request_hash"] != canonical_hash(orig):
            raise _reject(403, CODE_REQUEST_TAMPERED)

        subject, action, resource = orig["subject"], orig["action"], orig["resource"]
        if body["subject"] != subject or body["action"] != action or body["resource"] != resource:
            raise _reject(403, CODE_REQUEST_TAMPERED)

        actions_known = {r.action for r in policy.allowlist if r.action == action}
        if not actions_known:
            raise _reject(403, CODE_ACTION_FORBIDDEN, action=action)
        subject_ok = any(r.action == action and r.subject == subject for r in policy.allowlist)
        if not subject_ok:
            raise _reject(403, CODE_SUBJECT_FORBIDDEN, subject=subject)
        resource_ok = any(
            r.action == action
            and r.subject == subject
            and fnmatch.fnmatchcase(resource, r.resource)
            for r in policy.allowlist
        )
        if not resource_ok:
            raise _reject(403, CODE_RESOURCE_FORBIDDEN, resource=resource)

        # Action réelle : liaison stricte chemin <-> permis AVANT consommation.
        if action in self.real_actions:
            expected_resource = "effect/marker-" + body["permit_id"] + ".json"
            if resource != expected_resource:
                raise _reject(403, CODE_EFFECT_PATH_FORBIDDEN)

        nonce = body["nonce"]
        permit_id = body["permit_id"]

        _fault_inject("before_consume_commit")
        try:
            self.ledger.consume(nonce, permit_id, subject, action, resource, now)
        except NonceReused:
            raise _reject(403, CODE_NONCE_REUSED)
        except PermitIdReused:
            raise _reject(403, CODE_PERMIT_ID_REUSED)

        _fault_inject("after_consume_commit")

        self.ledger.add_event(
            now, nonce, permit_id, EVENT_ACTION_ATTEMPTED, f"{action}:{resource}"
        )
        _fault_inject("after_attempt")

        if action in self.real_actions:
            try:
                info = materialize_marker(
                    self.effect_dir,
                    permit_id,
                    nonce,
                    subject,
                    action,
                    resource,
                    now,
                    policy.policy_version,
                )
            except EffectError:
                self.ledger.mark_effect_unknown(now, nonce, permit_id)
                raise _reject(502, CODE_EFFECT_UNCONFIRMED)
            _fault_inject("after_effect")
            self.ledger.record_materialized_effect(now, nonce, permit_id, subject, action, resource)
            return {
                "status": "AUTHORIZED",
                "permit_consumed": True,
                "action_attempted": True,
                "effect_status": EFFECT_MODE_REAL,
                "effect_confirmed": False,
                "transaction": "COMMITTED",
                "note": "MATERIALIZED_LOCAL!=WITNESS_CONFIRMED; HTTP_200!=EFFECT_PROOF",
            }

        try:
            self.ledger.record_simulated_effect(now, nonce, permit_id, subject, action, resource)
        except Exception:
            self.ledger.mark_effect_unknown(now, nonce, permit_id)
            raise _reject(502, CODE_EFFECT_UNCONFIRMED)
        return {
            "status": "AUTHORIZED",
            "permit_consumed": True,
            "action_attempted": True,
            "effect_status": EFFECT_MODE_SIM,
            "effect_confirmed": False,
            "transaction": "COMMITTED",
            "note": "SIMULATED_ACTION!=PHYSICAL_ACTION; PERMIT_CONSUMED!=EFFECT_COMPLETED",
        }


# ---------------------------------------------------------------------------
# Fabrication d'app (API de compatibilité V3C conservée)
# ---------------------------------------------------------------------------


def build_app(
    policy_path: str,
    key_path: str,
    pin_path: str,
    db_path: str,
    pin_env: Optional[str] = None,
    effect_dir: Optional[str] = None,
    real_actions: Optional[Tuple[str, ...]] = None,
) -> FastAPI:
    pep = PEP(
        policy_path,
        key_path,
        pin_path,
        db_path,
        pin_env=pin_env,
        effect_dir=effect_dir,
        real_actions=real_actions,
    )
    app = FastAPI()
    app.state.pep = pep

    @app.get("/v1/health")
    async def health() -> dict:
        return {
            "trust_root": pep.trust.code if pep.trust.code != "OK" else pep.trust.code,
            "policy_loaded": pep.policy is not None,
            "policy_version": pep.policy.policy_version if pep.policy else None,
            "clock_mode": "TEST_FIXED"
            if (
                os.environ.get("AEGIS_TEST_MODE") == "1"
                and os.environ.get("AEGIS_FIXED_NOW") is not None
            )
            else "SYSTEM",
        }

    @app.post("/v1/execute")
    async def execute_action(req: ExecuteRequest) -> dict:
        try:
            return pep.execute(req.original_request, req.permit)
        except HTTPException:
            raise
        except Exception:
            raise _reject(500, CODE_INTERNAL)

    return app


def build_app_from_env() -> FastAPI:
    return build_app(
        policy_path=os.environ.get("AEGIS_POLICY_PATH", "pep_policy_v3d.json"),
        key_path=os.environ.get("AEGIS_KEY_PATH", "pep_public.key"),
        pin_path=os.environ.get("AEGIS_PIN_PATH", "trust_root.pin"),
        db_path=os.environ.get("AEGIS_DB_PATH", "pep_ledger.db"),
        pin_env=os.environ.get("AEGIS_TRUST_ROOT_PIN"),
        effect_dir=os.environ.get("AEGIS_EFFECT_DIR"),
    )


_app: Optional[FastAPI] = None


def __getattr__(name: str) -> FastAPI:
    global _app
    if name == "app":
        if _app is None:
            _app = build_app_from_env()
        return _app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
