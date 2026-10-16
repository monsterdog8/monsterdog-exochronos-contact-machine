"""MONSTERDOG AEGIS — PEP V3C (mission AEGIS_V3C_PIN_POLICY_SQLITE_INTEGRATION_003).

Successeur de `original/pep_v3_transactional.py` (V3) intégrant simultanément :

1. La racine de confiance épinglée de V2C (V3-C01) : l'empreinte SHA-256 de la clé
   publique est ancrée DANS la politique PEP et dans un fichier `trust_root.pin`
   séparé du fichier de clé mutable. Toute discordance => fail-closed (503).
2. La politique d'autorisation indépendante du PEP (V3-C02..C05) : allowlist
   (subject, action, resource), issuer autorisé, policy_version exacte, bornes TTL
   et skew. Une signature valide n'autorise jamais rien à elle seule.
3. Le registre SQLite transactionnel de V3 : `nonce PRIMARY KEY` comme arbitre de
   concurrence inter-processus, persistant au redémarrage.
4. Un schéma d'enveloppe strict + types stricts (V3-C07) : toute entrée hostile est
   un refus 4xx contrôlé, jamais un 500.
5. L'intégrité complète (request_hash) et les permissions validées AVANT la
   consommation transactionnelle du nonce (V3-C08) : une requête altérée ne brûle
   plus un permis légitime (anti-DoS).
6. Des événements distincts (V3-C09) : PERMIT_CONSUMED / ACTION_ATTEMPTED /
   EFFECT_SIMULATED. `EFFECT_CONFIRMED` est réservé à un canal d'effet externe
   authentifié qui n'existe pas dans ce mode LOCAL_ONLY : il n'est jamais émis, et
   la réponse ne prétend jamais qu'une action physique a eu lieu.

Posture : FAIL_CLOSED. La sécurité est bloquée par le hard gate le plus faible ;
SQLite ne compense jamais un contrôle d'autorisation manquant.

Frontière de confiance honnête (à rappeler dans tout verdict) :
    SIGNATURE_VALID != SIGNER_AUTHORIZED
    PERMIT_CONSUMED != EFFECT_COMPLETED
    SIMULATED_ACTION != PHYSICAL_ACTION
    DB_COMMIT != EXTERNAL_EFFECT

Ce module ne vise aucune cible OS réelle, aucun réseau externe, aucune production.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ValidationError

# ---------------------------------------------------------------------------
# Constantes d'enveloppe
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
HEX_SIG_RE = re.compile(r"^[0-9a-fA-F]{128}$")  # Ed25519 = 64 octets
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RESOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")

MAX_TTL_SECONDS_LIMIT = 86400.0  # plafond dur imposé par le PEP, indépendant de la politique
MAX_SKEW_SECONDS_LIMIT = 3600.0

# Codes machine (détail des HTTPException) — une famille par gate.
CODE_PERMIT_SCHEMA = "PERMIT_SCHEMA_VIOLATION"
CODE_REQUEST_SCHEMA = "REQUEST_SCHEMA_VIOLATION"
CODE_FIELD_TYPE = "INVALID_FIELD_TYPE"
CODE_FIELD_FORMAT = "INVALID_FIELD_FORMAT"
CODE_FIELD_VALUE = "INVALID_FIELD_VALUE"
CODE_TRUST_UNAVAILABLE = "PEP_TRUST_ROOT_UNAVAILABLE"
CODE_TRUST_PIN_MISMATCH = "PEP_TRUST_ROOT_PIN_MISMATCH"
CODE_POLICY_PIN_MISMATCH = "PEP_POLICY_PIN_MISMATCH"
CODE_POLICY_INVALID = "PEP_POLICY_INVALID"
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
CODE_NONCE_REUSED = "NONCE_REUSED"
CODE_INTERNAL = "INTERNAL_ERROR"
CODE_EFFECT_UNCONFIRMED = "EFFECT_UNCONFIRMED"

EVENT_PERMIT_CONSUMED = "PERMIT_CONSUMED"
EVENT_ACTION_ATTEMPTED = "ACTION_ATTEMPTED"
EVENT_EFFECT_SIMULATED = "EFFECT_SIMULATED"
EVENT_EFFECT_CONFIRMED = "EFFECT_CONFIRMED"  # vocabulaire réservé, jamais émis ici
EVENT_EFFECT_UNKNOWN = "EFFECT_UNKNOWN"

EFFECT_MODE = "SIMULATED_LOCAL_ONLY"


# ---------------------------------------------------------------------------
# Erreurs contrôlées 4xx / 503
# ---------------------------------------------------------------------------


def _reject(status: int, code: str, **extra: Any) -> HTTPException:
    detail: Dict[str, Any] = {"code": code}
    detail.update(extra)
    return HTTPException(status_code=status, detail=detail)


# ---------------------------------------------------------------------------
# Outils canoniques (identiques à V3 : tri des clés, séparateurs compacts)
# ---------------------------------------------------------------------------


def canonical_hash(obj: dict) -> str:
    c_str = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(c_str.encode("utf-8")).hexdigest()


def _sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_number(v: Any) -> bool:
    # bool est sous-classe de int en Python : explicitement exclu (A10).
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _now() -> float:
    """Horloge système. Un mode fixe n'existe qu'en AEGIS_TEST_MODE=1 (couture de test)."""
    if os.environ.get("AEGIS_TEST_MODE") == "1":
        fixed = os.environ.get("AEGIS_FIXED_NOW")
        if fixed is not None:
            try:
                return float(fixed)
            except ValueError:
                pass
    return time.time()


def _fault_inject(point: str) -> None:
    """Injection de panne TEST-ONLY (AEGIS_TEST_MODE=1 requis)."""
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
# Politique PEP indépendante (fichier JSON local, jamais signé par le demandeur)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AllowRule:
    subject: str
    action: str
    resource: str  # motif fnmatch


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
    """Charge et valide strictement la politique. Toute anomalie => PolicyError."""
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
# Racine de confiance épinglée
# ---------------------------------------------------------------------------


@dataclass
class TrustState:
    ok: bool
    code: str  # "OK" ou code d'erreur
    fingerprint: Optional[str] = None


def load_trust(
    key_path: str,
    policy: Optional[Policy],
    pin_path: str,
    pin_env: Optional[str],
) -> Tuple[TrustState, Optional[ed25519.Ed25519PublicKey]]:
    """Charge la clé publique et vérifie le double épinglage (pin fichier + politique).

    L'empreinte attendue vient de deux sources situées HORS du fichier de clé :
      1. variable d'environnement AEGIS_TRUST_ROOT_PIN (prioritaire) ou fichier pin ;
      2. champ trust_root_fingerprint de la politique PEP.
    Les trois (clé chargée, pin, politique) doivent concorder. Fail-closed sinon.
    """
    if policy is None:
        return TrustState(ok=False, code=CODE_POLICY_INVALID), None

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
# Registre transactionnel SQLite (V3) + journal d'événements (V3C)
# ---------------------------------------------------------------------------


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
                    status TEXT NOT NULL
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

    def consume(
        self,
        nonce: str,
        permit_id: str,
        subject: str,
        action: str,
        resource: str,
        ts: float,
    ) -> None:
        """Consomme le nonce de façon atomique. Lève `NonceReused` sur collision.

        Point de non-retour AT_MOST_ONCE : après COMMIT, le nonce est brûlé même si
        le processus meurt avant l'effet (fail-closed, jamais rejoué).
        """
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO consumed_permits"
                " (nonce, permit_id, subject, action, resource, consumed_at, status)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (nonce, permit_id, subject, action, resource, ts, "PENDING"),
            )
            cur.execute(
                "INSERT INTO events (ts, nonce, permit_id, event_type, detail)"
                " VALUES (?, ?, ?, ?, ?)",
                (ts, nonce, permit_id, EVENT_PERMIT_CONSUMED, "status=PENDING"),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            raise NonceReused() from exc
        finally:
            conn.close()

    def add_event(
        self,
        ts: float,
        nonce: str,
        permit_id: str,
        event_type: str,
        detail: str = "",
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
        self,
        ts: float,
        nonce: str,
        permit_id: str,
        subject: str,
        action: str,
        resource: str,
    ) -> None:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO effect_journal"
                " (nonce, permit_id, subject, action, resource, effect_mode, effect_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (nonce, permit_id, subject, action, resource, EFFECT_MODE, ts),
            )
            cur.execute(
                "INSERT INTO events (ts, nonce, permit_id, event_type, detail)"
                " VALUES (?, ?, ?, ?, ?)",
                (ts, nonce, permit_id, EVENT_EFFECT_SIMULATED, "effect_mode=" + EFFECT_MODE),
            )
            cur.execute(
                "UPDATE consumed_permits SET status = 'EFFECT_SIMULATED' WHERE nonce = ?",
                (nonce,),
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
                (ts, nonce, permit_id, EVENT_EFFECT_UNKNOWN, "effect_mode=" + EFFECT_MODE),
            )
            cur.execute(
                "UPDATE consumed_permits SET status = 'EFFECT_UNKNOWN' WHERE nonce = ?",
                (nonce,),
            )
            conn.commit()
        finally:
            conn.close()


class NonceReused(Exception):
    pass


# ---------------------------------------------------------------------------
# Application PEP
# ---------------------------------------------------------------------------


class ExecuteRequest(BaseModel):
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
    ) -> None:
        self.db_path = db_path
        self.policy_path = policy_path
        self.key_path = key_path
        self.pin_path = pin_path

        self.policy: Optional[Policy] = None
        self.policy_error: Optional[str] = None
        try:
            self.policy = load_policy(policy_path)
        except ValueError as exc:
            self.policy_error = str(exc)

        self.trust, self.public_key = load_trust(
            key_path, self.policy, pin_path, pin_env
        )
        self.ledger = Ledger(db_path)

    # -- helpers ----------------------------------------------------------

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

        if not TOKEN_RE.fullmatch(permit["permit_id"]):
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
            if not (0.0 <= float(permit[fname]) <= 4102444800.0):  # an 2100
                raise _reject(400, CODE_FIELD_VALUE, field=fname)

        rh = permit["request_hash"]
        if not isinstance(rh, str) or not HEX_SHA256_RE.fullmatch(rh):
            raise _reject(400, CODE_FIELD_FORMAT, field="request_hash")

        sig = permit["signature"]
        if not isinstance(sig, str) or not HEX_SIG_RE.fullmatch(sig):
            raise _reject(400, CODE_FIELD_FORMAT, field="signature")

        return permit

    # -- pipeline ----------------------------------------------------------

    def execute(self, orig_req: Any, permit: Any) -> Dict[str, Any]:
        """Pipeline fail-closed. Ordre des gates = ordre de la spec V3C :

        (1) schéma/types -> (2) racine épinglée -> (3) signature -> (4) temps ->
        (5) identité -> (6) intégrité requête -> (7) politique ->
        (8) consommation transactionnelle -> (9) tentative -> (10) effet simulé.
        Aucune consommation de nonce n'a lieu avant (1)–(7) : V3-C08.
        """
        self._require_trust()
        policy = self.policy
        assert policy is not None  # garanti par _require_trust

        # (1) Schéma strict + types stricts (jamais de 500 sur entrée hostile)
        orig = self._validate_request_shape(orig_req)
        permit = self._validate_permit_shape(permit)

        signature_hex = permit["signature"]
        body = {k: v for k, v in permit.items() if k != "signature"}

        # (2) Racine de confiance déjà épinglée dans _require_trust (V3-C01)

        # (3) Signature Ed25519 sur le corps canonique
        try:
            signature = bytes.fromhex(signature_hex)
            self.public_key.verify(signature, canonical_hash(body).encode("utf-8"))
        except (ValueError, InvalidSignature):
            raise _reject(403, CODE_BAD_SIGNATURE)

        # (4) Sémantique temporelle stricte (V3-C05)
        now = _now()
        issued_at = float(body["issued_at"])
        expires_at = float(body["expires_at"])

        if expires_at <= issued_at:
            raise _reject(403, CODE_TEMPORAL_INCONSISTENCY)
        # Frontière STRICTE et EXCLUSIVE : valide uniquement si now < expires_at.
        if now >= expires_at:
            raise _reject(403, CODE_EXPIRED)
        if issued_at > now + policy.max_issued_at_skew_seconds:
            raise _reject(403, CODE_FUTURE_ISSUED_AT)
        if (expires_at - issued_at) > policy.max_ttl_seconds:
            raise _reject(403, CODE_TTL_EXCEEDED)

        # (5) Identité et version (V3-C03, V3-C04)
        if body["audience"] != policy.audience:
            raise _reject(403, CODE_WRONG_AUDIENCE)
        if body["policy_version"] != policy.policy_version:
            raise _reject(403, CODE_POLICY_VERSION)
        if body["issuer"] not in policy.allowed_issuers:
            raise _reject(403, CODE_ISSUER_FORBIDDEN)

        # (6) Intégrité croisée AVANT consommation (V3-C08 : plus de burn-on-tamper)
        if body["request_hash"] != canonical_hash(orig):
            raise _reject(403, CODE_REQUEST_TAMPERED)

        # (7) Politique d'autorisation indépendante (V3-C02)
        subject, action, resource = orig["subject"], orig["action"], orig["resource"]
        if body["subject"] != subject or body["action"] != action or body["resource"] != resource:
            raise _reject(403, CODE_REQUEST_TAMPERED)

        actions_known = {r.action for r in policy.allowlist if r.action == action}
        if not actions_known:
            raise _reject(403, CODE_ACTION_FORBIDDEN, action=action)
        subject_ok = any(
            r.action == action and r.subject == subject for r in policy.allowlist
        )
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

        # (8) Consommation transactionnelle (V3) — AT_MOST_ONCE
        nonce = body["nonce"]
        permit_id = body["permit_id"]
        try:
            self.ledger.consume(nonce, permit_id, subject, action, resource, now)
        except NonceReused:
            raise _reject(403, CODE_NONCE_REUSED)

        _fault_inject("after_consume_commit")

        # (9) Tentative d'action — événement distinct (V3-C09)
        self.ledger.add_event(now, nonce, permit_id, EVENT_ACTION_ATTEMPTED, f"{action}:{resource}")

        # (10) Effet : SIMULATION LOCALE UNIQUEMENT. Aucun canal d'effet externe
        # n'existe dans ce mode (LOCAL_ONLY, cible OS interdite). EFFECT_CONFIRMED
        # n'est jamais produit ; la réponse ne prétend jamais d'exécution physique.
        try:
            self.ledger.record_simulated_effect(now, nonce, permit_id, subject, action, resource)
        except Exception:
            self.ledger.mark_effect_unknown(now, nonce, permit_id)
            raise _reject(502, CODE_EFFECT_UNCONFIRMED)

        return {
            "status": "AUTHORIZED",
            "permit_consumed": True,
            "action_attempted": True,
            "effect_status": EFFECT_MODE,
            "effect_confirmed": False,
            "transaction": "COMMITTED",
            "note": "SIMULATED_ACTION!=PHYSICAL_ACTION; PERMIT_CONSUMED!=EFFECT_COMPLETED",
        }


# ---------------------------------------------------------------------------
# Fabrication d'app (factory + entrée uvicorn)
# ---------------------------------------------------------------------------


def build_app(
    policy_path: str,
    key_path: str,
    pin_path: str,
    db_path: str,
    pin_env: Optional[str] = None,
) -> FastAPI:
    pep = PEP(policy_path, key_path, pin_path, db_path, pin_env=pin_env)
    app = FastAPI()
    app.state.pep = pep

    @app.get("/v1/health")
    async def health() -> dict:
        trust_code = pep.trust.code if pep.trust.ok else pep.trust.code
        return {
            "trust_root": trust_code,
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
            # Filet ultime : jamais de trace brute en sortie, fail-closed.
            raise _reject(500, CODE_INTERNAL)

    return app


def build_app_from_env() -> FastAPI:
    return build_app(
        policy_path=os.environ.get("AEGIS_POLICY_PATH", "pep_policy_v3c.json"),
        key_path=os.environ.get("AEGIS_KEY_PATH", "pep_public.key"),
        pin_path=os.environ.get("AEGIS_PIN_PATH", "trust_root.pin"),
        db_path=os.environ.get("AEGIS_DB_PATH", "pep_ledger.db"),
        pin_env=os.environ.get("AEGIS_TRUST_ROOT_PIN"),
    )


# Entrée uvicorn `pep_v3c_pinned:app` construite paresseusement (PEP 562) :
# importer ce module (ex. pour canonical_hash) n'ouvre aucune base.
_app: Optional[FastAPI] = None


def __getattr__(name: str) -> FastAPI:
    global _app
    if name == "app":
        if _app is None:
            _app = build_app_from_env()
        return _app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
