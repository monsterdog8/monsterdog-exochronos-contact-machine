# pep_v3_transactional.py
import time
import sqlite3
import hashlib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# Configuration
POLICY_VERSION = "v2.0.1"
AUDIENCE_PEP = "monsterdog.pep.local"
DB_PATH = "pep_ledger.db"

app = FastAPI()

# Initialisation de la racine de confiance (Clé Publique)
try:
    with open("pep_public.key", "rb") as f:
        PUBLIC_KEY = ed25519.Ed25519PublicKey.from_public_bytes(f.read())
except FileNotFoundError:
    PUBLIC_KEY = None  # Fail-Closed condition

# Initialisation du registre transactionnel (ACID)
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Le champ nonce est UNIQUE. La base de données gère les Race Conditions.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS consumed_permits (
            nonce TEXT PRIMARY KEY,
            permit_id TEXT NOT NULL,
            consumed_at REAL NOT NULL,
            status TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def canonical_hash(obj: dict) -> str:
    import json
    c_str = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(c_str.encode("utf-8")).hexdigest()

class ExecuteRequest(BaseModel):
    original_request: dict
    permit: dict

@app.post("/v1/execute")
async def execute_action(req: ExecuteRequest):
    if not PUBLIC_KEY:
        raise HTTPException(status_code=500, detail="PEP_MISCONFIGURED_NO_KEY")

    permit = req.permit
    orig_req = req.original_request

    # 1. Cryptographie
    try:
        signature = bytes.fromhex(permit.pop("signature"))
        PUBLIC_KEY.verify(signature, canonical_hash(permit).encode('utf-8'))
    except (KeyError, InvalidSignature):
        raise HTTPException(status_code=403, detail="INVALID_SIGNATURE")

    # 2. Sémantique Temporelle Stricte
    current_time = time.time()
    if current_time >= permit.get("expires_at", 0):
        raise HTTPException(status_code=403, detail="PERMIT_EXPIRED")

    if permit.get("audience") != AUDIENCE_PEP:
        raise HTTPException(status_code=403, detail="WRONG_AUDIENCE")

    nonce = permit.get("nonce")
    if not nonce:
        raise HTTPException(status_code=403, detail="MISSING_NONCE")

    # 3. VERROUILLAGE TRANSACTIONNEL (Race-Condition Protection)
    conn = sqlite3.connect(DB_PATH, isolation_level="IMMEDIATE")
    cursor = conn.cursor()
    try:
        # L'insertion échouera instantanément si le nonce existe, même via un autre processus.
        cursor.execute(
            "INSERT INTO consumed_permits (nonce, permit_id, consumed_at, status) VALUES (?, ?, ?, ?)",
            (nonce, permit.get("permit_id", "unknown"), current_time, "PENDING")
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=403, detail="NONCE_REUSED")

    # === POINT DE NON-RETOUR ===
    # Si le programme crashe ici, le nonce est brûlé. L'action ne sera pas rejouée.

    # 4. Intégrité croisée (Payload)
    if permit.get("request_hash") != canonical_hash(orig_req):
        # On marque l'échec dans la DB avant de rejeter
        cursor.execute("UPDATE consumed_permits SET status = 'FAILED_TAMPERED' WHERE nonce = ?", (nonce,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=403, detail="REQUEST_TAMPERED")

    # 5. Simulation de l'action physique
    # (Ici interviendrait l'appel système réel)

    # 6. Validation de l'exécution
    cursor.execute("UPDATE consumed_permits SET status = 'COMPLETED' WHERE nonce = ?", (nonce,))
    conn.commit()
    conn.close()

    return {"status": "SUCCESS", "executed": True, "transaction": "COMMITTED"}
