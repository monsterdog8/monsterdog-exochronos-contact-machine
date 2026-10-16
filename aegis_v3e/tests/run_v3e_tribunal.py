#!/usr/bin/env python3
"""Tribunal V3E — familles (A)-(E) + contrôles négatifs d'attestation (V1-V5).

Exécution RÉELLE uniquement : chaque contrôle produit une commande lancée,
un reçu brut (stdout/stderr/exit) et des octets d'effet capturés dans
RAW_EVIDENCE/. Oracle d'effet UNIQUE : INDEPENDENT_WITNESS_SOURCE/witness_v3e.sh
(UID aegis_witness). Aucun PASS sans exécution. CLAIM <= EVIDENCE.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness_v3e as H  # noqa: E402

RAW = H.RAW
EFFECT = H.EFFECT
SANDBOX = H.SANDBOX
CONFIG = H.CONFIG
STATE = H.STATE

FIXED_NOW = H.FIXED_NOW
POLICY_VERSION = H.POLICY_VERSION

results: List[Dict[str, Any]] = []
receipts: List[Dict[str, Any]] = []
_prev = "GENESIS"

# Marqueurs légitimes attendus (nom -> (sha256, size)) : chaque interrogation du
# témoin porte l'ensemble COMPLET attendu, pour que « aucun marqueur superflu »
# soit lui aussi vérifié par l'oracle indépendant.
legit: Dict[str, Tuple[str, int]] = {}


def assert_rows(*extra: Tuple[str, int, str]) -> List[Tuple[str, int, str]]:
    rows = [(sha, size, name) for name, (sha, size) in sorted(legit.items())]
    rows.extend(extra)
    return rows


def receipt(kind: str, payload: Dict[str, Any]) -> str:
    global _prev
    entry = {
        "seq": len(receipts) + 1,
        "kind": kind,
        "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "prev_hash": _prev,
        "payload": payload,
    }
    body = json.dumps(entry, sort_keys=True, ensure_ascii=False)
    entry["entry_hash"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
    receipts.append(entry)
    _prev = entry["entry_hash"]
    return _prev


def record(tid: str, passed: bool, evidence: Dict[str, Any], summary: str) -> None:
    results.append(
        {
            "id": tid,
            "status": "PASS_LOCAL" if passed else "FAIL",
            "evidence": evidence,
            "summary": summary,
        }
    )
    receipt("test_result", {"id": tid, "status": "PASS_LOCAL" if passed else "FAIL",
                            "summary": summary, "evidence": evidence})
    print(f"[{results[-1]['status']}] {tid}: {summary}")


def marker_names() -> List[str]:
    if not EFFECT.exists():
        return []
    return sorted(p.name for p in EFFECT.iterdir() if p.name.startswith("marker-") and p.is_file())


def expect_blob(pid: str, nonce: str, resource: str, subject: str = "agent-alpha",
                action: str = "marker.create") -> Tuple[bytes, str, int]:
    blob = H.expected_marker_blob(
        permit_id=pid, nonce=nonce, subject=subject, action=action,
        resource=resource, policy_version=POLICY_VERSION, materialized_at=FIXED_NOW,
    )
    return blob, hashlib.sha256(blob).hexdigest(), len(blob)


def agent_post(payload: Dict[str, Any], tag: str) -> Dict[str, Any]:
    out = H.agent_post(H.server_base, payload, tag)
    # capture reçu brut agent dans RAW_EVIDENCE
    dst = RAW / "agent_receipts"
    dst.mkdir(parents=True, exist_ok=True)
    (dst / f"out_{tag}.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )
    return out


def witness_checked(assertion_rows: List[Tuple[str, int, str]], run_id: str,
                    expect_valid: bool) -> Dict[str, Any]:
    rep = H.witness_run(assertion_rows, run_id)
    ok = (rep["verdict"] == "VALID") == expect_valid and rep["exit_code"] in (0, 1)
    rep["expect_valid"] = expect_valid
    rep["expectation_met"] = ok
    return rep


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    H.ensure_run_dirs()
    (RAW / "versions").mkdir(parents=True, exist_ok=True)

    # Versions des codes (liens vérifiables entre artefacts)
    for f in (H.V3E_DIR / "pep_v3e_effect.py",
              H.V3E_DIR / "INDEPENDENT_WITNESS_SOURCE" / "witness_v3e.sh",
              Path(__file__)):
        (RAW / "versions" / (f.name + ".sha256")).write_text(
            hashlib.sha256(f.read_bytes()).hexdigest() + "  " + f.name + "\n", encoding="utf-8"
        )
    pyver = subprocess.run([H.PY, "--version"], capture_output=True, text=True)
    (RAW / "versions" / "python.txt").write_text(pyver.stdout + pyver.stderr, encoding="utf-8")

    # ACL/UID constatés
    acl = {
        "sandbox": H.ls_ln(SANDBOX),
        "config": H.ls_ln(CONFIG),
        "effect": H.ls_ln(EFFECT),
        "state": H.ls_ln(STATE),
    }
    (RAW / "acl_uids.txt").write_text(
        "\n".join(f"== {k} ==\n{v}" for k, v in acl.items()), encoding="utf-8"
    )

    # Politique + hash + pin (publiques)
    pol = CONFIG / "pep_policy_v3e.json"
    pub = CONFIG / "pep_public.key"
    pin = CONFIG / "trust_root.pin"
    (RAW / "policy").mkdir(parents=True, exist_ok=True)
    (RAW / "policy" / "pep_policy_v3e.json").write_bytes(pol.read_bytes())
    (RAW / "policy" / "policy.sha256").write_text(
        hashlib.sha256(pol.read_bytes()).hexdigest() + "  pep_policy_v3e.json\n", encoding="utf-8"
    )
    (RAW / "policy" / "pep_public.key").write_bytes(pub.read_bytes())
    (RAW / "policy" / "trust_root.pin").write_bytes(pin.read_bytes())
    receipt("policy", {"policy_sha256": hashlib.sha256(pol.read_bytes()).hexdigest(),
                       "pin": pin.read_text().strip()})

    # Pré-calcul des marqueurs attendus (horloge figée)
    allow = {
        "permit_id": "P-V3E",
        "nonce": "nonce-v3e-allow-001",
        "resource": "effect/marker-P-V3E.json",
    }
    conc = {
        "permit_id": "P-V3E-C12",
        "nonce": "nonce-v3e-c12-001",
        "resource": "effect/marker-P-V3E-C12.json",
    }
    precalc: Dict[str, Any] = {}
    for label, fx in (("P-V3E", allow), ("P-V3E-C12", conc)):
        blob, sha, size = expect_blob(fx["permit_id"], fx["nonce"], fx["resource"])
        precalc[label] = {"sha256": sha, "size": size}
    crash_fx = {}
    for cid in ("C1", "C2", "C3", "C4"):
        pid = f"P-V3E-{cid}"
        blob, sha, size = expect_blob(pid, f"nonce-v3e-{cid.lower()}", f"effect/marker-{pid}.json")
        crash_fx[cid] = {"permit_id": pid, "nonce": f"nonce-v3e-{cid.lower()}",
                         "resource": f"effect/marker-{pid}.json", "sha256": sha, "size": size}
    (RAW / "precomputed_expectations.json").write_text(
        json.dumps({"allow": precalc["P-V3E"], "concurrency": precalc["P-V3E-C12"],
                    "crash": crash_fx}, indent=1) + "\n", encoding="utf-8"
    )

    now = float(FIXED_NOW) - 10.0
    permit_args = dict(issued_at=now, expires_at=now + 300)

    srv = H.ServerHandle(name="S_V3E_MAIN")
    srv.start()
    H.server_base = srv.base_url
    health = srv.health()
    receipt("server_health", health)

    # ------------------------------------------------------------------
    # (A) permission ALLOW -> marqueur unique confirmé par témoin
    # ------------------------------------------------------------------
    req = H.make_request("agent-alpha", "marker.create", allow["resource"])
    permit = H.forge_permit(permit_id=allow["permit_id"], nonce=allow["nonce"],
                            orig_request=req, **permit_args)
    envelope = {"original_request": req, "permit": permit}
    (RAW / "permits").mkdir(exist_ok=True)
    (RAW / "permits" / "P-V3E.json").write_text(
        json.dumps(envelope, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )
    receipt("permit_issued", {"permit_id": allow["permit_id"], "nonce": allow["nonce"],
                              "request_hash": permit["request_hash"]})

    before = marker_names()
    out_a1 = agent_post(envelope, "A1_allow")
    after = marker_names()
    body = out_a1.get("body") or {}
    effect_claim = body.get("effect") or {}
    captured = H.capture_marker_bytes("marker-P-V3E.json", "A1")
    legit["marker-P-V3E.json"] = (precalc["P-V3E"]["sha256"], precalc["P-V3E"]["size"])
    rep_a1 = witness_checked(assert_rows(), "W-A1-ALLOW-001", expect_valid=True)
    a1_ok = (
        out_a1.get("status_code") == 200
        and before == [] and after == ["marker-P-V3E.json"]
        and captured.get("sha256") == precalc["P-V3E"]["sha256"]
        and rep_a1["expectation_met"]
    )
    record("A1", a1_ok, {
        "http": out_a1.get("status_code"), "effect_claim": effect_claim,
        "markers_before": before, "markers_after": after,
        "raw_marker": captured, "precomputed": precalc["P-V3E"],
        "witness": {"run_id": rep_a1["run_id"], "verdict": rep_a1["verdict"],
                    "exit": rep_a1["exit_code"], "raw": rep_a1["raw_stdout"]},
    }, "ALLOW -> 1 marqueur unique, octets pré-calculés, confirmé par témoin indépendant")

    # ------------------------------------------------------------------
    # (B) identité/action/signature interdites -> aucun marqueur
    # ------------------------------------------------------------------
    def negative(tid: str, payload: Dict[str, Any], tag: str, expect_4xx: bool) -> None:
        before = marker_names()
        out = agent_post(payload, tag)
        after = marker_names()
        rc = out.get("status_code")
        ok = expect_4xx and isinstance(rc, int) and 400 <= rc < 500 and before == after
        # témoin : l'ensemble attendu (légitimes connus) est confirmé, aucun superflu
        rep = witness_checked(assert_rows(), f"W-{tag}", expect_valid=True)
        ok = ok and rep["expectation_met"]
        record(tid, ok, {
            "http": rc, "body": out.get("body"), "markers_before": before,
            "markers_after": after,
            "witness": {"run_id": rep["run_id"], "verdict": rep["verdict"],
                        "exit": rep["exit_code"], "raw": rep["raw_stdout"]},
        }, f"{tag}: 4xx sans effet, témoin confirme l'absence (rc={rc})")

    # X1 — champ d'enveloppe inconnu (identité système)
    negative("B1-X1", {"original_request": req, "permit": permit, "system_eval": "root"},
             "B1_x1", True)
    # X2 — action interdite admin.delete signée légitimement
    req_x2 = H.make_request("agent-alpha", "admin.delete", "effect/marker-P-V3E.json")
    p_x2 = H.forge_permit(permit_id="P-V3E-X2", nonce="nonce-v3e-x2", orig_request=req_x2,
                          **permit_args)
    negative("B2-X2", {"original_request": req_x2, "permit": p_x2}, "B2_x2", True)
    # X3 — clé de signature erronée
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _e
    evil = _e.Ed25519PrivateKey.generate()
    req_x3 = H.make_request("agent-alpha", "marker.create", "effect/marker-P-V3E-X3.json")
    p_x3 = H.forge_permit(evil, permit_id="P-V3E-X3", nonce="nonce-v3e-x3",
                          orig_request=req_x3, **permit_args)
    negative("B3-X3", {"original_request": req_x3, "permit": p_x3}, "B3_x3", True)
    # X4 — nonce altéré après signature
    p_x4 = H.forge_permit(permit_id="P-V3E-X4", nonce="nonce-v3e-x4",
                          orig_request=req_x3, **permit_args)
    p_x4_t = dict(p_x4)
    p_x4_t["nonce"] = "nonce-v3e-x4-TAMPERED"
    negative("B4-X4", {"original_request": req_x3, "permit": p_x4_t}, "B4_x4", True)
    # X5 — ressource hors allowlist
    req_x5 = H.make_request("agent-alpha", "marker.create", "reports/steal.txt")
    p_x5 = H.forge_permit(permit_id="P-V3E-X5", nonce="nonce-v3e-x5", orig_request=req_x5,
                          **permit_args)
    negative("B5-X6-resource", {"original_request": req_x5, "permit": p_x5}, "B5_x6", True)

    # X7 — révocation : politique sans agent-alpha
    pol_orig = pol.read_bytes()
    pol_obj = json.loads(pol_orig)
    pol_revoked = dict(pol_obj)
    pol_revoked["allowlist"] = [
        r for r in pol_obj["allowlist"] if r.get("subject") != "agent-alpha"
    ]
    stage = Path("/tmp/aegis_v3e_stage")
    stage.mkdir(exist_ok=True)
    (stage / "pep_policy_revoked.json").write_text(json.dumps(pol_revoked, indent=2) + "\n")
    H.run_priv("stage revoked policy to config (temporary, restored after)",
               ["cp", str(stage / "pep_policy_revoked.json"), str(pol)])
    srv.restart()
    H.server_base = srv.base_url
    req_x7 = H.make_request("agent-alpha", "marker.create", "effect/marker-P-V3E-X7.json")
    p_x7 = H.forge_permit(permit_id="P-V3E-X7", nonce="nonce-v3e-x7", orig_request=req_x7,
                          **permit_args)
    negative("B6-X7-revoked", {"original_request": req_x7, "permit": p_x7}, "B7_x7", True)
    H.run_priv("restore original policy (authorized agent-alpha)",
               ["cp", "/tmp/aegis_v3e_stage/pep_policy_v3e.json", str(pol)])
    srv.restart()
    H.server_base = srv.base_url

    # ------------------------------------------------------------------
    # (C) replay / restart / concurrence -> jamais de second effet
    # ------------------------------------------------------------------
    # C-replay immédiat du permis A1 (consommé)
    before = marker_names()
    out_c1 = agent_post(envelope, "C1_replay")
    after = marker_names()
    rep_c1 = witness_checked(assert_rows(), "W-C1-REPLAY", expect_valid=True)
    c1_ok = (isinstance(out_c1.get("status_code"), int) and out_c1["status_code"] >= 400
             and before == after == ["marker-P-V3E.json"] and rep_c1["expectation_met"])
    record("C1-replay", c1_ok, {
        "http": out_c1.get("status_code"), "body": out_c1.get("body"),
        "markers": after,
        "witness": {"run_id": rep_c1["run_id"], "verdict": rep_c1["verdict"],
                    "raw": rep_c1["raw_stdout"]},
    }, f"rejeu du permis consommé refusé (rc={out_c1.get('status_code')}), marqueur unique intact")

    # C-concurrence : 8 clients simultanés, même permis
    import threading
    conc_out: List[Dict[str, Any]] = []
    lock = threading.Lock()

    def one_post(i: int) -> None:
        o = H.agent_post(H.server_base, envelope, f"C2_conc_{i}")
        with lock:
            conc_out.append(o)

    req_c2 = H.make_request("agent-alpha", "marker.create", conc["resource"])
    p_c2 = H.forge_permit(permit_id=conc["permit_id"], nonce=conc["nonce"],
                          orig_request=req_c2, **permit_args)
    env_c2 = {"original_request": req_c2, "permit": p_c2}
    before = marker_names()
    threads = [threading.Thread(target=one_post, args=(i,)) for i in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    after = marker_names()
    codes = sorted((o.get("status_code") or 0) for o in conc_out)
    new_markers = [m for m in after if m not in before]
    if "marker-P-V3E-C12.json" in new_markers:
        legit["marker-P-V3E-C12.json"] = (precalc["P-V3E-C12"]["sha256"],
                                          precalc["P-V3E-C12"]["size"])
    (RAW / "agent_receipts").mkdir(parents=True, exist_ok=True)
    (RAW / "agent_receipts" / "C2_concurrency_out.json").write_text(
        json.dumps(conc_out, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    rep_c2 = witness_checked(assert_rows(), "W-C2-CONCURRENCY", expect_valid=True)
    successes = codes.count(200)
    c2_ok = successes == 1 and new_markers == ["marker-P-V3E-C12.json"] and rep_c2["expectation_met"]
    record("C2-concurrency", c2_ok, {
        "http_codes": codes, "markers_before": before, "markers_after": after,
        "new_markers": new_markers,
        "witness": {"run_id": rep_c2["run_id"], "verdict": rep_c2["verdict"],
                    "raw": rep_c2["raw_stdout"]},
    }, f"8 clients simultanés -> exactement 1 effet (200x{successes}), témoin confirme")

    # C-restart : redémarrage puis rejeu
    srv.restart()
    H.server_base = srv.base_url
    before = marker_names()
    out_c3 = agent_post(envelope, "C3_restart_replay")
    after = marker_names()
    rep_c3 = witness_checked(assert_rows(), "W-C3-RESTART", expect_valid=True)
    c3_ok = (isinstance(out_c3.get("status_code"), int) and out_c3["status_code"] >= 400
             and before == after and rep_c3["expectation_met"])
    record("C3-restart", c3_ok, {
        "http": out_c3.get("status_code"), "body": out_c3.get("body"), "markers": after,
        "witness": {"run_id": rep_c3["run_id"], "verdict": rep_c3["verdict"],
                    "raw": rep_c3["raw_stdout"]},
    }, f"rejeu après redémarrage refusé (rc={out_c3.get('status_code')})")

    # ------------------------------------------------------------------
    # (D) accès direct par UID agent -> EACCES
    # ------------------------------------------------------------------
    p_d1 = H.run_priv("D1 agent write effect dir", ["sudo", "-n", "-u", "aegis_agent",
                       "touch", str(EFFECT / "marker-AGENT-FORGED.json")])
    p_d2 = H.run_priv("D2 agent open registry", ["sudo", "-n", "-u", "aegis_agent",
                       "env", f"PYTHONPATH={H.RUN_ENV_PYTHONPATH}", H.PY, "-c",
                       "import sqlite3; sqlite3.connect('/tmp/aegis_v3e_sandbox/state/pep_ledger.db').execute('select 1')"])
    p_d3 = H.run_priv("D3 agent write config dir", ["sudo", "-n", "-u", "aegis_agent",
                       "touch", str(CONFIG / "evil.json")])
    d_ok = (
        p_d1.returncode != 0 and "Permission denied" in (p_d1.stderr + p_d1.stdout)
        and p_d2.returncode != 0
        and p_d3.returncode != 0 and "Permission denied" in (p_d3.stderr + p_d3.stdout)
    )
    record("D1-D3", d_ok, {
        "D1_touch_effect": {"rc": p_d1.returncode, "stderr": p_d1.stderr[:300]},
        "D2_open_registry": {"rc": p_d2.returncode, "stderr": p_d2.stderr[:300]},
        "D3_touch_config": {"rc": p_d3.returncode, "stderr": p_d3.stderr[:300]},
        "forged_marker_absent": "marker-AGENT-FORGED.json" not in marker_names(),
    }, "UID agent : EACCES effect/config + registre illisible (rc != 0)")

    # ------------------------------------------------------------------
    # (E) crash C1-C4 -> états composés
    # ------------------------------------------------------------------
    crash_specs = [
        ("C1", "before_consume_commit", "NO_CONSUMPTION", True),
        ("C2", "after_consume_commit", "CONSUMED_NO_ATTEMPT", False),
        ("C3", "after_attempt", "ATTEMPTED_NO_EFFECT", False),
        ("C4", "after_effect", "EFFECT_PRESENT_DB_INCOMPLETE", False),
    ]
    crash_report: Dict[str, Any] = {}
    for cid, point, expect_state, retry_should_succeed in crash_specs:
        fx = crash_fx[cid]
        req_c = H.make_request("agent-alpha", "marker.create", fx["resource"])
        p_c = H.forge_permit(permit_id=fx["permit_id"], nonce=fx["nonce"],
                             orig_request=req_c, **permit_args)
        env_c = {"original_request": req_c, "permit": p_c}
        s_f = H.ServerHandle(name=f"S_CRASH_{cid}",
                             env_overrides={"AEGIS_FAULT_INJECT": point,
                                            "AEGIS_FAULT_EXIT_CODE": "73"})
        s_f.start()
        H.server_base = s_f.base_url
        out_crash = H.agent_post(env_c, f"E_{cid}_crash")
        time.sleep(0.3)
        crash_exit = s_f.proc.poll() if s_f.proc else None
        s_f.stop()
        marker_name = fx["resource"].split("/")[-1]
        marker_present = marker_name in marker_names()
        snap = H.db_snapshot(f"E_{cid}_post_crash")
        # état composite déduit des faits observés (registre + marqueur) :
        # marqueur présent -> effet réel mais DB incomplète (C4)
        rows = (snap.get("rows") or {})
        consumed = any(
            fx["permit_id"] in json.dumps(r)
            for r in (rows.get("consumed_permits", {}) or {}).get("rows", [])
        )
        attempted = any(
            fx["permit_id"] in json.dumps(r) and "ATTEMPT" in json.dumps(r).upper()
            for r in (rows.get("events", {}) or {}).get("rows", [])
        )
        if marker_present:
            observed_state = "EFFECT_PRESENT_DB_INCOMPLETE"
        elif attempted:
            observed_state = "ATTEMPTED_NO_EFFECT"
        elif consumed:
            observed_state = "CONSUMED_NO_ATTEMPT"
        else:
            observed_state = "NO_CONSUMPTION"
        # témoin : présence/absence vérifiée sur l'ensemble attendu complet
        if marker_present:
            legit[marker_name] = (fx["sha256"], fx["size"])
        rep_e = witness_checked(assert_rows(), f"W-E-{cid}", expect_valid=True)
        if not marker_present and marker_name in legit:
            del legit[marker_name]
        # réessai sans injection
        s_r = H.ServerHandle(name=f"S_RETRY_{cid}")
        s_r.start()
        H.server_base = s_r.base_url
        out_retry = agent_post(env_c, f"E_{cid}_retry")
        s_r.stop()
        retry_rc = out_retry.get("status_code")
        if retry_should_succeed:
            retry_ok = retry_rc == 200
        else:
            retry_ok = isinstance(retry_rc, int) and retry_rc >= 400
        final_markers = marker_names()
        marker_count = final_markers.count(marker_name)
        # exactement UN effet au total après réessai (jamais de second effet)
        if marker_present or retry_should_succeed:
            exactly_one = marker_count == 1
        else:
            exactly_one = marker_count == 0
        # témoin post-réessai : ensemble complet confirmé
        if retry_should_succeed and marker_count == 1:
            legit[marker_name] = (fx["sha256"], fx["size"])
        rep_post = witness_checked(assert_rows(), f"W-E-{cid}-POST", expect_valid=True)
        ok = (crash_exit == 73 and observed_state == expect_state
              and rep_e["expectation_met"] and retry_ok and exactly_one
              and rep_post["expectation_met"])
        crash_report[cid] = {
            "fault_point": point, "crash_exit": crash_exit,
            "observed_state": observed_state, "expected_state": expect_state,
            "marker_present": marker_present,
            "witness_post_crash": {"run_id": rep_e["run_id"], "verdict": rep_e["verdict"],
                                   "raw": rep_e["raw_stdout"]},
            "witness_post_retry": {"run_id": rep_post["run_id"], "verdict": rep_post["verdict"],
                                   "raw": rep_post["raw_stdout"]},
            "retry_http": retry_rc, "retry_body": out_retry.get("body"),
            "marker_count_after_retry": marker_count,
            "post_crash_db": snap,
        }
        record(f"E-{cid}", ok, crash_report[cid],
               f"crash @{point} exit 73 -> état {observed_state} (attendu {expect_state}) ; "
               f"réessai rc={retry_rc}")

    # Événements PEP (A1) : reçu brut d'effet
    events_a1 = body.get("events") or []
    (RAW / "pep_event_receipts.json").write_text(
        json.dumps({"A1_events": events_a1, "A1_effect": effect_claim}, indent=1) + "\n",
        encoding="utf-8",
    )

    # ------------------------------------------------------------------
    # (V) contrôles négatifs d'attestation
    # ------------------------------------------------------------------
    attacks: Dict[str, Any] = {}

    # V1 — altération d'un octet de marqueur : le témoin refuse
    v1_dir = SANDBOX / "attacks" / "v1_tamper" / "effect"
    v1_dir.mkdir(parents=True, exist_ok=True)
    marker_src = EFFECT / "marker-P-V3E.json"
    tampered = v1_dir / "marker-P-V3E.json"
    data = bytearray(marker_src.read_bytes())
    data[len(data) // 2] ^= 0x01
    tampered.write_bytes(bytes(data))
    rep_v1 = H.witness_run(
        [(precalc["P-V3E"]["sha256"], precalc["P-V3E"]["size"], "marker-P-V3E.json")],
        "W-V1-TAMPERED", effect_dir=v1_dir, tag="v1")
    v1_ok = rep_v1["verdict"] == "INVALID" and rep_v1["exit_code"] == 1
    attacks["V1"] = {
        "attack": "1 octet altéré dans une copie du marqueur",
        "expected": "witness INVALID (exit 1)",
        "observed": {"verdict": rep_v1["verdict"], "exit": rep_v1["exit_code"],
                     "raw": rep_v1["raw_stdout"]},
        "result": "REFUSED_AS_REQUIRED" if v1_ok else "NOT_REFUSED",
    }
    record("V1-tamper", v1_ok, attacks["V1"], "altération d'octet -> témoin refuse")

    # V2 — substitution complète du rapport du témoin -> vérificateur externe refuse
    # (exécuté par verify_bundle.py sur copie du bundle ; voir ATTACK_LEDGER)
    attacks["V2"] = {
        "attack": "rapport de témoin substitué (faux VALID)",
        "expected": "verify_bundle REFUSED (recalcul depuis octets RAW)",
        "observed": "see verify_v2.json (executed at verification stage)",
        "result": "PENDING_VERIFY",
    }

    # V3 — tête de chaîne antérieure / rollback -> refuse par ancre
    attacks["V3"] = {
        "attack": "EXPERIMENT_FREEZE.json remplacé (rollback manifeste)",
        "expected": "verify_bundle REFUSED (empreinte != ancre git)",
        "observed": "see verify_v3.json",
        "result": "PENDING_VERIFY",
    }

    # V4 — ancien permis + registre reconstitué
    # (a) rejeu déjà couvert (C1/C3). (b) registre vidé par uid pep (reconstruction),
    # (c) le plancher O_EXCL du marqueur empêche un second effet.
    p_v4 = H.run_priv("V4b rebuild registry: delete all rows as aegis_pep (simulated rebuild)",
                      ["sudo", "-n", "-u", "aegis_pep", "env",
                       f"PYTHONPATH={H.RUN_ENV_PYTHONPATH}", H.PY, "-c",
                       "import sqlite3;con=sqlite3.connect('/tmp/aegis_v3e_sandbox/state/pep_ledger.db');"
                       "[con.execute('delete from '+t) for t in ('consumed_permits','events','effect_journal')];"
                       "con.commit();print('rebuilt')"])
    s_v4 = H.ServerHandle(name="S_V4_REBUILD")
    s_v4.start()
    H.server_base = s_v4.base_url
    before_v4 = marker_names()
    out_v4 = agent_post(envelope, "V4_rebuilt_registry_replay")
    s_v4.stop()
    after_v4 = marker_names()
    v4_rc = out_v4.get("status_code")
    v4_marker_unchanged = before_v4 == after_v4
    # si le registre reconstruit a tenté l'effet : O_EXCL refuse -> pas de second effet
    v4_ok = v4_marker_unchanged and (
        (isinstance(v4_rc, int) and v4_rc >= 400) or v4_rc == 200
    )
    # le critère : AUCUN second marqueur ; le corps peut être 200-EFFECT_UNCONFIRMED
    if v4_rc == 200:
        eff = (out_v4.get("body") or {}).get("effect") or {}
        v4_ok = v4_marker_unchanged and eff.get("effect_confirmed") is False
    attacks["V4"] = {
        "attack": "registre reconstruit (DELETE) + ancien permis signé rejoué",
        "expected": "aucun second effet (plancher O_EXCL / refusal) ; comparé aux ancres (reçus)",
        "observed": {"http": v4_rc, "body": out_v4.get("body"),
                     "markers_before": before_v4, "markers_after": after_v4},
        "result": "NO_SECOND_EFFECT" if v4_ok else "SECOND_EFFECT_POSSIBLE",
    }
    record("V4-rebuild", v4_ok, attacks["V4"],
           f"registre reconstruit + rejeu permis -> rc={v4_rc}, aucun second effet={v4_ok}")

    # V5 — témoin indisponible -> UNKNOWN/HOLD
    rep_v5 = H.witness_run(
        [(precalc["P-V3E"]["sha256"], precalc["P-V3E"]["size"], "marker-P-V3E.json")],
        "W-V5-UNAVAILABLE", effect_dir=Path("/tmp/aegis_v3e_sandbox/NO_SUCH_DIR"), tag="v5")
    v5_ok = rep_v5["verdict"] == "UNAVAILABLE" and rep_v5["exit_code"] == 3
    attacks["V5"] = {
        "attack": "témoin lancé sans répertoire d'effet (indisponible)",
        "expected": "UNAVAILABLE -> UNKNOWN/HOLD, jamais CONFIRMED",
        "observed": {"verdict": rep_v5["verdict"], "exit": rep_v5["exit_code"],
                     "raw": rep_v5["raw_stdout"]},
        "result": "UNKNOWN_HOLD_AS_REQUIRED" if v5_ok else "UNEXPECTED",
    }
    record("V5-unavailable", v5_ok, attacks["V5"], "témoin indisponible -> UNAVAILABLE/HOLD")

    # ------------------------------------------------------------------
    # sauvegardes : DB finale, octets de TOUS les marqueurs, attaques, résultats
    # ------------------------------------------------------------------
    for name in marker_names():
        H.capture_marker_bytes(name, "FINAL")
    H.db_snapshot("FINAL")
    (RAW / "ATTACK_LEDGER_partial.json").write_text(
        json.dumps(attacks, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )

    chain_head = receipt("run_complete", {"tests": len(results),
                                          "pass": sum(1 for r in results if r["status"] == "PASS_LOCAL")})
    (RAW / "receipts_chain.jsonl").write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in receipts), encoding="utf-8"
    )

    summary = {
        "mission": "AEGIS_V3E_INDEPENDENT_WITNESS_ATTESTATION_005",
        "tests_total": len(results),
        "tests_pass_local": sum(1 for r in results if r["status"] == "PASS_LOCAL"),
        "chain_head": chain_head,
        "results": results,
    }
    (RAW / "EXECUTION_RESULTS.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )
    print(f"\nTOTAL: {summary['tests_pass_local']}/{summary['tests_total']} PASS_LOCAL")
    print("chain_head:", chain_head)
    return 0 if summary["tests_pass_local"] == summary["tests_total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
