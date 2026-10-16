#!/usr/bin/env python3
"""Régressions V3C exigées par l'ordre V3D — sans aucune écriture rétroactive.

(a) `aegis_v3c/tests/run_v3c_tribunal.py` (PRÉSERVÉ, non modifié) contre le code
    V3C conservé : les 50 scénarios historiques doivent rester verts.
(b) La même suite historique contre le PEP V3D, via un wrapper de banc V3D :
    liaison `pep_v3c_pinned` -> `pep_v3d_effect` en mémoire + lancement uvicorn
    du module V3D. Aucun fichier V3C n'est modifié ; les tags d'écriture sont
    distincts (`v3d_reg_*`), les résultats historiques run1/run2 intacts.

Attendu : 50/50 dans les deux directions. Les actions `report.read` /
`email.send` conservent la sémantique simulée V3C ; l'action réelle est bornée à
`marker.create`, jamais sollicitée par la suite V3C.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
AEGIS_V3D_DIR = HERE.parent
REPO = AEGIS_V3D_DIR.parent
V3C_DIR = REPO / "aegis_v3c"
V3C_TESTS = V3C_DIR / "tests"
RESULTS = AEGIS_V3D_DIR / "results"
VENV_PY = "/home/user/.venv-aegis/bin/python"

RESULTS.mkdir(exist_ok=True)


def run_v3c_pure() -> dict:
    """(a) suite historique contre code V3C préservé."""
    tag = "v3d_reg_v3c"
    log = RESULTS / "regression_v3c_vs_v3c_stdout.txt"
    proc = subprocess.run(
        [VENV_PY, str(V3C_TESTS / "run_v3c_tribunal.py"), "--tag", tag],
        cwd=str(V3C_DIR), capture_output=True, text=True, timeout=600,
    )
    log.write_text(proc.stdout + "\n--- STDERR ---\n" + proc.stderr, encoding="utf-8")
    res_path = V3C_DIR / "results" / f"EXPERIMENT_RESULTS_{tag}.json"
    summary = json.loads(res_path.read_text())["summary"] if res_path.exists() else {}
    return {"runner_exit": proc.returncode, "summary": summary, "log": str(log)}


def run_v3d_wrapped() -> dict:
    """(b) suite historique contre PEP V3D (wrapper, sources V3C intactes)."""
    tag = "v3d_reg_vs_v3d"
    sys.path.insert(0, str(V3C_TESTS))
    sys.path.insert(0, str(AEGIS_V3D_DIR))

    import pep_v3d_effect  # noqa: E402

    # liaison en mémoire pour les imports en processus de la suite historique
    sys.modules["pep_v3c_pinned"] = pep_v3d_effect

    import harness as v3c_harness  # type: ignore  # noqa: E402

    _orig_start = v3c_harness.ServerHandle.start

    def patched_start(self, wait_s: float = 25.0) -> None:
        effect_dir = self.workspace / "effect_markers"
        effect_dir.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env.update(v3c_harness.workspace_env(self.workspace))
        env.update(self.env_overrides)
        env.update(
            {
                "PYTHONPATH": str(AEGIS_V3D_DIR),
                "PYTHONDONTWRITEBYTECODE": "1",
                "AEGIS_EFFECT_DIR": str(effect_dir),
                "AEGIS_REAL_ACTIONS": "marker.create",
            }
        )
        self.proc = subprocess.Popen(
            [
                VENV_PY, "-m", "uvicorn", "pep_v3d_effect:app",
                "--host", "127.0.0.1", "--port", str(self.port), "--log-level", "warning",
            ],
            cwd=str(AEGIS_V3D_DIR),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.time() + wait_s
        last_err = ""
        import httpx  # noqa: PLC0415

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

    v3c_harness.ServerHandle.start = patched_start

    import run_v3c_tribunal  # type: ignore  # noqa: E402

    sys.argv = ["run_v3c_tribunal.py", "--tag", tag]
    log = RESULTS / "regression_v3c_vs_v3d_stdout.txt"
    import contextlib
    import io

    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = run_v3c_tribunal.main()
    finally:
        v3c_harness.ServerHandle.start = _orig_start
        # ne pas laisser la liaison polluer d'éventuels imports ultérieurs
        sys.modules.pop("pep_v3c_pinned", None)
    log.write_text(buf.getvalue(), encoding="utf-8")
    print(buf.getvalue())
    res_path = V3C_DIR / "results" / f"EXPERIMENT_RESULTS_{tag}.json"
    summary = json.loads(res_path.read_text())["summary"] if res_path.exists() else {}
    return {"runner_exit": rc, "summary": summary, "log": str(log)}


def main() -> int:
    print("===== (a) suite V3C historique vs code V3C PRÉSERVÉ =====")
    a = run_v3c_pure()
    print(json.dumps(a, ensure_ascii=False))
    print()
    print("===== (b) suite V3C historique vs PEP V3D =====")
    b = run_v3d_wrapped()
    print(json.dumps(b, ensure_ascii=False))

    ok = (
        a.get("runner_exit") == 0 and a.get("summary", {}).get("fail") == 0
        and b.get("runner_exit") == 0 and b.get("summary", {}).get("fail") == 0
    )
    out = {
        "mission": "AEGIS_V3D_REAL_EFFECT_WITNESS_004",
        "suite": "V3C_REGRESSIONS",
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "v3c_vs_v3c": a,
        "v3c_vs_v3d": b,
        "verdict": "PASS_LOCAL" if ok else "FAIL",
    }
    path = RESULTS / "REGRESSION_RESULTS.json"
    path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nwritten: {path} | verdict: {out['verdict']}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
