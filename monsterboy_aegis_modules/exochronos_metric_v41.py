"""
EXOCHRONOS V41 metric provenance audit.

Purpose:
- Recompute the C76/C82 reference matrix with the frozen 25-edge graph.
- Separate the legacy pairwise-MI clamp from the shrinkage correlation matrix.
- Fail closed on non-positive-definite shrunk matrices.
- Emit deterministic checks[] and metrics[] suitable for external audit tooling.

This module is audit-only. It does not rewrite historical cycles.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Any

import numpy as np

MODULES = ["CA", "CL", "AI", "SS", "CR", "UF", "KG", "PM", "FR", "SI"]

EDGE_SET = [
    (0,1),(0,2),(0,3),(0,4),(0,5),(0,6),(0,8),(0,9),
    (1,2),(1,4),(1,5),(1,6),(1,7),(1,8),(1,9),
    (2,3),(2,4),(2,6),(2,8),
    (3,4),(3,6),(3,7),(3,9),
    (4,5),(5,7),
]

P_C76_REFERENCE = np.array([
    [0.7316110872815095, 0.6917908931903972, 0.7254946707827881, 0.6059331059118613, 0.955612850783262],
    [0.6040832520299946, 0.5887224961129919, 0.5783212837499814, 0.5206216463978565, 0.7160139882854805],
    [0.5189652016584215, 0.6766908736458294, 0.6327266851098928, 0.8258568945895813, 0.5919098138275883],
    [0.6664103770067265, 0.7240823697838008, 0.6681828706593986, 0.6602972493439938, 0.8035659467368055],
    [0.5598846859174667, 0.45300026533450466, 0.5942089651309489, 0.4966878168246583, 0.7473854964081418],
    [0.7431689776106852, 0.5757286714884113, 0.64772386790927, 0.38605733245481194, 0.8961306398567996],
    [0.8269311416143182, 0.5458529419837709, 0.5195639347577363, 0.9445090618645743, 0.7228115138506163],
    [0.8413494323702752, 0.7738752485359927, 0.6123044112312861, 0.35385185082424564, 0.7596370463165093],
    [0.5461071015474998, 0.6774414104382117, 0.7188262171059966, 0.47181523112896595, 0.5714764494491785],
    [0.5547439489385306, 0.560549654330068, 0.7257020454929365, 0.2320046944890612, 0.6023698046857914],
], dtype=float)

@dataclass(frozen=True)
class AuditConfig:
    lam: float = 0.30
    n_perm: int = 2000
    seed: int = 42
    rho_cap: float = 0.95


def build_triangles(edges: list[tuple[int, int]]) -> list[tuple[int, int, int]]:
    adj = {i: set() for i in range(10)}
    for u, v in edges:
        adj[u].add(v)
        adj[v].add(u)
    tris: list[tuple[int, int, int]] = []
    for u in range(10):
        for v in adj[u]:
            if v <= u:
                continue
            for w in adj[u] & adj[v]:
                if w > v:
                    tris.append((u, v, w))
    return sorted(tris)


TRIANGLES = build_triangles(EDGE_SET)


def _validate_P(P: np.ndarray) -> np.ndarray:
    P = np.asarray(P, dtype=float)
    if P.shape != (10, 5):
        raise ValueError(f"parameter_matrix must have shape (10, 5), got {P.shape}")
    if not np.all(np.isfinite(P)):
        raise ValueError("parameter_matrix contains non-finite values")
    return P


def compH_minmax_l1(P: np.ndarray) -> np.ndarray:
    P = _validate_P(P)
    mn = P.min(axis=1, keepdims=True)
    shifted = P - mn
    denom = shifted.sum(axis=1, keepdims=True)
    if np.any(denom <= 1e-15):
        raise ValueError("at least one module has zero min-max entropy support")
    Q = shifted / denom
    Q = np.clip(Q, 1e-15, 1.0)
    return -np.sum(Q * np.log2(Q), axis=1)


def correlation_matrix(P: np.ndarray) -> np.ndarray:
    """Correlation for shrinkage: symmetric, PSD up to roundoff, diag exactly 1."""
    P = _validate_P(P)
    centered = P - P.mean(axis=1, keepdims=True)
    std = P.std(axis=1, ddof=0, keepdims=True)
    if np.any(std <= 1e-12):
        raise ValueError("ZERO_VARIANCE_MODULE")
    Z = centered / std
    R = (Z @ Z.T) / P.shape[1]
    R = 0.5 * (R + R.T)
    np.fill_diagonal(R, 1.0)
    return R


def legacy_pairwise_correlation(P: np.ndarray, rho_cap: float = 0.95) -> np.ndarray:
    """Legacy pairwise audit correlation. Clamp off-diagonals only."""
    R = correlation_matrix(P)
    mask = ~np.eye(R.shape[0], dtype=bool)
    R[mask] = np.clip(R[mask], -rho_cap, rho_cap)
    return R


def tc_legacy(P: np.ndarray, rho_cap: float = 0.95) -> tuple[float, float, float]:
    R = legacy_pairwise_correlation(P, rho_cap=rho_cap)
    mi: dict[tuple[int, int], float] = {}
    sum_mi = 0.0
    for u, v in EDGE_SET:
        value = -0.5 * np.log2(max(1.0 - R[u, v] ** 2, 1e-15))
        mi[(u, v)] = float(value)
        sum_mi += float(value)

    sum_tri = 0.0
    for a, b, c in TRIANGLES:
        edges = [
            tuple(sorted((a, b))),
            tuple(sorted((b, c))),
            tuple(sorted((a, c))),
        ]
        sum_tri += min(mi[e] for e in edges)

    return sum_mi - sum_tri, sum_mi, sum_tri


def tc_shrink(P: np.ndarray, lam: float = 0.30) -> float:
    if not (0.0 < lam <= 1.0):
        raise ValueError("lam must be in (0, 1]")
    R = correlation_matrix(P)
    R_lam = (1.0 - lam) * R + lam * np.eye(R.shape[0])
    sign, logdet = np.linalg.slogdet(R_lam)
    if sign <= 0:
        raise ValueError("SHRUNK_CORRELATION_NOT_POSITIVE_DEFINITE")
    return float(-0.5 * logdet / np.log(2.0))


def legacy_v19_literal_tc(P: np.ndarray, lam: float = 0.30, rho_cap: float = 0.95) -> tuple[float, float]:
    """
    Reproduce the pasted v19 implementation defect for audit comparison only:
    diagonal is clamped to rho_cap, then negative eigenvalues are zeroed.
    """
    P = _validate_P(P)
    centered = P - P.mean(axis=1, keepdims=True)
    std = np.maximum(P.std(axis=1, ddof=0, keepdims=True), 1e-12)
    Z = centered / std
    R_bad = np.clip((Z @ Z.T) / P.shape[1], -rho_cap, rho_cap)
    evals = np.linalg.eigvalsh(R_bad)
    evals_nonneg = np.maximum(evals, 0.0)
    tc = -0.5 * np.sum(np.log2((1.0 - lam) * evals_nonneg + lam + 1e-15))
    return float(tc), float(evals.min())


def compute_cycle(P: np.ndarray, config: AuditConfig = AuditConfig()) -> dict[str, Any]:
    P = _validate_P(P)
    H_mod = compH_minmax_l1(P)
    H_total = float(H_mod.sum())

    tc_sh = tc_shrink(P, lam=config.lam)
    tc_old, sum_mi, sum_tri = tc_legacy(P, rho_cap=config.rho_cap)

    R = correlation_matrix(P)
    evals = np.linalg.eigvalsh(R)
    ev_n = np.maximum(evals, 0.0)
    ev_n = ev_n / max(float(ev_n.sum()), 1e-15)
    participation_ratio = float(1.0 / np.sum(ev_n ** 2))

    bad_tc, bad_min_eig = legacy_v19_literal_tc(
        P, lam=config.lam, rho_cap=config.rho_cap
    )

    out: dict[str, Any] = {
        "formula_version": f"v41_audit_shrink_lambda_{config.lam:.2f}",
        "H_total": H_total,
        "module_entropies": H_mod.tolist(),
        "TC_shrink": tc_sh,
        "global_coherence": tc_sh / H_total,
        "TC_legacy_corrected": tc_old,
        "global_coherence_legacy": tc_old / H_total,
        "legacy_sum_mi": sum_mi,
        "legacy_triangle_correction": sum_tri,
        "participation_ratio": participation_ratio,
        "corr_rank": int(np.linalg.matrix_rank(R, tol=1e-10)),
        "corr_min_eigenvalue": float(evals.min()),
        "literal_v19_TC_shrink": bad_tc,
        "literal_v19_min_eigenvalue": bad_min_eig,
        "parameter_matrix": P.tolist(),
    }
    return out


def permutation_test(P: np.ndarray, config: AuditConfig = AuditConfig()) -> dict[str, float]:
    P = _validate_P(P)
    rng = np.random.RandomState(config.seed)
    obs = compute_cycle(P, config)["global_coherence"]
    null = np.empty(config.n_perm, dtype=float)
    for b in range(config.n_perm):
        Pp = np.empty_like(P)
        for k in range(P.shape[1]):
            Pp[:, k] = rng.permutation(P[:, k])
        null[b] = compute_cycle(Pp, config)["global_coherence"]

    p_plus_one = (1.0 + float(np.sum(null >= obs))) / (config.n_perm + 1.0)
    z = (obs - float(null.mean())) / max(float(null.std(ddof=0)), 1e-15)
    return {
        "p_value_plus_one": p_plus_one,
        "z_score": float(z),
        "null_mean": float(null.mean()),
        "null_std": float(null.std(ddof=0)),
        "null_q025": float(np.quantile(null, 0.025)),
        "null_q975": float(np.quantile(null, 0.975)),
    }


def logistic_map(P: np.ndarray, r: float = 3.7, steps: int = 3) -> np.ndarray:
    X = np.clip(_validate_P(P).copy(), 1e-6, 1.0 - 1e-6)
    for _ in range(steps):
        X = r * X * (1.0 - X)
    return np.clip(X, 0.0, 1.0)


def _check(check_id: str, passed: bool, message: str) -> dict[str, Any]:
    return {"id": check_id, "status": "PASS" if passed else "FAIL", "message": message}


def plugin_eval_payload(P: np.ndarray, config: AuditConfig = AuditConfig()) -> dict[str, Any]:
    cycle = compute_cycle(P, config)
    perm = permutation_test(P, config)

    chaos = logistic_map(P)
    chaos_cycle = compute_cycle(chaos, config)
    chaos_perm = permutation_test(chaos, config)

    checks = [
        _check("exo_v41.graph.edge_count", len(EDGE_SET) == 25, f"edge_count={len(EDGE_SET)}"),
        _check("exo_v41.graph.triangle_count", len(TRIANGLES) == 21, f"triangle_count={len(TRIANGLES)}"),
        _check("exo_v41.corr.diagonal_is_one", np.allclose(np.diag(correlation_matrix(P)), 1.0), "diag(R)=1"),
        _check("exo_v41.corr.rank_expected", cycle["corr_rank"] <= 4, f"rank={cycle['corr_rank']} <= 4 for 5 observations"),
        _check("exo_v41.shrink.finite", np.isfinite(cycle["TC_shrink"]), f"TC_shrink={cycle['TC_shrink']:.12f}"),
        _check("exo_v41.permutation.no_supported_signal", perm["p_value_plus_one"] >= 0.01, f"p={perm['p_value_plus_one']:.6f}"),
        _check("exo_v41.chaos.no_supported_signal", chaos_perm["p_value_plus_one"] >= 0.01, f"chaos p={chaos_perm['p_value_plus_one']:.6f}"),
        _check("exo_v41.literal_v19.non_psd_detected", cycle["literal_v19_min_eigenvalue"] < -1e-10, f"literal min eig={cycle['literal_v19_min_eigenvalue']:.12f}"),
    ]

    metrics = [
        {"id": "exo_v41.H_total", "value": cycle["H_total"], "unit": "bits"},
        {"id": "exo_v41.TC_shrink", "value": cycle["TC_shrink"], "unit": "bits"},
        {"id": "exo_v41.C_shrink", "value": cycle["global_coherence"], "unit": "ratio"},
        {"id": "exo_v41.TC_legacy", "value": cycle["TC_legacy_corrected"], "unit": "bits"},
        {"id": "exo_v41.C_legacy", "value": cycle["global_coherence_legacy"], "unit": "ratio"},
        {"id": "exo_v41.permutation_p", "value": perm["p_value_plus_one"], "unit": "p_value"},
        {"id": "exo_v41.permutation_z", "value": perm["z_score"], "unit": "z"},
        {"id": "exo_v41.literal_v19_TC", "value": cycle["literal_v19_TC_shrink"], "unit": "bits"},
        {"id": "exo_v41.literal_v19_min_eigenvalue", "value": cycle["literal_v19_min_eigenvalue"], "unit": "eigenvalue"},
        {"id": "exo_v41.chaos_C_shrink", "value": chaos_cycle["global_coherence"], "unit": "ratio"},
        {"id": "exo_v41.chaos_permutation_p", "value": chaos_perm["p_value_plus_one"], "unit": "p_value"},
    ]
    return {"checks": checks, "metrics": metrics}


def self_test() -> None:
    cfg = AuditConfig(n_perm=2000, seed=42)
    cycle = compute_cycle(P_C76_REFERENCE, cfg)
    perm = permutation_test(P_C76_REFERENCE, cfg)
    chaos = compute_cycle(logistic_map(P_C76_REFERENCE), cfg)
    chaos_perm = permutation_test(logistic_map(P_C76_REFERENCE), cfg)

    assert len(EDGE_SET) == 25
    assert len(TRIANGLES) == 21
    assert abs(cycle["H_total"] - 17.68436508496739) < 1e-10
    assert abs(cycle["TC_shrink"] - 3.9211438241736754) < 1e-10
    assert abs(cycle["global_coherence"] - 0.22172940930216642) < 1e-10
    assert abs(cycle["TC_legacy_corrected"] - 5.877014995214978) < 1e-10
    assert abs(cycle["global_coherence_legacy"] - 0.33232830056255397) < 1e-10
    assert abs(cycle["literal_v19_TC_shrink"] - 4.015980639360169) < 1e-10
    assert cycle["literal_v19_min_eigenvalue"] < -0.07
    assert 0.15 < perm["p_value_plus_one"] < 0.19
    assert abs(chaos["global_coherence"] - 0.1886343334719996) < 1e-10
    assert 0.38 < chaos_perm["p_value_plus_one"] < 0.44


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-json", help="JSON file containing parameter_matrix")
    parser.add_argument("--n-perm", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--lambda-shrink", type=float, default=0.30)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print(json.dumps({"status": "PASS", "test": "EXOCHRONOS_V41_SELF_TEST"}, indent=2))
        return

    if args.input_json:
        with open(args.input_json, encoding="utf-8") as f:
            obj = json.load(f)
        P = np.asarray(obj["parameter_matrix"], dtype=float)
    else:
        P = P_C76_REFERENCE

    cfg = AuditConfig(lam=args.lambda_shrink, n_perm=args.n_perm, seed=args.seed)
    print(json.dumps(plugin_eval_payload(P, cfg), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
