# EXOCHRONOS NÉMÉSIS — V41 Metric Provenance Audit

**Status:** `FAIL_CLOSED_METRIC_PROVENANCE`  
**Scope:** C76/C82 reference matrix, v19 shrinkage implementation, historical claim lineage  
**Rule:** `CLAIM <= EVIDENCE`

## Executive verdict

The current GitHub repository remains correctly bounded at `LAB_ONLY` / local replay. The current repository does **not** contain `computeCycle_v19`, so the v19 implementation discussed in the live backend is not yet independently versioned here.

A fresh recomputation from the full-precision C76/C82 parameter matrix supplied by the live backend does **not** reproduce the sealed values `H_total=19.7134`, `TC_shrink=6.0560`, or `C_shrink=0.3072`.

The evidence-supported conclusion is narrower:

> **No detectable inter-module coherence signal is supported by the corrected V41 audit.**
>
> This is not equivalent to proving true coherence is exactly zero.

## V41 reference recomputation

| Quantity | Sealed V40 claim | V41 recomputation | Status |
|---|---:|---:|---|
| Edge count | 25 | 25 | PASS |
| Triangle count | 21 | 21 | PASS |
| `H_total` (`minmax+L1`) | 19.7134 | 17.6843650849674 | MISMATCH |
| `TC_legacy_corrected` | 5.6598 | 5.8770149952150 | MISMATCH |
| `C_legacy` | 0.2871 | 0.3323283005626 | MISMATCH |
| literal pasted-v19 `TC_shrink` | 6.0560 | 4.0159806393602 | MISMATCH |
| corrected `TC_shrink(lambda=0.30)` | n/a | 3.9211438241737 | NEW AUDIT |
| corrected `C_shrink` | 0.3072 | 0.2217294093022 | NEW AUDIT |
| permutation p-value (+1 correction, 2000 perms) | 0.091 | 0.1689155422289 | NON-SIGNIFICANT |
| permutation z-score | 1.6841 | 0.9670631593769 | NON-SIGNIFICANT |

## Root cause 1 — correlation diagonal was clamped

The pasted v19 function applied:

```python
np.clip((Pn @ Pn.T) / P.shape[1], -0.95, 0.95)
```

to the entire matrix, including the diagonal. A correlation matrix must satisfy `R_ii = 1`. Clamping the diagonal to `0.95` changes the matrix itself.

On the C76/C82 matrix, the literal pasted-v19 matrix has minimum eigenvalue:

```text
-0.0713382086940833
```

The subsequent operation

```python
ev = np.maximum(np.linalg.eigvalsh(R), 0.0)
```

then silently changes the spectrum before computing the determinant-equivalent quantity.

V41 separates the two objects:

- **legacy pairwise MI audit:** clamp only off-diagonal correlations;
- **shrinkage TC:** use a symmetric correlation matrix with exact unit diagonal and `slogdet((1-lambda)R + lambda I)`.

## Root cause 2 — entropy provenance mismatch

Applying the stated `min-max + L1` entropy function to the full-precision C76/C82 matrix gives:

```text
module_entropies =
[1.76112017, 1.81026288, 1.80041060, 1.23761073, 1.72059567,
 1.90585985, 1.66243892, 1.96522024, 1.84354886, 1.97729716]

H_total = 17.6843650849674 bits
```

This does not reproduce `19.7134`.

Therefore at least one of the following differs from the sealed narrative:

1. the backend entropy formula;
2. the parameter matrix used for the sealed calculation;
3. the numerical values persisted in the cycle;
4. the reported smoke-test output.

V41 does not choose among them without source evidence.

## Root cause 3 — C82 is a transition record, not yet a clean accumulation sample

The shown C82 creation payload did not include a persisted `parameter_matrix`. Therefore it should not be counted as a new raw observation solely from its scalar metrics.

Recommended lineage:

```text
C82 = HISTORICAL_TRANSITION
C83 = FIRST_RAW_VALID_ACCUMULATION_CYCLE
```

once `parameter_matrix`, `module_entropies`, `H_total`, `TC_shrink`, `lambda`, `p_permutation`, and `signal_tag` are persisted together.

## Chaos re-test under corrected V41 shrinkage

Applying the same `r=3.7`, three-step logistic transform to the C76/C82 matrix and then using the corrected shrinkage pipeline gives:

```text
C_shrink(chaos) = 0.1886343334720
permutation p   = 0.4067966016992
```

This does not support a surviving chaos signal under the corrected V41 shrinkage estimator.

The stronger historical statement "common logistic invariant measure causes positive correlation" should also be avoided: identical marginal distributions do not imply positive cross-module correlation.

## Claim-status repair

Use the following statuses without rewriting historical records:

```text
V40_SEAL                     = SUPERSEDED_BY_V41_AUDIT
C82                          = HISTORICAL_TRANSITION
C83_EXECUTION                = BLOCKED_METRIC_PROVENANCE
C33_C69_RAW_RECOMPUTATION    = NOT_COMPUTABLE
C70_C81_SIGNAL_CLAIM         = NO_SUPPORTED_SIGNAL
V19_NUMERIC_CONVERGENCE      = INVALIDATED
V41_CORRECTED_SHRINKAGE      = LOCAL_RECOMPUTATION_PASS
SCIENTIFIC_VALIDATION        = NOT_SUPPORTED
```

## Required gate before C83

1. Persist raw `parameter_matrix[10][5]` for every new cycle.
2. Persist `module_entropies[10]`, `H_total`, `TC_shrink`, `lambda`.
3. Persist `p_permutation`, permutation seed/count, and `signal_tag`.
4. Keep `tag` (regime/provenance) separate from `signal_tag`.
5. Keep rho clamp only in the legacy pairwise-MI audit.
6. Set correlation diagonal exactly to 1 for shrinkage.
7. Never zero negative eigenvalues silently.
8. Use `slogdet` on the shrunk correlation matrix and fail closed if sign <= 0.
9. Store formula hash / code version with each cycle.
10. Define the temporal observation unit before treating 30 cycles as `n=30`.
11. Do not automatically remove shrinkage at 30 cycles; require rank, conditioning, bootstrap stability, and dependence diagnostics.
12. Preserve V40 values as historical records marked `SUPERSEDED`, never overwrite them.

## Plugin Eval metric-pack shape

`monsterboy_aegis_modules/exochronos_metric_v41.py` emits only deterministic `checks[]` and `metrics[]`, matching the minimal custom-rubric output shape expected by Plugin Eval workflows.

Run:

```bash
python -m monsterboy_aegis_modules.exochronos_metric_v41 --self-test
python -m monsterboy_aegis_modules.exochronos_metric_v41
```

The self-test freezes the C76/C82 reference results and fails if they drift.

## Scientific ceiling

The repository's existing canonical governance already sets the global ceiling to `LAB_ONLY`, the production gate to `LOCKED`, and scientific validation to `NOT_SUPPORTED`. V41 preserves that ceiling.

**Final V41 verdict:**

```text
NO_DETECTABLE_SIGNAL
METRIC_PROVENANCE_REPAIR_REQUIRED
C83_BLOCKED_UNTIL_RAW_PERSISTENCE_AND_V41_CODE_LOCK
```
