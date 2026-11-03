# MONSTERBOY 4D HUNTER 020

Local evidence inventory and exact event capture for the MONSTERBOY 4D audit core.
Python 3.10+ and the standard library are sufficient.

The integrated core is the GATE002 3.1 correction. Blocks 1 and 2 retain their
original bytes. No external validation or official benchmark score is implied.

## Run local checks

From this folder:

```bash
python -m unittest -v test_MONSTERBOY4D_BLOCK2 test_MONSTERBOY4D_BLOCK3 test_MONSTERBOY4D_GATE002_REGRESSION tests.test_observatory.InventoryTests tests.test_observatory.CaptureTests
```

This selects 85 local tests. Nine additional OpenAI contract tests were run
offline before credential setup became available; live API activation awaits
an explicit key decision. No API key, live response or application log is
included in the source tree.

## Inventory the supplied archives

```bash
python -m mb4d_observatory inventory --source-root ./inputs --out ./new_inventory.json
```

Use a new output filename. Exit 2 preserves a `HOLD` report when references
are missing or inconsistent. Manifest checks count references, not independent
confirmations. CRC checks and newly computed hashes do not authenticate sources.
Unsupported and empty manifests cannot silently pass.

## Capture original application events

```bash
python -m mb4d_observatory capture --directory ./capture --payload ./receipt.bin --event-id anchor-001 --actor action-engine --action anchor-result --trace-id actual-trace-id --source-ref original-export
python -m mb4d_observatory export-capture --directory ./capture --out ./capture_input.json
python MONSTERBOY4D_MATH_METRIC_TOTAL_FINAL.py audit-input --input ./capture_input.json --out ./new_audit --run-id REAL-CAPTURE-001
```

Substitute actual trace metadata and original payload bytes. Source event time
and model visibility stay unknown unless explicitly supplied with timezones.
The capture observation time is the local observer's time. Clock synchronization
is a declaration, not authenticated proof. The optional reference digest must
come from a separately retained reference when used for a meaningful match.
The newly computed payload hash is never silently used as that reference.

Capture records are create-only. A changed record or payload cannot export
against its original local hash. An actor who rewrites every byte and every
hash still requires an external trust anchor to be detected.

## Qualification recorded on 3 November 2026

- Corrected core and regression tests: 66 passed.
- Inventory and event capture tests: 19 passed.
- OpenAI contract tests using synthetic transport: 9 passed; live requests: 0.
- Historical HUNTER 004/005/006/007/008/009/010/012/013: 171 passed.
- G013 source: 39 core checks and 8 adversarial scenarios passed.
- NEXUS fallback: three archived 100000-step simulations reproduced as Python
  objects, using their recorded time steps.
- Archive inventory: 25 input files, 19 ZIP archives, 315 member occurrences,
  285 matching manifest references covering 203 distinct payload hashes.
- Ten N2 input references remain missing from their supplied archive.

These families measure different properties and must not be combined into an
AI capability score. Known templates and same-author tests do not establish
independent validation. Official HumanEval/EvalPlus scores, GPU inference and
the historical 03:58 session anchor remain unverified.

## OpenAI boundary

`openai_review.py` contains the prepared optional Responses adapter. Any model
review stays `MODEL_PROPOSAL_UNVERIFIED` and cannot promote deterministic claims.
Incomplete outputs, refusals and invented evidence identifiers remain `HOLD`;
their response bytes are retained in the receipt. The secure API key decision
must be completed before activating this component.

Official reference consulted on 3 November 2026:
https://developers.openai.com/api/docs/guides/structured-outputs

The manual GitHub workflow runs only the 85 core, inventory and capture tests.
It sends no model requests and launches no GPU inference.
