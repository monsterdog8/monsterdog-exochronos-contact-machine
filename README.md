# monsterdog-exochronos-contact-machine
EXOCHRONOS — Fail-closed execution &amp; audit framework. Converts processes into verifiable evidence via logs, hashes, and replay. Pipeline: execution → observables → audit → replay → verdict. Rule: no claim without logs. Status: bootstrap, ready for first execution.

## AEGIS V3C

Le PEP transactionnel à racine épinglée (mission `AEGIS_V3C_PIN_POLICY_SQLITE_INTEGRATION_003`)
vit dans [`aegis_v3c/`](aegis_v3c/README.md) : code, banc adversarial 50 scénarios × 2
répétitions locales, résultats bruts et rapport forensique. Règle : `CLAIM <= EVIDENCE`.

## AEGIS V3D

Le témoin d'effet réel (mission `AEGIS_V3D_REAL_EFFECT_WITNESS_004`) vit dans
[`aegis_v3d/`](aegis_v3d/README.md) : effet OS réel borné, isolation UID
(aegis_pep / aegis_witness / aegis_agent), témoin séparé sans canal API,
contre-épreuves NEMESIS N01–N05 reproduites et corrigées, protocole de crash
C1–C4, régressions V3C 50/50 × 2. `PUBLIC_DEPLOYMENT = BLOCKED`.

## V41 audit reproduction

Use Python 3.11 or newer in a fresh virtual environment:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-audit.txt
python -m monsterboy_aegis_modules.exochronos_metric_v41 --self-test
python -m monsterboy_aegis_modules.exochronos_metric_v41
```

The strict detection cutoff is `p < 0.01` with the +1 permutation correction.
Runs with fewer than 100 permutations emit
`INSUFFICIENT_PERMUTATION_RESOLUTION`, a failing resolution check, and
`signal_tag=UNASSESSED`; they cannot support a no-signal conclusion.
A nonsignificant, resolution-capable result supports only a bounded
no-detectable/no-supported-signal conclusion, never NOISE by itself.
These checks are local audit evidence, not scientific validation.

## AEGIS V3E

Témoin indépendant et attestation (mission `AEGIS_V3E_INDEPENDENT_WITNESS_ATTESTATION_005`)
dans [`aegis_v3e/`](aegis_v3e/REPORT_FR.md) : manifeste gelé puis ancré avant exécution,
témoin POSIX sh distinct de l'auteur de conception, paquet RAW portable, attaques
d'attestation V1-V5, `REPLAY.sh` et verdict borné. `CLAIM <= EVIDENCE`.
