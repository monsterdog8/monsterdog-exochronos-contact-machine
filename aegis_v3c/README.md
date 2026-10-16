# AEGIS V3C — PEP transactionnel à racine épinglée

Mission : `AEGIS_V3C_PIN_POLICY_SQLITE_INTEGRATION_003`
Mode : `EVIDENCE_FIRST | FAIL_CLOSED | NO_SELF_VALIDATION | LOCAL_ONLY`
Règle : `CLAIM <= EVIDENCE`.

Successeur de `original/pep_v3_transactional.py` (V3, octets vérifiés SHA-256) qui
réintègre les protections perdues de V2C **en plus** du registre SQLite de V3 :

| # | Protection | Origine | Implémentation |
|---|---|---|---|
| 1 | Racine de confiance épinglée | V2C (fix V3-C01) | empreinte SHA-256 de la clé exigée par `trust_root.pin` **et** par la politique ; toute discordance => 503 fail-closed |
| 2 | Autorisation indépendante du PEP | V2C (fix V3-C02..C05) | allowlist sujet × action × ressource, issuer autorisé, `policy_version` exacte, TTL et skew bornés |
| 3 | Registre nonce transactionnel | V3 | SQLite `nonce PRIMARY KEY`, `synchronous=FULL`, WAL, inter-processus |
| 4 | Schéma + types stricts | fix V3-C07 | enveloppe fermée (12 champs), types explicitement vérifiés (bool ≠ number), toute entrée hostile => 4xx contrôlé |
| 5 | Intégrité avant consommation | fix V3-C08 | `request_hash` et permissions validés **avant** le COMMIT du nonce : plus de burn-on-tamper |
| 6 | Événements distincts | fix V3-C09 | `PERMIT_CONSUMED` / `ACTION_ATTEMPTED` / `EFFECT_SIMULATED` ; `EFFECT_CONFIRMED` réservé et jamais émis |

## Frontières de confiance (jamais confondre)

```
SIGNATURE_VALID  !=  SIGNER_AUTHORIZED
PERMIT_CONSUMED  !=  EFFECT_COMPLETED
SIMULATED_ACTION !=  PHYSICAL_ACTION
DB_COMMIT        !=  EXTERNAL_EFFECT
```

## Exécution

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r aegis_v3c/requirements-v3c.txt
python aegis_v3c/tests/run_v3c_tribunal.py --tag run1   # 50 scénarios
python aegis_v3c/tests/run_v3c_tribunal.py --tag run2   # répétition locale
```

Serveur manuel (clé + pin + politique dans le cwd, voir `policy/pep_policy_v3c.template.json`) :

```bash
export AEGIS_POLICY_PATH=... AEGIS_KEY_PATH=... AEGIS_PIN_PATH=... AEGIS_DB_PATH=...
uvicorn pep_v3c_pinned:app --host 127.0.0.1 --port 8001
```

Variables d'environnement du PEP : `AEGIS_POLICY_PATH`, `AEGIS_KEY_PATH`,
`AEGIS_PIN_PATH`, `AEGIS_DB_PATH`, `AEGIS_TRUST_ROOT_PIN` (pin prioritaire).
Coutures de test **uniquement** si `AEGIS_TEST_MODE=1` : `AEGIS_FIXED_NOW`
(horloge figée), `AEGIS_FAULT_INJECT=after_consume_commit`, `AEGIS_FAULT_EXIT_CODE`.

## Spécification crash / PENDING / récupération / durabilité / idempotence

1. **Point de non-retour** : le COMMIT du nonce (`status=PENDING`) précède tout
   effet. At-most-once strict : le nonce ne sera jamais réutilisable.
2. **Crash après COMMIT, avant effet** : la ligne reste `PENDING`, seul
   `PERMIT_CONSUMED` est journalisé (observé en T21, exit 73). Tout réessai est
   refusé (`NONCE_REUSED`) — fail-closed : l'agent doit forger un nouveau permis.
3. **Récupération** : un état `PENDING` signifie « consommé, effet inconnu ». La
   réconciliation (rejouer l'effet métier via une clé d'idempotence métier, ou
   notifier l'opérateur) est **spécifiée mais non implémentée** — voir CE-5 du
   rapport. Aucun statut `PENDING` n'est jamais promu automatiquement.
4. **Durabilité** : `journal_mode=WAL`, `synchronous=FULL`. La durabilité testée est
   la mort de processus (kill/restart, T02/T19/A02) ; la coupure de courant n'est
   **pas** testée (pas d'environnement matériel dédié).
5. **Idempotence métier** : distincte de l'idempotence du nonce. Le PEP garantit
   at-most-once *de la tentative* ; l'idempotence de l'effet (clé métier
   `permit_id` côté système cible) est requise côté actionneur réel — hors périmètre
   LOCAL_ONLY.

## Effet réel

Aucun. Ce prototype n'implémente **aucun** canal d'effet externe (vérifié
statiquement et par test : T18). Le journal `effect_journal` est une simulation
locale explicitement étiquetée `SIMULATED_LOCAL_ONLY`. La promotion à
`EFFECT_CONFIRMED` exige un témoin externe authentifié : c'est précisément l'objet
du NEXT_GATE.

## Arborescence

```
aegis_v3c/
  original/pep_v3_transactional.py   # V3 historique — SHA-256 VERIFIÉ, lecture seule
  original/PROVENANCE.md             # provenance V2C/V3 et gaps
  pep_v3c_pinned.py                  # PEP V3C
  policy/pep_policy_v3c.template.json
  tests/harness.py                   # clés, forge, serveur loopback, workers
  tests/run_v3c_tribunal.py          # T01–T24 + F01–F10 + A01–A16 (50 scénarios)
  results/                           # résultats bruts, verdict machine, stdout
  REPORT_AEGIS_V3C.md                # rapport forensique
  SHA256SUMS.txt
  bench_workspace/                   # éphémère (généré, non versionné)
```
