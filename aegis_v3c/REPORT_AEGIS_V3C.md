# MONSTERDOG AEGIS V3C — Rapport forensique

**MISSION_ID :** `AEGIS_V3C_PIN_POLICY_SQLITE_INTEGRATION_003`
**MODE :** `EVIDENCE_FIRST | FAIL_CLOSED | NO_SELF_VALIDATION | LOCAL_ONLY`
**DATE :** 2026-10-16 (UTC)
**RÈGLE :** `CLAIM <= EVIDENCE`
**STATUT :** `TRUTH_STATUS = OPEN`

---

## 0 — Résumé exécutif

Le successeur V3C (`pep_v3c_pinned.py`) intègre **simultanément** la racine de
confiance épinglée de V2C, la politique d'autorisation indépendante du PEP et le
registre SQLite transactionnel de V3. Il a été exécuté contre **50 scénarios**
locaux (les 24 contre-épreuves NEMESIS T01–T24, 10 fixtures fondatrices F01–F10,
16 attaques adversariales A01–A16), rejoués **deux fois sur le même hôte**.

| Métrique | Run 1 | Run 2 |
|---|---|---|
| Scénarios exécutés | 50 | 50 |
| PASS_LOCAL | **50** | **50** |
| FAIL | 0 | 0 |
| Répétitions indépendantes | 0 (même hôte, non indépendant) | idem |

**Les 9 régressions critiques du dossier NEMESIS (T07–T11, T13, T15, T16, T20,
T23, T24) sont réfutées en exécution, pas en intention.** Le CLAIM_CEILING
demeure plafonné : `LOCAL_EXECUTED_SIMULATOR`. Aucune permission OS réelle, aucun
effet externe, aucun déploiement — interdits par l'ordre de mission.

---

## 1 — Matrice T01–T24 : baseline V3 (dossier NEMESIS) vs V3C OBSERVED

Baseline = transcription du dossier NEMESIS (24 scénarios, 2 répétitions même
hôte). V3C = observations brutes de `results/EXPERIMENT_RESULTS.json`
(exécution loopback HTTP 127.0.0.1, interpréteurs Python distincts pour la
concurrence).

| ID | Scénario | V3 baseline | V3C OBSERVED | Évolution |
|---|---|---|---|---|
| T01 | Premier permis valide | 200 | 200 + corps honnête (sans `executed`) | ✅ |
| T02 | Rejeu après relance | 403 | 403 NONCE_REUSED avant **et** après restart | ✅ |
| T03 | 8 processus concurrents | 1×200 / 7×403 | 1×200 / 7×403 NONCE_REUSED | ✅ |
| T04 | Expiration dépassée | 403 | 403 PERMIT_EXPIRED | ✅ |
| T05 | Audience incorrecte | 403 | 403 WRONG_AUDIENCE | ✅ |
| T06 | Signature altérée | 403 | 403 INVALID_SIGNATURE | ✅ |
| T07 | Signature non hex | **500** | 400 INVALID_FIELD_FORMAT | ✅ corrigé |
| T08 | admin.delete signée | **200** | 403 ACTION_FORBIDDEN | ✅ corrigé |
| T09 | Issuer non autorisé | **200** | 403 ISSUER_FORBIDDEN | ✅ corrigé |
| T10 | Ancienne policy_version | **200** | 403 POLICY_VERSION_MISMATCH | ✅ corrigé |
| T11 | Req. altérée puis vraie | 403 / 403 (**nonce brûlé**) | 403 REQUEST_TAMPERED **puis 200** | ✅ corrigé |
| T12 | Action modifiée | 403 | 403 REQUEST_TAMPERED | ✅ |
| T13 | Clé publique substituée | **200** | 503 PEP_TRUST_ROOT_PIN_MISMATCH | ✅ corrigé |
| T14 | Clé manquante | 500 | 503 PEP_TRUST_ROOT_UNAVAILABLE | ✅ corrigé |
| T15 | Expiration en chaîne | **500** | 400 INVALID_FIELD_TYPE | ✅ corrigé |
| T16 | Claim erroné signé | **200** | 400 PERMIT_SCHEMA_VIOLATION | ✅ corrigé |
| T17 | Nonce modifié | 403 | 403 INVALID_SIGNATURE | ✅ |
| T18 | Effet réel | `executed=true` **trompeur** | `effect_confirmed=false`, 3 événements distincts, 0 canal externe | ✅ corrigé |
| T19 | Persistance (2e paire) | 200 / 403 | 200 / 403 NONCE_REUSED | ✅ |
| T20 | policy_version absente | **200** | 400 PERMIT_SCHEMA_VIOLATION | ✅ corrigé |
| T21 | Crash après COMMIT | PENDING / 403 | exit 73, PENDING, seul PERMIT_CONSUMED, réessai 403 | ✅ |
| T22 | Borne d'expiration | 403 | 403 à `now == expires_at` exactement ; 200 juste avant | ✅ |
| T23 | issued_at +24 h | **200** | 403 FUTURE_ISSUED_AT | ✅ corrigé |
| T24 | TTL ~1 an | **200** | 403 TTL_EXCEEDED | ✅ corrigé |

## 2 — Fixtures F01–F10 et attaques A01–A16 (reconstituées)

- **F01–F10** : canon JSON (indépendance d'ordre), roundtrip Ed25519, épinçage
  OK, sémantique allowlist (5 cas), schéma strict, bornes temporelles au
  milligramme (5 cas, horloge figée : expire exclusif, skew=60 s, TTL=300 s),
  unicité ledger, ordre des événements, contrat de réponse exact, fail-closed sur
  pin substitué. **10/10 PASS_LOCAL.**
- **A01–A16** : rejeu même processus, rejeu trans-redémarrage, pression
  concurrente 16 interpréteurs (1×200 / 15×403), collision de nonce entre deux
  permis distincts, permis forgé par clé attaquante, permis sans signature,
  usurpation d'issuer sous clé non épinglée, altération de `expires_at`,
  altération requête sans burn, confusion de types (bool/null/chaîne),
  canonisation (JSON réordonné accepté, homoglyphe refusé, ressource altérée =>
  REQUEST_TAMPERED), injection SQL dans le nonce (charset + table intacte),
  traversée `../` (refus précoce), usurpation de sujet `root`, rétrogradation de
  politique, champ géant + imbriquation profonde. **16/16 PASS_LOCAL.**

## 3 — Verdicts par gate (un verdict par gate)

| Gate | Scénarios | Verdict |
|---|---|---|
| `GATE_TRUST_ROOT_PIN` | T13 T14 F03 F10 A05 | **PASS_LOCAL** |
| `GATE_PEP_POLICY_AUTHZ` | T08 T09 T10 T20 F04 A14 A15 | **PASS_LOCAL** |
| `GATE_NONCE_PERSISTENCE` | T02 T19 A01 A02 | **PASS_LOCAL** |
| `GATE_CONCURRENCY` | T03 A03 A04 F07 | **PASS_LOCAL** |
| `GATE_TEMPORAL_SEMANTICS` | T04 T22 T23 T24 F06 | **PASS_LOCAL** |
| `GATE_CRYPTO_BINDING` | T05 T06 T17 A07 A08 A11 F02 | **PASS_LOCAL** |
| `GATE_STRICT_PARSING` | T07 T15 T16 A06 A10 A12 A13 A16 F05 | **PASS_LOCAL** |
| `GATE_BURN_ON_TAMPER` | T11 T12 A09 | **PASS_LOCAL** |
| `GATE_EFFECT_SEMANTICS` | T18 F09 | **PASS_LOCAL** (simulation honnête uniquement) |
| `GATE_CRASH_RECOVERY` | T21 F08 | **PASS_LOCAL** (fail-closed PENDING) |
| `GATE_REAL_OS_PERMISSIONS` | — | **NOT_EXECUTED** (interdit par ordre de mission) |
| `GATE_PRODUCTION_DEPLOYMENT` | — | **NOT_EXECUTED** (interdit par ordre de mission) |

## 4 — Événements et sémantique d'effet (T18 / T21)

État final de la base run 1 : `db_status_counts = {EFFECT_SIMULATED: 11, PENDING: 1}`,
`db_event_counts = {PERMIT_CONSUMED: 12, ACTION_ATTEMPTED: 11, EFFECT_SIMULATED: 11}`.

- `EFFECT_CONFIRMED` : **0 occurrence** — le vocabulaire existe, l'émission est
  réservée à un canal d'effet externe authentifié qui n'existe pas ici.
- Le `PENDING` unique est celui du crash injecté T21 : consommé, effet inconnu,
  jamais réutilisé, jamais promu automatiquement (fail-closed).
- Vérification statique : `pep_v3c_pinned.py` ne contient `os.system`, `os.popen`,
  `subprocess`, `urllib`, `requests.`, ni `socket.socket` (observé dans T18).
- La réponse HTTP ne contient jamais `executed` ; elle porte
  `permit_consumed / action_attempted / effect_status=SIMULATED_LOCAL_ONLY /
  effect_confirmed=false`.

## 5 — Contre-exemples non résolus (assumés)

| ID | Contre-exemple | État |
|---|---|---|
| CE-1 | **Split-brain multi-nœud** : SQLite n'est pas un consensus distribué ; deux PEP avec des bases divergentes ré-ouvrent le rejeu | NON RÉSOLU — exige PostgreSQL/Redis/consensus (hors LOCAL_ONLY) |
| CE-2 | **Vérité des claims / chaîne Core** : un permis signé ne rend jamais un énoncé vrai ; V3C refuse le contenu non attesté au schéma, mais aucun oracle n'existe | NON RÉSOLU — chaîne Core authentifiée hors périmètre |
| CE-3 | **Source d'horloge** : `time.time()` est fiable en local ; en production la fiabilité NTP conditionne les bornes TTL/skew | NON RÉSOLU — durcissement horloge non testé |
| CE-4 | **Amorçage du pin/policy** : un attaquant remplaçant simultanément clé + pin + politique contrôle le PEP ; l'épinglage ne protège que contre la substitution partielle | NON RÉSOLU — provisionnement hors bande requis (config management, HSM) |
| CE-5 | **Récupération des PENDING** : la réconciliation métier (effet inconnu) est spécifiée, pas implémentée | NON RÉSOLU — voir § crash du README |
| CE-6 | **Rotation de clé sans interruption** : non testée ; une rotation implique nouveau pin + nouvelle politique + chevauchement maîtrisé | NON RÉSOLU |

## 6 — Limites de portée (plafond de preuve)

- **LOCAL_ONLY** : loopback 127.0.0.1 uniquement. Aucune cible OS réelle, aucune
  permission système vérifiée, aucun réseau externe, aucune publication.
- **Répétitions non indépendantes** : 2 runs sur le même hôte, mêmes sources —
  répétabilité locale, **pas** de réplication indépendante par un tiers.
- **Environnement** : Python 3.11.2, Linux x86_64, FastAPI 0.143.3,
  cryptography 50.0.2, httpx 0.28.1. TestClient ASGI pour les fixtures unitaires,
  serveur uvicorn réel pour T01–T24 et attaques.
- **Le simulateur n'est pas le système** : `SIMULATED_ACTION != PHYSICAL_ACTION`.

## 7 — Provenance

- **V3** : `original/pep_v3_transactional.py` — **SHA-256 `e02355ae…804df`
  reproduit exactement** (3843 octets), concordant avec le registre NEMESIS.
  Octets historiques authentifiés, lecture seule.
- **V2C** : zip `AEGIS_V2C_CYCLE1_TRUST_ROOT_EVIDENCE.zip` **non disponible** —
  gap de provenance documenté (`original/PROVENANCE.md`). Ses deux protections
  (pin externe + allowlist) sont réimplémentées, ses octets ne sont pas
  prétendus préservés.
- **Listes F/A** : reconstituées (les listes historiques exactes ne sont ni dans
  le dépôt ni dans les PDFs) — statut `RECONSTRUCTED_LOCAL_LISTS`.
- Empreintes de tous les artefacts : `SHA256SUMS.txt`.

## 8 — Observations de méthode (transparence)

1. Un `NameError` interne (`CODE_FUTURE_ISSUED_AT`) a été **détecté par ce banc**
   au run préliminaire (T23/F06 en 500 `INTERNAL_ERROR`), corrigé, puis
   re-exécuté. Les fichiers `results/` ne contiennent que les runs post-correction ;
   l'incident est consigné ici, il démontre que le filet fail-closed fonctionne
   (aucune fuite de trace, aucun effet) mais aussi qu'un 500 peut masquer un bug —
   exactement l'enseignement de NEMESIS T07/T15.
2. EXPECTED est figé dans le code du runner avant exécution ; OBSERVED provient
   des réponses HTTP et de lectures SQLite **externes** au processus PEP.

---

## 9 — Tribunal V3C

```
EXECUTIVE_STATE:            V3C_LOCALLY_EXECUTED

SOURCE_INVENTORY:           pep_v3c_pinned.py, original/pep_v3_transactional.py (HASH_VERIFIED),
                            tests/run_v3c_tribunal.py, tests/harness.py, policy template

ARCHITECTURE:               ASYMMETRIC_CRYPTO + PINNED_TRUST_ROOT + INDEPENDENT_PEP_POLICY
                            + ACID_TRANSACTIONAL_LEDGER + STRICT_ENVELOPE_SCHEMA

TRUST_BOUNDARIES:           SIGNATURE_VALID != SIGNER_AUTHORIZED
                            PERMIT_CONSUMED != EFFECT_COMPLETED
                            SIMULATED_ACTION != PHYSICAL_ACTION

IMPLEMENTED_COMPONENTS:     DURABLE_NONCE_REGISTRY
                            STRICT_EXPIRATION_SEMANTICS (exclusive)
                            AT_MOST_ONCE_ENFORCEMENT (fail-closed)
                            PINNED_TRUST_ROOT (clé + pin fichier + politique)
                            PEP_ALLOWLIST (subject x action x resource)
                            STRICT_IDENTITY (issuer, audience, policy_version)
                            TTL_AND_SKEW_BOUNDS
                            BURN_ON_TAMPER_REMOVED (integrite avant consommation)
                            DISTINCT_EVENT_STREAM (PERMIT_CONSUMED / ACTION_ATTEMPTED /
                            EFFECT_SIMULATED ; EFFECT_CONFIRMED jamais emis)

EXECUTED_TESTS:             50 scenarios x 2 local repetitions = 100 executions
                            T01-T24 + F01-F10 + A01-A16, runner + raw logs

ADVERSARIAL_FAILURES:       NONE_IN_TESTED_SCOPE (0/50 fail aux deux runs)

PROVENANCE_GAPS:            V2C_BYTES_NOT_AVAILABLE
                            HISTORICAL_FIXTURE_ATTACK_LISTS_RECONSTRUCTED

PERMISSION_GATES:           CRYPTOGRAPHIC + DURABLE_STATE + INDEPENDENT_POLICY

SECURITY_LIMITATIONS:       CE-1 split-brain, CE-2 oracle de verite, CE-3 horloge,
                            CE-4 bootstrap pin/policy, CE-5 recovery PENDING,
                            CE-6 rotation de cle — voir section 5

CLAIM_CEILING:              LOCAL_EXECUTED_SIMULATOR

NEXT_GATE:                  AEGIS_V3D_REAL_EFFECT_WITNESS_004

TRUTH_STATUS:               OPEN
```

**Message au labo MONSTERDOG :** le XFAIL multi-processus est enterré en
exécution, pas seulement en théorie — 8 puis 16 interpréteurs réels, redémarrages
de processus, crash injecté après COMMIT. Les deux régressions de confiance
(T13, T08) qui avaient raisonnablement mis V3 sous SECURITY_HOLD sont réfutées
localement. Mais SQLite ne sauve personne d'un pin bootstrap compromis, d'un
split-brain ou d'un effet réel non témoigné : le plafond reste
`LOCAL_EXECUTED_SIMULATOR` et le NEXT_GATE unique est le témoin d'effet réel.

`CLAIM <= EVIDENCE. 𓂀 Ω∞`
