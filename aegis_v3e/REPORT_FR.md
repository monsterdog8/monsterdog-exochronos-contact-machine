# AEGIS V3E — TÉMOIN INDÉPENDANT & ATTESTATION

**Mission** : `AEGIS_V3E_INDEPENDENT_WITNESS_ATTESTATION_005`
**Date** : 2026-10-16 (UTC) · **Branche** : `arena/5e228b8f-monsterdog-exochronos-contact`
**Principe** : `CLAIM <= EVIDENCE` — « un seul reçu d'effet qu'un tiers peut vérifier sans me croire »

> Aucun PASS sans exécution. `REPORT != RAW` · `SHA256_MATCH != TRUTH` ·
> `UID_SEPARATION != AUTHOR_INDEPENDENCE` · `DB_COMMIT != EFFECT` ·
> `O_EXCL != POWER_LOSS_DURABILITY`.

---

## 0. ÉTAT FINAL OBLIGATOIRE

| Champ | Statut | Faits |
|---|---|---|
| EXECUTION_ENVIRONMENT | **OBSERVED** | Conteneur éphémère E2B (`e2b.local`, `/dev/vda`, recyclage inter-sessions observé) ; 3 UID de test sans privilège (999/997/996) ; provisioning minimal opt-in, préflighté, **chaque commande privilégiée journalisée** ; `/home` et dépôts intouchés ; aucune suppression récursive, aucun chmod global, aucune installation système |
| RAW_ARTIFACTS_OBSERVED | **OBSERVED** | `RAW_EVIDENCE/` : octets exacts des marqueurs, rapports bruts du témoin, stdout/stderr + exit codes, ACL/UID, permis signés (sans clé privée), politique + hash + pin, nonce/permit_id, états SQLite, versions, premiers essais et échecs, chaîne de reçus (22 entrées) |
| PROCESS_ISOLATION | **OBSERVED** | PEP uid 999 · témoin uid 997 · client uid 996 ; registre 0700 pep ; config root:root 0644 ; sondes EACCES journalisées |
| AUTHOR_INDEPENDENCE | **PARTIAL_NOT_FULL** | Témoin indépendant de conception (POSIX sh + coreutils, zéro code partagé, source épinglée `ec7da55c…`) + vérificateur externe (3ᵉ implémentation). Écrit par la même instance : `AUTHOR_INSTANCE_SEPARATED = NOT_PROVEN` |
| ACTION_EFFECT | **OBSERVED** | 1 effet réel unique : `marker-P-V3E.json` = **283 octets**, sha256 `e123024a5523152eb3bc4c14d65bdf259efa269eb37283311f2913ba2ea25c43` = octets **pré-calculés avant exécution**, confirmé par le témoin (euid 997) |
| ACL_ENFORCEMENT | **OBSERVED** | uid agent : `EACCES` effect/ + config/ ; registre illisible (famille D exécutée sous autorisation ciblée) |
| REPLAY_PERSISTENCE | **OBSERVED** | Rejeu → 403 `NONCE_REUSED` ; concurrence 8 → exactement 1 effet ; crash C1 → réessai 1 seul effet ; registre reconstruit → 502, 0 second effet (plancher `O_EXCL`) ; `REPLAY.sh` fourni |
| POWER_LOSS_DURABILITY | **NOT_EXECUTED** | `fsync(file)` + `fsync(dir)` faits (correctif V3D-004) ; aucun banc de coupure → interdiction de déclarer `POWER_LOSS_SAFE` |
| NEGATIVE_CONTROLS | **OBSERVED** | V1 REFUSED · V2 REFUSED · V3 REFUSED (ancre) · V4 AUCUN second effet · V5 UNKNOWN/HOLD |
| CLAIM_CEILING | `LOCAL_SINGLE_ACTION_REAL_EFFECT_WITNESSED_BY_DESIGN_SEPARATED_WITNESS_WITH_ANCHORED_PREREGISTRATION` | |
| SINGLE_NEXT_GATE | `AEGIS_V3F_AUTHOR_SEPARATED_WITNESS_AND_POWER_LOSS_006` | |
| PUBLIC_DEPLOYMENT | **BLOCKED** · TRUTH_STATUS = **OPEN** | |

**Veto critique** : aucun dans le périmètre observé. Un seul veto critique imposerait `HOLD`.
La conclusion la plus forte admissible reste bornée au périmètre observé.

---

## 1. PRÉ-ENREGISTREMENT ET ANCRE (correctif V3D-003)

`EXPERIMENT_FREEZE.json` fixe l'oracle, les cinq familles de contrôles, le refus
fail-closed, la racine de confiance et la déclaration de qui contrôle l'OS — **gelé
puis poussé AVANT toute exécution de test** :

| Élément | Valeur |
|---|---|
| Empreinte du freeze | `5a4aee5c06df8981bdbe537a7466655758b93d6b3fbf1ff648c107518e9dd8d7` |
| Ancre git | commit `c6a64294dfc7de550c9abace31de7084b317a9b2` |
| Horodatage serveur GitHub | **2026-10-16T22:59:50Z** (avant tout test) |
| Témoin (`witness_v3e.sh`) | `ec7da55cd40cb26a2192f2cb357c008f56a4b85429afa254dd942374cc4443fb` |

Un rollback du manifeste est **détecté** par le vérificateur (attaque V3 : `REFUSED`).

## 2. TÉMOIN DISTINCT DE L'AUTEUR

`INDEPENDENT_WITNESS_SOURCE/witness_v3e.sh` — implémentation **minimale POSIX sh +
coreutils** (`sha256sum`, `wc`, `find`, `stat`, `date`, `id`) : elle n'importe ni le PEP
Python ni `effect_witness.py` V3D. Elle ouvre les fichiers du répertoire d'effet,
recalcule octets/longueur/SHA-256, compare à l'assertion d'entrée **pré-enregistrée**,
et déclare son **UID effectif (997)**, l'**empreinte de sa propre source** et son
**identifiant de run**. Codes : `0 VALID · 1 INVALID · 2 usage · 3 UNAVAILABLE`.
`tests/verify_bundle.py` (troisième implémentation) recalcule tout depuis les octets
RAW et refuse toute incohérence. `effect_witness.py` et le corps HTTP ne sont jamais
des oracles.

## 3. RÉSULTATS — TRIBUNAL DÉCISIF (run4, 18/18 PASS_LOCAL, EXIT=0)

**Familles de contrôles (gelées avant exécution)**

| Famille | Résultat brut |
|---|---|
| (A) ALLOW → marqueur unique | 200 ; `marker-P-V3E.json` 283 octets ; sha256 `e123024a…` = pré-calcul ; témoin `VALID` (euid 997) |
| (B) interdits → zéro marqueur | X1 champ `system_eval`→422 · X2 `admin.delete`→403 · X3 mauvaise clé→403 · X4 nonce altéré→403 · X5 ressource hors allowlist→403 · X6 révocation (sans `agent-alpha`)→403 ; **0 marqueur** ; témoin confirme l'absence à chaque fois |
| (C) replay/restart/concurrence | rejeu→403 `NONCE_REUSED` ; 8 clients simultanés→**exactement 1×200**, 1 seul marqueur ; rejeu après restart→403 |
| (D) accès direct uid agent | `touch effect/…`→**EACCES** ; registre SQLite→**OperationalError/EACCES** ; `touch config/…`→**EACCES** |
| (E) crash C1–C4 (exit 73) | C1 `NO_CONSUMPTION` → réessai 200 (1 effet) · C2 `CONSUMED_NO_ATTEMPT` · C3 `ATTEMPTED_NO_EFFECT` · C4 `EFFECT_PRESENT_DB_INCOMPLETE` (marqueur présent, DB incomplète, réessai 403) |

**Attestation — mécanismes attaqués (V1–V5)**

| Attaque | Observé | Verdict |
|---|---|---|
| V1 altération d'1 octet du marqueur | témoin `INVALID` exit 1 (MISMATCH) | **REFUSED** |
| V2 rapport de témoin substitué (faux VALID) | vérificateur : `claimed 0000… but RAW bytes give e123024a…/283` | **REFUSED** |
| V3 rollback du manifeste gelé | `freeze hash 2fee5f85… != anchor 5a4aee5c…` | **REFUSED** |
| V4 registre reconstitué + ancien permis signé | rc=502 `EFFECT_UNCONFIRMED` ; marqueurs inchangés (plancher `O_EXCL`) | **AUCUN second effet** |
| V5 témoin indisponible | `UNAVAILABLE` exit 3 | **UNKNOWN/HOLD** (jamais CONFIRMED par défaut) |

**Vérification du paquet** : `VERIFY_VERDICT=VERIFIED` (exit 0) — ancre OK, chaîne de
reçus 22 entrées sans rupture, 5 copies RAW de marqueurs recalculées, rapports du témoin
concordants avec les octets.

## 4. PAQUET RAW PORTABLE (`RAW_EVIDENCE/`)

- `markers/` — **octets exacts** des marqueurs (copies vérifiables) ;
- `witness_reports/` — rapports **bruts** du témoin (stdout + exit codes) ;
- `agent_receipts/` — stdout/stderr/exit de chaque appel client (uid 996) ;
- `privileged_journal.jsonl` + `PROVISION_JOURNAL.jsonl` — chaque commande sudo ;
- `acl_uids.txt` — ACL/UID constatés (`ls -ln`) ;
- `permits/` — entrées signées (clé privée **exclue**) ;
- `policy/` — politique + sha256 + clé publique + pin ;
- `db_states/` — états SQLite (instantanés) ;
- `versions/` — empreintes des sources + version Python ;
- `receipts_chain.jsonl` — chaîne de reçus liés par `prev_hash` ;
- `first_attempt_failed/`, `run2_partial/`, `run3_reset_failure/` — **premier essai,
  échecs et corrections de fixture** conservés (exigence §4 du prompt) ;
- `precomputed_expectations.json` — marqueurs attendus calculés **avant** exécution.

Tous les liens entre artefacts sont vérifiables par `tests/verify_bundle.py` et `REPLAY.sh`.

## 5. HÉBERGEMENT, PROVISIONING, CONFORMITÉ (V3D-001)

Autorisation conditionnelle de l'utilisateur respectée à la lettre :
comptes de test uniquement · tout sous `/tmp/aegis_v3e_sandbox` · **préflight avant
toute modification** (identité, comptes, chemins, ACL, isolation) · aucune écriture
dans `/home` ni les dépôts · **aucune suppression récursive** (archivage par `mv`) ·
**aucun chmod global** · **aucune installation système** · aucune publication ·
**chaque commande privilégiée journalisée** avec sortie et code de sortie · arrêt
immédiat si l'isolation n'est pas vérifiable (critère appliqué : `hostname=e2b.local`
+ éphéméralité observée) · actions limitées aux marqueurs de test non destructifs.

**Transparence** : la copie locale des libs Python a échoué (environnement recyclé
entre les sessions ; `~/.local` vidé). Les dépendances (fastapi, uvicorn, httpx,
cryptography) ont été installées **uniquement** dans `/tmp/aegis_v3e_sandbox/pylibs`
depuis pypi.org (hôte autorisé), journalisé — aucun paquet système, aucune
modification de l'hôte.

## 6. CRASH ≠ DURABILITÉ (V3D-004)

- Crash processus (`os._exit(73)` / SIGKILL) **≠** panne électrique.
- `fsync(file)` **≠** `fsync(dir)` : `pep_v3e_effect.py` fait les deux (successeur de
  `pep_v3d_effect.py`, **V3D préservé inchangé**).
- `POWER_LOSS_DURABILITY = NOT_EXECUTED` — aucun essai de coupure ; interdiction de
  déclarer `POWER_LOSS_SAFE` ; marqueur observé ≠ preuve de durabilité au reboot.

## 7. NOTES D'AUDIT — CORRECTIONS DE FIXTURE (aucune exigence assouplie)

1. **run1** : POST A1 réellement exécuté (marqueur + témoin VALID) mais reçu non écrit
   (bug de chemin de sortie agent) — conservé dans `first_attempt_failed/` comme
   premier essai exigé.
2. **run2** : la fermeture de thread C2 rejouait l'enveloppe A1 déjà consommée
   (`NONCE_REUSED`×8) ; une allowlist **vide** est rejetée par le PEP
   (`503 PEP_POLICY_INVALID` — fail-closed, zéro effet) — fixture affinée : allowlist
   non vide sans `agent-alpha` → 403 par sujet. Critère inchangé (4xx + zéro marqueur).
3. **run3** : `mv` du registre raté (`test -e` utilisateur sur dossier 0700) et
   collision de sous-chaîne `P-V3E-C1` ⊂ `P-V3E-C12` dans la déduction d'état —
   corrigés (correspondance exacte par colonne).
4. **run4 = exécution décisive 18/18**, `EXIT=0`.

## 8. PLAFOND ET PROCHAIN GATE

`CLAIM_CEILING = LOCAL_SINGLE_ACTION_REAL_EFFECT_WITNESSED_BY_DESIGN_SEPARATED_WITNESS_WITH_ANCHORED_PREREGISTRATION`

Reste hors garantie : séparation d'**auteur** (même instance), root / rollback
privilégié, coupure électrique, multisite, rotation de clés. `PUBLIC_DEPLOYMENT=BLOCKED`.
**NEXT_GATE unique** : `AEGIS_V3F_AUTHOR_SEPARATED_WITNESS_AND_POWER_LOSS_006`
(témoin révisé par un auteur/runner réellement distinct + banc de durabilité coupure
alimentation + ancre immuable tierce). `TRUTH_STATUS = OPEN`.

---

## 9. COMMANDES DE REJEU (toutes locales)

```bash
bash aegis_v3e/tests/setup_sandbox_v3e.sh      # préflight + provisioning journalisé (opt-in)
PYTHONPATH=/tmp/aegis_v3e_sandbox/pylibs python3 aegis_v3e/tests/provision_config_v3e.py
PYTHONPATH=/tmp/aegis_v3e_sandbox/pylibs python3 aegis_v3e/tests/run_v3e_tribunal.py
PYTHONPATH=/tmp/aegis_v3e_sandbox/pylibs python3 aegis_v3e/tests/verify_bundle.py \
  --bundle aegis_v3e/RAW_EVIDENCE --freeze aegis_v3e/EXPERIMENT_FREEZE.json \
  --anchor-sha256 "$(cat aegis_v3e/ANCHOR.txt)" \
  --witness-source aegis_v3e/INDEPENDENT_WITNESS_SOURCE/witness_v3e.sh
# ou intégralement :
bash aegis_v3e/REPLAY.sh
```

Empreintes : `aegis_v3e/SHA256SUMS.txt` · ancre : `aegis_v3e/ANCHOR_RECORD.json`.
