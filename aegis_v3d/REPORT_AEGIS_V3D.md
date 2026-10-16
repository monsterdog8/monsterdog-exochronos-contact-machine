# MONSTERDOG AEGIS V3D — Rapport forensique

**MISSION_ID :** `AEGIS_V3D_REAL_EFFECT_WITNESS_004`
**DATE :** 2026-10-16 (UTC)
**RÈGLE :** `CLAIM <= EVIDENCE` — un 200 HTTP n'est pas une preuve d'effet ;
une ligne SQLite n'est pas une preuve d'effet OS.
**STATUT :** `TRUTH_STATUS = OPEN`

---

## 0 — Verdicts obligatoires (format imposé par l'ordre V3D)

```
REAL_EFFECT              = OBSERVED
OS_PERMISSION_BOUNDARY   = OBSERVED
RAW_WITNESS              = OBSERVED
DB_ANTI_ROLLBACK         = PROVEN_SCOPE_ONLY
CLAIM_CEILING            = LOCAL_SINGLE_ACTION_REAL_EFFECT_WITNESSED
PUBLIC_DEPLOYMENT        = BLOCKED
```

Justification par verdict :

- **REAL_EFFECT = OBSERVED** — D01 : sous `aegis_pep`, création exclusive
  (`O_CREAT|O_EXCL` + fsync) de `effect/marker-P-D1.json`, contenu canonique
  intégré. Observé par le témoin (uid 997) : taille, inode, SHA-256
  `965d1417…deaa`, `content_digest` valide ; relecture admin concordante.
  **La confirmation ne vient ni de l'API ni de SQLite.**
- **OS_PERMISSION_BOUNDARY = OBSERVED** — D11 : l'UID `aegis_agent` obtient
  `EACCES` à la création (`marker-EVIL.json`), `EACCES` à la suppression du
  marqueur, `OperationalError` (registre inaccessible) au rollback ; N04 :
  `EACCES` sur les 3 fichiers de config (clé, pin, politique).
- **RAW_WITNESS = OBSERVED** — D18 : 100 % des marqueurs observés ont un digest
  témoin == digest relecture indépendante ; rapport JSON horodaté dans
  `witness/` (0700, hors contrôle du PEP) ; oracle = `OS_OPEN_READ_SHA256`.
- **DB_ANTI_ROLLBACK = PROVEN_SCOPE_ONLY** — N05 : rollback agent **bloqué OS** ;
  rollback privilégié (propriétaire/root) **démontré possible** puis **détecté**
  (tête de chaîne `b5400ae6…` → `cb164645…`, `chain_regression_detected=true`) ;
  et même après rollback DB privilégié, l'effet n'est PAS rejouable
  (`502 EFFECT_UNCONFIRMED`) : le fichier marqueur `O_EXCL` constitue un
  **deuxième étage anti-rejeu**. Un rollback complet DB **et** système de
  fichiers par un attaquant privilégié reste possible — hors périmètre, assumé.
- **CLAIM_CEILING ≤ OBSERVED_EVIDENCE** — plafonné à une action réelle unique,
  locale, non destructive, témoin séparé **écrit par le même modèle** (voir §5).
- **PUBLIC_DEPLOYMENT = BLOCKED** — aucune publication, aucun réseau externe,
  aucun paiement, aucune donnée privée, aucune mutation de production.

---

## 1 — Reproduction des 5 contre-épreuves NEMESIS (N01–N05)

`tests/run_n01_n05.py` — Partie A sur **V3C préservé** (chargé sans modification),
Partie B sur V3D dans le bac OS. JSON brut : `results/N01_N05_RESULTS.json`.

| ID | Constat NEMESIS | V3C (RECOMPUTED) | V3D (OBSERVED) | Qualification |
|---|---|---|---|---|
| N01 | `system_eval` accepté silencieusement | **200** ✅ reproduit | **422** `extra_forbidden` | `FIXED` |
| N02 | 2 permis, même `permit_id` : 200/200 | **200/200** ✅ reproduit | **200 / 403 PERMIT_ID_REUSED** | `FIXED` |
| N03 | révocation de politique ignorée | **200** après modification ✅ reproduit | **403 ACTION_FORBIDDEN** dès la requête suivante | `FIXED` |
| N04 | remplacement clé+pin+politique => 200 | **200** ✅ reproduit | agent : **EACCES ×3** (config root-owned) ; PEP sain (`trust_root=OK`) | `SCOPE_MOVED_TO_OS` |
| N05 | rollback registre => rejeu 200 | **200** ✅ reproduit | agent : rollback bloqué (OS) + replay **403 NONCE_REUSED** ; rollback privilégié démontré + détecté (chaîne) + effet non rejouable (`502`, O_EXCL) | `LAYERED` |

**5/5 REPRODUCED sur V3C — 5/5 qualifiés sur V3D.** Les constats de NEMESIS
sont donc confirmés en exécution, pas seulement admis.

## 2 — Banc décisif V3D (D01–D18) — 18/18 PASS_LOCAL

`tests/run_v3d_tribunal.py` — JSON brut : `results/V3D_DECISIVE_RESULTS.json`.

| ID | Scénario | Résultat OBSERVED |
|---|---|---|
| D01 | ALLOW signé + nonce neuf | 200 + marqueur matérielisé + **témoin CONFIRMED** (digest concordant, uid 997) |
| D02–D06 | X1–X5 : signature invalide, clé substituée, `admin.delete`, chemins interdits (4 cas), expiré | 4xx avant effet ; **0 marqueur** |
| D07 | Témoin des absences | 8 fichiers négatifs confirmés absents par lecture OS |
| D08 | X6 `system_eval` | 422 (enveloppe fermée) |
| D09 | X7 `permit_id` réutilisé | 200 puis 403 `PERMIT_ID_REUSED` ; un seul marqueur |
| D10 | X8 révocation à chaud | 200 avant ; **403 ACTION_FORBIDDEN** après |
| D11 | X9/X10 frontière OS | `EACCES` création, `EACCES` suppression, `OperationalError` registre ; marqueur intact |
| D12 | Concurrence 8 clients (UID agent) | 1×200 + 7×403 ; **exactement 1 `EFFECT_MATERIALIZED`** ; témoin CONFIRMED |
| D13 | Rejeu après redémarrage PEP | 403 `NONCE_REUSED` ; aucun second marqueur |
| D14 | **C1** crash avant COMMIT | exit 73 ; `NO_CONSUMPTION` ; réessai **200** ; **exactement un** effet (`CONFIRMED`) |
| D15 | **C2** crash après COMMIT | exit 73 ; `CONSUMED_NO_ATTEMPT` (PENDING) ; réessai 403 ; aucun marqueur |
| D16 | **C3** crash après tentative | exit 73 ; `ATTEMPTED_NO_EFFECT` ; réessai 403 ; aucun marqueur |
| D17 | **C4** crash après effet | exit 73 ; **`EFFECT_PRESENT_DB_INCOMPLETE`** (témoin PRÉSENT, DB incomplète) ; réessai 403 |
| D18 | RAW_WITNESS | digest témoin == relecture admin sur 100 % des fichiers |

Les **4 états distincts** exigés (PENDING / ATTEMPTED / CONFIRMED / UNKNOWN→
spécialisations `*_NO_*` et `EFFECT_PRESENT_DB_INCOMPLETE`) sont observés
séparément, sans invention : chaque état est un couple (événements DB, témoin).

## 3 — Régressions V3C (aucun sous-ensemble vert)

`tests/run_v3d_regression.py` — `results/REGRESSION_RESULTS.json` :

| Direction | Résultat | Exit |
|---|---|---|
| suite V3C (50 scénarios) vs **code V3C préservé** | **50/50 PASS_LOCAL** | 0 |
| suite V3C (50 scénarios) vs **PEP V3D** (wrapper, sources V3C intactes) | **50/50 PASS_LOCAL** | 0 |

Vérification d'intégrité : `sha256sum -c` sur `aegis_v3c/SHA256SUMS.txt` →
**toutes les entrées historiques OK** (`pep_v3_transactional.py` = `e02355ae…`,
run1/run2 intacts). Seuls des fichiers de résultats **nouveaux** (tags
`v3d_reg_*`) ont été ajoutés — aucune écriture rétroactive.

## 4 — Commandes et exit codes (exécution réelle)

| Commande | Exit | Preuve |
|---|---|---|
| `bash tests/setup_sandbox.sh` | 0 | users uid 996/997/999, bac `/tmp/aegis_v3d_sandbox` |
| `python tests/run_n01_n05.py` | **0** | `results/N01_N05_STDOUT.txt`, `N01_N05_RESULTS.json` |
| `python tests/run_v3d_tribunal.py` | **0** | `results/V3D_DECISIVE_STDOUT.txt`, `V3D_DECISIVE_RESULTS.json` |
| `python tests/run_v3d_regression.py` | **0** | `results/REGRESSION_STDOUT.txt`, `REGRESSION_RESULTS.json` |

Environnement : Python 3.11.2, Linux x86_64, FastAPI 0.143.3,
cryptography 50.0.2, uvicorn loopback 127.0.0.1 uniquement.

## 5 — Limites et transparence (part du plafond)

1. **Le témoin est indépendant du PEP et de l'API, mais PAS du modèle** :
   `effect_witness.py` a été écrit par la même instance qui a écrit le PEP.
   La séparation processus/UID/fichiers est réelle ; l'**indépendance
   d'auteur** ne l'est pas. C'est précisément la preuve unique qui peut
   élever le plafond (§6).
2. **Admin = hors menace** : l'orchestrateur possède sudo. N04/N05 démontrent
   explicitement ce que root/propriétaire peut encore faire (config remplacée,
   rollback registre) et ce qui est couvert (agent non privilégié).
3. **Action unique, non destructive** : un fichier marqueur dans un répertoire
   temporaire dédié. Aucune généralisation à des effets à argent/données/vie
   privée.
4. **Un seul hôte** : aucune réplication indépendante par un tierce partie.
5. **Journalisation honnête des itérations d'exécution** : (a) un `dataclass` +
   `importlib` a exigé l'enregistrement du module dans `sys.modules` ;
   (b) les journaux du PEP s'ouvrent sous son UID (shell intermédiaire) ;
   (c) une assertion de test C4 a été corrigée (le comportement sécurité était
   déjà conforme au modèle figé : `EFFECT_PRESENT_DB_INCOMPLETE`) ; (d) la
   prédiction de code de porte X4D (`EFFECT_PATH_FORBIDDEN` → observé
   `RESOURCE_FORBIDDEN`) a été affinée **sans toucher au critère figé**
   (4xx avant effet, 0 marqueur). Aucun de ces points ne modifie une
   exigence de sécurité.
6. **Coutures de test** (`AEGIS_TEST_MODE`, `AEGIS_FAULT_INJECT`,
   `AEGIS_FIXED_NOW`) : réservées au protocole de crash figé ; à désactiver en
   toute construction non-test.

## 6 — Tribunal V3D

```
EXECUTIVE_STATE:          V3D_REAL_EFFECT_WITNESSED_LOCAL

SOURCE_INVENTORY:         pep_v3d_effect.py (ligneée V3C), effect_witness.py,
                          harness_v3d.py, run_n01_n05.py, run_v3d_tribunal.py,
                          run_v3d_regression.py, setup_sandbox.sh, THREAT_MODEL.md

OS_ISOLATION:             OBSERVED (uid 996/997/999, ACL fichiers vérifiées)

NEMESIS_COUNTERTESTS:     5/5 REPRODUCED (V3C) + 5/5 QUALIFIED (V3D)

DECISIVE_SUITE:           18/18 PASS_LOCAL (D01-D18)

V3C_REGRESSIONS:          50/50 + 50/50 PASS_LOCAL, historique hash-vérifié

CRASH_PROTOCOL:           C1 NO_CONSUMPTION->CONFIRMED | C2 CONSUMED_NO_ATTEMPT
                          | C3 ATTEMPTED_NO_EFFECT | C4 EFFECT_PRESENT_DB_INCOMPLETE

REAL_EFFECT:              OBSERVED (oracle: témoin uid 997 + relecture admin)
OS_PERMISSION_BOUNDARY:   OBSERVED (EACCES/OperationalError pour aegis_agent)
RAW_WITNESS:              OBSERVED (SHA-256 concordants, 0 canal API)
DB_ANTI_ROLLBACK:         PROVEN_SCOPE_ONLY (agent bloqué ; root démontré+détecté ;
                          O_EXCL = 2e étage contre le double effet)

SECURITY_LIMITATIONS:     témoin non indépendant en auteur ; admin=root assumé ;
                          action unique locale ; hôte unique

CLAIM_CEILING:            LOCAL_SINGLE_ACTION_REAL_EFFECT_WITNESSED

NEXT_GATE:                AEGIS_V3E_INDEPENDENT_WITNESS_ATTESTATION_005

PUBLIC_DEPLOYMENT:        BLOCKED
TRUTH_STATUS:             OPEN
```

**Message au labo MONSTERDOG :** le plafond a bougé pour la première fois depuis
V2C : il existe maintenant un **effet OS réel**, créé uniquement par le PEP,
observé par un processus qui ne croit aucune API, et **inaccessible à l'agent
sans PEP** (contrôle négatif OS). La persistance, la cryptographie, la
politique et les permissions fonctionnent ensemble, sans réintroduire les
anciens contournements (N01–N05 traités, 100 scénarios V3C toujours verts).
Reste l'aveu structurant : mon témoin est de confiance *technique*, pas
d'auteur. La prochaine victoire expérimentale est un témoin qui ne vient pas
de moi.

`CLAIM <= EVIDENCE. 𓂀 Ω∞`
