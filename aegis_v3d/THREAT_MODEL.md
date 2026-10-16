# AEGIS V3D — MODÈLE DE MENACE FIGÉ (avant exécution)

**MISSION :** `AEGIS_V3D_REAL_EFFECT_WITNESS_004`
**Statut du document :** `FROZEN_BEFORE_EXECUTION` — écrit avant tout test V3D.
Toute modification postérieure serait une violation du protocole et devrait être
journalisée comme telle (aucune prévue).

---

## 1. Menace (threat model)

**Acteurs :**

| Rôle | Identité OS | Capacités | Hypothèses |
|---|---|---|---|
| Agent non fiable (« le modèle ») | `aegis_agent` (uid 996) | Client HTTP loopback du PEP ; tentative d'écriture directe | **Ne possède pas** de droits d'écriture sur la ressource d'effet, le registre, ni la config |
| PEP | `aegis_pep` (uid 999) | Seul détenteur du droit d'écriture sur la ressource d'effet et le registre | Exécute le code `pep_v3d_effect.py` |
| Témoin | `aegis_witness` (uid 997) | Lecture de la ressource d'effet ; écriture de son propre journal | Indépendant du PEP : **aucun canal d'API**, lecture seule OS sur l'effet |
| Orchestrateur / admin | `user` (uid 1001, sudo) | Provisionne users, config, dossiers ; lance les bancs | **Hors menace** (admin racine assumé) — toute preuve « admin peut tout » est hors périmètre et documentée |

**Adversaire couvert :** un agent non privilégié limité au loopback HTTP et à son
propre UID. **Adversaire NON couvert (explicitement) :** root / CAP_DAC_OVERRIDE,
compromission totale de l'admin, kernel, hardware, réseau. C'est la frontière que
NEMESIS a demandé de distinguer (N04/N05 : « test simulé d'attaquant root vs menace
réellement couverte »).

## 2. Ressource d'effet réel (unique)

- **Action réelle unique :** `marker.create`.
- **Effet :** création **exclusive** ( `O_CREAT|O_EXCL|O_WRONLY` ) d'un fichier
  marqueur `marker-<permit_id>.json` dans le répertoire d'effet dédié, écriture du
  contenu canonique, `fsync`, fermeture. **Non destructif** : rien d'autre n'est
  modifié ; un seul fichier par permis ; pas de suppression implémentée.
- **Rien en dehors** de `/tmp/aegis_v3d_sandbox/` ne sera écrit. Aucun réseau
  externe, aucune publication, aucun paiement, aucune donnée privée, aucune
  mutation de production : `PUBLIC_DEPLOYMENT = BLOCKED`.

## 3. Chemin autorisé

- Répertoire d'effet : `/tmp/aegis_v3d_sandbox/effect/` — propriétaire
  `aegis_pep:aegis_pep`, mode `0755` (lecture pour tous, écriture pour le seul
  propriétaire).
- Fichier marqueur : `effect/marker-<permit_id>.json` uniquement. Le `permit_id`
  est restreint au charset `[A-Za-z0-9._-]`; la correspondance
  `resource == "effect/marker-<permit_id>.json"` est exigée et vérifiée par
  containment `realpath` sous le répertoire d'effet.
- Tout autre chemin (`effect/../…`, `etc/passwd`, sous-répertoires, chemins
  absolus) est refusé **avant** effet.

## 4. Identités OS des processus (observables)

| Processus | UID lancement | Commande de banc |
|---|---|---|
| uvicorn PEP | `aegis_pep` | `sudo -u aegis_pep env … python -m uvicorn pep_v3d_effect:app --host 127.0.0.1` |
| témoin d'effet | `aegis_witness` | `sudo -u aegis_witness python tests/effect_witness.py …` |
| client HTTP (tests) | `aegis_agent` | `sudo -u aegis_agent python tests/http_client.py …` |
| écriture directe interdite | `aegis_agent` | `sudo -u aegis_agent python -c "open(marqueur,'w')"` → doit lever `PermissionError` |

## 5. Permissions des répertoires (gelées)

| Chemin | Propriétaire | Mode | Rôle |
|---|---|---|---|
| `/tmp/aegis_v3d_sandbox/config/` | root:root | 0755 | politique, clé publique, pin — **illisibles en écriture par agent ET pep** |
| `/tmp/aegis_v3d_sandbox/config/*` | root:root | 0644 | lecture PEP/témoin, écriture admin seule |
| `/tmp/aegis_v3d_sandbox/effect/` | aegis_pep | 0755 | ressource d'effet |
| `/tmp/aegis_v3d_sandbox/state/` | aegis_pep | 0700 | registre SQLite (rollback impossible pour l'agent) |
| `/tmp/aegis_v3d_sandbox/witness/` | aegis_witness | 0700 | journal du témoin — hors contrôle du PEP |
| `/tmp/aegis_v3d_sandbox/logs/` | aegis_pep | 0700 | stdout/stderr serveur |

## 6. Politique, clé, pin, registre (gelés)

- **Politique** : `config/pep_policy_v3d.json` — `policy_version=v3d.1.0`, audience
  `monsterdog.pep.v3d.local`, issuer `monsterdog.core.v3d`, TTL max 300 s, skew
  60 s, allowlist minimale :

```json
[
  {"subject": "agent-alpha", "action": "marker.create", "resource": "effect/marker-P-*.json"},
  {"subject": "agent-alpha", "action": "report.read",    "resource": "reports/*"},
  {"subject": "agent-alpha", "action": "email.send",     "resource": "outbox/digest"},
  {"subject": "agent-beta",  "action": "report.read",    "resource": "reports/public/*"}
]
```

- **Clé** : Ed25519, `config/pep_public.key` (32 octets bruts), empreinte SHA-256
  épinglée dans `config/trust_root.pin` ET dans la politique (triple concordance).
  La clé privée de test n'existe que dans le processus du banc (forge), jamais dans
  le bac de l'agent.
- **Registre** : `state/pep_ledger.db` — tables `consumed_permits` (PK nonce +
  **UNIQUE permit_id** + `chain_digest`), `events`, `effect_journal`. Chaînage
  `chain_digest = sha256(prev_digest || row_canonical)` : tout rollback prive la
  tête de chaîne connue du témoin (détection, pas prévention).

## 7. Protocole de crash (gelé, 4 points d'injection)

| Point | Injection | État DB attendu | Effet attendu | Réessai attendu |
|---|---|---|---|---|
| C1 `before_consume_commit` | exit 73 avant COMMIT du nonce | aucune ligne | aucun marqueur | **200** (rien n'a été consommé) — 1 effet total |
| C2 `after_consume_commit` | exit 73 après COMMIT, avant tentative | `PENDING` + seul `PERMIT_CONSUMED` | aucun marqueur | 403 NONCE_REUSED |
| C3 `after_attempt` | exit 73 après `ACTION_ATTEMPTED`, avant effet | `PENDING` + CONSUMED+ATTEMPTED | aucun marqueur | 403 NONCE_REUSED |
| C4 `after_effect` | exit 73 après écriture+fsync du marqueur, avant statut | `PENDING` + CONSUMED+ATTEMPTED (pas de MATERIALIZED) | **marqueur présent** | 403 NONCE_REUSED |

**Taxonomie d'état composite (jamais d'invention) :**

| DB (events) | Témoin | État rapporté |
|---|---|---|
| PENDING (consumed seul) | ABSENT | `CONSUMED_NO_ATTEMPT` |
| + ATTEMPTED | ABSENT | `ATTEMPTED_NO_EFFECT` |
| + ATTEMPTED (pas de MATERIALIZED) | **PRÉSENT** | `EFFECT_PRESENT_DB_INCOMPLETE` (fenêtre COMMIT→effet, C4) |
| + EFFECT_MATERIALIZED | PRÉSENT + digest concordant | **`CONFIRMED`** |
| + EFFECT_MATERIALIZED | ABSENT / digest divergent | `WITNESS_CONTRADICTION` (jamais attendu) |
| tout état | témoin indisponible | `UNKNOWN` |

`CONFIRMED` n'est **jamais** déclaré par l'API du PEP : il exige l'observation du
témoin séparé.

## 8. Oracle d'effet (le seul comptable)

1. `tests/effect_witness.py` exécuté sous UID `aegis_witness` : `opendir`, `open`,
   `read` complets, `sha256` des octets, validation structure (JSON canonique,
   `content_digest = sha256(champs canoniques)`), comparaison aux champs attendus
   passés en CLI ; écrit `witness_report.json` dans `witness/`.
2. Relecture indépendante de second niveau par l'orchestrateur (recalcul SHA-256
   du fichier) — concordance exigée témoin/orchestrateur.
3. **Non-oracles (explicitement réfutés) :** code HTTP 200 ; champ `executed` /
   `effect_confirmed` de l'API ; ligne SQLite `EFFECT_MATERIALIZED` seule ;
   message du PEP.

## 9. Fixtures (gelées)

**Fixture positive (P) :** sujet `agent-alpha`, action `marker.create`, ressource
`effect/marker-P-D1.json`, nonce neuf, signataire épinglé, TTL ≤ 300 s, permis_id
`P-D1`. Attendu : 200 + marqueur matérielisé + témoin CONFIRMED (digest concordant).

**Fixtures négatives (toutes : aucun marqueur créé, aucun 2xx) :**

| ID | Cas | Attendu |
|---|---|---|
| X1 | signature invalide (octet modifié) | 403 INVALID_SIGNATURE |
| X2 | signature par clé substituée (non épinglée) | 403 INVALID_SIGNATURE |
| X3 | action hors périmètre (`admin.delete`) signée | 403 ACTION_FORBIDDEN |
| X4 | chemin non autorisé (`etc/passwd`, `effect/../escape`, `effect/sub/x.json`) | 400/403 avant effet |
| X5 | permis expiré | 403 PERMIT_EXPIRED |
| X6 | champ supplémentaire `system_eval` au wrapper | 422 (extra=forbid) |
| X7 | même permit_id, second nonce | 403 PERMIT_ID_REUSED |
| X8 | politique révoquée à chaud (action retirée) | 403 ACTION_FORBIDDEN dès la requête suivante |
| X9 | écriture directe agent dans `effect/` | `PermissionError` OS (EACCES) |
| X10 | rollback registre par l'agent | `PermissionError` OS (EACCES) |

## 10. Critères de refus du banc (un seul échec ⇒ FAIL, pas de PASS mou)

1. Tout 2xx sur une fixture négative.
2. Tout marqueur créé sans permis valide, ou hors `effect/`.
3. Plus d'un marqueur pour un même nonce/permis (concurrence ou redémarrage
   compris).
4. Toute divergence digest témoin ↔ relecture.
5. Toute réussite d'écriture directe par `aegis_agent`.
6. Toute non-concordance des états C1–C4 avec le tableau §7.
7. Toute régression du banc V3C (50 scénarios) non pré-déclarée.

## 11. Révocation — contrat (gelé, fix N03)

Contrat : **toute modification de `pep_policy_v3d.json` est effective au plus tard
à la requête suivante.** Mécanisme : empreinte SHA-256 du fichier de politique
re-vérifiée à chaque `/v1/execute` (checkpoint par requête) ; changement ⇒
rechargement atomique ; rechargement invalide ⇒ 503 fail-closed (aucun effet).
Événements : `POLICY_RELOADED`. Le test N03 utilise une modification **admin**
(sudo) — la révocation administrative est couverte ; la modification par l'agent
est couverte par les ACL (§5).

## 12. Anti-rollback — contrat (gelé, fix N05)

- **Prévention dans le périmètre :** registre `0700/0600` propriété `aegis_pep` —
  l'agent ne peut ni lire ni écrire (N05 replays via rollback = OS-blocked).
- **Détection :** chaînage `chain_digest` + tête de chaîne journalisée par le
  témoin ; un rollback privilégié (root/propriétaire) **reste possible** et sera
  démontré comme tel, puis détecté par divergence de tête de chaîne.
- Verdict attendu : `DB_ANTI_ROLLBACK = PROVEN_SCOPE_ONLY` (périmètre : agent non
  privilégié, hôte unique). Jamais `NOT_PROVEN` déguisé en PASS.

## 13. Régressions V3C

Le banc V3C (`aegis_v3c/tests/run_v3c_tribunal.py`, **préservé sans modification**)
est ré-exécuté : (a) contre le code V3C conservé — résultat historique attendu
inchangé 50/50 ; (b) contre le PEP V3D via un wrapper de banc V3D (aucun fichier
V3C touché) — les 50 scénarios doivent rester verts : les actions `report.read` /
`email.send` conservent la sémantique simulée V3C ; l'action réelle est bornée à
`marker.create`, jamais sollicitée par le banc V3C.

## 14. Verdicts obligatoires (rappel du prompt)

```
REAL_EFFECT            = OBSERVED | NOT_EXECUTED
OS_PERMISSION_BOUNDARY = OBSERVED | NOT_EXECUTED
RAW_WITNESS            = OBSERVED | MISSING
DB_ANTI_ROLLBACK       = PROVEN_SCOPE_ONLY | NOT_PROVEN
CLAIM_CEILING         <= OBSERVED_EVIDENCE
PUBLIC_DEPLOYMENT      = BLOCKED
```

États utilisés : `OBSERVED / RECOMPUTED / REPORTED / NOT_EXECUTED / BLOCKED`.
`CLAIM <= EVIDENCE`.
