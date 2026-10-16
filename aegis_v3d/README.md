# AEGIS V3D — Témoin d'effet réel (bac à sable OS isolé)

**MISSION :** `AEGIS_V3D_REAL_EFFECT_WITNESS_004`
**MODE :** `EVIDENCE_FIRST | FAIL_CLOSED | NO_SELF_VALIDATION | LOCAL_ONLY`
**RÈGLE :** `CLAIM <= EVIDENCE`. Un 200 HTTP n'est pas une preuve d'effet.
Une ligne SQLite `EFFECT_MATERIALIZED` n'est pas une preuve d'effet OS.

## Ce que V3D ajoute à V3C (préservé sans écriture rétroactive)

| Correctif | Origine | Mécanisme |
|---|---|---|
| N01 enveloppe fermée | wrapper permissif | `ExecuteRequest(extra="forbid")` — tout champ externe (`system_eval`) => 422 |
| N02 idempotence métier | `permit_id` non unique | `UNIQUE(permit_id)` + priorité de diagnostic `NONCE_REUSED` |
| N03 révocation | politique chargée une fois | checkpoint SHA-256 de la politique **à chaque requête** ; révocation effective à la requête suivante ; politique invalide => 503 |
| N04 bootstrap confiance | 3 fichiers mutables | config **root-owned 0644** (écriture admin seule) + contrôle in-app des permissions ; portée : agent non privilégié |
| N05 anti-rollback | registre malléable | registre `0700/0600` `aegis_pep` + chaînage `chain_digest` + tête de chaîne hors PEP (détection) + effet `O_EXCL` (2e étage) |
| Effet réel | `executed=true` sans effet | **une seule action réelle** : `marker.create` => création exclusive `O_CREAT\|O_EXCL` d'un marqueur dans `effect/`, fsync. `EFFECT_CONFIRMED` jamais émis par le PEP — le témoin tranche |

## Isolation OS (réelle, pas simulée)

| Rôle | UID | Droits |
|---|---|---|
| `aegis_pep` | 999 | seul écrit dans `effect/` (0755) et `state/` (0700) |
| `aegis_witness` | 997 | lecture `effect/` ; écrit son journal dans `witness/` (0700) |
| `aegis_agent` | 996 | client HTTP loopback **seulement** — écriture directe refusée OS |
| admin (`user`) | 1001+sudo | provisioning — **hors menace** (documenté) |

## Exécution (commandes exactes)

```bash
bash aegis_v3d/tests/setup_sandbox.sh                 # users + bac + config root-owned
python aegis_v3d/tests/run_n01_n05.py                 # N01-N05 : V3C (5/5) puis V3D (5/5)
python aegis_v3d/tests/run_v3d_tribunal.py            # D01-D18 : banc décisif (18/18)
python aegis_v3d/tests/run_v3d_regression.py          # régressions V3C (50/50 + 50/50)
```

## Oracle d'effet (le seul comptable)

`tests/effect_witness.py`, exécuté sous `aegis_witness` : `opendir/open/read`
complets, SHA-256 des octets, `content_digest` canonique, comparaison aux
attentes CLI. Concordance exigée avec une relecture admin indépendante
(D18). **Non-oracles :** code HTTP, message d'API, ligne SQLite seule.

## États composites (jamais d'invention)

| DB (events) | Témoin | État |
|---|---|---|
| rien | absent | `NO_CONSUMPTION` |
| `PENDING` (consumed seul) | absent | `CONSUMED_NO_ATTEMPT` |
| + `ATTEMPTED` | absent | `ATTEMPTED_NO_EFFECT` |
| + `ATTEMPTED` (pas de MATERIALIZED) | **présent** | `EFFECT_PRESENT_DB_INCOMPLETE` (C4, fenêtre COMMIT→effet) |
| + `EFFECT_MATERIALIZED` | présent + digest | **`CONFIRMED`** (témoin seulement) |

## Contenu

```
aegis_v3d/
  THREAT_MODEL.md            # modèle de menace FIGÉ avant exécution
  pep_v3d_effect.py          # PEP V3D (ligneée V3C)
  tests/setup_sandbox.sh     # provisioning OS exact et rejouable
  tests/provision_config.py  # clé/pin/politique (config root-owned)
  tests/harness_v3d.py       # rôles OS, serveur, client agent, témoin
  tests/effect_witness.py    # TÉMOIN — processus/UID distinct, aucun canal API
  tests/http_client.py       # client minimal pour l'UID non fiable
  tests/run_n01_n05.py       # reproduction N01-N05 (V3C puis V3D)
  tests/run_v3d_tribunal.py  # D01-D18 décisif
  tests/run_v3d_regression.py# régressions V3C (sources préservées)
  results/                   # JSON bruts + stdout + exit codes
  REPORT_AEGIS_V3D.md        # verdicts obligatoires + limites
  SHA256SUMS.txt
```

Les sources V2C/V3/V3C ne sont **jamais** modifiées : `git status` et
`SHA256SUMS.txt` de `aegis_v3c/` en sont les témoins.
