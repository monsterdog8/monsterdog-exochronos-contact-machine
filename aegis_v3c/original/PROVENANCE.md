# PROVENANCE — sources historiques AEGIS V2C / V3

Mission : `AEGIS_V3C_PIN_POLICY_SQLITE_INTEGRATION_003`
Règle : `CLAIM <= EVIDENCE`. Ce document distingue strictement les octets dont nous
disposons de ceux qui sont seulement cités.

## 1. V3 — `original/pep_v3_transactional.py` — ✅ OCTETS VÉRIFIÉS

| Champ | Valeur |
|---|---|
| Origine annoncée par NEMESIS | `original/pep_v3_transactional.py` du paquet `AEGIS_V3_TRANSACTIONAL_TRIBUNAL`, 3843 octets |
| SHA-256 annoncé par NEMESIS | `e02355ae2fbd4c635e6135923c027dba7117b9f48cdb759e66964741264804df` |
| SHA-256 de la copie de ce dépôt | `e02355ae2fbd4c635e6135923c027dba7117b9f48cdb759e66964741264804df` |
| Taille | 3843 octets |
| Statut | **`HASH_VERIFIED`** — la retranscription depuis l'annexe du PDF reproduit exactement l'empreinte et la taille du registre NEMESIS. Lecture seule, ne jamais modifier. |

Méthode : transcription du listing intégral reproduit en annexe du
`MONSTERDOG_AEGIS_V3_NEMESIS_DOSSIER_GEMINI.pdf` (pages 9–10), puis confrontation de la
copie à l'empreinte annoncée page 1 du même dossier. Concordance totale (taille +
SHA-256). Les octets historiques V3 sont donc **matérialisés et authentifiés** dans ce
dépôt, malgré l'absence du ZIP d'origine.

## 2. V2C — Cycle 1 (`AEGIS_V2C_CYCLE1_TRUST_ROOT_EVIDENCE.zip`)

| Champ | Valeur |
|---|---|
| Disponible dans ce checkout | **NON** |
| Citée par | Dossier NEMESIS V3 (référence historique) |
| Statut | `NOT_AVAILABLE` — **GAP DE PROVENANCE** |

Conséquence : les octets V2C ne peuvent pas être « préservés » dans ce dépôt puisqu'ils
n'y ont jamais été présents. En revanche, les **protections** V2C dont le dossier porte
la spécification (findings V3-C01 et V3-C02) sont réimplémentées dans
`pep_v3c_pinned.py` :

1. **Racine de confiance épinglée** (empreinte SHA-256 de la clé publique, ancrée hors
   du fichier de clé mutable : fichier `trust_root.pin` **et** champ
   `trust_root_fingerprint` de la politique PEP, les deux devant concorder avec la clé
   effectivement chargée).
2. **Allowlist d'autorisation indépendante du PEP** (sujet × action × ressource),
   évaluée **même pour un permis correctement signé** — une signature valide prouve
   l'origine cryptographique, jamais l'autorisation.

Si le ZIP V2C est fourni plus tard, il doit être importé sous `original/v2c/` sans
réécrire l'histoire, et son empreinte ajoutée à `SHA256SUMS.txt`.

## 3. Listes historiques (10 fixtures fondatrices / 16 attaques adversariales)

Les listes exactes des cycles antérieurs ne figurent ni dans le dépôt ni dans les deux
PDF fournis. Les suites `V3C-F01..F10` et `V3C-A01..A16` de `tests/run_v3c_tribunal.py`
sont donc **reconstituées** à partir des familles de menaces documentées dans le dossier
NEMESIS (T01–T24, findings V3-C01..C09). Statut : `RECONSTRUCTED_LOCAL_LISTS`.

## 4. PDF d'entrée de cette mission

| Fichier | Rôle | SHA-256 |
|---|---|---|
| `MONSTERDOG_AEGIS_V3_NEMESIS_DOSSIER_GEMINI.pdf` | Dossier forensique NEMESIS (24 scénarios, 9 findings) | voir `SHA256SUMS.txt` |
| `MONSTERDOG_AEGIS_V3C_PROMPT_GEMINI_ARENA.pdf` | Ordre de construction V3C (2 pages) | voir `SHA256SUMS.txt` |

Les PDF ne sont pas copiés dans le dépôt (artefacts d'entrée hors Git). Leurs empreintes
sont calculées dans `SHA256SUMS.txt` depuis les fichiers joints à la mission.
