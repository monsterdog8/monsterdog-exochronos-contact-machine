# AEGIS V3E — MODÈLE DE MENACE (V3E_THREAT_MODEL)

Mission : `AEGIS_V3E_INDEPENDENT_WITNESS_ATTESTATION_005`
Gelé AVANT toute exécution de test (voir `EXPERIMENT_FREEZE.json`, ancré hors dépôt).
Verdicts : OBSERVED / RECOMPUTED / REPORTED / NOT_EXECUTED / BLOCKED / BLOCKED_ENVIRONMENT.
Règle : `CLAIM <= EVIDENCE` — `REPORT != RAW` — `SHA256_MATCH != TRUTH` —
`UID_SEPARATION != AUTHOR_INDEPENDENCE` — `DB_COMMIT != EFFECT` — `O_EXCL != POWER_LOSS_DURABILITY`.

## 1. Périmètre observé vs hors périmètre

| Effet | Statut périmètre |
|---|---|
| Création d'un fichier marqueur unique dans `/tmp/aegis_v3e_sandbox/effect/` | DANS le périmètre (non destructif, réversible) |
| Tout autre effet fichier/réseau/processus | HORS périmètre |
| Machine d'utilisateur réelle, production, publication | INTERDIT — `PUBLIC_DEPLOYMENT=BLOCKED` |
| Données biomédicales/privées, dépenses, connexion extérieure obligatoire | INTERDIT |
| Root / rollback privilégié / panne électrique / multisite / rotation de clés | HORS périmètre (déclaré) |

## 2. Racine de confiance (déclarée qui la détient)

1. **Plateforme Arena/E2B** : conteneur éphémère `e2b.local`, disque virtuel `/dev/vda`,
   environnement détruit et recyclé entre sessions (observé : comptes et bac V3D du cycle
   précédent disparus). La plateforme accorde le sudo du compte `user` (uid 1001).
2. **Utilisateur (ordre humain)** : autorisation conditionnelle du provisioning root
   minimal (comptes de test + bac `/tmp/aegis_v3e_sandbox`), journalisé commande par commande.
3. **OS du conteneur** : contrôle l'arbitrage UID/permissions des trois identités de test
   (`aegis_pep` 999°, `aegis_witness`, `aegis_agent` — sans privilège administratif).
4. **Ancrage Git externe (GitHub)** : le manifeste gelé est poussé AVANT les tests ;
   le commit et son horodatage serveur constituent l'ancre indépendante de pré-réservation
   (corrige V3D-003). L'expérimentation elle-même ne dépend d'aucune connexion extérieure.

## 3. Adversaires modélisés

| ID | Adversaire | Capacités | Doit être arrêté par |
|---|---|---|---|
| A1 | Agent non privilégié (uid `aegis_agent`) | API PEP, lecture config 0644 | Signature, nonce, policy, allowlist, EACCES OS |
| A2 | Client réseau distant | Aucune | Refus (mode local seulement) |
| A3 | Contrefacteur d'artefacts (post-course) | Altère octets/rapports hors PEP | Témoin indépendant + vérificateur externe + ancre |
| A4 | Rejoueur | Rejeu permis/nonce/registre/état reconstitué | NONCE/PERMIT REUSED + O_EXCL + ancrages |
| A5 | Auteur malhonnête (auto-attestation) | Écrit témoin et PEP | HORS garantie — plafond `AUTHOR_INDEPENDENCE` |

## 4. Oracle d'effet

L'**unique** oracle de confirmation d'effet est le **témoin indépendant**
`INDEPENDENT_WITNESS_SOURCE/witness_v3e.sh` : implémentation minimale POSIX sh +
coreutils, sans import du code Python du PEP ni de `effect_witness.py` (séparation de
conception vérifiable : langage, chaîne d'outils et code distincts). Il ouvre les fichiers
du répertoire d'effet, recalcule octets/longueur/SHA-256, compare à l'assertion d'entrée,
et déclare son UID effectif, l'empreinte de sa propre source et son identifiant de run.
`effect_witness.py` (V3D) et le corps de réponse HTTP ne sont **jamais** des oracles.

## 5. Permission et effets autorisés

Une seule famille d'effet : `marker.create` (O_CREAT|O_EXCL + fsync fichier + fsync
répertoire parent), ressources limitées à `/tmp/aegis_v3e_sandbox/effect/marker-*.json`.
Toute autre action/ressource est refusée par la politique épinglée (hash de politique
ancré dans la clé provisionnée).

## 6. Critères de refus (fail-closed)

- Marqueur absent/malformé/altéré → aucune confirmation ; `UNKNOWN`/`HOLD`, jamais `CONFIRMED` par défaut.
- Témoin indisponible ou rapport absent → `UNKNOWN` / `HOLD`.
- Rupture de la chaîne de reçus ou écart d'ancre → `HOLD` (`ATTACK_LEDGER.json`).
- Crash entre effet et commit → `EFFECT_PRESENT_DB_INCOMPLETE` → `5xx EFFECT_UNCONFIRMED`.
- Un seul veto critique impose `HOLD` global.

## 7. Crash vs durabilité (V3D-004)

- Crash processus (SIGKILL / `os._exit`) ≠ panne électrique.
- `fsync(fd)` ≠ `fsync(dir)` ; le PEP V3E synchronise les deux (correction documentée) —
  cela ne démontre **pas** la durabilité après coupure d'alimentation.
- `POWER_LOSS_DURABILITY = NOT_EXECUTED` (aucun banc de coupure) ; interdiction de
  déclarer `POWER_LOSS_SAFE`.
- Marqueur observé ≠ preuve de durabilité au reboot.

## 8. Opérations administratives (autorisation conditionnelle respectée)

Comptes de test uniquement (`aegis_pep`, `aegis_witness`, `aegis_agent`, sans privilège),
tout sous `/tmp/aegis_v3e_sandbox`, préflight avant modification, aucune écriture dans
`/home` ni dans les dépôts, aucune suppression récursive, aucun chmod global, aucune
installation externe (les dépendances Python sont **copiées** depuis l'environnement déjà
présent, pas installées), aucun déploiement public, chaque commande privilégiée journalisée
avec sortie et code, arrêt immédiat si l'isolation n'est pas vérifiée.
