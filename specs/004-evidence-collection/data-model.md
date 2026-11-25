# Data Model: Collecte des preuves

Complète le modèle de la spec 002 (`specs/002-case-management/data-model.md`).

## ManifestEntry (amendé, rétrocompatible)

| Champ JSON | Type | Règles |
|---|---|---|
| `file`, `sha256`, `size`, `collected_at` | — | inchangés (spec 002) |
| `origin` | objet, optionnel | absent pour une preuve enregistrée sans origine |

### Origin

| Champ JSON | Type | Règles |
|---|---|---|
| `source_path` | chaîne | chemin absolu du fichier source tel que lu sur la station |
| `modified` | date-heure, optionnel | UTC, RFC 3339 avec nanosecondes |
| `accessed` | date-heure, optionnel | UTC ; valeur lue avant la copie |
| `changed` | date-heure, optionnel | UTC ; changement de métadonnées (Linux) |
| `created` | date-heure, optionnel | UTC ; création (Windows) |

Un horodatage que le système de fichiers ne fournit pas est omis. La taille est celle de `size`.

## Artifact pattern

| Champ | Valeur (spec 004) |
|---|---|
| Name | `evtx` |
| Dirs | `Windows`, `System32`, `winevt`, `Logs` (comparés sans casse) |
| Ext | `.evtx` (sans casse) |

Table versionnée dans le code ; les specs suivantes y ajoutent leurs motifs.

## CollectResult

| Champ | Description |
|---|---|
| File | chemin relatif à la cible (= chemin relatif à `evidence/`), séparateur `/` |
| Status | `COLLECTED`, `ALREADY`, `CONFLICT`, `FAILED`, `SKIPPED` |
| SHA256 | empreinte enregistrée (`COLLECTED`, `ALREADY`) ou attendue (`CONFLICT`) |
| Actual | empreinte de la source (`CONFLICT` seulement) |
| Reason | raison (`FAILED`, `SKIPPED`) |

Liste triée par `File`.

## États d'un fichier candidat

```text
candidat ──Lstat non régulier──────────────────────────► SKIPPED
   │
   ├─ déjà au manifeste ─ hash source ─ égal ──────────► ALREADY
   │                                   └ différent ────► CONFLICT
   │
   └─ AddEvidence (spec 002) ─ succès ─────────────────► COLLECTED
                              └ échec (dont verrou) ───► FAILED
```

## LogEntry `collect` (`case.log`)

Champs communs de la spec 002 ; `summary` :

```json
{"target":"/mnt/img","COLLECTED":2,"ALREADY":0,"CONFLICT":0,"FAILED":1,"SKIPPED":0,
 "problems":[{"file":"Windows/System32/winevt/Logs/Security.evtx","status":"FAILED","reason":"permission denied"}]}
```

`problems` liste les fichiers `FAILED`, `CONFLICT` et `SKIPPED`, triés par chemin.
