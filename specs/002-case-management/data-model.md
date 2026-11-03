# Data Model: Gestion des cas d'investigation

## Case (`case.json`)

| Champ JSON | Type | Règles |
|---|---|---|
| `schema_version` | entier | `1` ; tout autre valeur → cas invalide |
| `case_id` | chaîne | `^[A-Za-z0-9_-]{1,64}$` (validé par la CLI) |
| `hostname` | chaîne | non vide |
| `analyst` | chaîne | non vide |
| `created_at` | date-heure | UTC, RFC 3339 |
| `tool_version` | chaîne | version du binaire à la création |

Chemin du dossier (non stocké) : `<dir>/<case_id>`.

## ManifestEntry (`hashes/manifest.jsonl`, une ligne par preuve)

| Champ JSON | Type | Règles |
|---|---|---|
| `file` | chaîne | relatif à `evidence/`, séparateur `/`, ne sort pas de `evidence/`, unique |
| `sha256` | chaîne | 64 caractères hexadécimaux minuscules |
| `size` | entier | octets, ≥ 0 |
| `collected_at` | date-heure | UTC, RFC 3339 |

Ajout seul ; jamais modifié ni supprimé.

## VerifyResult

| Champ | Description |
|---|---|
| File | chemin relatif à `evidence/` |
| Status | `OK`, `MODIFIED`, `MISSING`, `UNTRACKED` |
| Expected | empreinte du manifeste (vide pour `UNTRACKED`) |
| Actual | empreinte recalculée (vide pour `MISSING`, `UNTRACKED`) |

Liste triée par `File`. Le cas est intègre si tous les statuts sont `OK`.

## LogEntry (`case.log`, une ligne par commande)

| Champ JSON | Type |
|---|---|
| `command` | chaîne (`case init`, `case verify`…) |
| `args` | liste de chaînes |
| `started_at`, `finished_at` | date-heure UTC |
| `tool_version` | chaîne |
| `exit_code` | entier |
| `summary` | objet libre propre à la commande (ex. `{"OK":3,"MODIFIED":1}`) |

## États d'une preuve

```text
source ──copie+hash──► <rel>.partial ──relecture OK──► <rel> ──manifeste──► <rel> (lecture seule)
           │ échec                │ échec                       │ échec
           ▼                      ▼                             ▼
      supprimé               supprimé                       supprimé
```
