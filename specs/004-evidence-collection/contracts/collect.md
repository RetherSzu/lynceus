# Contrat : commande `collect`

Grammaire inchangée (spec 001) : `dfirflow collect --case <chemin> --target <chemin>`.

## Sortie standard

Une ligne par fichier, triée par chemin relatif, séparateur deux espaces, puis un résumé :

```text
COLLECTED  Windows/System32/winevt/Logs/Security.evtx  sha256=<empreinte>
ALREADY    Windows/System32/winevt/Logs/System.evtx  sha256=<empreinte>
CONFLICT   Windows/System32/winevt/Logs/Setup.evtx  expected=<manifeste> actual=<source>
FAILED     Windows/System32/winevt/Logs/Application.evtx  reason=<raison>
SKIPPED    Windows/System32/winevt/Logs/link.evtx  reason=not a regular file
5 files: 1 COLLECTED, 1 ALREADY, 1 CONFLICT, 1 FAILED, 1 SKIPPED
```

Fichier verrouillé (Windows) : `reason=locked by the system: live collection is not supported`.

## Erreurs (stderr, format `dfirflow: collect: <message>`)

| Cas | Message | Code |
|---|---|---|
| Cas invalide | message de `case` (spec 002) | 1 |
| Cible absente, illisible ou non répertoire | `invalid target <chemin>: <raison>` | 1 |
| Cas sous la cible | `case directory must not be inside the target` | 1 |
| Aucun fichier régulier reconnu (y compris cible ne contenant que des `SKIPPED`) | `no artifact found under <chemin>` | 1 |
| Au moins un `FAILED` ou `CONFLICT` | `collection incomplete` | 1 |
| Interruption | `interrupted` | 130 |

Code 0 si au moins un fichier est `COLLECTED` ou `ALREADY` et qu'aucun n'est `FAILED` ni `CONFLICT` (les `SKIPPED` sont tolérés). Une entrée `collect` est
ajoutée à `case.log` dans tous les cas où le cas a pu être ouvert.

## Manifeste

Ligne enrichie du champ `origin` (voir [data-model.md](../data-model.md)) :

```json
{"file":"Windows/System32/winevt/Logs/Security.evtx","sha256":"9f86d0…","size":69632,"collected_at":"2026-11-25T10:00:00Z","origin":{"source_path":"/mnt/img/Windows/System32/winevt/Logs/Security.evtx","modified":"2026-10-01T08:00:00Z","accessed":"2026-11-20T14:12:03.5Z","changed":"2026-10-01T08:00:00Z"}}
```
