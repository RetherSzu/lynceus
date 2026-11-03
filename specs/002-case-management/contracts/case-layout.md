# Contrat : dossier de cas DFIRFlow (schema_version 1)

## Arborescence

```text
<dir>/<case_id>/
├── case.json              # métadonnées (voir data-model.md)
├── case.log               # journal JSONL, ajout seul
├── evidence/              # preuves, en lecture seule
├── parsed/
├── normalized/
├── timeline/
├── detections/
├── reports/
└── hashes/
    └── manifest.jsonl     # manifeste JSONL, ajout seul
```

## Exemples

`case.json` :

```json
{
  "schema_version": 1,
  "case_id": "CASE-001",
  "hostname": "WIN-CLIENT01",
  "analyst": "dfir-team",
  "created_at": "2026-11-03T09:00:00Z",
  "tool_version": "v0.1.0"
}
```

`hashes/manifest.jsonl` :

```json
{"file":"Windows/System32/winevt/Logs/Security.evtx","sha256":"9f86d0…","size":12345678,"collected_at":"2026-11-03T09:05:00Z"}
```

`case.log` :

```json
{"command":"case verify","args":["--case","./cases/CASE-001"],"started_at":"2026-11-03T10:00:00Z","finished_at":"2026-11-03T10:00:02Z","tool_version":"v0.1.0","exit_code":4,"summary":{"MODIFIED":1,"MISSING":0,"OK":2,"UNTRACKED":0}}
```

## Commandes

| Commande | stdout | Codes |
|---|---|---|
| `case init <ID> --host --analyst [--dir]` | chemin du cas créé | 0 ; 1 si le dossier existe ou création impossible |
| `case verify --case <path>` | une ligne par preuve triée par chemin, puis le résumé | 0 intègre ; 4 altération ; 1 cas invalide ; 130 interruption |

Format des lignes de `case verify` (séparateur : deux espaces) :

```text
OK         Security.evtx  sha256=<attendu>
MODIFIED   System.evtx  expected=<attendu> actual=<obtenu>
MISSING    Setup.evtx  expected=<attendu>
UNTRACKED  notes.txt
4 evidence files: 1 OK, 1 MODIFIED, 1 MISSING, 1 UNTRACKED
```

En cas d'altération, stderr contient `dfirflow: case verify: integrity check failed`.
