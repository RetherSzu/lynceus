# Contrat : commande `timeline`

```text
dfirflow timeline --case <cas> [--from <date-heure>] [--to <date-heure>] [--source <liste>]
```

Grammaire et validation des options : spec 001 (FR-011, FR-019). `--source` accepte `evtx`, `mft`,
`usnjrnl`, `registry`, `prefetch`, `memory` (spec 003, FR-026), séparés par des virgules.

## Fichier produit

`timeline/timeline.jsonl` : JSONL canonique de la spec 003 (`contracts/event-model.md` de la spec
003), un événement par ligne, dans l'ordre FR-018a, chaque événement apparaissant une seule fois à
son horodatage principal. Chronologie vide : fichier de zéro octet. Le fichier est remplacé à
chaque exécution réussie, jamais modifié en place.

## Sortie standard

Une ligne :

```text
timeline: 2 files, 1478 events read, 312 written: timeline/timeline.jsonl
```

## Sortie d'erreur

Avertissements, sans effet sur le code de sortie :

```text
dfirflow: timeline: warning: no event from source mft
dfirflow: timeline: warning: not in the case manifest: normalized/old/Security.evtx.jsonl
```

Erreurs (code 1) :

```text
dfirflow: timeline: no normalized events in the case; run ingest first
dfirflow: timeline: normalized/Windows/System32/winevt/Logs/Security.evtx.jsonl: line 12: <cause>
```

## Codes de sortie

| Code | Cas |
|---|---|
| 0 | chronologie écrite, vide comprise |
| 1 | aucun fichier d'événements, ligne refusée, erreur de lecture ou d'écriture |
| 2 | erreur d'usage (option inconnue, date invalide, `--from` après `--to`, source inconnue) |
| 130 | interruption |

## `case.log`

Une entrée `timeline` par exécution qui a ouvert le cas, réussie ou non (voir
[data-model.md](../data-model.md)).

## `investigate`

Enchaîne `collect`, `ingest`, `timeline` (sans filtre), puis s'arrête à `detect` :
`dfirflow: detect: not implemented yet`, code 3.
