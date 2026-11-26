# Data Model: Parser EVTX et ingestion des journaux

Complète le modèle de la spec 003 (`specs/003-event-model/data-model.md`) ; aucun champ de
`normalizer.Event` n'est ajouté ni modifié.

## Événement EVTX (application de la spec 003)

| Champ | Valeur |
|---|---|
| `uid` | `normalizer.UID(source_sha256, source_file, record_locator)` |
| `timestamp`, `timestamp_type` | R7 : `UtcTime` (type de l'entrée de table) ou `TimeCreated` (`logged`) |
| `timestamps` | `logged` (`TimeCreated`) et `written` (`RecordHeader`) s'ils diffèrent du principal |
| `source` | `evtx` |
| `event_type` | table de correspondance, `other` par défaut |
| `host`, `host_fqdn` | `normalizer.NormalizeHost(System/Computer)` |
| `channel`, `provider`, `event_id` | `System/Channel`, `System/Provider/@Name`, `System/EventID` |
| `subject`, `target`, `process`… | champs désignés par l'entrée de table |
| `source_file`, `source_sha256` | chemin relatif de la preuve et empreinte du manifeste |
| `record_id` | numéro d'en-tête de l'enregistrement (C3) |
| `record_locator` | `chunk:<index>/record:<numéro d'en-tête>` |
| `ingest` | `native` |
| `metadata` | toutes les valeurs de `EventData` / `UserData`, rendues selon spec 003 FR-013 |

## Entrée de la table de correspondance

| Champ JSON | Type | Règles |
|---|---|---|
| `channel` | chaîne | non vide, comparé sans casse |
| `provider` | chaîne | non vide, comparé sans casse |
| `event_id` | entier | ≥ 0 ; (`channel`, `provider`, `event_id`) unique |
| `event_type` | chaîne | dans la liste de la spec 003 FR-007, différent de `other` |
| `action_time` | chaîne, optionnel | champ de `EventData` portant l'instant de l'action (ex. `UtcTime`) |
| `action_time_type` | chaîne, optionnel | type d'horodatage (spec 003 FR-006) ; requis si `action_time` |
| `fields` | objet | clés parmi `subject.sid`, `subject.domain`, `subject.name`, `target.sid`, `target.domain`, `target.name`, `process`, `process_id`, `parent_process`, `parent_process_id`, `command_line`, `file_path`, `registry_path`, `hashes` ; valeur = nom du champ source |

Format complet et exemples : `contracts/evtx-mapping.md`.

## Anomalie écrite (`normalized/<rel>.anomalies.jsonl`)

| Champ JSON | Type | Règles |
|---|---|---|
| `record_locator` | chaîne | R8 ; `file` pour une anomalie de niveau fichier |
| `kind` | chaîne | `unreadable`, `missing`, `truncated`, `invalid` (spec 003 FR-016) |
| `message` | chaîne | non vide |

## Résultat d'ingestion d'une preuve

| Champ | Description |
|---|---|
| File | chemin relatif à `evidence/` |
| Status | `INGESTED`, `SKIPPED` (pas un EVTX), `ALTERED` (empreinte différente), `FAILED` (erreur fatale) |
| Events | nombre d'événements écrits |
| Anomalies | nombre d'anomalies écrites |
| Reason | raison (`SKIPPED`, `ALTERED`, `FAILED`) |

## Entrée `ingest` de `case.log`

```json
{"command":"ingest", "...":"champs communs (spec 002)",
 "summary":{"INGESTED":2,"SKIPPED":1,"ALTERED":0,"FAILED":0,"events":1478,"anomalies":3,
  "other_ratio":"0.412",
  "top_other":[{"channel":"Security","event_id":4672,"count":210}],
  "files":[{"file":"Windows/System32/winevt/Logs/Security.evtx","status":"INGESTED","events":739,"anomalies":0},
   {"file":"Windows/System32/winevt/Logs/System.evtx","status":"FAILED","events":0,"anomalies":0,"reason":"truncated file header"}]}}
```

`files` est trié par chemin ; `reason` est présent pour les statuts `ALTERED` et `FAILED`, omis sinon ; `top_other` contient au plus dix entrées (R13).

## États d'une preuve

```text
preuve du manifeste
  ├─ signature non EVTX ─────────────────────────────► SKIPPED
  ├─ empreinte différente du manifeste ──────────────► ALTERED
  └─ décodage ─ succès (anomalies possibles) ────────► INGESTED (fichiers renommés)
               └ erreur fatale (format, E/S) ────────► FAILED (.partial supprimés)
```
