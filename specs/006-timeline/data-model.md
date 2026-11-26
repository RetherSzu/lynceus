# Data Model: Chronologie consolidée du cas

Aucune modification du modèle d'événement de la spec 003 : la chronologie recopie les événements
de `normalized/` tels qu'encodés (JSONL canonique, `schema_version` 1).

## Filtre

| Champ | Type | Règle |
|---|---|---|
| `from` | instant UTC, facultatif | tronqué à la µs ; événement retenu si `timestamp >= from` |
| `to` | instant UTC, facultatif | tronqué à la µs ; événement retenu si `timestamp <= to` |
| `sources` | liste, facultative | valeurs de la spec 003 (FR-026), triées, sans doublon ; vide = toutes |

`from <= to` est garanti par la CLI avant l'appel (spec 001).

## Clé de tri

`(timestamp µs, source_file, record_id, uid)`, ordre croissant, chaînes comparées octet par octet
(spec 003, FR-018a). Ordre total : deux événements distincts n'ont jamais la même clé.

## Résumé d'exécution

| Champ | Sens |
|---|---|
| `files` | nombre de fichiers d'événements lus |
| `events_read` | événements lus, avant filtre |
| `events_written` | événements écrits dans la chronologie |
| `sha256` | empreinte de `timeline/timeline.jsonl` (succès seulement) |
| `missing_sources` | sources demandées sans aucun événement lu (avertissement FR-008) |
| `unknown_files` | fichiers de `normalized/` sans preuve au manifeste, relatifs au cas (FR-002) |

## Entrée `timeline` de `case.log`

```json
{"command":"timeline", "...":"champs communs (spec 002)",
 "summary":{"filter":{"from":"2026-11-01T08:00:00.000000Z","sources":["evtx","mft"]},
  "files":2,"events_read":1478,"events_written":312,
  "sha256":"<64 hex>",
  "missing_sources":["mft"],
  "unknown_files":["normalized/old/Security.evtx.jsonl"]}}
```

`from`, `to` et `sources` sont omis quand ils ne sont pas donnés ; `missing_sources` et
`unknown_files` sont omis quand ils sont vides. En cas d'échec, `sha256` est
omis et `error` porte la cause ; `exit_code` est celui de la commande.

## États de la chronologie

```text
absente ou précédente
  ├─ aucun fichier d'événements ────────────► inchangée (code 1)
  ├─ ligne refusée / erreur d'écriture ─────► inchangée, temporaires supprimés (code 1)
  ├─ interruption ──────────────────────────► inchangée, temporaires supprimés (code 130)
  └─ succès ────────────────────────────────► remplacée par la nouvelle (code 0)
```
