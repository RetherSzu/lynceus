# Contrat : modèle d'événement DFIRFlow

Contrat normatif du format des événements (`normalized/`, `timeline/`) et des détections
(`detections/`). Toute modification suit la procédure de la section « Évolution ».

## Historique

| `schema_version` | Spec | Modifications | Nature |
|---|---|---|---|
| 1 | 003 | Version initiale | — |

## Fichier JSONL

- Un objet JSON par ligne, UTF-8 sans BOM, terminé par `\n` ; aucune ligne vide.
- `schema_version` (entier) en premier champ, puis les champs dans l'ordre ci-dessous.
- Champs facultatifs vides omis (jamais `null` ni `""`) ; clés des objets `metadata`, `hashes`,
  `subject`, `target` en ordre croissant d'octets.
- Seuls les échappements JSON obligatoires sont appliqués (`<`, `>`, `&` littéraux).
- Horodatages : `AAAA-MM-JJThh:mm:ss.ffffffZ`, UTC, 6 décimales exactement, tronqués.

## Événement

Ordre des champs : `schema_version`, `uid`, `timestamp`, `timestamp_type`, `timestamps`,
`source`, `event_type`, `host`, `host_fqdn`, `channel`, `provider`, `event_id`, `subject`,
`target`, `process`, `process_id`, `parent_process`, `parent_process_id`, `command_line`,
`file_path`, `registry_path`, `hashes`, `source_file`, `source_sha256`, `record_id`,
`record_locator`, `recovered`, `ingest`, `metadata`.

Règles de chaque champ : [spec.md](../spec.md) FR-001 à FR-013. Rappel des listes fermées :

| Liste | Valeurs |
|---|---|
| `source` | `evtx`, `mft`, `usnjrnl`, `registry`, `prefetch`, `memory` |
| `timestamp_type`, `timestamps[].type` | `created`, `modified`, `accessed`, `changed`, `executed`, `logged`, `written`, `last_write` |
| `event_type` | `logon`, `logon_failed`, `logoff`, `process_creation`, `service_install`, `script_execution`, `log_cleared`, `malware_detected`, `av_config_change`, `other` |
| clés de `hashes` | `md5` (32), `sha1` (40), `sha256` (64), `imphash` (32) |

**`uid`** = 32 premiers caractères hexa minuscules de
`SHA-256(source_sha256 ‖ 0x00 ‖ source_file ‖ 0x00 ‖ record_locator)`.

**Rendu de `metadata`** : entier décimal ; `HexInt32`/`HexInt64` `0x` + hexa minuscules sans zéro
de tête ; booléen `true`/`false` ; flottant forme la plus courte se relisant à l'identique ; GUID
`{…}` majuscules ; SID `S-1-…` ; date au format horodatage ci-dessus ; binaire hexa minuscules ;
`%%nnnn` tel quel. Clés : nom `EventData` d'origine ; `Data[n]` (base 1) pour les données sans
nom ; `UserData` sans élément racine, niveaux joints par `.` ; `System.<chemin>` pour `System`.

Exemple (une ligne, coupée ici pour la lecture) :

```json
{"schema_version":1,"uid":"…32 hexa…","timestamp":"2020-09-09T13:18:23.627952Z",
 "timestamp_type":"logged","source":"evtx","event_type":"logon","host":"WIN-77LTAPHIQ1R",
 "host_fqdn":"WIN-77LTAPHIQ1R.example.corp","channel":"Security",
 "provider":"Microsoft-Windows-Security-Auditing","event_id":4624,
 "subject":{"domain":"EXAMPLE","name":"WIN-77LTAPHIQ1R$","sid":"S-1-5-18"},
 "target":{"domain":"EXAMPLE","name":"alice","sid":"S-1-5-21-1-2-3-1104"},
 "source_file":"Logs/Security.evtx","source_sha256":"…64 hexa…","record_id":1234,
 "record_locator":"record=1234","ingest":"native",
 "metadata":{"LogonType":"3","Status":"0x0","System.EventRecordID":"1234"}}
```

**Ordre canonique** : `timestamp`, `source_file` (octets), `record_id`, `uid`, croissants.

## Détection

Ordre des champs : `schema_version`, `id`, `timestamp`, `rule_id`, `rule_version`, `severity`,
`confidence`, `mitre`, `events`. Règles : FR-019 à FR-021.

**`id`** = 32 premiers caractères hexa minuscules de
`SHA-256(rule_id ‖ 0x00 ‖ rule_version ‖ 0x00 ‖ uid₁ ‖ 0x00 ‖ … ‖ uidₙ)`, `uid` triés.

**Ordre canonique** : `timestamp`, `id`, croissants.

## Lecture

Une ligne est refusée, avec son numéro et la cause, si : elle n'est pas en UTF-8 valide, se
termine par `\r`, n'est pas un objet JSON unique, porte un champ inconnu, a un
`schema_version` non pris en charge, ou viole une règle de validation.

## Contrat de parseur

Voir [data-model.md](../data-model.md) § `parser` et FR-014 à FR-016d. Anomalies :
`{record_locator, kind, message}`, `kind` ∈ `unreadable`, `missing`, `truncated`, `invalid`.

## Évolution

- Toute modification du format ou d'une liste fermée incrémente `schema_version` de 1 et ajoute
  une ligne à l'historique.
- **Additive** (champ facultatif, valeur de liste) : les versions antérieures restent lisibles.
- **Cassante** (renommage, suppression, changement de sens ou de rendu) : les versions antérieures
  sont refusées avec l'invitation à réingérer le cas.
- Gelés hors changement cassant justifié : formule du `uid`, rendu de `metadata`, écriture des
  horodatages.
- Dans le même commit : ce contrat, le fichier de référence `testdata/events.v<N>.jsonl`, et
  conservation du fichier de la version précédente comme jeu de compatibilité.
