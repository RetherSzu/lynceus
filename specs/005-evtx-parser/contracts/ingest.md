# Contrat : commande `ingest` (EVTX)

Grammaire inchangée (spec 001) : `dfirflow ingest --case <chemin> [chemins…]`. Les chemins sont
relatifs à `evidence/` (séparateur `/` ou celui du système) ; sans chemin, toutes les preuves du
manifeste sont considérées.

## Sortie standard

Une ligne par preuve, triée par chemin, séparateur deux espaces, puis le résumé :

```text
INGESTED  Windows/System32/winevt/Logs/Security.evtx  events=739 anomalies=0
INGESTED  Windows/System32/winevt/Logs/System.evtx  events=736 anomalies=3
SKIPPED   Windows/System32/winevt/Logs/notes.evtx  reason=not an EVTX file
3 files: 2 INGESTED, 1 SKIPPED, 0 ALTERED, 0 FAILED; 1475 events, 3 anomalies
other: 41.2% (608 events); top: Security/4672=210, System/7036=95, ...
```

La ligne `other` liste au plus dix couples `canal/EventID=nombre` (R13) ; elle est omise si aucun
événement n'est classé `other`.

Preuve altérée : `ALTERED   <chemin>  reason=expected=<manifeste> actual=<calculé>`.
Erreur fatale : `FAILED    <chemin>  reason=<message>`.

## Fichiers écrits

| Fichier | Contenu |
|---|---|
| `normalized/<rel>.jsonl` | événements valides, JSONL canonique de la spec 003, ordre du journal |
| `normalized/<rel>.anomalies.jsonl` | anomalies, une par ligne, ordre du journal |

Écriture atomique par `.partial` puis renommage ; une relance remplace les deux fichiers.

## Erreurs (stderr, format `dfirflow: ingest: <message>`)

| Cas | Message | Code |
|---|---|---|
| Cas invalide | message de `case` (spec 002) | 1 |
| Chemin hors manifeste | `not in the case manifest: <chemin>` | 1 |
| Aucune preuve EVTX | `no EVTX evidence to ingest` | 1 |
| Au moins une preuve `FAILED` | `ingestion incomplete` | 1 |
| Au moins une preuve `ALTERED` | `integrity check failed` | 4 |
| Interruption | (aucun message) | 130 |

`ALTERED` l'emporte sur `FAILED`. Code 0 si toutes les preuves sont `INGESTED` ou `SKIPPED`, y
compris avec des anomalies. Une entrée `ingest` est ajoutée à `case.log` dès que le cas est ouvert
et que l'ingestion a démarré.
