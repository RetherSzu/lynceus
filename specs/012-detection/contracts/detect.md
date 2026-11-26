# Contrat : commande `detect`

```text
dfirflow detect --case <cas> [--rules <fichier ou dossier>]
```

Grammaire des options : spec 001 (FR-012). Sans `--rules`, le jeu embarqué est appliqué. Avec
`--rules`, seul le fichier désigné, ou les fichiers `.yml` et `.yaml` du dossier et de ses
sous-dossiers hors fichiers et dossiers cachés, sont appliqués. Les identifiants en double sont
contrôlés parmi les règles appliquées. Format et sous-ensemble Sigma : [research.md](../research.md) R2 à
R4 et [data-model.md](../data-model.md).

L'aide de `detect` indique : `Apply detection rules to normalized events (detections are leads to
examine, not proof of compromise)`.

## Fichier produit

`detections/detections.jsonl` : JSONL canonique de la spec 003, une détection par ligne, triées
par `timestamp` puis `id`. Aucune détection : fichier de zéro octet. Le fichier est remplacé à
chaque exécution réussie, jamais modifié en place.

## Sortie standard

Une ligne :

```text
detect: 7 rules applied, 0 skipped, 0 refused, 739 events read, 15 detections: detections/detections.jsonl
```

## Sortie d'erreur

Avertissements, sans effet sur le code de sortie :

```text
dfirflow: detect: warning: rule refused: rules/agg.yml: aggregation is not supported
dfirflow: detect: warning: not in the case manifest: normalized/old/Security.evtx.jsonl
```

Raisons de refus (texte exact) :

| Cas | Raison |
|---|---|
| fichier de plus de 1 Mio | `file too large` |
| YAML invalide | `invalid YAML: <cause>` |
| plusieurs documents | `more than one rule in the file` |
| champ obligatoire absent ou vide | `missing <champ>` |
| `level`, `status` ou `confidence` invalide | `invalid <champ>: <valeur>` |
| `logsource.category` | `logsource category is not supported` |
| service inconnu | `unknown logsource service: <service>` |
| `|` dans la condition | `aggregation is not supported` |
| `timeframe` | `timeframe is not supported` |
| liste de mots-clés | `keyword search is not supported` |
| modificateur inconnu, option de `re` autre que `i`, `re` combiné à `contains`, `startswith` ou `endswith` | `unsupported modifier: <mod>` |
| expression régulière invalide | `invalid regular expression: <cause>` |
| condition illisible, sélection inconnue | `invalid condition: <cause>` |
| imbrication au-delà de 64 niveaux | `invalid condition: too deeply nested` |
| sélection qui n'est ni une table ni une liste de tables, valeur non scalaire, champ sans valeur | `invalid selection <nom>: ...` |

Erreurs (code 1) :

```text
dfirflow: detect: no normalized events in the case; run ingest first
dfirflow: detect: rules: <chemin>: no such file or directory
dfirflow: detect: no applicable rule in <chemin>
dfirflow: detect: duplicate rule id <id>: <fichier 1>, <fichier 2>
dfirflow: detect: normalized/Windows/System32/winevt/Logs/Security.evtx.jsonl: line 12: <cause>
```

Les fichiers de règles sont cités relativement au répertoire courant, tels que reçus en
`--rules` ; une règle embarquée est citée `embedded:<fichier>`.

## Codes de sortie

| Code | Cas |
|---|---|
| 0 | détections écrites, aucune comprise, règles refusées comprises |
| 1 | aucun fichier d'événements, ligne refusée, `--rules` introuvable, aucune règle applicable, identifiants en double, erreur de lecture ou d'écriture |
| 2 | erreur d'usage (spec 001) |
| 130 | interruption |

## `case.log`

Une entrée `detect` par exécution qui a ouvert le cas, réussie ou non (voir
[data-model.md](../data-model.md)).

## `investigate`

Enchaîne `collect`, `ingest`, `timeline` (sans filtre), `detect` (jeu embarqué), puis s'arrête à
`correlate` : `dfirflow: correlate: not implemented yet`, code 3.
