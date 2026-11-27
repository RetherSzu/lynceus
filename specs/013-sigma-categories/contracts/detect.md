# Contrat : commande `detect` (évolution 013)

Ce contrat complète celui de la spec 012 (`specs/012-detection/contracts/detect.md`), qui reste
valable pour tout ce qui n'est pas repris ici : grammaire, fichier produit, ligne de résumé,
codes de sortie, erreurs.

## Sources acceptées

`logsource.service` (spec 012) ou `logsource.category` parmi les catégories de
[data-model.md](../data-model.md), ou les deux (sources de la catégorie sur le canal du service).

## Sortie standard

Inchangée :

```text
detect: 12 rules applied, 0 skipped, 0 refused, 739 events read, 15 detections: detections/detections.jsonl
```

Une règle exclue de certaines sources par la garde reste comptée dans `rules applied`.

## Sortie d'erreur

Nouvel avertissement, un par source partielle ayant exclu au moins une règle, après les
avertissements de refus et avant ceux du manifeste :

```text
dfirflow: detect: warning: 42 rules not applied to Security 4688 (missing fields), see case.log
```

Avec une seule règle : `1 rule not applied to Security 4688 (missing fields), see case.log`.

## Raisons de refus

Ajoutées :

| Cas | Raison (texte exact) |
|---|---|
| ni service ni catégorie | `missing logsource.service or logsource.category` |
| catégorie hors de la table | `unknown logsource category: <c>` |
| catégorie et service sans source commune | `logsource category and service do not match` |
| règle exclue de toutes ses sources par la garde | `fields not available in any source: <champs>` |
| combinaison de modificateurs invalide | `unsupported modifier: <mod>` |
| préfixe `cidr`, valeur `exists`, cible `fieldref` invalides | `invalid selection <nom>: field <champ>: <cause>` |

Retirées : `logsource category is not supported` ; `missing logsource.service` (remplacée).

## `case.log`

Clés ajoutées à l'entrée `detect` : `categories_version`, `rules_restricted`
([data-model.md](../data-model.md)).

## Invariants

- Les détections des règles de service sont identiques à celles de la spec 012.
- Une détection par couple (règle, événement), même si deux événements de sources différentes
  décrivent la même activité.
- Pour une même table des catégories, mêmes règles et même cas : fichier identique octet par
  octet.
