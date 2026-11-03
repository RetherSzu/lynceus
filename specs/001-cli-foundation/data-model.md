# Data Model: Fondation de la CLI DFIRFlow

Aucune donnée persistée. Les « entités » sont des structures en mémoire décrivant la grammaire.

## Command

| Champ | Description | Règles |
|---|---|---|
| Name | `case init`, `case verify`, `collect`, `ingest`, `import`, `timeline`, `detect`, `correlate`, `report`, `investigate` | Unique ; ordre fixe = ordre du pipeline (aide déterministe) |
| Summary | Description d'une ligne pour l'aide générale | Obligatoire |
| Usage | Ligne d'usage | Obligatoire |
| Positionals | Arguments positionnels attendus | Cardinalité : 0, 1 ou 0..n selon la commande |
| Options | Liste d'`Option` | Ordre fixe dans l'aide |
| Example | Exemple d'invocation | Obligatoire (SC-001) |
| Implemented | Commande fonctionnelle livrée ou non | `false` pour les 10 commandes dans cette feature |

## Option

| Champ | Description | Règles |
|---|---|---|
| Name | Nom long (`case`, `host`, `from`…) | Unique dans une commande |
| Required | Obligatoire ou non | Absence d'une option obligatoire → code 2 |
| Kind | `string`, `path`, `enum-list`, `datetime` | Détermine la validation |
| Allowed | Valeurs acceptées (`enum-list`) | Voir contracts/cli.md |
| Default | Valeur par défaut | `--dir` = `./cases` ; `--format` = `html,sqlite,jsonl` |

Règles transverses : valeur vide refusée ; option répétée refusée ; validation terminée avant tout
accès disque.

## Case reference

Valeur de `--case` : chemin (relatif ou absolu) vers un dossier de cas. Non vide. Son existence
n'est **pas** vérifiée dans cette feature (spec 002).

## Case ID

Argument positionnel de `case init` : `^[A-Za-z0-9_-]{1,64}$`.

## Exit status

| Code | Signification | Déclencheur |
|---|---|---|
| 0 | Succès | Aide, version, commande réussie |
| 1 | Échec d'exécution | Erreur à l'exécution d'une commande fonctionnelle |
| 2 | Erreur d'usage | Commande inconnue, option manquante/invalide/répétée, argument en trop |
| 3 | Non implémenté | Commande valide dont la spec fonctionnelle n'est pas livrée |
| 4 | Échec d'intégrité | `case verify` détecte une preuve `MODIFIED`, `MISSING` ou `UNTRACKED` (spec 002) |
| 130 | Interruption | Ctrl+C |

## Transitions

```text
args ─► parse global ─► commande connue ? ─non─► 2
                            │oui
                            ▼
                  parse + validation ─échec─► 2
                            │ok
                            ▼
                  Implemented ? ─non─► 3
                            │oui
                            ▼
                     exécution ─► 0 | 1 | 130
```
