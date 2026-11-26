# Implementation Plan: Détection par règles mono-événement

**Branch**: `feature/012-detection` | **Date**: 2026-11-26 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/012-detection/spec.md`

## Summary

Créer le package `internal/detection` qui charge un jeu de règles Sigma mono-événement (jeu
embarqué par `embed`, ou fichiers de `--rules`), les compile en un arbre de conditions, puis lit en
flux les événements de `normalized/` des preuves du manifeste et évalue, pour chaque événement
EVTX, les seules règles de son canal. Chaque correspondance donne une `normalizer.Detection`
(spec 003). Les détections sont triées par `timestamp` puis `id` avec le tri externe de la
spec 006, extrait dans un package commun `internal/extsort`, et écrites de façon atomique dans
`detections/detections.jsonl`. Brancher la commande `detect` (entrée `case.log`, résumé,
avertissements, codes de sortie) ; `investigate` s'arrête alors à `correlate`.

## Technical Context

**Language/Version**: Go, `go 1.18` (`go.mod`)

**Primary Dependencies**: bibliothèque standard (`embed`, `regexp`, `crypto/sha256`,
`io/fs`) ; première dépendance externe `go.yaml.in/yaml/v3` v3.0.6 (MIT et Apache-2.0, aucune
dépendance transitive, `go 1.16`) pour lire les règles (R1) ; packages internes `normalizer`
(`ReadEvents`, `Detection`, `DetectionID`, encodeur canonique), `case` (manifeste, journal),
`ingest` (nom des fichiers d'événements), `extsort` (tri externe et écriture atomique, extraits de
`internal/timeline`)

**Storage**: dossier de cas — lecture du manifeste et de `normalized/`, écriture de
`detections/` (fichier de détections et dossier de travail temporaire) et de `case.log`

**Testing**: `go test -race` ; un cas positif et un cas négatif par règle embarquée, sur des
événements synthétiques (R7) ; tests du sous-ensemble Sigma (modificateurs, jokers, conditions,
refus) ; journal Security de référence pour SC-001 (15 détections) ; test de volume sous
`DFIRFLOW_LARGE=1`

**Target Platform**: Windows x64 et Linux x64

**Project Type**: CLI + packages internes

**Performance Goals**: 10 millions d'événements en moins de 5 minutes, mémoire au plus 256 Mio
(SC-004)

**Constraints**: mémoire bornée indépendante du nombre d'événements et de détections ; sortie
octet par octet identique quel que soit l'ordre des règles et des fichiers ; remplacement
atomique ; aucune écriture dans `evidence/`, `normalized/`, `timeline/`

**Scale/Scope**: de quelques centaines à plusieurs dizaines de millions d'événements ; de quelques
règles à quelques milliers (corpus fourni par `--rules`)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principe | Vérification | Statut |
|---|---|---|
| I. Binaire autonome | Règles embarquées dans le binaire ; dépendance YAML en Go pur, compilée statiquement ; aucun réseau | Conforme |
| II. Natif d'abord | Aucun outil tiers lancé ; Sigma est un format de règles lu, pas un moteur externe | Conforme |
| III. Chaîne de preuve | Chaque détection cite l'`uid` de l'événement, qui porte `source_file`, `source_sha256` et `record_id` ; lecture seule du cas hors `detections/` ; entrée `detect` avec version des règles et SHA-256 | Conforme |
| IV. Reproductibilité | `rule_version` = empreinte du fichier normalisé en fin de ligne LF (R4) ; version du jeu enregistrée ; tri total `(timestamp, id)` ; règles appliquées indépendamment de leur ordre | Conforme |
| V. Traitement en flux | Événements lus ligne à ligne ; détections triées par le tri externe borné de la 006 (R6) | Conforme |
| VI. Tests d'abord et oracle | Positif et négatif par règle embarquée, vérifié par un test qui échoue si une règle en manque (R7) ; les parsers ne changent pas, pas de nouvel oracle | Conforme |
| VII. Licences | `go.yaml.in/yaml/v3` MIT et Apache-2.0, version figée dans `go.mod` et `go.sum` ; règles embarquées écrites pour DFIRFlow (Apache-2.0) | Conforme |
| VIII. Détection | Règles déclaratives Sigma versionnées ; identifiant, sévérité, technique ATT&CK obligatoires dans le jeu embarqué ; champs structurés seulement (R3) ; aide et contrat présentent une détection comme une piste | Conforme |
| IX. Windows-first | Seul le produit `windows` est applicable ; chemins via `filepath` ; empreinte des règles indépendante des fins de ligne Windows | Conforme |

Aucune violation. Revérifié après la phase 1 (research, data-model, contrat) : inchangé.

## Project Structure

### Documentation (this feature)

```text
specs/012-detection/
├── spec.md
├── plan.md              # ce fichier
├── research.md          # R1 à R8
├── data-model.md        # règle, sous-ensemble Sigma, jeu embarqué, détection, entrée case.log
├── quickstart.md        # validation de bout en bout
├── contracts/
│   └── detect.md        # sortie standard et d'erreur, fichier produit, case.log, codes de sortie
├── checklists/
│   └── requirements.md
└── tasks.md             # /speckit-tasks
```

### Source Code (repository root)

```text
internal/extsort/                # extrait de internal/timeline (R6), sans changement de comportement
├── extsort.go           # Key, Sorter (Add, Finish, Cleanup), décodeur de clé fourni par l'appelant
├── atomic.go            # WriteAtomic : .partial, SHA-256 au fil de l'eau, Sync, Rename
└── extsort_test.go      # tests repris de timeline/sort_test.go

internal/ingest/
├── files.go             # EventFiles(c) : fichiers d'événements des preuves et fichiers inconnus (R5)
└── ingest_test.go       # TestEventFiles ajouté

internal/timeline/
├── timeline.go          # utilise ingest.EventFiles, extsort.Sorter, extsort.WriteAtomic
└── sort.go              # réduit à la clé canonique des événements et à son décodeur

internal/detection/
├── rule.go              # Rule, chargement et validation d'un fichier Sigma, refus motivés
├── condition.go         # analyse de la condition, arbre d'évaluation
├── match.go             # valeurs, jokers, modificateurs, accès aux champs de l'événement
├── ruleset.go           # Load (embarqué ou --rules), doublons, version du jeu, index par canal
├── detection.go         # Summary, Run : lecture des événements, détections, tri, écriture
├── rules/*.yml          # jeu embarqué (7 règles, data-model.md)
├── rule_test.go         # chargement, champs, refus motivés
├── match_test.go        # valeurs, jokers, modificateurs, champs
├── condition_test.go    # condition, priorités, imbrication
├── ruleset_test.go      # --rules : parcours, doublons, version du jeu
├── fuzz_test.go         # FuzzParseRule : aucune panique sur une règle malformée
├── rules_test.go        # positif et négatif par règle embarquée
└── detection_test.go    # Run : entrées, ordre, déterminisme, erreurs, nettoyage, volume

cmd/dfirflow/
├── commands.go          # detectCmd branchée ; aide de detect ; investigate s'arrête à correlate
└── main_test.go         # TestDetectCommand, TestDetectLog, investigate jusqu'à correlate

go.mod, go.sum                   # go.yaml.in/yaml/v3 v3.0.6
docs/architecture-actuelle.md    # 012 marquée Codé, flux detect, dépendance YAML
```

**Structure Decision**: un package `internal/detection` (nom prévu par `docs/README_dfirflow.md`)
avec le même découpage que `ingest` et `timeline` : un `Run` appelé par la CLI, la CLI se charge
de l'affichage et du journal. Le tri externe et l'écriture atomique de la 006 sont déplacés tels
quels dans `internal/extsort` plutôt que dupliqués ; la sélection des fichiers d'événements passe
dans `ingest`, qui en fixe le nommage. Aucune modification du modèle 003.

## Complexity Tracking

| Écart | Pourquoi | Alternative plus simple écartée |
|---|---|---|
| Première dépendance externe (`go.yaml.in/yaml/v3`) | Les règles Sigma sont du YAML, entrée non fiable (constitution) ; un lecteur YAML sûr (ancres, scalaires en bloc, guillemets, échappements) est un projet en soi | Lecteur YAML maison limité : plusieurs centaines de lignes non éprouvées sur une entrée non fiable ; JSON au lieu de YAML : incompatible avec Sigma |
| Extraction de `internal/extsort` | Les détections doivent être triées sous mémoire bornée comme la chronologie | Copier le tri dans `detection` : deux implémentations à maintenir ; tri en mémoire : contraire à FR-019 |
