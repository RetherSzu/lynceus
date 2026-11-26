# Implementation Plan: Chronologie consolidée du cas

**Branch**: `feature/006-timeline` | **Date**: 2026-11-26 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/006-timeline/spec.md`

## Summary

Créer le package `internal/timeline` qui lit en flux les fichiers d'événements de `normalized/`
des preuves du manifeste, filtre chaque événement (fenêtre et sources), et produit
`timeline/timeline.jsonl` dans l'ordre canonique de la spec 003 par un tri externe : segments triés
en mémoire sous un budget d'octets, écrits dans un dossier de travail du cas, puis fusionnés.
L'écriture passe par un fichier `.partial` renommé à la fin, avec calcul de l'empreinte SHA-256 au
fil de l'écriture. Brancher la commande `timeline` (entrée `case.log`, résumé, codes de sortie) ;
`investigate` s'arrête alors à `detect`.

## Technical Context

**Language/Version**: Go, `go 1.18` (`go.mod`)

**Primary Dependencies**: bibliothèque standard uniquement (`container/heap`, `bufio`,
`encoding/json`, `crypto/sha256`, `sort`) ; packages internes `normalizer` (décodage strict,
encodage canonique) et `case` (manifeste, journal)

**Storage**: dossier de cas — lecture du manifeste et de `normalized/`, écriture de `timeline/`
(chronologie et dossier de travail temporaire) et de `case.log`

**Testing**: `go test -race` ; l'oracle de l'ordre est `normalizer.SortEvents` appliqué en mémoire
au même jeu d'événements ; test du tri externe en forçant un petit budget ; test de volume sous
`DFIRFLOW_LARGE=1`

**Target Platform**: Windows x64 et Linux x64

**Project Type**: CLI + packages internes

**Performance Goals**: 10 millions d'événements en moins de 5 minutes, mémoire au plus 256 Mio
(SC-003)

**Constraints**: mémoire bornée indépendante du volume, sortie octet par octet identique,
remplacement atomique, aucune écriture dans `evidence/` ni `normalized/`

**Scale/Scope**: de quelques centaines à plusieurs dizaines de millions d'événements par cas

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principe | Vérification | Statut |
|---|---|---|
| I. Binaire autonome | Bibliothèque standard uniquement ; aucun réseau ; aucune base externe | Conforme |
| II. Natif d'abord | Aucun outil tiers ; la chronologie lit seulement les sorties de `ingest` | Conforme |
| III. Chaîne de preuve | Lecture seule de `evidence/` et `normalized/` ; événements recopiés sans modification (provenance conservée) ; entrée `timeline` avec filtres et SHA-256 dans `case.log` | Conforme |
| IV. Reproductibilité | Ordre total canonique (FR-018a) ; fichiers lus dans l'ordre du manifeste ; fusion par clé, indépendante du découpage en segments (R3) | Conforme |
| V. Traitement en flux | Lecture ligne à ligne ; budget d'octets par segment (R2) ; fusion à fan-in borné par fichier ouvert | Conforme |
| VI. Tests d'abord et oracle | Tests avant le code ; oracle de tri `SortEvents` ; équivalence segment unique et segments multiples ; pas d'outil de référence externe pour une chronologie JSONL (R6) | Conforme |
| VII. Licences | Aucun code tiers ajouté | Conforme |
| VIII. Détection | Aucune détection ; la chronologie est l'entrée de la spec 012 | Conforme |
| IX. Windows-first | Renommage atomique avec remplacement sous Windows (`os.Rename`) ; chemins via `filepath` | Conforme |

Aucune violation. Revérifié après la phase 1 (research, data-model, contrat) : inchangé.

## Project Structure

### Documentation (this feature)

```text
specs/006-timeline/
├── spec.md
├── plan.md              # ce fichier
├── research.md          # R1 à R7
├── data-model.md        # filtre, clé de tri, résumé, entrée case.log
├── quickstart.md        # validation de bout en bout
├── contracts/
│   └── timeline.md      # sortie standard, fichier produit, case.log, codes de sortie
├── checklists/
│   └── requirements.md
└── tasks.md             # /speckit-tasks
```

### Source Code (repository root)

```text
internal/timeline/
├── timeline.go          # Filter, Summary, Run : sélection des fichiers, filtrage, écriture atomique
├── sort.go              # clé canonique, segments triés, fusion k voies
├── sort_test.go         # ordre des clés, tri externe multi-segments et multi-passes
└── timeline_test.go     # Run : entrées, filtres, erreurs, nettoyage, journal, volume

cmd/dfirflow/
├── commands.go          # timelineCmd branchée ; investigate s'arrête à detect
└── main_test.go         # TestTimelineCommand, TestTimelineLog, investigate jusqu'à detect

docs/architecture-actuelle.md   # 006 marquée Codé, flux timeline
```

**Structure Decision**: un package `internal/timeline` à côté de `internal/ingest`, même découpage
(un `Run` appelé par la CLI, la CLI se charge de l'affichage et du journal). Aucune modification
du modèle 003 ni de `normalizer`, hormis la réutilisation de `ReadEvents` et `NewEncoder`.

## Complexity Tracking

Aucune dérogation.
