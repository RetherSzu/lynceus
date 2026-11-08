# Implementation Plan: Modèle d'événement normalisé et contrat de parseur

**Branch**: `feature/003-event-model` | **Date**: 2026-11-03 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/003-event-model/spec.md`

## Summary

Remplacer le squelette `internal/normalizer` par le modèle `Event` et `Detection` des décisions
D2–D11 : constantes des listes fermées, `uid`, aides de normalisation (hôte, compte, hexa),
validation, encodeur et décodeur JSONL canoniques, tri. Remplacer l'interface de
`internal/parser` par le contrat D9 (`Source`, `Anomaly`, `Sink`, `Parser`) et fournir le `Sink`
de validation, testé par un faux parseur. Amender `timeline --source` (FR-026).

## Technical Context

**Language/Version**: Go, `go 1.18` (`go.mod`) ; APIs postérieures interdites (`slices`, `maps`,
`cmp`, `min`)

**Primary Dependencies**: bibliothèque standard uniquement (`encoding/json`, `crypto/sha256`,
`bufio`, `time`, `sort`, `unicode/utf8`, `regexp`)

**Storage**: fichiers JSONL (écrits par les specs 005/006) ; fichier de référence
`internal/normalizer/testdata/events.v1.jsonl`

**Testing**: `go test` ; fichier de référence comparé octet par octet ; faux parseur dans
`internal/parser/fake_test.go`

**Target Platform**: Windows x64 et Linux x64 (CI de test sur les deux : job `test-windows`, vérifié par T021)

**Project Type**: packages internes + amendement CLI

**Performance Goals**: encodage et décodage en flux, une ligne à la fois ; mémoire indépendante de
la taille du fichier (hors tri, appelé par les specs 005/006)

**Constraints**: sortie identique à l'octet (principe IV) ; aucune perte silencieuse (principe V) ;
aucune dépendance (principe VII)

**Scale/Scope**: millions d'événements par cas ; lignes jusqu'à plusieurs Mo (scripts 4104)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principe | Vérification | Statut |
|---|---|---|
| I. Binaire autonome | Stdlib uniquement | ✅ |
| II. Natif d'abord | Contrat commun parseurs / importers ; importers en lecture seule (FR-016d) | ✅ |
| III. Chaîne de preuve | `uid` dérivé du SHA-256 du manifeste ; `source_file`, `record_locator`, `ingest` sur chaque événement | ✅ |
| IV. Reproductibilité | Ordre des champs, clés triées, horodatages à largeur fixe, tri total, fichier de référence | ✅ |
| V. Traitement en flux | `ReaderAt` + rappels synchrones ; lecture JSONL ligne à ligne ; anomalies obligatoires | ✅ |
| VI. Tests d'abord | Tests et fichier de référence écrits avant le code ; oracle EVTX différé à la 005 | ✅ |
| VII. Licences | Aucune dépendance ; artefacts GPL du spike non commités | ✅ |
| VIII. Détection | `Detection` déterministe (id par hash), aucun moteur ici | ✅ |
| IX. Windows-first | Rendu des valeurs aligné sur la vue XML Windows ; `\n` sur toutes plateformes | ✅ |

Aucune violation.

**Re-check post-design** : ✅ (aucune dépendance ajoutée ; aucune écriture de fichier par ces
packages hors tests).

## Project Structure

### Documentation (this feature)

```text
specs/003-event-model/
├── decisions.md          # D1–D11 validées
├── spike-report.md       # constats C1–C14
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── event-model.md    # contrat normatif versionné (historique)
├── checklists/requirements.md
└── tasks.md
```

### Source Code (repository root)

```text
internal/normalizer/
├── event.go              # Event, Account, TimestampEntry, constantes (remplace le squelette)
├── time.go               # Time (JSON à 6 décimales)
├── normalize.go          # UID, NormalizeHost, NewAccount, FormatHex
├── validate.go           # Violation, Event.Validate, Detection.Validate
├── detection.go          # Detection, DetectionID
├── jsonl.go              # Encoder, ReadEvents, ReadDetections, SortEvents, SortDetections
├── *_test.go
└── testdata/events.v1.jsonl
internal/parser/
├── parser.go             # Source, Anomaly, Kind*, Sink, Parser, Validating (remplace l'interface)
├── parser_test.go
└── fake_test.go          # faux parseur (R7)
cmd/dfirflow/commands.go  # FR-026 : liste `sources`
cmd/dfirflow/main_test.go # cas `--source powershell` refusé
.github/workflows/ci.yml  # job test-windows (SC-001)
.gitattributes            # *.jsonl en LF
```

**Structure Decision**: les packages existants sont conservés et leurs squelettes remplacés ;
aucun appelant n'existe (vérifié par recherche). `internal/collector` n'est pas touché.
Rupture annoncée (constitution, *Contraintes*) : le squelette `Event` n'a jamais été exporté ; le
format démarre à `schema_version 1`, sans compatibilité à assurer.

## Complexity Tracking

Aucune violation à justifier.
