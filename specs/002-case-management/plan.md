# Implementation Plan: Gestion des cas d'investigation

**Branch**: `feature/002-case-management` | **Date**: 2026-11-03 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/002-case-management/spec.md`

## Summary

Implémenter le package `internal/case` (package Go `casefile`) : création atomique d'un dossier de
cas, lecture et validation d'un cas existant, enregistrement en flux d'une preuve (copie + SHA-256
+ vérification + lecture seule + manifeste en ajout seul), vérification d'intégrité
(`OK`/`MODIFIED`/`MISSING`/`UNTRACKED`) et journal JSONL des opérations. Brancher `case init` et
`case verify` de la CLI (spec 001) sur ce package ; ajouter le code de sortie 4.

## Technical Context

**Language/Version**: Go, `go 1.18` (`go.mod`)

**Primary Dependencies**: bibliothèque standard uniquement (`crypto/sha256`, `encoding/json`,
`io`, `os`, `path/filepath`)

**Storage**: fichiers du dossier de cas — `case.json`, `hashes/manifest.jsonl`, `case.log`

**Testing**: `go test` dans `internal/case` (dossiers temporaires) et `cmd/dfirflow` (bout en bout
via `cli`)

**Target Platform**: Windows x64 et Linux x64

**Project Type**: CLI + package interne

**Performance Goals**: hachage limité par le débit disque ; mémoire < 100 Mo quel que soit le
volume (SC-004)

**Constraints**: lecture en flux (tampon fixe), aucune réécriture d'un fichier sous `evidence/`,
manifeste et journal en ajout seul, sorties déterministes

**Scale/Scope**: cas de quelques fichiers à plusieurs dizaines de Go

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principe | Vérification | Statut |
|---|---|---|
| I. Binaire autonome | Stdlib uniquement | ✅ |
| II. Natif d'abord | Sans objet (aucun outil tiers) | ✅ N/A |
| III. Chaîne de preuve | SHA-256 à l'enregistrement, preuve en lecture seule, manifeste et journal en ajout seul, `case verify` détecte toute altération | ✅ |
| IV. Reproductibilité | Dates UTC, sortie de `verify` triée par chemin, `schema_version` et `tool_version` enregistrés | ✅ |
| V. Traitement en flux | Copie et hachage par `io.Copy` à tampon fixe ; jamais de fichier entier en mémoire | ✅ |
| VI. Tests d'abord | Tests unitaires du package et tests CLI écrits avant le code | ✅ |
| VII. Licences | Aucune dépendance | ✅ |
| VIII. Détection | Sans objet | ✅ N/A |
| IX. Windows-first | `os.Chmod(0o444)` pose l'attribut lecture seule sous Windows ; chemins du manifeste en `/` | ✅ |

Aucune violation.

**Re-check post-design** : ✅ (le design n'ajoute ni dépendance ni écriture hors du dossier du cas).

## Project Structure

### Documentation (this feature)

```text
specs/002-case-management/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── case-layout.md    # format du dossier de cas, manifeste, journal, sortie de verify
└── tasks.md
```

### Source Code (repository root)

```text
internal/case/            # package casefile
├── case.go               # Case, Create, Open (remplace New / Load)
├── manifest.go           # ManifestEntry, AddEvidence (remplace SaveManifest)
├── verify.go             # Verify, VerifyResult, statuts
├── journal.go            # LogEntry, Log
└── case_test.go
cmd/dfirflow/
├── commands.go           # exec de case init / case verify
├── main.go               # errIntegrity → code 4
└── main_test.go
```

**Structure Decision**: le package existant `internal/case` est complété ; l'API squelette
(`New`, méthode `Load`, `SaveManifest`, `Verify() (bool, error)`) est remplacée par une API
adaptée à la spec — aucun appelant n'existe encore.

## Complexity Tracking

Aucune violation à justifier.
