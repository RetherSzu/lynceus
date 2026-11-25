# Implementation Plan: Collecte des preuves

**Branch**: `feature/004-evidence-collection` | **Date**: 2026-11-25 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/004-evidence-collection/spec.md`

## Summary

Implémenter `internal/collector` (squelette vide aujourd'hui) : repérage sans casse des EVTX sous la
racine d'un volume, garde-fous sur la cible, relevé des métadonnées d'origine, puis enregistrement
de chaque fichier par `casefile.AddEvidence` avec statuts `COLLECTED`/`ALREADY`/`CONFLICT`/
`FAILED`/`SKIPPED`. Amender `internal/case` (champ `origin` du manifeste, contexte d'annulation,
empreinte des preuves connues) et brancher la commande `collect` de la CLI, avec sortie triée et
entrée `collect` dans `case.log`.

## Technical Context

**Language/Version**: Go, `go 1.18` (`go.mod`)

**Primary Dependencies**: bibliothèque standard uniquement (`os`, `io`, `path/filepath`,
`syscall` derrière build tags)

**Storage**: dossier de cas de la spec 002 — `evidence/`, `hashes/manifest.jsonl`, `case.log`

**Testing**: `go test -race` dans `internal/case`, `internal/collector` (arborescences
temporaires) et `cmd/dfirflow` (bout en bout via `cli`)

**Target Platform**: Windows x64 et Linux x64

**Project Type**: CLI + packages internes

**Performance Goals**: débit limité par le disque ; mémoire constante quel que soit le volume
(SC-005)

**Constraints**: aucune écriture dans la cible, copie en flux, sorties triées, manifeste et journal
en ajout seul

**Scale/Scope**: une cible par exécution, de quelques à quelques centaines de fichiers EVTX
(jusqu'à plusieurs Go)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principe | Vérification | Statut |
|---|---|---|
| I. Binaire autonome | Stdlib uniquement, aucun réseau | ✅ |
| II. Natif d'abord | Copie de fichiers, aucun outil tiers lancé | ✅ |
| III. Chaîne de preuve | Cible en lecture seule, SHA-256 + vérification de la copie (spec 002), origine dans le manifeste, entrée `collect` dans `case.log` | ✅ |
| IV. Reproductibilité | Sortie et `problems` triés par chemin, dates UTC, version de l'outil journalisée | ✅ |
| V. Traitement en flux | `io.Copy` à tampon fixe, aucun fichier entier en mémoire ; une erreur fichier n'arrête pas la collecte | ✅ |
| VI. Tests d'abord | Tests écrits avant le code, sur fixtures synthétiques ; pas d'oracle (aucun parser) | ✅ |
| VII. Licences | Aucune dépendance | ✅ |
| VIII. Détection | Sans objet | ✅ N/A |
| IX. Windows-first | Horodatages et détection de verrou via `syscall` dans des fichiers `_windows.go` / `_linux.go` / repli générique ; compilation Linux intacte | ✅ |

Aucune violation.

**Re-check post-design** : ✅ — le design ajoute un champ optionnel au manifeste (rétrocompatible,
`case verify` inchangé) et ne crée aucune écriture hors du dossier du cas.

## Project Structure

### Documentation (this feature)

```text
specs/004-evidence-collection/
├── plan.md
├── research.md           # R1–R7
├── data-model.md         # Origin, CollectResult, entrée de journal
├── quickstart.md
├── contracts/
│   └── collect.md        # sortie, erreurs et codes de `collect`
└── tasks.md              # /speckit-tasks
```

### Source Code (repository root)

```text
internal/case/                # package casefile (amendé)
├── case.go                   # entries: fichier → empreinte ; Recorded()
├── manifest.go               # Origin, ManifestEntry.Origin, AddEvidence(ctx, src, rel, origin)
└── case_test.go
internal/collector/           # package collector (implémenté ; squelette remplacé)
├── collector.go              # Collect(ctx, *casefile.Case, target) ([]Result, error), statuts
├── patterns.go               # table des motifs (evtx) et résolution sans casse
├── origin.go                 # relevé commun (Lstat, ModTime)
├── origin_windows.go         # création/accès via Win32FileAttributeData
├── origin_linux.go           # accès/changement via Stat_t
├── origin_other.go           # repli : modification seule
├── locked_windows.go         # ERROR_SHARING_VIOLATION / LOCK_VIOLATION
├── locked_other.go
└── collector_test.go
cmd/dfirflow/
├── commands.go               # exec de `collect` (sortie, journal, codes)
└── main_test.go
```

**Structure Decision** : le package `internal/collector` existant porte la logique de collecte ;
`internal/case` reste seul à écrire dans le dossier du cas. Les fichiers `filesystem.go` et
`metadata.go` du squelette sont remplacés par la structure ci-dessus. Les contrats de la spec 002
(`case-layout.md`, `data-model.md`) reçoivent une note renvoyant au champ `origin`.

## Complexity Tracking

Aucune violation à justifier.
