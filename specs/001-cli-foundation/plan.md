# Implementation Plan: Fondation de la CLI DFIRFlow

**Branch**: `feature/001-cli-foundation` | **Date**: 2026-11-02 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/001-cli-foundation/spec.md`

## Summary

Remplacer la CLI actuelle (`--help`, `--version` seulement) par la grammaire complète des
10 commandes du pipeline DFIRFlow : dispatch des sous-commandes, aide générale et par commande,
validation syntaxique stricte avant tout accès disque, contrat de codes de sortie
(0/1/2/3/130) et séparation stdout/stderr. Chaque commande valide répond « not implemented yet »
(code 3) en attendant sa spec fonctionnelle. Approche : bibliothèque standard Go uniquement
(`flag`, `os/signal`, `regexp`, `time`), une table de commandes dans `cmd/dfirflow`, aucune
nouvelle dépendance.

## Technical Context

**Language/Version**: Go, `go 1.18` déclaré dans `go.mod` (CI : `stable`, local : 1.22)

**Primary Dependencies**: aucune — bibliothèque standard uniquement (voir research.md R1)

**Storage**: N/A — la feature n'écrit rien sur le disque (FR-021, FR-024)

**Testing**: `go test` (tests table-driven sur `run(args, stdout, stderr)`), `-race` en CI

**Target Platform**: Windows x64 et Linux x64 (station d'analyse), binaire statique

**Project Type**: CLI (binaire unique)

**Performance Goals**: toute réponse (aide, erreur, non implémenté) en < 1 s (SC-005) — triviale
sans I/O

**Constraints**: hors ligne, aucune écriture disque, aucune dépendance externe, compatible
`go 1.18`

**Scale/Scope**: 10 commandes, ~15 options, 5 codes de sortie

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principe | Vérification | Statut |
|---|---|---|
| I. Binaire autonome et hors ligne | Stdlib uniquement, aucun accès réseau, 100 % CLI | ✅ |
| II. Natif d'abord, import sans exécution | `import` ne fait que valider ses arguments ; aucune exécution de programme tiers (FR-016) | ✅ |
| III. Chaîne de preuve | Validation complète avant tout accès disque ; aucune écriture tant que non implémenté | ✅ |
| IV. Reproductibilité | Sorties d'aide déterministes (ordre fixe des commandes et options) ; dates en UTC | ✅ |
| V. Traitement en flux | Sans objet (aucun artefact lu) | ✅ N/A |
| VI. Tests d'abord | Tests table-driven écrits avant l'implémentation pour chaque scénario et cas limite | ✅ |
| VII. Licences permissives | Aucune dépendance ajoutée | ✅ |
| VIII. Détection déterministe | Sans objet | ✅ N/A |
| IX. Windows-first | Aucun appel spécifique OS ; `os.Interrupt` portable Windows/Linux | ✅ |

Aucune violation ; *Complexity Tracking* vide.

**Re-check post-design** : le design (research, data-model, contrat CLI) n'introduit ni
dépendance, ni I/O, ni appel système spécifique. ✅

## Project Structure

### Documentation (this feature)

```text
specs/001-cli-foundation/
├── plan.md              # Ce fichier
├── research.md          # Phase 0
├── data-model.md        # Phase 1
├── quickstart.md        # Phase 1
├── contracts/
│   └── cli.md           # Phase 1 : grammaire et contrat de sortie
└── tasks.md             # Phase 2 (/speckit-tasks)
```

### Source Code (repository root)

```text
cmd/dfirflow/
├── main.go          # point d'entrée : signal → contexte, run(), mapping erreur → code de sortie
├── commands.go      # table des 10 commandes (nom, usage, options, validation, exemple)
├── flags.go         # parsing options/positionnels entremêlés, option à valeur unique, listes
└── main_test.go     # tests existants conservés + tests table-driven de la grammaire
```

**Structure Decision**: la CLI reste dans `cmd/dfirflow` (package `main`), là où se trouvent déjà
`run()` et ses tests. Pas de package `internal/cli` : aucune autre partie du code n'en a besoin
aujourd'hui. Les commandes fonctionnelles futures appelleront `internal/case`, `internal/collector`,
etc. depuis la table de commandes.

## Complexity Tracking

Aucune violation à justifier.
