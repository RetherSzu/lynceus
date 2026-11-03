---

description: "Task list for 001-cli-foundation"
---

# Tasks: Fondation de la CLI DFIRFlow

**Input**: Design documents from `/specs/001-cli-foundation/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/cli.md, quickstart.md

**Tests**: inclus — la constitution (principe VI, NON-NEGOTIABLE) impose les tests avant
l'implémentation. Chaque test doit échouer avant la tâche d'implémentation correspondante.

**Organization**: tâches groupées par user story ; tout le code vit dans `cmd/dfirflow/`
(package `main`), cf. plan.md « Structure Decision ».

## Format: `[ID] [P?] [Story] Description`

- **[P]**: parallélisable (fichier différent, aucune dépendance sur une tâche non terminée)
- **[Story]**: user story de spec.md (US1…US4)

---

## Phase 1: Setup

**Purpose**: aucune initialisation nécessaire (module Go, Makefile et CI existent déjà).

- [ ] T001 Vérifier l'état de départ : `go vet ./...` et `go test ./cmd/dfirflow/` passent, `TestRunVersion` et `TestRunHelp` sont présents dans cmd/dfirflow/main_test.go (référence SC-006)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: briques partagées par toutes les stories — parsing des options, erreurs typées,
table des commandes, mapping des codes de sortie.

**⚠️ CRITICAL**: aucune story ne peut commencer avant la fin de cette phase.

- [ ] T002 [P] Écrire les tests unitaires du parsing dans cmd/dfirflow/flags_test.go : options avant/après positionnels (`ingest ./logs --case X` ⇒ positionnel `./logs`, case `X`), `--` termine les options (`-- -f.evtx` ⇒ positionnel `-f.evtx`), formes `-x`, `--x v`, `--x=v`, option à valeur unique répétée ⇒ erreur, valeur vide ⇒ erreur, liste CSV « pas de doublon, pas d'élément vide » (research.md R2, R3, R6)
- [ ] T003 [P] Écrire les tests du mapping erreur → code de sortie dans cmd/dfirflow/main_test.go (`TestExitCode`) : `nil`→0, erreur d'usage→2, `errNotImplemented`→3, contexte annulé→130, autre erreur→1 (data-model.md « Exit status ») ; ne pas modifier `TestRunVersion` ni `TestRunHelp`
- [ ] T004 Implémenter dans cmd/dfirflow/flags.go : `parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error)` (boucle de research.md R2), le type `flag.Value` à valeur unique `onceString` (R3), et `parseList(v string, allowed []string) ([]string, error)` (R6) — fait passer T002
- [ ] T005 Implémenter dans cmd/dfirflow/main.go : type `usageError`, variable `errNotImplemented`, fonction `exitCode(err error) int` (R4), et `main()` avec `signal.NotifyContext(context.Background(), os.Interrupt)` passant `ctx` à `run(ctx, args, stdout, stderr)` (R5) — adapter les deux appels de `run` dans main_test.go à la nouvelle signature sans changer leurs attentes — fait passer T003
- [ ] T006 Créer dans cmd/dfirflow/commands.go la structure `command` (Name, Summary, Usage, Example, fonction `setup(fs *flag.FlagSet)` déclarant les options, fonction `validate(positionals) error`, fonction `exec(ctx) error`) et la table ordonnée des 10 commandes du contrat (contracts/cli.md « Commandes »), chaque `exec` renvoyant `errNotImplemented` ; dispatch dans `run` sur 1 ou 2 mots (`case init`, `case verify`)

**Checkpoint**: la grammaire est câblée ; chaque story ajoute ses comportements et tests.

---

## Phase 3: User Story 1 — Découvrir les commandes disponibles (Priority: P1) 🎯 MVP

**Goal**: aide générale et aide par commande complètes, `--version` conservé.

**Independent Test**: `dfirflow`, `dfirflow --help`, `dfirflow <cmd> --help` pour les 10 commandes,
`dfirflow --version` — tous code 0, sortie sur stdout (quickstart.md §2).

### Tests for User Story 1

- [ ] T007 [US1] Écrire `TestHelp` dans cmd/dfirflow/main_test.go : sans argument et `-h`/`--help` ⇒ code 0, stdout contient `Usage: dfirflow [options]` et les 10 noms de commande dans l'ordre du pipeline (`case init`, `case verify`, `collect`, `ingest`, `import`, `timeline`, `detect`, `correlate`, `report`, `investigate`), stderr vide
- [ ] T008 [US1] Écrire `TestCommandHelp` (table sur les 10 commandes) dans cmd/dfirflow/main_test.go : `<cmd> --help` ⇒ code 0, stdout contient la ligne d'usage, chaque option du contrat, les mentions obligatoire/optionnelle, valeurs acceptées et défauts (`./cases`, `html,sqlite,jsonl`), et une ligne `Example:` (FR-017, SC-001) ; `--help` combiné à des arguments invalides ⇒ aide, code 0

### Implementation for User Story 1

- [ ] T009 [US1] Implémenter l'aide générale dans cmd/dfirflow/main.go : usage global commençant par `Usage: dfirflow [options] <command> [arguments]`, liste des commandes avec `Summary` dans l'ordre de la table, options globales `-h, --help` et `--version` (FR-005, FR-018)
- [ ] T010 [US1] Implémenter l'aide par commande dans cmd/dfirflow/commands.go : usage, positionnels, options (obligatoire/optionnelle, valeurs acceptées, défaut), exemple ; `-h`/`--help` prioritaire sur toute autre erreur (FR-017)
- [ ] T011 [US1] Garder `--version` global uniquement dans cmd/dfirflow/main.go : `--version` seul ⇒ `DFIRFlow <version>` ; `--version` avec une commande ⇒ erreur d'usage (cas limite de spec.md) — `TestRunVersion` doit passer inchangé

**Checkpoint**: US1 livrable seule (aide navigable, grammaire visible).

---

## Phase 4: User Story 2 — Être arrêté net par une commande mal formée (Priority: P1)

**Goal**: toute commande invalide est refusée avant tout accès disque, code 2, message précis.

**Independent Test**: jeu de commandes invalides de quickstart.md §3 — code 2, stdout vide,
message nommant l'option ou l'argument.

### Tests for User Story 2

- [ ] T012 [US2] Écrire `TestUsageErrors` (table) dans cmd/dfirflow/main_test.go couvrant : commande inconnue `analyze` ; `detect` sans `--case` ; `--case ""` ; `--case A --case B` ; `import --tool foo` (message liste `kape, orc, eztools, hayabusa, plaso, volatility`) ; `import` sans chemin et avec 2 chemins ; `report --format pdf`, `--format html,html`, `--format html,` ; `case init` sans ID, `case init ../evil`, ID de 65 caractères ; `case init` sans `--host` ou `--analyst` ; `timeline --from` non RFC 3339 ; `timeline --from` > `--to` ; `timeline --source foo` ; argument positionnel en trop pour `correlate`. Pour chaque cas : code 2, stdout vide, stderr commence par `dfirflow: <commande>: ` et contient le nom de l'option/argument, puis `Run 'dfirflow <commande> --help' for usage.`

### Implementation for User Story 2

- [ ] T013 [US2] Implémenter dans cmd/dfirflow/commands.go la validation de `case init` : exactement 1 positionnel correspondant à `^[A-Za-z0-9_-]{1,64}$`, `--host` et `--analyst` obligatoires non vides, `--dir` défaut `./cases` (FR-006)
- [ ] T014 [US2] Implémenter dans cmd/dfirflow/commands.go la validation de `case verify`, `collect`, `ingest`, `correlate`, `detect` : `--case` obligatoire « chemin non vide » (FR-002, FR-003), `--target` obligatoire pour `collect`, 0..n positionnels pour `ingest`, aucun positionnel pour les autres, `--rules` optionnel non vide (FR-007, FR-008, FR-009, FR-012, FR-013)
- [ ] T015 [US2] Implémenter dans cmd/dfirflow/commands.go la validation de `import` : `--case`, `--tool` obligatoires, `--tool` ∈ `kape`, `orc`, `eztools`, `hayabusa`, `plaso`, `volatility`, exactement 1 positionnel (FR-010)
- [ ] T016 [US2] Implémenter dans cmd/dfirflow/commands.go la validation de `timeline` : `--from`/`--to` au format `2006-01-02T15:04:05Z07:00` ou `2006-01-02T15:04:05` (UTC), `--from` ≤ `--to`, `--source` liste parmi `evtx`, `mft`, `usnjrnl`, `registry`, `prefetch`, `powershell`, `defender`, `memory` (FR-011, R6)
- [ ] T017 [US2] Implémenter dans cmd/dfirflow/commands.go la validation de `report` (`--format` liste parmi `html`, `sqlite`, `jsonl`, défaut les trois) et de `investigate` (`--case`, `--target` obligatoires) (FR-014, FR-015)
- [ ] T018 [US2] Implémenter dans cmd/dfirflow/main.go le format des erreurs d'usage : préfixe `dfirflow: <commande>: `, suggestion `Run 'dfirflow <commande> --help' for usage.` (ou `dfirflow --help` pour une commande inconnue), rien sur stdout ; neutraliser la sortie par défaut de `flag` (FR-022, FR-023, R8)

**Checkpoint**: US1 + US2 — grammaire complète et sûre.

---

## Phase 5: User Story 3 — Savoir qu'une commande n'est pas disponible (Priority: P2)

**Goal**: commande valide ⇒ `not implemented yet`, code 3, aucune écriture disque.

**Independent Test**: quickstart.md §4 — code 3, dossier courant inchangé, `investigate` nomme
`collect`.

### Tests for User Story 3

- [ ] T019 [US3] Écrire `TestNotImplemented` (table sur les 10 commandes avec arguments valides) dans cmd/dfirflow/main_test.go : code 3, stderr = `dfirflow: <commande>: not implemented yet\n`, stdout vide ; chemins pointant dans `t.TempDir()` et vérification que ce dossier reste vide (SC-003) ; `investigate` ⇒ `dfirflow: investigate: collect: not implemented yet`

### Implementation for User Story 3

- [ ] T020 [US3] Implémenter dans cmd/dfirflow/main.go le message `dfirflow: <commande>: not implemented yet` sur stderr pour `errNotImplemented` (FR-021)
- [ ] T021 [US3] Implémenter `investigate.exec` dans cmd/dfirflow/commands.go : appelle dans l'ordre les `exec` de `collect`, `ingest`, `timeline`, `detect`, `correlate`, `report`, s'arrête à la première erreur et la préfixe du nom de l'étape (FR-015, R7)

**Checkpoint**: US1–US3 — contrat de sortie complet sauf usage script.

---

## Phase 6: User Story 4 — Enchaîner le pipeline dans un script (Priority: P3)

**Goal**: comportements utiles aux scripts : options entremêlées, `--`, séparation stdout/stderr,
interruption.

**Independent Test**: quickstart.md §5 — codes de sortie corrects et stdout vide en cas d'erreur.

### Tests for User Story 4

- [ ] T022 [US4] Écrire `TestScriptUsage` dans cmd/dfirflow/main_test.go : `ingest ./logs --case X` ⇒ code 3 (options après positionnel acceptées) ; `ingest --case X -- -fichier.evtx` ⇒ code 3 ; `run` avec un contexte déjà annulé ⇒ `exitCode` 130 et aucun message supplémentaire sur stderr

### Implementation for User Story 4

- [ ] T023 [US4] Vérifier dans cmd/dfirflow/main.go que `exitCode` renvoie 130 sans écrire de message quand `ctx.Err() != nil` et que `run` consulte `ctx` avant chaque `exec` (y compris entre les étapes d'`investigate`) (R5)

**Checkpoint**: les 4 stories sont livrées.

---

## Phase 7: Polish & Cross-Cutting Concerns

- [ ] T024 Exécuter `gofmt -l .`, `go vet ./...`, `go test ./... -race -cover` et corriger toute anomalie
- [ ] T025 Dérouler manuellement quickstart.md §2 à §5 avec `make build` et cocher chaque attendu
- [ ] T026 [P] Mettre à jour la section « Utilisation » de docs/README_dfirflow.md uniquement si le dossier docs/ est versionné — sinon consigner l'écart dans le message de PR (grammaire : `--case <chemin>`, `import --tool`)

---

## Dependencies & Execution Order

- **Phase 1** → **Phase 2** (T002/T003 en parallèle, puis T004, T005, T006) → stories.
- **US1** (P1) et **US2** (P1) dépendent seulement de la Phase 2 ; elles modifient les mêmes
  fichiers (`commands.go`, `main.go`, `main_test.go`), donc à exécuter séquentiellement : US1 puis US2.
- **US3** dépend de la Phase 2 (indépendante fonctionnellement de US1/US2, même fichier).
- **US4** dépend de la Phase 2 et de T021 (`investigate`).
- **Polish** après toutes les stories.

## Parallel Opportunities

- T002 (`flags_test.go`) ∥ T003 (`main_test.go`) : fichiers distincts.
- T026 ∥ T024/T025.
- Les autres tâches touchent `commands.go`, `main.go` ou `main_test.go` : séquentielles.

```text
# Phase 2, en parallèle :
T002  flags_test.go   — tests du parsing
T003  main_test.go    — tests des codes de sortie
```

## Implementation Strategy

1. **MVP** = Phase 1 + 2 + US1 : la grammaire est visible et navigable.
2. **+ US2** : la CLI devient sûre (validation stricte) — livrable minimal recommandé pour la PR.
3. **+ US3, US4** : contrat de sortie complet ; ouvrir la PR `feature/001-cli-foundation` → `dev`.
4. À chaque checkpoint : `go test ./cmd/dfirflow/ -race`.
