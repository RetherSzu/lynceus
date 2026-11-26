---

description: "Task list for 006-timeline"
---

# Tasks: Chronologie consolidée du cas

**Input**: Design documents from `/specs/006-timeline/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/timeline.md,
quickstart.md

**Tests**: inclus (constitution, principe VI) ; chaque test est écrit avant le code qu'il couvre.
Compatibilité `go 1.18` : pas de `slices`, `maps`, `cmp`, `min`, `errors.Join`. Aucun module
externe ne doit être ajouté à `go.mod`. Les fixtures d'événements sont synthétiques, écrites par
les tests avec `normalizer.NewEncoder` dans un cas créé par `casefile.Create`.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [X] T001 Vérifier que `go test -race ./...` passe sur `feature/006-timeline` (base `dev`, specs 001 à 005) et que `go.mod` ne déclare aucune dépendance

---

## Phase 2: Foundational (clé de tri et tri externe, bloquant pour toutes les stories)

- [X] T002 Écrire dans internal/timeline/sort_test.go `TestKeyOrder` : la comparaison des clés `(timestamp µs, source_file, record_id, uid)` donne le même ordre que `normalizer.SortEvents` sur un jeu d'événements synthétiques avec égalités d'horodatage à la µs (différences sous la µs comprises), de `source_file` et de `record_id` (research.md R3)
- [X] T003 Écrire dans internal/timeline/sort_test.go `TestExternalSort` : 5 000 événements synthétiques mélangés, triés avec un budget de 4 Kio (plusieurs segments) et une limite de fusion abaissée à 3 (plusieurs passes) → octets identiques à ceux d'un tri à segment unique et à l'encodage canonique de `SortEvents` ; aucun fichier restant dans le dossier de travail (research.md R2)
- [X] T004 Créer internal/timeline/sort.go : type `key` (`ts int64` en µs UTC, `src string`, `rid uint64`, `uid string`) et `less` ; `sorter` qui accumule `(key, ligne canonique)`, compte la taille des lignes et des clés, trie et écrit un segment dans le dossier de travail quand le budget est dépassé (par défaut 64 Mio, variable de package modifiable par les tests) ; `finish(w io.Writer)` écrit directement si un seul segment en mémoire, sinon fusionne avec `container/heap` en ne décodant que la clé de chaque ligne et en recopiant les octets, par passes de 128 segments au plus (variable de package) ; la fusion vérifie le contexte entre deux lignes
- [X] T005 Faire passer T002 et T003 ; `go vet ./internal/timeline/`

**Checkpoint** : tri externe vert et équivalent à `SortEvents`.

---

## Phase 3: User Story 1 — Obtenir la chronologie complète du cas (P1) MVP

**Goal**: `timeline --case <cas>` écrit `timeline/timeline.jsonl` avec tous les événements ingérés, dans l'ordre canonique.

**Independent Test**: deux fichiers d'événements dans un cas, `timeline.Run` → réunion des événements, ordre de `SortEvents`, relance identique octet par octet.

### Tests

- [X] T006 [P] [US1] Écrire `TestRunAll` dans internal/timeline/timeline_test.go : cas avec deux preuves au manifeste et leurs `normalized/<preuve>.jsonl` (événements dans le désordre) plus leurs `.anomalies.jsonl` et un `.partial` → `timeline/timeline.jsonl` égal à l'encodage canonique de la réunion triée par `SortEvents` ; `Summary` : `Files = 2`, `EventsRead = EventsWritten`, `SHA256` égal au SHA-256 du fichier ; aucun autre fichier dans `timeline/` ; SHA-256 de chaque fichier de `normalized/` et du manifeste identiques avant et après l'exécution (FR-001, FR-010, FR-011, FR-018, SC-001)
- [X] T007 [P] [US1] Écrire `TestRunDeterministic` dans internal/timeline/timeline_test.go : deux exécutions, puis une troisième avec un budget de tri forcé à 4 Kio → trois fichiers identiques octet par octet (FR-012, SC-002)
- [X] T008 [P] [US1] Écrire `TestRunInputs` dans internal/timeline/timeline_test.go : (a) aucune preuve ingérée → erreur `no normalized events in the case; run ingest first`, `timeline/` vide ; (b) preuve au manifeste sans fichier d'événements → ignorée, `Files` ne la compte pas ; (c) fichier d'événements vide → chronologie vide de zéro octet ; (d) `normalized/old/x.evtx.jsonl` sans preuve au manifeste → `UnknownFiles` contient `normalized/old/x.evtx.jsonl`, son contenu n'est pas lu ; (e) preuve nommée `y.anomalies` → son fichier `y.anomalies.jsonl` est lu comme événements (FR-001 à FR-003, research.md R1)
- [X] T009 [P] [US1] Écrire `TestRunBadLine` dans internal/timeline/timeline_test.go : une ligne au champ inconnu à la ligne 3 d'un fichier → erreur contenant le chemin relatif au cas et `line 3` ; chronologie précédente intacte octet par octet ; ni `.partial` ni `.work-*` sous `timeline/` (FR-004, FR-013)
- [X] T010 [P] [US1] Écrire `TestRunCanceled` dans internal/timeline/timeline_test.go : contexte annulé pendant la lecture puis pendant la fusion (budget forcé à 4 Kio) → `context.Canceled`, chronologie précédente intacte, aucun fichier temporaire ; un `.partial` et un `.work-x/` laissés avant l'exécution sont supprimés par une exécution réussie (FR-013, FR-016, SC-005, research.md R5)
- [X] T011 [P] [US1] Écrire `TestTimelineCommand` et `TestTimelineLog` dans cmd/dfirflow/main_test.go : sur un cas collecté et ingéré à partir de internal/parser/evtx/testdata/Security.evtx copié sous deux noms → sortie standard exactement `timeline: 2 files, 1478 events read, 1478 written: timeline/timeline.jsonl`, code 0 ; sans ingestion → code 1 et message `run ingest first` ; dernière entrée de `case.log` : `command = timeline`, `summary.files = 2`, `summary.events_read`, `summary.events_written`, `summary.sha256` égal au SHA-256 du fichier, `filter` sans `from`/`to`/`sources` ; un fichier orphelin dans `normalized/` → `summary.unknown_files` le contient ; en échec `summary.error` présent et `sha256` absent (FR-014, FR-017, FR-019, contracts/timeline.md)

### Implementation

- [X] T012 [US1] Créer internal/timeline/timeline.go : `Filter{From, To time.Time; Sources []string}` (zéro = borne absente), `Summary{Files, EventsRead, EventsWritten int; SHA256 string; MissingSources, UnknownFiles []string}`, `ErrNoEvents` ; `Run(ctx, c *casefile.Case, f Filter) (Summary, error)` : supprime un `timeline/timeline.jsonl.partial` et les `timeline/.work-*` restants, avec le commentaire `// shortcut: suppose une seule exécution de timeline à la fois sur le cas, à revoir avec un verrou de cas` ; parcourt `c.Evidence()` et lit `normalized/<preuve>.jsonl` s'il existe avec `normalizer.ReadEvents` (erreur préfixée du chemin relatif au cas) ; réencode chaque événement retenu par `normalizer.NewEncoder` vers le `sorter` ; `ErrNoEvents` si aucun fichier ; dossier de travail `os.MkdirTemp(timeline/, ".work-")` supprimé par `defer` ; écrit `timeline.jsonl.partial` via `io.MultiWriter(fichier, sha256)`, `Sync`, `Close`, `os.Rename` vers `timeline.jsonl`, et supprime le `.partial` sur toute erreur ; parcourt `normalized/` pour `UnknownFiles` (connus : `<preuve>.jsonl`, `<preuve>.anomalies.jsonl` ; `*.partial` ignorés), chemins relatifs au cas avec `/`, triés (research.md R1, R2, R5)
- [X] T013 [US1] Brancher `timelineCmd` dans cmd/dfirflow/commands.go à la place de `notImplemented` : `casefile.Open`, `timeline.Run` avec un `timeline.Filter{}` vide (les options restent validées par `checkTimeline` mais ne sont appliquées qu'en US2, T019), avertissements `dfirflow: timeline: warning: not in the case manifest: <chemin>` sur la sortie d'erreur, ligne de résumé de contracts/timeline.md sur la sortie standard, `logOperation` avec le résumé de data-model.md (`filter`, `files`, `events_read`, `events_written`, `sha256`, `unknown_files` et `missing_sources` omis s'ils sont vides ; `error` en cas d'échec) ; `ErrNoEvents` → code 1 avec le message du contrat
- [X] T014 [US1] Faire passer T006 à T011 ; retirer la ligne `timeline` de `TestNotImplemented` dans cmd/dfirflow/main_test.go (ligne 192 : sur un cas inexistant la commande sort désormais en code 1) ; ne pas toucher à `pipelineOrder` (ligne 74-77, ordre de l'aide vérifié par `TestHelp`)

**Checkpoint** : US1 vérifiable seule ; la chronologie complète est produite et tracée.

---

## Phase 4: User Story 2 — Restreindre la chronologie à une fenêtre et à des sources (P2)

**Goal**: `--from`, `--to` et `--source` ne retiennent que les événements demandés.

**Independent Test**: sur un jeu synthétique, la chronologie filtrée est égale à la chronologie complète restreinte par une fonction de test indépendante.

### Tests

- [X] T015 [P] [US2] Écrire `TestRunFilter` dans internal/timeline/timeline_test.go : événements de sources `evtx` et `mft` (synthétiques), horodatages sur et autour des bornes, dont des écarts sous la microseconde ; pour une table de filtres (from seul, to seul, from et to, bornes égales, sources `evtx`, `mft`, `evtx,mft`, aucune) → chronologie égale à la chronologie complète restreinte par `from <= t <= to` (`t` tronqué à la µs) et par source ; `EventsRead` constant, `EventsWritten` égal au nombre retenu ; filtre n'excluant rien → fichier identique à celui sans filtre (FR-006, FR-007, US2-5, SC-004, research.md R4)
- [X] T016 [P] [US2] Écrire `TestRunMissingSource` dans internal/timeline/timeline_test.go : cas avec événements `evtx` seulement et `Sources = [evtx, mft, prefetch]` → `MissingSources = [mft, prefetch]` (triés) ; une source présente hors fenêtre n'est pas signalée (FR-008)
- [X] T017 [P] [US2] Écrire `TestTimelineFilterCommand` dans cmd/dfirflow/main_test.go : `--source mft` sur le cas ingéré → `0 written`, sortie d'erreur `dfirflow: timeline: warning: no event from source mft`, fichier vide, code 0, `summary.missing_sources = ["mft"]` dans `case.log` ; `--from 2026-11-01T00:00:00` sans fuseau → `summary.filter.from = "2026-11-01T00:00:00.000000Z"` dans `case.log` ; `--from` après `--to` → code 2 et `timeline/` vide (FR-005, contracts/timeline.md)

### Implementation

- [X] T018 [US2] Ajouter le filtrage dans internal/timeline/timeline.go : bornes et horodatage tronqués à la µs, comparaison incluse, ensemble de sources ; sources rencontrées relevées avant le filtre temporel, `MissingSources` trié
- [X] T019 [US2] Compléter `timelineCmd` dans cmd/dfirflow/commands.go : `--from`/`--to` via `parseTime` existant, `--source` via `parseList` existant ; avertissement `no event from source <s>` par source manquante ; `filter` du journal avec `from`/`to` au format canonique des horodatages (`normalizer.Time`) et `sources`, champs omis si absents
- [X] T020 [US2] Faire passer T015 à T017

**Checkpoint** : US1 et US2 vertes.

---

## Phase 5: User Story 3 — Enchaîner l'investigation jusqu'à la chronologie (P3)

**Goal**: `investigate` produit la chronologie puis s'arrête à `detect`.

**Independent Test**: `investigate` sur un dossier contenant Security.evtx → `timeline/timeline.jsonl` présent, sortie `detect: not implemented yet`, code 3.

### Tests

- [X] T021 [US3] Adapter le test `investigate` de cmd/dfirflow/main_test.go (ligne 218) : message attendu `dfirflow: investigate: detect: not implemented yet\n`, code 3, `timeline/timeline.jsonl` du cas identique à celui de l'enchaînement manuel `collect`, `ingest`, `timeline` sur la même source (FR-020, SC-006)

### Implementation

- [X] T022 [US3] Vérifier que `investigate` dans cmd/dfirflow/commands.go n'a besoin d'aucune modification (elle appelle déjà `timeline` sans filtre) ; mettre à jour seulement son aide si elle mentionne l'arrêt à `timeline` ; faire passer T021

**Checkpoint** : les trois stories vertes.

---

## Phase 6: Polish

- [X] T023 [P] Écrire `TestRunLarge` dans internal/timeline/timeline_test.go, sauté sans `DFIRFLOW_LARGE=1` : 10 millions d'événements synthétiques répartis dans 4 fichiers, horodatages pseudo-aléatoires à graine fixe → ordre vérifié ligne à ligne en flux, `runtime.MemStats.HeapInuse` maximal échantillonné sous 256 Mio ; consigner durée et mémoire dans le message du test (FR-015, SC-003)
- [X] T024 Exécuter `gofmt -l .`, `go vet ./...`, `GOOS=windows go vet ./...`, `go test -race ./...` ; vérifier `go.mod` sans dépendance ; dérouler quickstart.md et corriger la fenêtre du scénario 4 selon les horodatages réels de Security.evtx
- [X] T025 [P] Mettre à jour docs/architecture-actuelle.md : spec 006 marquée Codé, commande `timeline` et flux `normalized/ → timeline/` (tri externe, `.partial`, `case.log`), `investigate` jusqu'à `detect` ; cocher les tâches terminées dans specs/006-timeline/tasks.md

---

## Dependencies & Execution Order

- Phase 1 → Phase 2 (bloquante) → US1 → US2 → US3 → Polish.
- US2 étend timeline.go et commands.go écrits en US1 : à enchaîner après US1.
- US3 dépend de US1 (la commande doit exister) ; indépendante de US2.
- Dans chaque story : tests (rouges) → implémentation → checkpoint vert.

## Parallel Examples

- Phase 2 : T002 et T003 ensemble, puis T004.
- US1 : T006 à T011 ensemble, puis T012 → T013 → T014.
- US2 : T015, T016, T017 ensemble, puis T018 → T019 → T020.
- Polish : T023 et T025 en parallèle de T024.

## Implementation Strategy

1. **MVP** = Phases 1 à 3 (US1) : chronologie complète, déterministe, atomique et tracée ; sans
   filtre (les options sont acceptées par la CLI mais non encore appliquées).
2. US2 : filtres et avertissement de source absente.
3. US3 : bascule du test `investigate` jusqu'à `detect`.
4. Polish : volume, vérifications croisées Windows / Linux, documentation.
