---

description: "Task list for 002-case-management"
---

# Tasks: Gestion des cas d'investigation

**Input**: Design documents from `/specs/002-case-management/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/case-layout.md

**Tests**: inclus (constitution, principe VI) ; chaque test est écrit avant le code qu'il couvre.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [x] T001 Vérifier que `go test ./...` passe sur la branche (base spec 001)

---

## Phase 2: Foundational

- [x] T002 Ajouter `errIntegrity` et le code de sortie 4 dans cmd/dfirflow/main.go (`exitCode`), avec le cas correspondant dans `TestExitCode` de cmd/dfirflow/main_test.go (contrat 001 amendé)
- [x] T003 Remplacer l'API squelette de internal/case/case.go : struct `Case` avec tags JSON `schema_version`, `case_id`, `hostname`, `analyst`, `created_at`, `tool_version` et champ non sérialisé `BaseDir` ; supprimer `New` et la méthode `Load` ; conserver `Dir(kind)`

---

## Phase 3: User Story 1 — Ouvrir une investigation (P1) 🎯 MVP

**Independent Test**: quickstart.md §2.

- [x] T004 [US1] Écrire `TestCreate` et `TestCreateExisting` dans internal/case/case_test.go : arborescence complète (`case.json`, `case.log`, `hashes/manifest.jsonl` vide, `evidence/`, `parsed/`, `normalized/`, `timeline/`, `detections/`, `reports/`, `hashes/`), `case.json` conforme à data-model.md (`created_at` UTC), dossier existant (même vide) ⇒ erreur et contenu inchangé, `--dir` inexistant créé, `--dir` désignant un fichier ⇒ erreur sans rien créer
- [x] T005 [US1] Implémenter `Create(dir, id, hostname, analyst, toolVersion string, now time.Time) (*Case, error)` dans internal/case/case.go : `os.MkdirAll(dir)`, `os.Mkdir(dir/id)` puis contenu ; `os.RemoveAll` du dossier créé en cas d'échec (research.md R1)
- [x] T006 [US1] Écrire `TestOpen` dans internal/case/case_test.go : cas valide relu à l'identique ; `case.json` absent, illisible ou `schema_version` ≠ 1 ⇒ erreur nommant le fichier
- [x] T007 [US1] Implémenter `Open(path string) (*Case, error)` dans internal/case/case.go (lecture de `case.json` et chargement du manifeste ; ligne de manifeste illisible ou sortant de `evidence/` ⇒ erreur avec le numéro de ligne)
- [x] T008 [US1] Brancher `case init` dans cmd/dfirflow/commands.go : appelle `Create(o.dir, id, host, analyst, version, time.Now())`, écrit le chemin du cas sur stdout ; écrire `TestCaseInit` dans cmd/dfirflow/main_test.go (exit 0, stdout = chemin, ré-exécution ⇒ exit 1) et retirer `case init` de `TestNotImplemented`

---

## Phase 4: User Story 2 — Vérifier l'intégrité (P1)

**Independent Test**: quickstart.md §3.

- [x] T009 [US2] Écrire `TestVerify` dans internal/case/case_test.go : cas vide ⇒ intègre ; preuves intactes ⇒ `OK` ; un octet modifié et troncature ⇒ `MODIFIED` avec attendu/obtenu ; suppression ⇒ `MISSING` ; fichier ajouté et lien symbolique ⇒ `UNTRACKED` (lien ignoré si non supporté) ; résultats triés par chemin ; deux exécutions identiques ; contexte annulé ⇒ `context.Canceled`
- [x] T010 [US2] Implémenter dans internal/case/verify.go `Verify(ctx) ([]VerifyResult, error)` et les constantes `StatusOK`, `StatusModified`, `StatusMissing`, `StatusUntracked` : hachage en flux avec lecteur sensible à `ctx`, `filepath.WalkDir` sans suivre les liens (research.md R5)
- [x] T011 [US2] Brancher `case verify` dans cmd/dfirflow/commands.go : `Open`, `Verify`, sortie au format de contracts/case-layout.md (lignes triées puis résumé `N evidence files: a OK, b MODIFIED, c MISSING, d UNTRACKED`), `errIntegrity` (message `integrity check failed`) si un statut ≠ `OK` ; écrire `TestCaseVerify` dans cmd/dfirflow/main_test.go (intègre ⇒ 0, fichier ajouté ⇒ 4, `--case` invalide ⇒ 1) et retirer `case verify` de `TestNotImplemented`

---

## Phase 5: User Story 3 — Enregistrer une preuve (P2)

**Independent Test**: tests du package (pas de commande avant la spec 004).

- [x] T012 [US3] Écrire `TestAddEvidence` dans internal/case/case_test.go : copie identique, entrée de manifeste (`file` en `/`, `sha256` 64 hexa minuscules, `size`, `collected_at` UTC), copie en lecture seule, `Verify` ⇒ `OK` ; chemin déjà enregistré, absolu, `.`, ou sortant par `..` ⇒ refus sans changement ; source illisible ⇒ aucun `.partial`, aucune entrée ; manifeste relu par `Open` après ajout
- [x] T013 [US3] Implémenter dans internal/case/manifest.go `ManifestEntry` (tags `file`, `sha256`, `size`, `collected_at`) et `AddEvidence(src, rel string) (ManifestEntry, error)` selon research.md R2/R3 ; supprimer `SaveManifest`

---

## Phase 6: User Story 4 — Retracer les opérations (P3)

**Independent Test**: quickstart.md §4.

- [x] T014 [US4] Écrire `TestLog` dans internal/case/case_test.go : deux appels ⇒ deux lignes JSON, la première inchangée
- [x] T015 [US4] Implémenter dans internal/case/journal.go `LogEntry` (tags `command`, `args`, `started_at`, `finished_at`, `tool_version`, `exit_code`, `summary`) et `(c *Case) Log(LogEntry) error` (ajout `O_APPEND` + `Sync`)
- [x] T016 [US4] Journaliser `case init` et `case verify` dans cmd/dfirflow/commands.go via `defer` (code calculé par `exitCode`, résumé des statuts pour `verify`) ; compléter `TestCaseInit`/`TestCaseVerify` : `case.log` contient une entrée par exécution avec le bon `exit_code`

---

## Phase 7: Polish

- [x] T017 `gofmt -l .`, `go vet ./...`, `go test ./... -race -cover`
- [x] T018 Dérouler quickstart.md §2 à §4 avec le binaire construit

## Dependencies & Execution Order

Phase 2 → US1 (T004–T008) → US2 (T009–T011) → US3 (T012–T013) → US4 (T014–T016) → Polish.
US2 a besoin d'`Open` (US1) ; ses tests de `MODIFIED`/`MISSING` utilisent `AddEvidence` (US3) :
implémenter T013 avant d'exécuter T009 si l'on suit strictement l'ordre des tests.

## Parallel Opportunities

- T004/T006/T009/T012/T014 (même fichier de test) : séquentiels ; T002 ∥ T003 (fichiers distincts).

## Implementation Strategy

MVP = US1 + US2 (créer et vérifier un cas) ; US3 prépare la spec 004 ; US4 complète la traçabilité.
