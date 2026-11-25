---

description: "Task list for 004-evidence-collection"
---

# Tasks: Collecte des preuves

**Input**: Design documents from `/specs/004-evidence-collection/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/collect.md, quickstart.md

**Tests**: inclus (constitution, principe VI) ; chaque test est écrit avant le code qu'il couvre,
sur des arborescences synthétiques (`t.TempDir()`). Compatibilité `go 1.18` : pas de `slices`,
`maps`, `cmp`, `min`, `errors.Join`.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [x] T001 Vérifier que `go test -race ./...` passe sur la branche (base specs 001–003) et que `AddEvidence` n'a pour appelants que internal/case/case_test.go (`grep -rn AddEvidence --include=*.go . | grep -v spikes`)
- [x] T002 Supprimer le squelette internal/collector/filesystem.go et internal/collector/metadata.go ; réduire internal/collector/collector.go à la déclaration `package collector` avec un commentaire de package (« collecte des artefacts d'un volume Windows dans un cas DFIRFlow »)

---

## Phase 2: Foundational (amendements de `internal/case`, bloquant pour toutes les stories)

- [x] T003 Mettre à jour internal/case/case_test.go : appels `AddEvidence(context.Background(), src, rel, nil)` ; nouveau `TestAddEvidenceOrigin` (une `Origin` avec `SourcePath` et `Modified` est relue telle quelle depuis `hashes/manifest.jsonl` ; avec `nil`, la ligne ne contient pas la clé `origin`) ; nouveau `TestAddEvidenceCancelled` (contexte annulé → erreur, ni `evidence/<rel>` ni `<rel>.partial`, manifeste inchangé) ; nouveau `TestRecorded` (`Recorded(file)` renvoie l'empreinte après `AddEvidence` et après `Open` du cas ; `ok == false` pour un fichier inconnu) ; `TestOpen` lit un manifeste de la spec 002 sans `origin`
- [x] T004 Dans internal/case/manifest.go, ajouter `type Origin struct` avec tags JSON dans cet ordre : `source_path` (`string`), `modified`, `accessed`, `changed`, `created` (`*time.Time`, tous `omitempty`) — « UTC ; un horodatage que le système de fichiers ne fournit pas est omis » ; ajouter `Origin *Origin \`json:"origin,omitempty"\`` en dernier champ de `ManifestEntry` ; convertir les horodatages présents en UTC à l'écriture
- [x] T005 Dans internal/case/manifest.go, changer la signature en `AddEvidence(ctx context.Context, src, rel string, origin *Origin) (ManifestEntry, error)` : envelopper la source dans le `ctxReader` de internal/case/verify.go avant `copyHashed` (interruption → `.partial` supprimé, `ctx.Err()` renvoyée) ; renseigner `Origin` dans l'entrée écrite
- [x] T006 Dans internal/case/case.go, passer `entries` de `map[string]bool` à `map[string]string` (fichier → `sha256`) dans `Create`, `Open` et `AddEvidence` ; ajouter `func (c *Case) Recorded(file string) (sha256 string, ok bool)` (`file` relatif à `evidence/`, séparateur `/`)
- [x] T007 [P] Ajouter dans specs/002-case-management/contracts/case-layout.md et specs/002-case-management/data-model.md une note : « champ optionnel `origin` ajouté par la spec 004, voir specs/004-evidence-collection/data-model.md »

**Checkpoint** : `go test -race ./internal/case/...` vert.

---

## Phase 3: User Story 1 — Collecter les journaux EVTX d'un volume (P1) 🎯 MVP

**Goal**: `collect --case --target` copie les `.evtx` de `Windows/System32/winevt/Logs` (sans casse) dans le cas.

**Independent Test**: quickstart.md scénarios 1, 2, 7 et 8.

### Tests

- [x] T008 [P] [US1] Écrire `TestFind` dans internal/collector/collector_test.go : arborescence `windows/System32/WINEVT/Logs/{Security.evtx,System.EVTX,notes.txt}` → candidats `windows/System32/WINEVT/Logs/Security.evtx` et `…/System.EVTX` (chemin réel conservé, `notes.txt` exclu) ; deux répertoires `Windows` et `windows` (Linux uniquement, `t.Skip` sinon) → les deux explorés ; aucun répertoire `Windows` → liste vide ; résultat trié
- [x] T009 [P] [US1] Écrire `TestCollect` dans internal/collector/collector_test.go : deux EVTX, dont un de 0 octet, → deux résultats `COLLECTED` avec `SHA256` égal à l'empreinte de la source, fichiers identiques sous `evidence/` ; puis `c.Verify` → tous `OK` (SC-001, SC-002) ; contenu, liste et dates de modification de la cible identiques avant/après (SC-004)
- [x] T010 [P] [US1] Écrire `TestCollectTargetErrors` dans internal/collector/collector_test.go : cible absente, cible fichier → erreur `invalid target` ; cas égal à la cible ou sous la cible → erreur `case directory must not be inside the target` et aucune entrée au manifeste ; cible sans artefact → erreur `ErrNoArtifact` ; cible ne contenant qu'un lien `.evtx` → `ErrNoArtifact` (`t.Skip` si `os.Symlink` échoue)
- [x] T011 [P] [US1] Écrire `TestCollectCommand` dans cmd/dfirflow/main_test.go : sortie exacte du contrat contracts/collect.md pour deux `COLLECTED` (lignes triées, deux espaces, ligne de résumé `2 files: 2 COLLECTED, 0 ALREADY, 0 CONFLICT, 0 FAILED, 0 SKIPPED`), code 0 ; cible sans artefact → stderr `dfirflow: collect: no artifact found under <chemin>`, code 1 ; retirer `collect` de `TestNotImplemented` ; dans ce même test, `investigate` est appelé avec un cas valide (`case init` préalable) et une cible contenant un EVTX : `investigate` exécute réellement `collect` (il appelle `lookup("collect").exec`) puis s'arrête sur stderr `dfirflow: investigate: ingest: not implemented yet`, code 3 ; la vérification « aucune écriture sur disque » ne porte plus que sur les commandes encore non implémentées

### Implementation

- [x] T012 [US1] Créer internal/collector/patterns.go : `type pattern struct{ name string; dirs []string; ext string }`, table `patterns = []pattern{{"evtx", []string{"Windows","System32","winevt","Logs"}, ".evtx"}}` ; `func find(root string) ([]candidate, error)` résolvant chaque niveau par `os.ReadDir` + `strings.EqualFold`, extension comparée sans casse, chemins relatifs en `/`, liste triée (research.md R1)
- [x] T012b [US1] Dans internal/collector/patterns.go et internal/collector/collector.go, utiliser `os.Lstat` à chaque niveau et pour chaque fichier : entrée non régulière (lien, point de jonction, périphérique) → résultat `SKIPPED` avec raison `not a regular file`, jamais suivie (research.md R6)
- [x] T013 [US1] Implémenter dans internal/collector/collector.go : statuts `Collected = "COLLECTED"`, `Already = "ALREADY"`, `Conflict = "CONFLICT"`, `Failed = "FAILED"`, `Skipped = "SKIPPED"` ; `type Result struct{ File, Status, SHA256, Actual, Reason string }` ; `var ErrNoArtifact` ; `func Collect(ctx context.Context, c *casefile.Case, target string) ([]Result, error)` : cible résolue par `filepath.Abs` + `filepath.EvalSymlinks`, doit être un répertoire ; refus si `c.BaseDir` résolu est égal à la cible ou dessous (research.md R6) ; `find` ; aucune candidate **régulière** (seuls les fichiers réguliers comptent ; une cible ne contenant que des `SKIPPED` donne aussi `ErrNoArtifact`) ; pour chaque candidate `c.AddEvidence(ctx, abs, filepath.FromSlash(rel), origin)` → `COLLECTED` ou `FAILED` (raison = message d'erreur) ; arrêt et renvoi de `ctx.Err()` si le contexte est annulé ; résultats triés par `File`
- [x] T014 [US1] Brancher `collect` dans cmd/dfirflow/commands.go sur le modèle de `case verify` : `casefile.Open(--case)`, `collector.Collect`, une ligne par résultat au format de contracts/collect.md (statut aligné sur 9 caractères + deux espaces, `sha256=` / `expected= actual=` / `reason=`), ligne de résumé, `errCollectIncomplete` (`collection incomplete`) si au moins un `FAILED` ou `CONFLICT` → code 1 ; message `no artifact found under <chemin>` pour `ErrNoArtifact`

**Checkpoint** : US1 utilisable seule ; scénarios 1, 2, 7, 8 du quickstart OK.

---

## Phase 4: User Story 2 — Conserver les métadonnées d'origine (P1)

**Goal**: chaque preuve porte `origin` (chemin source, horodatages disponibles, UTC).

**Independent Test**: quickstart.md scénario 3.

### Tests

- [x] T015 [P] [US2] Écrire `TestOrigin` dans internal/collector/collector_test.go : fichier dont `os.Chtimes` fixe accès `2026-11-20T14:12:03Z` et modification `2026-10-01T08:00:00Z` → après `Collect`, l'entrée du manifeste a `origin.source_path` = chemin absolu de la source, `origin.modified` = `2026-10-01T08:00:00Z`, `origin.accessed` = valeur fixée ; sous Linux `created` absent et `changed` présent ; sous Windows `created` présent et `changed` absent (US2-1, US2-2)

### Implementation

- [x] T016 [P] [US2] Créer internal/collector/origin.go : `func readOrigin(abs string, fi os.FileInfo) *casefile.Origin` remplissant `SourcePath` et `Modified` (`fi.ModTime().UTC()`) puis appelant `platformTimes(fi, o)`
- [x] T017 [P] [US2] Créer internal/collector/origin_windows.go (`//go:build windows`) : `platformTimes` lit `fi.Sys().(*syscall.Win32FileAttributeData)` → `Created` (`CreationTime`), `Accessed` (`LastAccessTime`), via `time.Unix(0, ft.Nanoseconds()).UTC()`
- [x] T018 [P] [US2] Créer internal/collector/origin_linux.go (`//go:build linux`) : `platformTimes` lit `fi.Sys().(*syscall.Stat_t)` → `Accessed` (`Atim`), `Changed` (`Ctim`), via `time.Unix(sec, nsec).UTC()` ; `Created` omis (research.md R2)
- [x] T019 [P] [US2] Créer internal/collector/origin_other.go (`//go:build !windows && !linux`) : `platformTimes` sans effet
- [x] T020 [US2] Dans internal/collector/collector.go, passer `readOrigin(abs, fi)` à `AddEvidence` en réutilisant le `FileInfo` obtenu par le `os.Lstat` de T012b (pas de second `Lstat`), ce qui garantit une lecture des métadonnées **avant** la copie

**Checkpoint** : scénario 3 du quickstart OK ; `GOOS=windows go vet ./...` et `GOOS=linux go vet ./...` passent.

---

## Phase 5: User Story 3 — Tracer la collecte dans le cas (P2)

**Goal**: une entrée `collect` dans `case.log` avec cible, compteurs et `problems` ; une erreur fichier n'arrête pas la collecte.

**Independent Test**: quickstart.md scénario 6.

### Tests

- [x] T021 [P] [US3] Écrire `TestCollectContinuesOnError` dans internal/collector/collector_test.go : trois EVTX dont un illisible (`os.Chmod(0)`, `t.Skip` si exécuté en root ou sous Windows) → deux `COLLECTED`, un `FAILED` avec raison non vide, pas d'erreur globale (FR-009)
- [x] T022 [P] [US3] Écrire `TestCollectLog` dans cmd/dfirflow/main_test.go : après une collecte avec un `FAILED`, code 1, stderr `dfirflow: collect: collection incomplete`, dernière ligne de `case.log` : `command` = `collect`, `exit_code` = 1, `summary` = `{"target":<cible absolue>,"COLLECTED":2,"ALREADY":0,"CONFLICT":0,"FAILED":1,"SKIPPED":0,"problems":[{"file":…,"status":"FAILED","reason":…}]}` (problems triés par `file`) ; collecte réussie → `problems` vide ou absent, `exit_code` 0

### Implementation

- [x] T023 [P] [US3] Créer internal/collector/locked_windows.go (`//go:build windows`) et internal/collector/locked_other.go (`//go:build !windows`) : `func isLocked(err error) bool` (Windows : `errors.Is(err, syscall.Errno(32))` ou `syscall.Errno(33)` ; ailleurs : `false`) ; dans internal/collector/collector.go, raison `locked by the system: live collection is not supported` quand `isLocked` (FR-012, research.md R5)
- [x] T024 [US3] Dans cmd/dfirflow/commands.go, journaliser `collect` via `logOperation` avec le résumé de data-model.md (`target` absolu, compteurs des cinq statuts, `problems` = résultats `FAILED`, `CONFLICT`, `SKIPPED` triés par `file` avec `file`, `status`, `reason`) ; entrée écrite aussi en cas d'interruption (code 130) et d'erreur de cible, dès que le cas est ouvert (FR-011)

**Checkpoint** : scénario 6 du quickstart OK.

---

## Phase 6: User Story 4 — Relancer une collecte sans doublon (P2)

**Goal**: `ALREADY` / `CONFLICT` sans recopie ni écrasement ; test des liens non suivis (implémentés en T012b).

**Independent Test**: quickstart.md scénarios 4 et 5.

### Tests

- [x] T025 [P] [US4] Écrire `TestCollectTwice` dans internal/collector/collector_test.go : deuxième `Collect` sur cible inchangée → tous `ALREADY` avec `SHA256` du manifeste, nombre de lignes du manifeste inchangé (SC-003) ; source modifiée puis troisième `Collect` → `CONFLICT` avec `SHA256` = attendu, `Actual` = nouvelle empreinte, fichier sous `evidence/` inchangé (US4-2)
- [x] T026 [P] [US4] Écrire `TestCollectSymlink` dans internal/collector/collector_test.go : (`t.Skip` si `os.Symlink` échoue, ex. Windows sans privilège) (a) `Logs/` réel contenant `Security.evtx` régulier et `link.evtx` lien symbolique → 1 `COLLECTED` + 1 `SKIPPED` (raison `not a regular file`), aucune erreur ; (b) `Logs` lui-même lien symbolique vers un dossier contenant un `.evtx` → `ErrNoArtifact`, le `.evtx` pointé n'est jamais copié (FR-015, FR-013)

### Implementation

- [x] T027 [US4] Dans internal/collector/collector.go, avant `AddEvidence` : si `c.Recorded(rel)` → hacher la source en flux (`sha256` + `io.Copy`, contexte respecté) → `ALREADY` si égal, `CONFLICT` sinon, sans écrire dans le cas (research.md R7)
- [x] T029 [US4] Dans cmd/dfirflow/main_test.go et cmd/dfirflow/commands.go, vérifier les lignes `ALREADY … sha256=` et `CONFLICT … expected=… actual=…` du contrat et le code 1 sur `CONFLICT`

**Checkpoint** : scénarios 4 et 5 du quickstart OK.

---

## Phase 7: Polish

- [x] T030 [P] Écrire `TestCollectDeterministic` dans internal/collector/collector_test.go : même cible collectée dans deux cas distincts → mêmes `[]Result` et manifestes identiques hors `collected_at` et `origin.accessed` (la lecture peut modifier l'heure d'accès d'une source non montée en lecture seule) (SC-006)
- [x] T031 [P] Écrire `TestCollectInterrupted` dans cmd/dfirflow/main_test.go : contexte annulé → code 130, aucun `.partial` sous `evidence/`, `case verify` sans `MODIFIED` ni `UNTRACKED`
- [x] T031b [P] Écrire `TestCollectMemory` dans internal/collector/collector_test.go (ignoré avec `-short`) : fichier creux de 1 Gio (`f.Truncate`) sous `Windows/System32/winevt/Logs/Big.evtx` ; `runtime.ReadMemStats` avant/après `Collect` → `TotalAlloc` augmente de moins de 16 Mio et `HeapInuse` reste < 64 Mio (SC-005 : mémoire indépendante de la taille du fichier)
- [x] T032 Exécuter `gofmt -l .`, `go vet ./...`, `GOOS=windows go vet ./...`, `go test -race ./...` ; dérouler quickstart.md et corriger les écarts
- [x] T033 [P] Mettre à jour l'exemple de `collect` dans cmd/dfirflow/commands.go (`--target /mnt/image`, résumé « Copy and hash Windows event logs into the case ») et cocher les tâches terminées dans specs/004-evidence-collection/tasks.md

---

## Dependencies & Execution Order

- Phase 1 → Phase 2 (bloquante) → US1 → {US2, US3, US4} → Polish.
- US2, US3 et US4 modifient toutes internal/collector/collector.go : à enchaîner dans l'ordre US2 → US3 → US4 si un seul développeur ; leurs tests [P] peuvent être écrits en parallèle.
- Dans chaque story : tests (rouges) → implémentation → checkpoint vert.

## Parallel Examples

- Phase 2 : T007 en parallèle de T003–T006.
- US1 : T008, T009, T010, T011 ensemble, puis T012 → T012b → T013 → T014.
- US2 : T015 puis T016–T019 en parallèle (fichiers distincts), puis T020.
- US3 : T021, T022, T023 ensemble, puis T024.

## Implementation Strategy

1. **MVP** = Phases 1–3 (US1) : `collect` utilisable pour alimenter la spec 005 ; limite connue : pas encore d'entrée `collect` dans `case.log` (FR-011, ajoutée en US3/T024).
2. US2 (métadonnées) avant toute collecte sur données réelles : sans elle, les horodatages d'origine sont perdus.
3. US3 puis US4 : traçabilité et robustesse aux relances.
4. Polish : déterminisme, interruption, vet croisé Windows/Linux.
