---

description: "Task list for 012-detection"
---

# Tasks: Détection par règles mono-événement

**Input**: Design documents from `/specs/012-detection/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/detect.md,
quickstart.md

**Tests**: inclus (constitution, principe VI) ; chaque test est écrit avant le code qu'il couvre.
Compatibilité `go 1.18` : pas de `slices`, `maps`, `cmp`, `min`, `errors.Join`. Seul module
externe autorisé : `go.yaml.in/yaml/v3` v3.0.6. Les événements de test sont synthétiques, écrits
par les tests avec `normalizer.NewEncoder` dans un cas créé par `casefile.Create`.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [X] T001 Vérifier que `go test -race ./...` passe sur `feature/012-detection` (base `dev`, specs 001 à 006) ; lancer une fois `DFIRFLOW_LARGE=1 go test -run TestRunLarge ./internal/timeline/` et noter durée et mémoire comme référence avant le refactor
- [X] T002 Ajouter `go.yaml.in/yaml/v3 v3.0.6` à go.mod et go.sum (`go get go.yaml.in/yaml/v3@v3.0.6`), vérifier que `go mod graph` ne liste aucune autre dépendance et que `go build ./...` passe ; vérifier la licence (LICENSE et NOTICE du module : MIT et Apache-2.0)

---

## Phase 2: Foundational (refactor de la 006, bloquant pour toutes les stories)

Déplacements sans changement de comportement (research.md R5, R6) ; les tests de `internal/timeline` restent la garde.

- [X] T003 Créer internal/extsort/extsort.go en déplaçant `sorter`, `cursor`, `merge`, `segmentBudget` et `maxFanIn` de internal/timeline/sort.go : types exportés `Key{TS int64; S string; N uint64; T string}` avec `Less`, `Sorter{Ctx context.Context; Parent string; Decode func(line []byte) (Key, error)}` avec `Add(k Key, line []byte) error`, `Finish(w io.Writer) error`, `Cleanup()` ; `cursor.next` appelle `Decode` au lieu de décoder la clé des événements ; variables `SegmentBudget` et `MaxFanIn` exportées pour les tests
- [X] T004 Créer internal/extsort/atomic.go en déplaçant `writeAtomic` de internal/timeline/timeline.go sous le nom `WriteAtomic(out string, write func(io.Writer) error) (sha256 string, err error)`, plus `CleanStale(dir, name string)` qui supprime `<name>.partial` et les `.work-*` de `dir` (avec le commentaire `// shortcut: suppose une seule exécution à la fois sur le cas, à revoir avec un verrou de cas`)
- [X] T005 Déplacer `TestExternalSort` et `TestSortCanceled` de internal/timeline/sort_test.go vers internal/extsort/extsort_test.go, avec une clé de test simple (entier et texte) et son décodeur ; garder `TestKeyOrder` dans internal/timeline/sort_test.go
- [X] T006 Créer internal/ingest/files.go : `EventFiles(c *casefile.Case) (files, unknown []string, err error)` reprenant la sélection de `timeline.Run` et `unknownFiles` (manifeste trié, `normalized/<preuve>.jsonl` s'il existe, fichiers inconnus hors `.partial`, chemins relatifs au cas avec `/`, triés) ; test `TestEventFiles` dans internal/ingest/ingest_test.go reprenant les cas (b), (d) et (e) de `TestRunInputs` de la 006
- [X] T007 Réduire internal/timeline/sort.go à `keyOf(ev) extsort.Key` et `decodeKey(line) (extsort.Key, error)` ; faire utiliser à internal/timeline/timeline.go `ingest.EventFiles`, `extsort.Sorter`, `extsort.WriteAtomic` et `extsort.CleanStale` ; supprimer le code devenu mort
- [X] T008 `go vet ./...`, `go test -race ./internal/...` vert avec les assertions des tests de la 006 inchangées (seule la référence au budget de tri passe à `extsort.SegmentBudget`) ; relancer `DFIRFLOW_LARGE=1 go test -run TestRunLarge ./internal/timeline/` et comparer à T001 (écart de durée au plus 10 %)

**Checkpoint** : 006 inchangée vue de l'extérieur ; tri externe et sélection des fichiers réutilisables.

---

## Phase 3: User Story 1 — Repérer les événements suspects avec les règles fournies (P1) MVP

**Goal**: `detect --case <cas>` applique le jeu embarqué et écrit `detections/detections.jsonl`.

**Independent Test**: journal Security de référence ingéré → 15 détections (1 × 1102, 14 × 4719), valides, relance identique octet par octet.

### Tests du moteur

- [X] T009 [P] [US1] Écrire `TestLoadRule` dans internal/detection/rule_test.go, table de règles YAML en ligne → règle chargée avec `ID`, `Version` (16 hexa du SHA-256, identique pour le même texte en fins de ligne `\n` et `\r\n`), `Severity` (`informational` → `info`), `Confidence` (déclarée, ou 0.8 / 0.6 / 0.4 selon `stable`, `test`, `experimental` ou absent), `MITRE` (première étiquette `attack.tNNNN[.NNN]` en majuscules, tactiques sautées), canal (table des services de data-model.md) ; `logsource.product: linux` et `status: deprecated` ou `unsupported` → écartée ; chaque ligne du tableau « Raisons de refus » de contracts/detect.md → refusée avec exactement la raison du contrat (research.md R2, R4)
- [X] T010 [P] [US1] Écrire `TestMatch` dans internal/detection/match_test.go, table (règle, événement synthétique, attendu) : égalité insensible à la casse ; liste de valeurs (OU) et `all` (ET) ; jokers `*`, `?` et leurs échappements `\*`, `\?`, `\\` ; `contains`, `startswith`, `endswith` ; `re` sensible à la casse et non ancré, `re|i` insensible ; `null` vrai si champ absent ou vide ; champ absent → faux ; `EventID: 4688` contre `event_id` 4688 ; `Channel`, `Provider_Name`, `Computer` et un nom quelconque lus selon la table des champs de data-model.md ; sélection en liste de tables (OU) (research.md R2, R3)
- [X] T011 [P] [US1] Écrire `TestCondition` dans internal/detection/condition_test.go : priorité `not` > `and` > `or`, parenthèses, `1 of sel*`, `all of sel*`, `1 of them` et `all of them` excluant les sélections `_x`, nom simple ; condition illisible, identifiant inconnu, motif sans sélection → erreur `invalid condition: …` ; 65 parenthèses ou `not` imbriqués → `invalid condition: too deeply nested`, 64 acceptés
- [X] T012 [P] [US1] Écrire `TestEmbeddedRules` dans internal/detection/rules_test.go : le jeu embarqué se charge avec 7 règles appliquées, 0 écartée, 0 refusée, identifiants et `MITRE` de data-model.md ; une table associe à chaque fichier de internal/detection/rules/ au moins un événement positif et un négatif (dont, pour `privileged_group_member_added.yml`, un 4732 vers `S-1-5-32-545` et pour les règles à `Provider_Name`, un mauvais fournisseur) ; le test échoue si un fichier de rules/ n'a pas d'entrée ou si une entrée n'a pas de positif et de négatif (FR-017, FR-018, SC-002, research.md R7)
- [X] T013 [P] [US1] Écrire `TestRunEmbedded` dans internal/detection/detection_test.go : cas avec deux preuves et leurs `normalized/<preuve>.jsonl` (événements synthétiques dans le désordre, dont un satisfaisant deux règles et des événements non EVTX) → `detections/detections.jsonl` : une détection par couple (règle, événement), champs de data-model.md « Détection produite », `id = normalizer.DetectionID(...)`, chaque ligne relue par `normalizer.ReadDetections`, ordre `normalizer.SortDetections` ; `Summary` (`Files`, `EventsRead`, `Detections`, `SHA256` du fichier, `RulesApplied = 7`, `RulesetVersion`) ; SHA-256 de `normalized/`, `timeline/` et du manifeste inchangés (FR-001, FR-011 à FR-013, FR-021)
- [X] T014 [P] [US1] Écrire `TestRunDeterministic` et `TestRunErrors` dans internal/detection/detection_test.go : deux exécutions, puis une troisième avec `extsort.SegmentBudget` forcé à 4 Kio et `MaxFanIn` à 3 → fichiers identiques ; aucune preuve ingérée → `ErrNoEvents`, `detections/` vide ; ligne au champ inconnu → erreur avec chemin et `line N`, fichier précédent intact ; contexte annulé pendant la lecture et pendant la fusion → `context.Canceled`, fichier précédent intact, ni `.partial` ni `.work-*` ; restes d'un arrêt brutal supprimés par une exécution réussie ; aucun événement satisfaisant → fichier de zéro octet (FR-002, FR-014, US1-4, SC-003, SC-006)

### Implémentation du moteur

- [X] T015 [US1] Créer internal/detection/rule.go : `Rule{File, ID, Title, Version, Severity string; Confidence float64; MITRE, Channel string; cond node}` ; `parseRule(name string, data []byte) (r *Rule, skipped bool, err error)` : refus au-delà de 1 Mio, décodage `yaml.Node` avec refus de plusieurs documents, produit examiné en premier, champs obligatoires et facultatifs, version sur le contenu en `\n`, raisons de refus au texte exact du contrat (research.md R1, R4)
- [X] T016 [US1] Créer internal/detection/match.go : compilation d'une sélection (table → ET, liste de tables → OU, liste de valeurs nues → refus `keyword search is not supported`), modificateurs `contains`, `startswith`, `endswith`, `all`, `re`, `re|i` (préfixe `(?i)`), autres et `re` combiné à `contains`/`startswith`/`endswith` → `unsupported modifier: <mod>` ; valeurs scalaires en texte, `null` ; filtrage glob itératif insensible à la casse avec échappements ; accès aux champs (table de data-model.md)
- [X] T017 [US1] Créer internal/detection/condition.go : analyseur par descente récursive de la condition (tokens, priorités, `1 of`, `all of`, `them`), refus de `|` (`aggregation is not supported`) et de `timeframe` ; profondeur d'imbrication comptée et limitée à 64 (`invalid condition: too deeply nested`) ; arbre `node` évalué sur un événement
- [X] T018 [US1] Créer internal/detection/rules/ avec les 7 fichiers de data-model.md « Jeu embarqué » (identifiants, canaux, conditions, niveaux, statuts, étiquettes ATT&CK de la table ; en-tête `author: DFIRFlow`, `license: Apache-2.0`, `description` en anglais) et internal/detection/ruleset.go : `//go:embed rules/*.yml`, `Load(path string) (*Ruleset, error)` (`path` vide = embarqué, fichiers cités `embedded:<nom>` ; sinon fichier ou parcours trié des `.yml`/`.yaml`), `Applied`, `Skipped`, `Refused []Refusal{File, Reason}` triés par fichier, erreurs `no applicable rule in <path>` et `duplicate rule id <id>: <f1>, <f2>`, `Version` du jeu (research.md R4), index par canal en minuscules (research.md R8)
- [X] T019 [US1] Créer internal/detection/detection.go : `ErrNoEvents` (même texte que `timeline`), `Summary{Files, EventsRead, Detections int; SHA256 string; UnknownFiles []string}`, `Run(ctx, c *casefile.Case, rs *Ruleset) (Summary, error)` : `extsort.CleanStale(detections/, "detections.jsonl")`, `ingest.EventFiles`, `normalizer.ReadEvents` par fichier (erreur préfixée du chemin), règles du canal de chaque événement EVTX, `normalizer.Detection` encodée par `normalizer.NewEncoder` vers `extsort.Sorter` avec la clé `(timestamp µs, id, 0, "")` et son décodeur, `extsort.WriteAtomic` vers `detections/detections.jsonl`
- [X] T020 [US1] Faire passer T009 à T014 ; `go vet ./internal/detection/`

### Commande

- [X] T021 [P] [US1] Écrire `TestDetectCommand` et `TestDetectLog` dans cmd/dfirflow/main_test.go : sur un cas collecté et ingéré à partir de internal/parser/evtx/testdata/Security.evtx → sortie standard exactement `detect: 7 rules applied, 0 skipped, 0 refused, 739 events read, 15 detections: detections/detections.jsonl`, code 0, 1 détection de la règle `8ad87a09-…` et 14 de `16e98cfe-…` (SC-001) ; sans ingestion → code 1 et `run ingest first` ; dernière entrée de `case.log` : `command = detect`, `summary.rules = "embedded"`, `ruleset_version`, `rules_applied = 7`, `rules_skipped = 0`, `files`, `events_read`, `detections = 15`, `sha256` égal au SHA-256 du fichier, `rules_refused` et `unknown_files` absents ; en échec `error` présent et `sha256` absent (FR-015, FR-020, FR-022, contracts/detect.md)
- [X] T022 [US1] Brancher `detectCmd` dans cmd/dfirflow/commands.go à la place de `notImplemented` : `casefile.Open`, `detection.Load(o.rules.value)`, `detection.Run`, avertissements `rule refused` et `not in the case manifest` sur la sortie d'erreur, ligne de résumé du contrat, `logOperation` avec le résumé de data-model.md (`rules_refused`, `unknown_files` omis s'ils sont vides ; `ruleset_version` et comptes de règles omis si `Load` a échoué ; `error` en cas d'échec) ; résumé de l'aide de `detect` remplacé par le texte du contrat (FR-016)
- [X] T023 [US1] Faire passer T021 ; retirer la ligne `detect` de `TestNotImplemented` dans cmd/dfirflow/main_test.go (ligne 192) ; vérifier que `TestHelp` et `TestCommandHelp` passent avec la nouvelle aide et que la sortie de `dfirflow detect --help` contient `not proof of compromise` (FR-016)

**Checkpoint** : US1 vérifiable seule ; le jeu embarqué produit les détections attendues, tracées.

---

## Phase 4: User Story 2 — Appliquer ses propres règles (P2)

**Goal**: `--rules <fichier ou dossier>` remplace le jeu embarqué ; règles refusées et écartées signalées.

**Independent Test**: dossier avec une règle valide, une règle à agrégation et une règle Linux → 1 appliquée, 1 écartée, 1 refusée avec sa raison.

### Tests

- [X] T024 [P] [US2] Écrire `TestLoadPath` dans internal/detection/ruleset_test.go : dossier avec sous-dossier, fichiers `.yml`, `.yaml`, `.txt` (ignoré), un dossier `.github/` contenant un `.yml` (ignoré), une règle valide, une à agrégation, une Linux, une à `re|m` → `Applied`, `Skipped`, `Refused` attendus, raisons du contrat, ordre trié par fichier ; fichier unique désigné (extension quelconque) → chargé ; chemin inexistant → erreur `rules: <chemin>: …` ; dossier sans règle applicable → `no applicable rule in <chemin>` ; deux règles appliquées de même `id` → `duplicate rule id …` citant les deux fichiers ; une règle appliquée et une règle Linux de même `id` → pas d'erreur ; même jeu dans un autre ordre de fichiers → même `Version` ; une règle modifiée → `Version` de la règle et du jeu différentes (FR-003, FR-006 à FR-008, US2-6, SC-005)
- [X] T025 [P] [US2] Écrire `TestDetectRulesCommand` dans cmd/dfirflow/main_test.go : dossier de quickstart.md (copie de `security_log_cleared.yml`, `agg.yml`, `linux.yml`) → sortie `detect: 1 rules applied, 1 skipped, 1 refused, 739 events read, 1 detections: …`, avertissement `dfirflow: detect: warning: rule refused: <chemin>/agg.yml: aggregation is not supported`, code 0, `summary.rules` égal au chemin donné et `summary.rules_refused` ; `--rules` inexistant → code 1, fichier de détections précédent inchangé ; doublon d'identifiant → code 1 ; chaque règle refusée apparaît avec son fichier et sa raison dans la sortie d'erreur et dans `summary.rules_refused` (US2-1 à US2-5, SC-005)

### Implementation

- [X] T026 [US2] Compléter `Load` dans internal/detection/ruleset.go et `detectCmd` dans cmd/dfirflow/commands.go pour les cas de T024 et T025 non encore couverts par l'US1 ; faire passer T024 et T025

**Checkpoint** : US1 et US2 vertes.

---

## Phase 5: User Story 3 — Enchaîner l'investigation jusqu'à la détection (P3)

**Goal**: `investigate` produit les détections puis s'arrête à `correlate`.

**Independent Test**: `investigate` sur un dossier contenant Security.evtx → `detections/detections.jsonl` présent, sortie `correlate: not implemented yet`, code 3.

### Tests

- [X] T027 [US3] Adapter le test `investigate` de cmd/dfirflow/main_test.go (ligne 217) : message attendu `dfirflow: investigate: correlate: not implemented yet\n`, code 3, `detections/detections.jsonl` identique octet par octet à celui de l'enchaînement manuel `collect`, `ingest`, `timeline`, `detect` sur la même source (FR-023, SC-007)

### Implementation

- [X] T028 [US3] Vérifier que `investigate` dans cmd/dfirflow/commands.go appelle `detect` sans `--rules` (jeu embarqué) sans modification ; faire passer T027

**Checkpoint** : les trois stories vertes.

---

## Phase 6: Polish

- [X] T029 [P] Écrire `TestRunLarge` dans internal/detection/detection_test.go, sauté sans `DFIRFLOW_LARGE=1` : 10 millions d'événements synthétiques Security et System répartis dans 4 fichiers, dont 1 % satisfaisant une règle embarquée → nombre de détections attendu, ordre vérifié en flux, `runtime.MemStats.HeapInuse` maximal échantillonné sous 256 Mio ; consigner durée et mémoire dans le message du test (FR-019, SC-004)
- [X] T030 [P] Écrire `FuzzParseRule` dans internal/detection/fuzz_test.go (corpus initial : les 7 règles embarquées et les règles refusées de T009) : aucune panique, toute erreur de chargement porte une raison non vide, une règle chargée a un `ID`, une `Version` de 16 hexa et un canal de la table ; lancé 60 s avec `go test -fuzz` lors de T031 (constitution, « Contraintes » : entrée non fiable)
- [X] T031 Exécuter `gofmt -l .`, `go vet ./...`, `GOOS=windows go vet ./...`, `go test -race ./...` ; vérifier que go.mod ne déclare que `go.yaml.in/yaml/v3` ; dérouler les 11 scénarios de quickstart.md
- [X] T032 [P] Mettre à jour docs/architecture-actuelle.md : spec 012 marquée Codé, 006 marquée Livré, commande `detect` et flux `normalized/ → detections/` (règles embarquées ou `--rules`, sous-ensemble Sigma, `case.log`), packages `internal/extsort` et `internal/detection`, dépendance `go.yaml.in/yaml/v3`, `investigate` jusqu'à `correlate` ; cocher les tâches terminées dans specs/012-detection/tasks.md

---

## Dependencies & Execution Order

- Phase 1 → Phase 2 (bloquante : refactor) → US1 → US2 → US3 → Polish.
- Dans US1 : T015 → T016 → T017 (le chargement d'une règle compile sélections et condition), puis T018 → T019 ; la commande (T021 à T023) après le moteur.
- US2 étend ruleset.go et commands.go écrits en US1 : à enchaîner après US1.
- US3 dépend de US1 ; indépendante de US2.
- Dans chaque story : tests (rouges) → implémentation → checkpoint vert.

## Parallel Examples

- Phase 2 : T003 et T004 ensemble, puis T005, T006, puis T007 → T008.
- US1 : T009 à T014 ensemble, puis T015 → T020 ; T021 en parallèle du moteur, puis T022 → T023.
- US2 : T024 et T025 ensemble, puis T026.
- Polish : T029, T030 et T032 en parallèle, puis T031.

## Implementation Strategy

1. **MVP** = Phases 1 à 3 (US1) : jeu embarqué, détections déterministes, atomiques et tracées ;
   `--rules` est déjà lu par `Load` mais sa couverture complète (refus, doublons) vient en US2.
2. US2 : règles fournies par l'analyste, refus motivés.
3. US3 : bascule du test `investigate` jusqu'à `correlate`.
4. Polish : volume, vérifications croisées Windows / Linux, documentation.
