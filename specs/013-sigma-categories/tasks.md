---

description: "Task list for 013-sigma-categories"
---

# Tasks: Catégories de sources et modificateurs Sigma

**Input**: Design documents from `/specs/013-sigma-categories/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/detect.md,
quickstart.md

**Tests**: inclus (constitution, principe VI) ; chaque test est écrit avant le code qu'il couvre.
Compatibilité `go 1.18` : pas de `slices`, `maps`, `cmp`, `min`, `errors.Join` ; `net/netip` est
disponible. Aucune dépendance ajoutée. Les événements de test sont synthétiques (helpers `evtx`,
`rule`, `mustRule`, `newCase`, `writeEvents` de internal/detection), sauf le journal Security de
référence. Aucune règle SigmaHQ (DRL 1.1) n'entre dans le dépôt.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [X] T001 Vérifier que `go test -race ./...` passe sur `feature/013-sigma-categories` (base `dev` avec la 012) ; produire avec le binaire actuel les détections du journal Security de référence ingéré et les enregistrer dans internal/detection/testdata/security_012.jsonl (référence de SC-006, 15 lignes)
- [X] T002 Écrire internal/detection/categories.json selon la table « Contenu » de data-model.md : 16 catégories, 17 sources ; `security-4688` avec `label` `Security 4688`, `rename` `Image` → `NewProcessName` et `ParentImage` → `ParentProcessName`, `fields` `Image`, `ParentImage`, `CommandLine` ; contraintes `EventType` `CreateKey` (sysmon-12-add), `DeleteKey`, `DeleteValue` (sysmon-12-delete), `SetValue` (sysmon-13)

---

## Phase 2: Foundational (bloquant pour toutes les stories)

Refactor sans changement de comportement : les règles de service deviennent des entrées
`(règle, source)` et les champs sont lus à travers une source (research.md R4).

- [X] T003 Écrire `TestCategoriesTable` dans internal/detection/categories_test.go : la table embarquée se charge ; catégories et noms de sources uniques ; `event_ids` non vide ; tout champ renommé d'une source partielle figure dans `fields` ; `CategoriesVersion` = 16 hexa du SHA-256 de categories.json ; une table modifiée (copie en mémoire) change la version ; une table invalide (doublon, `event_ids` vide) est rejetée par la fonction de validation
- [X] T004 Créer internal/detection/categories.go : `//go:embed categories.json`, type `Source{Name, Label, Channel string; EventIDs map[uint32]bool; EventType map[string]bool; Rename map[string]string; Fields map[string]bool}` (Fields nil = source complète ; clés `EventType` en minuscules), `categories map[string][]*Source`, `CategoriesVersion`, chargement et validation au démarrage du package (panique sur table invalide, jamais atteinte hors bogue de construction, couvert par T003)
- [X] T005 Dans internal/detection/match.go, faire lire les champs à travers une source : `field(ev, name, src *Source)` applique `src.Rename[name]` si présent ; propager la source dans l'évaluation (`node.eval(ev, src)`, `selection.match`, `group.match`, `fieldCond.match`) ; une source nil (règle de service) garde la lecture de la spec 012 ; adapter internal/detection/condition.go
- [X] T006 Dans internal/detection/rule.go, calculer à la compilation `Rule.fields` (ensemble trié des champs cités par les sélections) ; dans internal/detection/ruleset.go, remplacer `byChannel map[string][]*Rule` par `byChannel map[string]*channelIndex` avec `channelIndex{any []entry; byID map[uint32][]entry}` et `entry{rule *Rule; src *Source}` (research.md R4), une entrée sans source dans `any` par règle de service, ordre des entrées stable ; dans internal/detection/detection.go, examiner `byID[event_id]` puis `any`, et évaluer `e.rule.match(&ev, e.src)` après le filtre `src.EventType` quand `src` n'est pas nil
- [X] T007 Ajouter à `TestDetectCommand` dans cmd/dfirflow/main_test.go la comparaison octet par octet du fichier produit sur le cas de référence avec internal/detection/testdata/security_012.jsonl (SC-006) ; `go vet ./...` et `go test -race ./...` verts sans modifier les autres assertions existantes

**Checkpoint** : comportement de la 012 inchangé ; moteur prêt à recevoir des sources.

---

## Phase 3: User Story 1 — Règles Sigma décrites par catégorie (P1) MVP

**Goal**: une règle `logsource.category` couverte est appliquée aux seuls événements de ses sources.

**Independent Test**: une règle par catégorie sur des événements Sysmon et PowerShell synthétiques → détection du positif, rien pour une autre catégorie, un autre journal ou un autre EventID.

### Tests

- [X] T008 [P] [US1] Écrire `TestCategoryRules` dans internal/detection/categories_test.go : pour chacune des 16 catégories, une règle `category: <c>` sur un champ commun (par exemple `Marker: x`) et quatre événements synthétiques : positif (canal, EventID et `EventType` de la source), même champ dans une autre catégorie du même canal, même EventID dans un autre canal, autre EventID → seule la première correspondance ; `registry_add` contre Sysmon 12 `EventType: DeleteKey` → faux ; `registry_event` vrai pour 12, 13 et 14 ; `EventType` comparé sans tenir compte de la casse (FR-001, FR-002, SC-001)
- [X] T009 [P] [US1] Ajouter à `TestRefusedRule` dans internal/detection/rule_test.go, avec exactement les raisons de contracts/detect.md : ni service ni catégorie → `missing logsource.service or logsource.category` ; `category: webserver` → `unknown logsource category: webserver` ; `category: process_creation` avec `service: system` → `logsource category and service do not match` ; retirer le cas `logsource category is not supported` ; remplacer l'attente `missing logsource.service` de internal/detection/rule_test.go par `missing logsource.service or logsource.category` ; vérifier que `product: linux` avec une catégorie inconnue reste écartée et non refusée (data-model.md, ordre des contrôles de `logsource`)
- [X] T010 [P] [US1] Ajouter à internal/detection/ruleset_test.go `TestCategoryAndService` : `category: process_creation` avec `service: sysmon` → une seule entrée, source `sysmon-1` ; `category: ps_script` avec `service: powershell` → source `powershell-4104` (FR-007, research.md R5)
- [X] T011 [P] [US1] Ajouter à internal/detection/detection_test.go `TestRunCategories` : un cas mêlant Sysmon 1, 3, 13, PowerShell 4104 et Security, règles de catégorie et de service via `Load(dir)` → une détection par couple (règle, événement satisfait), ordre et format de la spec 012, version du jeu de règles inchangée par la présence de la table (FR-016)

### Implémentation

- [X] T012 [US1] Dans internal/detection/rule.go, remplacer le refus `logsource category is not supported` par l'ordre des contrôles de data-model.md (étapes 1 à 5) ; `Rule.Channel` devient facultatif ; `Rule.sources []*Source` pour une règle de catégorie, dans l'ordre de la table ; la confiance, la sévérité, la version et `MITRE` restent calculées comme en spec 012
- [X] T013 [US1] Dans internal/detection/ruleset.go, créer une entrée par source d'une règle de catégorie, rangée sous chacun des EventID de la source (research.md R4) ; l'index reste trié de façon stable ; `go test -race ./internal/detection/` vert pour T008 à T011

**Checkpoint** : US1 fonctionnelle et testable seule avec `--rules`.

---

## Phase 4: User Story 2 — Créations de processus sans Sysmon (P1)

**Goal**: `process_creation` s'applique à 4688 avec renommage ; la garde exclut les règles qui citent un champ absent ; l'analyste est prévenu.

**Independent Test**: une règle sur `Image` et `CommandLine` détecte un lancement Sysmon et le même en 4688 ; une règle qui exclut `Hashes` ne détecte que l'événement Sysmon ; un avertissement et `case.log` signalent la restriction.

### Tests

- [X] T014 [P] [US2] Écrire `TestGuard4688` dans internal/detection/ruleset_test.go : règle `Image|endswith` + `CommandLine|contains` → entrées `sysmon-1` et `security-4688`, aucune restriction ; règle avec filtre `Hashes|contains` → seule `sysmon-1`, `Ruleset.Restricted` = `[{file, "security-4688", ["Hashes"]}]` ; règle `fieldref` vers `OriginalFileName` → restriction citant ce champ ; règle `category: process_creation` + `service: security` citant `Hashes` → refus `fields not available in any source: Hashes` ; `EventID`, `Channel`, `Provider_Name`, `Computer` toujours fournis ; `Restricted` trié par fichier puis source (FR-006, FR-008, research.md R3, R7)
- [X] T015 [P] [US2] Écrire `TestRun4688` dans internal/detection/detection_test.go : un même lancement en Sysmon 1 (`Image`, `ParentImage`, `CommandLine`) et en 4688 (`NewProcessName`, `ParentProcessName`, `CommandLine`) → deux détections pour une règle sur ces champs (FR-005a) ; une seule pour la règle à filtre `Hashes` (SC-003) ; un 4688 sans `CommandLine` et une règle `not CommandLine|contains` → comportement de la spec 012 (champ absent → sélection fausse)
- [X] T016 [P] [US2] Ajouter à cmd/dfirflow/main_test.go `TestDetectCategories` sur le cas de référence (`newDetectCase`) : règle `category: process_creation`, `ParentImage|endswith: '\smss.exe'` → 7 détections, aucun avertissement ; ajout d'une règle à filtre `Hashes` → sortie d'erreur exactement `dfirflow: detect: warning: 1 rule not applied to Security 4688 (missing fields), see case.log`, toujours 7 détections ; `case.log` : `categories_version` de 16 hexa, `rules_restricted` `[{file, source: "security-4688", missing: ["Hashes"]}]`, `rules_refused` absent ; avec deux règles restreintes → `2 rules not applied …` (contracts/detect.md, FR-015, FR-015a)

### Implémentation

- [X] T017 [US2] Dans internal/detection/ruleset.go, appliquer la garde (research.md R3) : pour une source partielle, exclure l'entrée si `Rule.fields` (plus les cibles `fieldref`, ajoutées en US3) contient un champ hors `src.Fields` et hors des champs communs ; type exporté `Restriction{File, Source string; Missing []string}` avec étiquettes JSON `file`, `source`, `missing` ; `Ruleset.Restricted` trié ; aucune entrée restante → refus FR-008 ; une restriction ne compte pas comme un refus
- [X] T018 [US2] Dans cmd/dfirflow/commands.go (`detectCmd`) : après les avertissements de refus, un avertissement par source partielle ayant au moins une restriction, au texte exact de contracts/detect.md (singulier `1 rule`, pluriel sinon, libellé `Label` de la source), avant les avertissements du manifeste ; clés `categories_version` (dès que le jeu est chargé) et `rules_restricted` (omise si vide) dans le résumé `case.log` ; ligne de résumé inchangée (FR-017)

**Checkpoint** : US1 et US2 couvrent les règles `process_creation` sur toutes les machines.

---

## Phase 5: User Story 3 — Modificateurs Sigma courants (P2)

**Goal**: `windash`, `cidr`, `base64`, `base64offset`, `wide`/`utf16le`, `utf16be`, `exists`, `cased`, `fieldref` pris en charge ; combinaisons invalides refusées.

**Independent Test**: pour chaque modificateur, un positif et un négatif ; pour chaque combinaison refusée, le refus cite le modificateur.

### Tests

- [X] T019 [P] [US3] Ajouter à `TestMatch` dans internal/detection/match_test.go, un positif et un négatif par cas : `CommandLine|windash|contains: ' -enc '` contre `-enc`, `/enc`, `–enc` (U+2013), `—enc` (U+2014), `―enc` (U+2015), et négatif `xenc` ; règle `CommandLine|windash: 'a-enc'` contre `a/enc` → faux (tiret au milieu d'un mot non remplacé) ; `DestinationIp|cidr` IPv4 `10.0.0.0/8` et IPv6 `fe80::/10`, valeur non IP → faux ; `|base64|contains: 'abc'` contre `YWJj` et négatif en casse différente `ywjj` ; `|base64offset|contains: 'IEX'` contre l'encodage de `xIEX`, `xxIEX`, `xxxIEX` (les trois alignements) ; `|wide|base64offset|contains: 'IEX'` contre une ligne PowerShell `-enc` réelle encodée en UTF-16LE ; `|utf16be|base64|contains` ; `|exists: true` et `false` contre champ présent vide, présent, absent ; `|cased|endswith: '.EXE'` contre `a.EXE` et `a.exe` ; `|cased|windash|contains` ; `SourceUser|fieldref: TargetUser` égal, différent en casse (vrai), différent, champ cible absent (faux) ; `|fieldref|cased` différent en casse (faux) ; `|base64offset|contains|all` avec deux valeurs (research.md R6, SC-004)
- [X] T020 [P] [US3] Ajouter à `TestRefusedRule` dans internal/detection/rule_test.go, chaque refus de data-model.md « Modificateurs » avec le texte exact `unsupported modifier: <mod>` : `re|windash`, `re|base64`, `re|cased`, `base64|base64offset`, `wide|utf16be|base64`, `wide` seul, `base64|wide`, `base64|windash`, `base64|cased`, `cidr|contains`, `exists|contains`, `fieldref|startswith`, `contains|contains`, `utf16`, `expand`, `gt`, `re|m` ; refus de valeur `invalid selection <nom>: field <champ>: …` pour `cidr: 300.0.0.0/8`, `exists: maybe`, `exists: [true, false]`, `fieldref: ''` (FR-011)

### Implémentation

- [X] T021 [US3] Créer internal/detection/modifiers.go : analyse de la chaîne de modificateurs d'une clé (ordre et combinaisons de data-model.md) ; `windash` : jeton de classe dans `glob` (`globTok` de type classe avec l'ensemble `- / – — ―`) aux positions de research.md R6, sans expansion ; `cased` : `glob` sensible à la casse ; `base64` et `base64offset` (`encoding/base64.StdEncoding`, décalages `[0, 2, 3]` en tête et `[0, 3, 2]` en fin selon `(n + i) mod 3`), motifs toujours sensibles à la casse, `base64offset` comme un OU de trois motifs par valeur ; `wide`/`utf16le` et `utf16be` via `unicode/utf16` sans marque d'ordre des octets
- [X] T022 [US3] Dans internal/detection/match.go, brancher modifiers.go dans `compileGroup` en conservant le comportement des modificateurs de la spec 012 ; ajouter `exists` (booléen YAML unique, présence du champ même vide), `cidr` (`netip.ParsePrefix` à la compilation, `netip.ParseAddr` sur la valeur de l'événement), `fieldref` (cible lue à travers la source, égalité insensible à la casse sauf `cased`) ; ajouter les cibles `fieldref` à `Rule.fields` pour la garde (T017)
- [X] T023 [P] [US3] Ajouter à internal/detection/fuzz_test.go des amorces avec catégories, `windash`, `base64offset`, `cidr`, `exists`, `fieldref` et combinaisons refusées ; lancer `go test -run '^$' -fuzz FuzzParseRule -fuzztime 60s ./internal/detection/` : aucune panique

**Checkpoint** : les règles `process_creation` et `network_connection` du corpus public ne sont plus refusées pour leurs modificateurs.

---

## Phase 6: User Story 4 — Règles par catégorie dans le jeu embarqué (P3)

**Goal**: 5 règles embarquées de plus, chacune avec positif et négatif, sans refus ni restriction.

**Independent Test**: `detect` sans `--rules` : une détection par cas positif, aucune pour les négatifs ; 15 détections inchangées sur la référence.

- [X] T024 [P] [US4] Ajouter à `embeddedCases` dans internal/detection/rules_test.go les cas de data-model.md « Jeu embarqué » : positif et négatif Sysmon par règle ; positif et négatif 4688 pour les trois règles `process_creation` ; pour `registry_set_run_key.yml`, négatif Sysmon 12 de même `TargetObject` ; pour `ps_script_download_execute.yml`, négatif qui télécharge sans exécuter ; `TestEmbeddedRules` attend 12 règles, 0 écartée, 0 refusée, `Restricted` vide, et les identifiants et techniques de data-model.md (FR-013, FR-014, SC-005)
- [X] T025 [US4] Écrire dans internal/detection/rules/ les cinq fichiers de data-model.md (`proc_creation_powershell_encoded.yml`, `proc_creation_vssadmin_delete_shadows.yml`, `proc_creation_certutil_download.yml`, `registry_set_run_key.yml`, `ps_script_download_execute.yml`) avec un UUID v4 chacun (reporté dans data-model.md), `author: DFIRFlow`, `license: Apache-2.0`, description en anglais, `status: test` et le niveau et la technique ATT&CK de la table ; règles de la spec 012 inchangées
- [X] T026 [US4] Mettre à jour cmd/dfirflow/main_test.go : `TestDetectCommand` et `TestDetectLog` attendent `12 rules applied` et `rules_applied` 12, toujours 15 détections sur la référence ; la comparaison à internal/detection/testdata/security_012.jsonl ajoutée en T007 reste verte (SC-006)

**Checkpoint** : jeu embarqué complété ; `investigate` en bénéficie sans option.

---

## Phase 7: Polish

- [X] T027 [P] Étendre `TestRunLarge` dans internal/detection/detection_test.go : 10 millions d'événements mêlant Sysmon 1, 3, 13, PowerShell 4104 et Security 4624, 4688, dont 1 % satisfaisant une règle embarquée de catégorie ou de service → nombre de détections attendu, ordre vérifié en flux, pic `HeapInuse` sous 256 Mio, moins de 5 minutes ; second passage avec 2 000 règles de catégorie synthétiques, toutes fausses, chargées par `Load(dir)` avec le jeu embarqué, dont 1 800 sur des catégories absentes du flux et 200 `process_creation` et `registry_set` : durée au plus le double du premier passage ; consigner durées et mémoire (SC-007, research.md R4)
- [X] T028 [P] Écrire `TestSigmaCorpus` dans internal/detection/sigma_test.go, sauté sans `DFIRFLOW_SIGMA_DIR` : parcourt les `.yml` du dossier, garde les règles `product: windows` dont la catégorie est couverte, charge chacune avec `parseRule`, journalise la part chargée et les raisons de refus regroupées et comptées (raison sans la partie variable après `: `) ; n'échoue pas sous 90 % mais journalise l'écart, à reporter dans docs/architecture-actuelle.md par T030 (SC-002 non bloquant, research.md R8). La mesure elle-même demande une release SigmaHQ copiée hors du dépôt : demander l'accord de l'utilisateur avant tout téléchargement
- [X] T029 [P] Mettre à jour README.md : tableau du sous-ensemble Sigma (catégories prises en charge, nouveaux modificateurs, refus restants), jeu embarqué à 12 règles, règle d'exemple avec `category: process_creation`, garde 4688 et son avertissement ; retirer la limite connue sur les catégories ; aucun lien vers specs/ ni docs/
- [X] T030 [P] Mettre à jour docs/architecture-actuelle.md : spec 013 marquée Codé, table des catégories et garde 4688 dans la section Détection, point ouvert sur les catégories rares et les sources hors Sysmon ; mettre à jour la ligne `ps_module` et les sources si la mesure de T028 les a fait évoluer
- [X] T032 Amender spec.md (Q2 révisée, FR-005a, cas limite, hypothèses), contracts/detect.md (invariant, `detections_merged`), data-model.md (« Rapprochement »), research.md R9
- [X] T033 Modifier `TestRun4688` dans internal/detection/detection_test.go : le lancement vu par Sysmon 1 et 4688 → une détection, `events` = les deux `uid` triés, horodatage du plus ancien, `id` = `DetectionID` des deux ; règle à filtre `Hashes` → une détection (Sysmon seul) ; négatifs : PID différent, PID parent différent, image différente, écart de 3 s, deux règles différentes → pas de rapprochement ; deux Sysmon de même clé → pas de rapprochement entre eux ; `Summary.Merged` et `Detections` exacts ; ajouter à `TestDetectLog` ou `TestDetectCategories` la clé `detections_merged` (omise si nulle)
- [X] T034 Implémenter le rapprochement dans internal/detection/detection.go (research.md R9, data-model.md « Rapprochement ») : second `extsort.Sorter` pour les candidates, fenêtre de 2 s, ajout au tri principal ; `Summary.Merged` ; `detections_merged` dans cmd/dfirflow/commands.go
- [X] T035 Mettre à jour README.md et docs/architecture-actuelle.md (une détection pour un lancement vu par Sysmon et 4688 ; DF-36 traité par la 013) ; relancer T031 et `TestRunLarge`
- [X] T031 Exécuter `gofmt -l .`, `go vet ./...`, `GOOS=windows go vet ./...`, `go test -race ./...` ; vérifier que go.mod n'a pas changé ; dérouler les scénarios 1 à 8 et 10 de quickstart.md (le 9 après T028) ; cocher les tâches terminées dans specs/013-sigma-categories/tasks.md

---

## Dependencies & Execution Order

- Phase 1 → Phase 2 (bloquante : entrées et lecture par source) → US1 → US2 → US3 → US4 → Polish.
- US2 dépend de US1 (sources de catégorie) ; la garde de `fieldref` (T017) est complétée par T022.
- US3 ne dépend que de la phase 2 (modificateurs utilisables aussi par les règles de service) ; elle peut suivre US1 en parallèle de US2, mais touche match.go comme T005 : à enchaîner après la phase 2.
- US4 dépend de US1, US2 (règles `process_creation` sur 4688) et US3 (`windash` dans deux règles).
- Dans chaque story : tests (rouges) → implémentation → checkpoint vert.

## Parallel Examples

- Phase 2 : T003 en parallèle de T002, puis T004 → T005 → T006 → T007.
- US1 : T008 à T011 ensemble, puis T012 → T013.
- US2 : T014 à T016 ensemble, puis T017 → T018.
- US3 : T019 et T020 ensemble, puis T021 → T022, puis T023.
- Polish : T027 à T030 en parallèle, puis T031.

## Implementation Strategy

1. **MVP** = Phases 1 à 3 (US1) : règles de catégorie Sysmon et PowerShell via `--rules`, sans
   changement pour les règles de service.
2. US2 : `process_creation` sur 4688, garde et avertissement — la valeur sur les machines sans
   Sysmon.
3. US3 : modificateurs, pour charger la majorité du corpus public des catégories couvertes.
4. US4 : jeu embarqué, visible avec `investigate`.
5. Polish : volume, mesure SigmaHQ (avec accord), documentation, vérifications Windows et Linux.
