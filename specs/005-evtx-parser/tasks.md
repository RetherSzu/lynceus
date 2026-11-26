---

description: "Task list for 005-evtx-parser"
---

# Tasks: Parser EVTX et ingestion des journaux

**Input**: Design documents from `/specs/005-evtx-parser/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/ingest.md,
contracts/evtx-mapping.md, quickstart.md

**Tests**: inclus (constitution, principe VI) ; chaque test est écrit avant le code qu'il couvre.
Compatibilité `go 1.18` : pas de `slices`, `maps`, `cmp`, `min`, `errors.Join`. Aucun module
externe ne doit être ajouté à `go.mod`.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [X] T001 Vérifier que `go test -race ./...` passe sur la branche (base specs 001 à 004) et que `go.mod` ne déclare aucune dépendance
- [X] T002 Copier depuis le cache de modules `www.velocidex.com/golang/evtx@v0.2.0` les fichiers `evtx.go`, `normalize.go`, `debug.go` et `LICENSE` vers internal/parser/evtx/binxml/ ; renommer le package en `binxml` ; créer internal/parser/evtx/binxml/NOTICE (origine, version v0.2.0, licence Apache-2.0, liste des modifications tenue à jour par les tâches suivantes) (research.md R1)
- [X] T003 Copier `testdata/Security.evtx` (739 enregistrements) et `testdata/Security_1_record.evtx` du même module vers internal/parser/evtx/testdata/ ; ajouter internal/parser/evtx/testdata/README.md (origine, licence Apache-2.0)
- [X] T004 Obtenir `evtx_dump` v0.12.3 (binaire de release `omerbenamram/evtx`, licence MIT/Apache-2.0) hors du dépôt, vérifier son SHA-256 publié, générer `evtx_dump -o jsonl internal/parser/evtx/testdata/Security.evtx` vers internal/parser/evtx/testdata/oracle/Security.evtx_dump.jsonl ; créer internal/parser/evtx/testdata/oracle/README.md (outil, version, commande, date, écarts connus) (research.md R11). Demande l'accord de l'utilisateur pour le téléchargement.

---

## Phase 2: Foundational (fork compilable et sans dépendance, bloquant pour toutes les stories)

- [X] T005 Écrire `TestDecodeBaseline` dans internal/parser/evtx/binxml/binxml_test.go : décoder internal/parser/evtx/testdata/Security.evtx chunk par chunk → 739 enregistrements, numéros d'en-tête strictement croissants, chaque enregistrement porte `System/EventID` et `System/Channel`
- [X] T006 Créer internal/parser/evtx/binxml/odict.go : type ordonné minimal remplaçant `ordereddict.Dict` (méthodes utilisées par evtx.go et normalize.go uniquement : `NewDict`, `Set`, `Get`, `Keys`, itération ordonnée) ; remplacer toutes les références dans evtx.go et normalize.go (research.md R2)
- [X] T007 Remplacer `github.com/pkg/errors` par `fmt.Errorf` / `errors.New` dans internal/parser/evtx/binxml/evtx.go ; remplacer `os.SEEK_SET` par `io.SeekStart` ; supprimer toute référence à `Debug`/`spew` ; vérifier `go build ./...` et que `go.mod` est inchangé
- [X] T008 Ajouter dans internal/parser/evtx/binxml/evtx.go une API de lecture pour le parser : `OpenFile(r io.ReaderAt, size int64) (*File, error)` (en-tête de fichier, signature `ElfFile\x00`, nombre de chunks borné par `size/65536`) et `(*File) Chunk(i int) (*Chunk, error)` sur un `io.SectionReader` ; consigner la modification dans NOTICE
- [X] T009 Écrire `TestNoExternalDependency` dans internal/parser/evtx/binxml/binxml_test.go : lire `go.mod` à la racine du module et échouer sur toute directive `require` ; vérifier qu'aucun fichier .go du dépôt, hors `_test.go`, n'importe `golang-lru` (non-régression C12 / E1, FR-021)

**Checkpoint** : `go test ./internal/parser/evtx/binxml/` vert, `go.mod` sans dépendance.

---

## Phase 3: User Story 1 — Ingérer les journaux EVTX collectés (P1) MVP

**Goal**: `ingest` produit `normalized/<rel>.jsonl` pour chaque preuve EVTX, avec les champs communs de la spec 003 et `event_type = other`.

**Independent Test**: quickstart.md scénarios 1 à 5.

### Tests

- [X] T010 [P] [US1] Écrire `TestMatch` et `TestParseBaseline` dans internal/parser/evtx/parser_test.go : `Match` vrai sur les 8 premiers octets `ElfFile\x00`, faux sur `MZ`, sur un contenu vide et sur un texte ; `Parse` de Security.evtx avec un `Sink` de test → 739 événements, aucune anomalie, chacun avec `source = evtx`, `channel`, `provider`, `event_id`, `host` non vide, `record_id` = numéro d'en-tête, `record_locator` au format `chunk:<i>/record:<n>`, `ingest = native`, `uid = normalizer.UID(sha, file, locator)`, et valide selon `Validate()` ; enregistrement décodé construit en mémoire avec `Computer` vide et passé à la fonction de conversion du parser → anomalie `invalid` avec les violations, aucun événement (pas de modification d'octets : `Computer` peut appartenir à un modèle BinXML partagé) (Edge Case « invalide pour le modèle 003 »)
- [X] T011 [P] [US1] Écrire `TestIngest` dans internal/ingest/ingest_test.go : cas créé par `casefile.Create`, preuve Security.evtx ajoutée par `AddEvidence` sous `Windows/System32/winevt/Logs/`, fichier texte `notes.evtx` ajouté aussi → résultats `INGESTED` (events=739, anomalies=0) et `SKIPPED` (reason `not an EVTX file`) triés par chemin ; `normalized/Windows/System32/winevt/Logs/Security.evtx.jsonl` relu par `normalizer.ReadEvents` → 739 événements ; fichier `.anomalies.jsonl` présent et vide ; aucun `.partial` ; deuxième appel → fichiers identiques octet par octet (SC-005) ; sélection d'un seul chemin → une seule preuve traitée ; chemin hors manifeste → erreur `not in the case manifest: <chemin>` sans écriture ; aucune preuve EVTX → erreur `no EVTX evidence to ingest` ; preuve `Security.dat` au contenu EVTX → `INGESTED` (FR-002) ; preuve EVTX dont l'en-tête est tronqué à 100 octets → `FAILED` avec une raison non vide (texte non imposé), aucun fichier normalisé ni `.partial` pour elle, les autres preuves traitées
- [X] T012 [P] [US1] Écrire `TestIngestCommand` dans cmd/dfirflow/main_test.go : sortie exacte de contracts/ingest.md pour un cas avec Security.evtx (ligne `INGESTED  …  events=739 anomalies=0`, ligne de résumé), code 0 ; cas avec une preuve à l'en-tête tronqué → ligne `FAILED    <chemin>  reason=…`, stderr `dfirflow: ingest: ingestion incomplete`, code 1 (FR-019) ; retirer `ingest` de `TestNotImplemented` ; dans `TestNotImplemented`, la cible d'`investigate` contient une copie de internal/parser/evtx/testdata/Security.evtx et l'erreur attendue devient `dfirflow: investigate: timeline: not implemented yet` (code 3) ; dans `TestScriptUsage`, remplacer `ingest` par `timeline --case ./cases/CASE-001` pour les deux vérifications de syntaxe (la commande doit rester non implémentée)

### Implementation

- [X] T013 [US1] Créer internal/parser/evtx/parser.go : `type Parser struct{}` implémentant `parser.Parser` ; `Name() = "evtx"` ; `Match(head)` sur la signature ; `Parse(ctx, r, size, src, out)` : `binxml.OpenFile`, boucle séquentielle sur les chunks (FR-007), contrôle de `ctx` entre chunks et entre enregistrements, construction de l'événement selon data-model.md (`System/Channel`, `System/Provider/@Name`, `System/EventID`, `normalizer.NormalizeHost(System/Computer)`, `TimeCreated` en horodatage principal de type `logged`, `metadata` = toutes les valeurs de `EventData`/`UserData` en chaînes, `event_type = other`) ; erreur fatale si la signature est invalide
- [X] T014 [US1] Créer internal/ingest/ingest.go : `type Result struct{ File, Status, Reason string; Events, Anomalies int }` ; statuts `Ingested`, `Skipped`, `Altered`, `Failed` ; `func Run(ctx context.Context, c *casefile.Case, paths []string, parsers []parser.Parser) ([]Result, error)` : liste des preuves depuis le manifeste (nouvelle méthode `(*Case) Evidence() []ManifestEntry` dans internal/case/case.go, triée par `File`), filtre `paths` (relatifs à `evidence/`, séparateurs normalisés, chemin hors manifeste refusé avant tout traitement), lecture des 8 premiers octets et choix du parser par `Match`, ouverture en lecture seule, `parser.Validating` vers un écrivain JSONL (`normalizer.NewEncoder`) et un écrivain d'anomalies, fichiers `<rel>.jsonl.partial` et `<rel>.anomalies.jsonl.partial` puis renommage (R9) ; suppression des `.partial` en cas d'erreur ou d'annulation
- [X] T015 [US1] Brancher `ingest` dans cmd/dfirflow/commands.go : `casefile.Open`, `ingest.Run` avec `[]parser.Parser{evtx.Parser{}}`, une ligne par résultat au format de contracts/ingest.md (statut aligné sur 9 caractères puis deux espaces), ligne de résumé ; `errIngestIncomplete` (`ingestion incomplete`, code 1) si au moins un `FAILED` ; mettre à jour l'exemple d'aide en `dfirflow ingest --case ./cases/CASE-001 Windows/System32/winevt/Logs/Security.evtx`

**Checkpoint** : scénarios 1 à 5 du quickstart OK (sans la ligne `other`, ajoutée en US4).

---

## Phase 4: User Story 2 — Ne perdre aucun enregistrement en silence (P1)

**Goal**: événements + anomalies = enregistrements annoncés ; aucune panique ; mémoire bornée.

**Independent Test**: tests ci-dessous sur fixtures dérivées de Security.evtx.

### Tests

- [X] T016 [P] [US2] Écrire `TestCorruptChunk` dans internal/parser/evtx/parser_test.go : copie en mémoire de Security.evtx avec 200 octets inversés au début du premier enregistrement du chunk 0 → somme événements + anomalies = 739, anomalies `unreadable` puis `missing` localisées `chunk:0/record:<n>`, enregistrements des autres chunks émis (E2, constat C11)
- [X] T017 [P] [US2] Écrire `TestTruncated` dans internal/parser/evtx/parser_test.go : fichier coupé au milieu d'un chunk → enregistrements complets émis, une anomalie `truncated`, somme = enregistrements annoncés par les chunks lisibles ; fichier coupé dans l'en-tête → erreur fatale ; journal vide (en-tête valide, aucun chunk) → aucun événement, aucune anomalie, pas d'erreur (Edge Case « Journal vide »)
- [X] T018 [P] [US2] Écrire `TestMalformed` dans internal/parser/evtx/binxml/binxml_test.go : taille d'enregistrement démesurée (0xFFFFFFFF), longueur de chaîne démesurée, nombre de chunks de l'en-tête à 0xFFFF sur un fichier de 2 chunks → aucune panique, moins de 1 Mio alloué au total (`runtime.ReadMemStats`, écart de `TotalAlloc` avant et après), anomalie ou erreur (E5)
- [X] T019 [P] [US2] Écrire `FuzzChunk` dans internal/parser/evtx/binxml/fuzz_test.go : corpus initial = chunks de Security.evtx ; la propriété vérifiée est l'absence de panique et l'égalité lus + manquants = annoncés (R12)
- [X] T020 [P] [US2] Écrire `TestParseMemory` dans internal/parser/evtx/parser_test.go (ignoré avec `-short`) : fichier EVTX synthétique de 1 Gio obtenu en répétant les chunks de Security.evtx et en ajustant le nombre de chunks de l'en-tête, lu via un `io.ReaderAt` qui génère les octets à la volée → `HeapInuse` < 64 Mio pendant le décodage (SC-004)

### Implementation

- [X] T021 [US2] Dans internal/parser/evtx/binxml/evtx.go, modifier `Chunk.Parse` : ne plus renvoyer `result, nil` sur erreur ; renvoyer les enregistrements lus et la liste ordonnée des numéros attendus (`FirstEventRecNumber` à `LastEventRecNumber`) non lus avec leur cause (`unreadable`, `missing`, `truncated`) ; consigner dans NOTICE (R3)
- [X] T022 [US2] Dans internal/parser/evtx/binxml/evtx.go, borner `ConsumeBytes`, `SkipBytes`, `ReadPrefixedUnicodeString`, `ReadName` et la taille d'enregistrement (`[24, 65024]`) sur la place restante du chunk : dépassement → erreur de l'enregistrement, jamais `make` de la taille lue ; `recover` par enregistrement converti en erreur `unreadable` ; consigner dans NOTICE (R4)
- [X] T023 [US2] Dans internal/parser/evtx/parser.go, convertir les manques de chaque chunk en `parser.Anomaly` au bon rang (ordre du journal), et une erreur de lecture de chunk en anomalies `truncated`/`missing` pour tous ses enregistrements annoncés

**Checkpoint** : T016 à T020 verts ; `go test -fuzz=FuzzChunk -fuzztime=60s ./internal/parser/evtx/binxml/` sans échec.

---

## Phase 5: User Story 3 — Des événements fidèles à Windows (P1)

**Goal**: rendu des valeurs conforme à la spec 003 FR-013, horodatages corrects, table de correspondance déclarative.

**Independent Test**: test oracle contre `evtx_dump` et tests de la table.

### Tests

- [X] T024 [P] [US3] Écrire `TestOracleEvtxDump` dans internal/parser/evtx/parser_test.go : pour chaque ligne de testdata/oracle/Security.evtx_dump.jsonl, comparer avec l'événement de même `record_id` : `timestamp` (= `TimeCreated` à la microseconde), `event_id`, `channel`, `provider`, `EventRecordID` dans `metadata` si présent, et chaque valeur de `EventData` rendue (les `HexInt` de evtx_dump `0x…` en minuscules) ; tout écart non listé dans testdata/oracle/README.md fait échouer le test (FR-020, SC-002)
- [X] T025 [P] [US3] Écrire `TestRenderValues` dans internal/parser/evtx/binxml/binxml_test.go : `HexInt32` `0xC000006D` rendu `0xc000006d`, `HexInt64` `0x3E7` rendu `0x3e7`, booléen, GUID `{…}` majuscules, SID, FILETIME au format de la spec 003 ; enregistrement 4104 synthétique → `MessageNumber = 1` (E3, E4, constats C8, C14)
- [X] T026 [P] [US3] Écrire `TestMappingTable` dans internal/parser/evtx/mapping_test.go : chargement de mapping.json réel sans erreur ; triplets uniques (sans casse) ; `event_type` dans la liste de la spec 003 et différent de `other` ; clés de `fields` dans la liste de contracts/evtx-mapping.md ; `action_time` exige `action_time_type` valide ; table invalide construite en mémoire (doublon, type `other`, champ inconnu, champ JSON inconnu) → erreur nommant l'entrée (FR-012a)
- [X] T027 [P] [US3] Écrire `TestMappingApply` dans internal/parser/evtx/mapping_test.go : un cas par entrée de la couverture initiale (contracts/evtx-mapping.md) avec un événement construit en mémoire → `event_type` et champs attendus ; cas Sysmon 1 : `timestamp` = `UtcTime` de type `executed`, `timestamps` contient `logged` (`TimeCreated`) et `written` (en-tête) ; `User = DOMAIN\name` découpé ; `Hashes` découpé en minuscules ; `ProcessId` `0x1a4` → 420 ; valeurs `-` et `S-1-0-0` absentes ; EventID inconnu → `other`

### Implementation

- [X] T028 [US3] Dans internal/parser/evtx/binxml/evtx.go, conserver le type des valeurs `0x14`/`0x15` (`HexInt32`/`HexInt64`) et corriger le décodage à l'origine de `MessageNumber` ; exposer pour chaque valeur son type BinXML ; consigner dans NOTICE (R5)
- [X] T029 [US3] Créer internal/parser/evtx/render.go : rendu en chaîne de chaque type BinXML selon la spec 003 FR-013 (`normalizer.FormatHex` pour les `HexInt`) ; utilisé pour `metadata` et pour les champs extraits
- [X] T030 [US3] Créer internal/parser/evtx/mapping.json avec les 15 EventID de contracts/evtx-mapping.md et internal/parser/evtx/NOTICE (attribution des correspondances reprises des Maps d'EvtxECmd, licence MIT, le cas échéant)
- [X] T031 [US3] Créer internal/parser/evtx/mapping.go : `//go:embed mapping.json`, décodage strict (`DisallowUnknownFields`), validation (règles de T026), index par (canal, fournisseur, EventID) en minuscules ; `apply(entry, record, *normalizer.Event)` : `event_type`, `subject`/`target` via `normalizer.NewAccount` (découpage `DOMAINE\nom`), processus et identifiants (décimal ou `0x`), `command_line`, `file_path`, `registry_path`, `hashes` (découpage Sysmon, minuscules), horodatage d'action (R7) ; chargement une seule fois (`sync.Once`) ; une table invalide ne provoque jamais de panique : `Parse` renvoie l'erreur
- [X] T032 [US3] Dans internal/parser/evtx/parser.go, appliquer la table, les horodatages secondaires `logged` et `written` quand ils diffèrent du principal (en-tête nul omis, constat C1) et le rendu de render.go ; documenter les écarts éventuels avec `evtx_dump` dans testdata/oracle/README.md

**Checkpoint** : T024 à T027 verts.

---

## Phase 6: User Story 4 — Tracer l'ingestion dans le cas (P2)

**Goal**: preuve altérée refusée, entrée `ingest` dans `case.log`, résumé des événements `other`.

**Independent Test**: quickstart.md scénarios 6 et 7.

### Tests

- [X] T033 [P] [US4] Écrire `TestIngestAltered` dans internal/ingest/ingest_test.go : preuve modifiée sous `evidence/` après `AddEvidence` (`os.Chmod` puis écriture) → résultat `ALTERED` avec `Reason = expected=<manifeste> actual=<calculé>`, aucun fichier sous `normalized/` pour elle, les autres preuves traitées (FR-015, SC-006)
- [X] T034 [P] [US4] Écrire `TestIngestLog` dans cmd/dfirflow/main_test.go : après une ingestion avec une preuve altérée → code 4, stderr `dfirflow: ingest: integrity check failed`, dernière entrée de `case.log` : `command = ingest`, `exit_code = 4`, `summary` conforme à data-model.md (`files` trié par chemin avec `reason` pour toute preuve `ALTERED` ou `FAILED` (FR-018), compteurs, `events`, `anomalies`, `other_ratio`, `top_other`) ; ingestion propre → `exit_code = 0`
- [X] T035 [P] [US4] Écrire `TestOtherSummary` dans internal/ingest/ingest_test.go : sur Security.evtx, `other_ratio` et `top_other` égaux aux valeurs calculées indépendamment depuis le fichier normalisé ; au plus dix entrées, triées par nombre décroissant puis canal puis EventID (FR-018a, R13)

### Implementation

- [X] T036 [US4] Dans internal/ingest/ingest.go, recalculer le SHA-256 de chaque preuve en flux (contexte respecté) avant décodage et le comparer à `ManifestEntry.SHA256` → `ALTERED` sans décodage (R10) ; compter les événements `other` par (canal, EventID) et exposer `type Summary struct{ OtherRatio string; TopOther []OtherCount }`
- [X] T037 [US4] Dans cmd/dfirflow/commands.go, ligne `other: …` du contrat (omise si aucun `other`), `errIntegrity` (code 4) si au moins un `ALTERED` (prioritaire sur `FAILED`), entrée `ingest` dans `case.log` via `logOperation` avec le résumé de data-model.md, écrite aussi en cas d'interruption (code 130) dès que l'ingestion a démarré

**Checkpoint** : scénarios 6 et 7 du quickstart OK.

---

## Phase 7: Polish

- [X] T038 [P] Écrire `TestIngestInterrupted` dans cmd/dfirflow/main_test.go avec le contexte `cancelAfter` existant : code 130, aucun `.partial` sous `normalized/`, fichiers normalisés d'une ingestion précédente intacts, entrée `ingest` avec `exit_code = 130`
- [X] T039 [P] Écrire `TestParseDeterministic` dans internal/parser/evtx/parser_test.go : deux `Parse` du même fichier → mêmes suites d'événements et d'anomalies (FR-016c de la spec 003)
- [X] T040 Exécuter `gofmt -l .`, `go vet ./...`, `GOOS=windows go vet ./...`, `go test -race ./...` ; vérifier `go.mod` sans dépendance ; dérouler quickstart.md
- [X] T041 [P] Relire docs/guide-table-evtx.md et docs/architecture-actuelle.md (section 8, état de la spec 005 à passer en Livré) contre l'implémentation ; cocher les tâches terminées dans specs/005-evtx-parser/tasks.md

---

## Dependencies & Execution Order

- Phase 1 → Phase 2 (bloquante) → US1 → US2 → US3 → US4 → Polish.
- T004 (oracle) n'est requis qu'à partir de T024 ; il peut être fait en parallèle des phases 2 à 4.
- US2 et US3 modifient toutes deux internal/parser/evtx/binxml/evtx.go et internal/parser/evtx/parser.go : à enchaîner, leurs tests [P] peuvent être écrits ensemble.
- Dans chaque story : tests (rouges) → implémentation → checkpoint vert.

## Parallel Examples

- Phase 1 : T003 et T004 en parallèle de T002.
- US1 : T010, T011, T012 ensemble, puis T013 → T014 → T015.
- US2 : T016 à T020 ensemble, puis T021 → T022 → T023.
- US3 : T024 à T027 ensemble, puis T028 → T029 → T030 → T031 → T032.
- US4 : T033, T034, T035 ensemble, puis T036 → T037.

## Implementation Strategy

1. **MVP** = Phases 1 à 3 (US1) : `ingest` produit des événements valides ; limites connues : tout
   est `other`, pas de comptage des pertes (US2), pas de contrôle d'intégrité (US4).
2. US2 avant toute ingestion de journaux réels : sans elle, des pertes silencieuses restent
   possibles.
3. US3 : fidélité des valeurs et table de correspondance (nécessite l'oracle T004).
4. US4 : intégrité, journal, résumé `other`.
5. Polish : interruption, déterminisme, vérifications croisées Windows / Linux, mise à jour de la
   documentation.
