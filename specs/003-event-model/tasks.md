---

description: "Task list for 003-event-model"
---

# Tasks: Modèle d'événement normalisé et contrat de parseur

**Input**: Design documents from `/specs/003-event-model/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/event-model.md, decisions.md

**Tests**: inclus (constitution, principe VI) ; chaque test est écrit avant le code qu'il couvre.
Compatibilité `go 1.18` : pas de `slices`, `maps`, `cmp`, `min`.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [x] T001 Vérifier que `go test ./...` passe sur la branche (base specs 001–002) et qu'aucun fichier hors `internal/parser` n'importe `internal/normalizer` (recherche `grep -rn normalizer --include=*.go . | grep -v spikes`)

---

## Phase 2: Foundational

- [x] T002 Remplacer internal/normalizer/event.go par les types de data-model.md : `Event` (champs et tags JSON **dans l'ordre exact** du contrat : `uid`, `timestamp`, `timestamp_type`, `timestamps,omitempty`, `source`, `event_type`, `host`, `host_fqdn,omitempty`, `channel,omitempty`, `provider,omitempty`, `event_id,omitempty` en `*uint32`, `subject,omitempty` et `target,omitempty` en `*Account`, `process`, `process_id` (`uint32`), `parent_process`, `parent_process_id` (`uint32`), `command_line`, `file_path`, `registry_path`, `hashes` — tous `omitempty` —, `source_file`, `source_sha256`, `record_id` (`uint64`, **sans** `omitempty`), `record_locator`, `recovered,omitempty`, `ingest`, `metadata,omitempty`) ; `Account{Domain, Name, SID}` (tags `domain`, `name`, `sid`, tous `omitempty`, dans cet ordre) ; `TimestampEntry{Type, Time, Origin}` (tags `type`, `time`, `origin`) ; constantes `SchemaVersion = 1`, `Source*` (`evtx`, `mft`, `usnjrnl`, `registry`, `prefetch`, `memory`), `TS*` (`created`, `modified`, `accessed`, `changed`, `executed`, `logged`, `written`, `last_write`), `Type*` (`logon`, `logon_failed`, `logoff`, `process_creation`, `service_install`, `script_execution`, `log_cleared`, `malware_detected`, `av_config_change`, `other`), `IngestNative = "native"` ; supprimer `User`, `Severity`, `Confidence`, `RuleID`, `MITRE`, `SourcePowerShell`, `SourceDefender`, `TSMFTModified` ; conserver le nom Go `SourceHash` (constitution, principe III), tag JSON `source_sha256`
- [x] T003 Écrire `TestTime` dans internal/normalizer/time_test.go : encodage `"2020-09-09T13:18:23.627952Z"` ; entrée en `CET` convertie en UTC ; 1,999 µs tronqué à `.000001` (jamais arrondi) ; décodage refusant 5 ou 7 décimales, l'absence de décimales et un décalage autre que `Z` ; aller-retour identique ; pour 1 000 instants aléatoires (1601–9999, à la µs), tri des chaînes encodées == tri chronologique (SC-006)
- [x] T004 Implémenter dans internal/normalizer/time.go `type Time struct{ time.Time }` avec `MarshalJSON` (`UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.000000Z")`) et `UnmarshalJSON` (`time.Parse` du même gabarit) (research.md R2)

---

## Phase 3: User Story 1 — Représenter tout enregistrement par un événement valide (P1) 🎯 MVP

**Independent Test**: `go test ./internal/normalizer/ -run 'UID|Normalize|Account|Hex|Validate'`.

- [x] T005 [US1] Écrire dans internal/normalizer/normalize_test.go : `TestUID` (32 hexa minuscules ; égal aux 32 premiers caractères de SHA-256(`sha256 + "\x00" + file + "\x00" + locator`) calculé dans le test ; change si l'un des trois change ; ne dépend d'aucun autre champ) ; `TestNormalizeHost` (`WIN-77LTAPHIQ1R.example.corp` → `WIN-77LTAPHIQ1R`, fqdn conservé ; `msedgewin10` → `MSEDGEWIN10`, fqdn vide) ; `TestNewAccount` (`-`, `""`, `S-1-0-0` absents ; SID mis en majuscules ; `nil` si tout est absent ; casse de `domain`/`name` conservée) ; `TestFormatHex` (`0xc000006d`, `0x3e7`, `0x0`)
- [x] T006 [US1] Implémenter dans internal/normalizer/normalize.go `UID(sha256, file, locator string) string`, `NormalizeHost(raw string) (host, fqdn string)`, `NewAccount(sid, domain, name string) *Account`, `FormatHex(v uint64) string` (research.md R6)
- [x] T007 [US1] Écrire `TestValidate` dans internal/normalizer/validate_test.go, table d'événements partant d'un 4624 valide, une mutation par cas, vérifiant le `Field` de chaque `Violation` : `uid` non « 32 caractères hexadécimaux minuscules » ; `timestamp` nul ; `timestamp_type`, `source`, `event_type` hors liste (dont `persistence`) ; `host` vide, avec `.` ou minuscules ; `host_fqdn` sans `.` ; `source_file` absolu, avec `\`, `..` ou non nettoyé ; `source_sha256` de 63 caractères ou majuscules ; `record_locator` vide ; `ingest` hors `native` / `import:<outil>@<version>` (outil et version non vides) ; `source = evtx` sans `channel`, `provider` ou `event_id` ; `source = mft` avec l'un des trois ; `timestamps[i]` à `time` nul, `type` hors liste ou `origin` vide ; `hashes` à clé hors `md5`/`sha1`/`sha256`/`imphash` ou de longueur ≠ 32/40/64/32 ou en majuscules ; compte à `sid` hors `S-1-<n>(-<n>)+`, ou valant `-`/`S-1-0-0`, ou objet vide ; chaîne non UTF-8 dans un champ ou une clé/valeur de `metadata` ; `record_id = 0` et `event_type = other` **valides** ; trois défauts simultanés ⇒ trois violations
- [x] T008 [US1] Implémenter dans internal/normalizer/validate.go `Violation{Field, Rule string}` (`String()` = `field: rule`) et `func (e Event) Validate() []Violation`, liste complète dans l'ordre des champs (FR-001 à FR-013, research.md R5)

---

## Phase 4: User Story 2 — JSONL canonique identique à l'octet (P1)

**Independent Test**: `go test ./internal/normalizer/ -run 'Golden|RoundTrip|Sort|Read|Encode'`.

- [x] T009 [US2] Écrire dans internal/normalizer/jsonl_test.go un jeu de référence `referenceEvents()` (au moins : 4624 complet avec `subject`/`target`/`host_fqdn`, Sysmon 1 avec `hashes` et `timestamps`, 4104 avec `command_line` contenant `<`, `>`, `&`, entrée `mft` avec `record_id = 0`, événement `other`, événement `recovered`, `event_id = 0` en EVTX) et les tests : `TestGolden` (encodage == internal/normalizer/testdata/events.v1.jsonl octet par octet ; option `-update` réécrit le fichier) ; `TestRoundTrip` (lecture puis réencodage == fichier) ; `TestEncodeNoHTMLEscape` ; `TestEncodeRejectsInvalid` (événement invalide ⇒ erreur, rien d'écrit) ; `TestSortEvents` (ordre `timestamp`, `source_file`, `record_id`, `uid` ; deux tris d'un même ensemble mélangé identiques) ; `TestReadEventsErrors` (ligne 3 : JSON invalide, champ inconnu, `schema_version` 2, ligne finissant par `\r`, octets non UTF-8, contenu après l'objet, événement invalide ⇒ erreur contenant `line 3`) ; fichier vide ⇒ zéro événement, sans erreur ; `TestReadEventsGarbage` (octets aléatoires, lignes JSON tronquées : aucune panique, toute erreur porte un numéro de ligne)
- [x] T010 [US2] Implémenter dans internal/normalizer/jsonl.go : `Encoder` (`NewEncoder(w io.Writer)`, `json.Encoder` + `SetEscapeHTML(false)`, enveloppe `struct{ SchemaVersion int \`json:"schema_version"\`; Event }`, validation avant écriture) avec la méthode `Event(Event) error` ; `ReadEvents(r io.Reader, fn func(Event) error) error` (research.md R3 : `bufio.Reader.ReadBytes('\n')`, `utf8.Valid`, refus du `\r`, `DisallowUnknownFields`, refus du contenu après l'objet, contrôle de `schema_version`, `Validate`, erreur `line N: …`) ; `SortEvents([]Event)` (`sort.Slice`, R8) ; commentaire `shortcut:` sur les clés dupliquées non détectées
- [x] T011 [US2] Générer internal/normalizer/testdata/events.v1.jsonl (`go test -run Golden -update`), le relire ligne à ligne contre contracts/event-model.md (ordre des champs, clés triées, 6 décimales, `\n` final, aucun `null`), puis relancer `TestGolden` sans `-update`

---

## Phase 5: User Story 3 — Contrat de parseur commun (P1)

**Independent Test**: `go test ./internal/parser/ -race`.

- [x] T012 [US3] Écrire le faux parseur dans internal/parser/fake_test.go (research.md R7) : `Name() = "fake"`, `Match` sur la signature `FAKE1\n`, `Parse` lisant par `io.NewSectionReader(r, 0, size)` une ligne par enregistrement `numéro|horodatage|event_type|commande`, émettant des `Event` (`source = mft`, pour ne pas exiger `channel`/`provider`/`event_id` ; `uid` via `normalizer.UID(src.SHA256, src.File, "line=N")`, `host` via `NormalizeHost(src.Host)`, `ingest = native`) ; ligne `!` ⇒ `Anomaly{kind: unreadable}` ; saut de numéro ⇒ `missing` ; horodatage vide ⇒ événement invalide émis tel quel ; fin sans `\n` final ⇒ `truncated` ; signature absente ⇒ erreur fatale ; contrôle de `ctx.Err()` à chaque ligne ; arrêt et retour de l'erreur renvoyée par le `Sink`
- [x] T013 [US3] Écrire dans internal/parser/parser_test.go, avec un `Sink` d'enregistrement : entrée saine ⇒ événements dans l'ordre du fichier, aucune anomalie, `nil` ; entrée avec `!`, saut de numéro, horodatage vide et troncature ⇒ anomalies `unreadable`, `missing`, `invalid` (via `Validating`, message `uid=<uid>: …` nommant la violation), `truncated`, et lignes suivantes émises ; **SC-005** : événements émis + anomalies == enregistrements de l'entrée ; `Match` faux sur une entrée inconnue et `Parse` forcé ⇒ erreur fatale ; contexte annulé ⇒ `context.Canceled`, événements déjà reçus valides ; `Sink` renvoyant une erreur ⇒ arrêt immédiat et même erreur ; deux exécutions ⇒ suites identiques (`reflect.DeepEqual`)
- [x] T014 [US3] Remplacer internal/parser/parser.go par le contrat de data-model.md : `Source{File, SHA256, Host string}`, `Anomaly{Locator, Kind, Message string}`, constantes `KindUnreadable`, `KindMissing`, `KindTruncated`, `KindInvalid`, interfaces `Sink` et `Parser` (`Name() string`, `Match(head []byte) bool`, `Parse(ctx context.Context, r io.ReaderAt, size int64, src Source, out Sink) error`), et `Validating(next Sink) Sink` (FR-016b : `Validate` ; valide ⇒ `next.Event` ; invalide ⇒ `next.Anomaly{Locator: e.RecordLocator, Kind: KindInvalid, Message: "uid=" + e.UID + ": " + violations jointes par "; "}` ; anomalies transmises telles quelles)

---

## Phase 6: User Story 4 — Résultats de détection (P2)

**Independent Test**: `go test ./internal/normalizer/ -run Detection`.

- [x] T015 [US4] Écrire dans internal/normalizer/detection_test.go : `TestDetectionValidate` (valide ⇒ aucune violation ; `rule_id` ou `rule_version` vide ; `severity` hors `info`/`low`/`medium`/`high`/`critical` (dont `urgent`) ; `confidence` < 0 ou > 1 (dont 1,5) ; `mitre` hors `T####` / `T####.###` (dont `T59`) ; `events` vide, non trié, avec doublon ou `uid` invalide ; `timestamp` nul ; `id` ≠ `DetectionID(...)`) ; `TestDetectionID` (32 hexa ; mêmes `uid` dans un autre ordre ⇒ même `id` ; égal à SHA-256(`rule_id` \x00 `rule_version` \x00 `uid` triés séparés par \x00) calculé dans le test) ; `TestDetectionJSONL` (ordre des champs `schema_version`, `id`, `timestamp`, `rule_id`, `rule_version`, `severity`, `confidence`, `mitre`, `events` ; `confidence` 0 écrit ; aller-retour identique ; `SortDetections` par `timestamp` puis `id` ; erreurs de lecture avec numéro de ligne)
- [x] T016 [US4] Implémenter dans internal/normalizer/detection.go `Detection` (tags dans l'ordre ci-dessus, `mitre,omitempty`, `confidence` sans `omitempty`), constantes `Severity*`, `DetectionID(ruleID, ruleVersion string, uids []string) string` (trie une copie), `func (d Detection) Validate() []Violation` ; et dans internal/normalizer/jsonl.go `Encoder.Detection`, `ReadDetections`, `SortDetections` en réutilisant le code commun des événements

---

## Phase 7: User Story 5 — Évolution du modèle (P3)

**Independent Test**: `go test ./internal/normalizer/ -run Version`.

- [ ] T017 [US5] Écrire `TestUnsupportedVersion` dans internal/normalizer/jsonl_test.go : ligne `schema_version` 2 (et 0) ⇒ erreur contenant `line 1`, `schema_version 2` et `upgrade` ; idem pour `ReadDetections`
- [ ] T018 [US5] Ajuster dans internal/normalizer/jsonl.go le message de version non prise en charge (`line N: unsupported schema_version N, upgrade dfirflow`) ; vérifier que specs/003-event-model/contracts/event-model.md porte l'historique avec la version 1 (spec 003) et la procédure FR-025

---

## Phase 8: Amendement de la spec 001 (FR-026)

- [ ] T019 Mettre à jour cmd/dfirflow/main_test.go : `--source powershell` et `--source defender` ⇒ code 2 ; `--source evtx,mft,usnjrnl,registry,prefetch,memory` ⇒ code 3 ; l'aide de `timeline` liste `evtx, mft, usnjrnl, registry, prefetch, memory`
- [ ] T020 Retirer `powershell` et `defender` de `sources` dans cmd/dfirflow/commands.go ; reporter la liste dans specs/001-cli-foundation/spec.md (FR-011) et specs/001-cli-foundation/contracts/cli.md avec la mention « amendé par la spec 003 (FR-026) »

---

## Phase 9: Polish

- [ ] T021 Vérifier au premier push que le job `test-windows` de .github/workflows/ci.yml (ajouté à l'analyse, sans `-race` qui exige cgo) est vert et que .gitattributes (`*.jsonl text eol=lf`, sinon Git extrait le fichier de référence en `\r\n` sous Windows) est respecté ; si les tests de la spec 002 échouent sous Windows au nettoyage des preuves en lecture seule, ajouter dans internal/case/case_test.go un `t.Cleanup` qui rétablit les droits d'écriture
- [ ] T022 `gofmt -l .`, `go vet ./...`, `go test ./... -race -cover`, `GOOS=windows go build ./...`
- [ ] T023 Dérouler specs/003-event-model/quickstart.md §1 à §4 (dont `sha256sum` stable sur deux exécutions et lecture `jq`)
- [ ] T024 Passer de 📐 à ✅ les éléments livrés dans docs/architecture-actuelle.md et docs/dictionnaire-donnees.md (fichiers locaux, non commités)

## Dependencies & Execution Order

Setup → Phase 2 (T002–T004) → US1 (T005–T008) → US2 (T009–T011) → US3 (T012–T014) → US4
(T015–T016) → US5 (T017–T018) → Phase 8 → Polish (T021 avant T022).

- US2 a besoin de `Validate` (US1) : l'encodeur et le décodeur valident.
- US3 a besoin de `UID`, `NormalizeHost` et `Validate` (US1), pas de US2.
- US4 réutilise le code JSONL de US2.
- Phase 8 est indépendante de tout le reste.

## Parallel Opportunities

- T003 ∥ T002 (fichiers distincts) ; T005 ∥ T007 (fichiers de test distincts).
- Après US1 : US2 (internal/normalizer/jsonl*) ∥ US3 (internal/parser/).
- Phase 8 (cmd/dfirflow/) ∥ toute autre phase.

## Implementation Strategy

MVP = Phase 2 + US1 + US2 : modèle validé et JSONL canonique, ce dont la spec 005 a besoin pour
écrire `normalized/`. US3 fige le contrat avant le premier vrai parseur ; US4 et US5 terminent le
format. Après chaque phase : `go test ./...` vert avant de passer à la suivante.
