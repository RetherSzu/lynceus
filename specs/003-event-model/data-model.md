# Data Model: Modèle d'événement normalisé

Format sérialisé et règles normatives : [contracts/event-model.md](contracts/event-model.md).
Ce document décrit les types Go.

## `normalizer.Event`

Champs dans l'ordre de sérialisation (FR-018). `opt` = facultatif, omis si vide.

| Champ Go | JSON | Type | Règle |
|---|---|---|---|
| `UID` | `uid` | `string` | FR-008 |
| `Timestamp` | `timestamp` | `Time` | non nul |
| `TimestampType` | `timestamp_type` | `string` | `TS*` |
| `Timestamps` | `timestamps` | `[]TimestampEntry` opt | FR-005 |
| `Source` | `source` | `string` | `Source*` |
| `EventType` | `event_type` | `string` | `Type*` |
| `Host` | `host` | `string` | majuscules, sans `.` |
| `HostFQDN` | `host_fqdn` | `string` opt | contient un `.` |
| `Channel` | `channel` | `string` opt | requis ssi `evtx` |
| `Provider` | `provider` | `string` opt | requis ssi `evtx` |
| `EventID` | `event_id` | `*uint32` opt | requis ssi `evtx` |
| `Subject` | `subject` | `*Account` opt | FR-011 |
| `Target` | `target` | `*Account` opt | FR-011 |
| `Process` | `process` | `string` opt | |
| `ProcessID` | `process_id` | `uint32` opt | 0 = absent |
| `ParentProcess` | `parent_process` | `string` opt | |
| `ParentProcessID` | `parent_process_id` | `uint32` opt | 0 = absent |
| `CommandLine` | `command_line` | `string` opt | |
| `FilePath` | `file_path` | `string` opt | |
| `RegistryPath` | `registry_path` | `string` opt | |
| `Hashes` | `hashes` | `map[string]string` opt | FR-003 |
| `SourceFile` | `source_file` | `string` | relatif, `/`, sans `..` |
| `SourceHash` | `source_sha256` | `string` | 64 hexa minuscules |
| `RecordID` | `record_id` | `uint64` | toujours écrit |
| `RecordLocator` | `record_locator` | `string` | non vide |
| `Recovered` | `recovered` | `bool` opt | |
| `Ingest` | `ingest` | `string` | `native` \| `import:<outil>@<version>` |
| `Metadata` | `metadata` | `map[string]string` opt | FR-013 |

Supprimés par rapport au squelette : `User` (→ `Subject`/`Target`), `Severity`, `Confidence`,
`RuleID`, `MITRE` (→ `Detection`), constantes `SourcePowerShell`, `SourceDefender`,
`TSMFTModified` (→ `TSChanged`).

## Types associés

- `Time struct{ time.Time }` — JSON `2006-01-02T15:04:05.000000Z` (UTC, troncature µs).
- `TimestampEntry{Type string; Time Time; Origin string}` — JSON `type`, `time`, `origin`.
- `Account{Domain, Name, SID string}` — JSON `domain`, `name`, `sid` (ordre alphabétique,
  FR-018), tous `omitempty`.
- `Violation{Field, Rule string}` — `String()` = `field: rule`.

## `normalizer.Detection`

| Champ Go | JSON | Type | Règle |
|---|---|---|---|
| `ID` | `id` | `string` | FR-020 |
| `Timestamp` | `timestamp` | `Time` | non nul |
| `RuleID` | `rule_id` | `string` | non vide |
| `RuleVersion` | `rule_version` | `string` | non vide |
| `Severity` | `severity` | `string` | `info` … `critical` |
| `Confidence` | `confidence` | `float64` | 0 ≤ c ≤ 1, toujours écrit |
| `MITRE` | `mitre` | `string` opt | `T####` ou `T####.###` |
| `Events` | `events` | `[]string` | ≥ 1, `uid` valides, triés, sans doublon |

## Constantes

- `SchemaVersion = 1`.
- `Source*` : `evtx`, `mft`, `usnjrnl`, `registry`, `prefetch`, `memory`.
- `TS*` : `created`, `modified`, `accessed`, `changed`, `executed`, `logged`, `written`,
  `last_write`.
- `Type*` : `logon`, `logon_failed`, `logoff`, `process_creation`, `service_install`,
  `script_execution`, `log_cleared`, `malware_detected`, `av_config_change`, `other`.
- `Severity*` : `info`, `low`, `medium`, `high`, `critical`.
- `IngestNative = "native"`.

## `parser`

```go
type Source struct{ File, SHA256, Host string }      // provenance (manifeste + case.json)
type Anomaly struct{ Locator, Kind, Message string } // Kind ∈ Kind*
type Sink interface {
    Event(normalizer.Event) error
    Anomaly(Anomaly) error
}
type Parser interface {
    Name() string
    Match(head []byte) bool
    Parse(ctx context.Context, r io.ReaderAt, size int64, src Source, out Sink) error
}
func Validating(next Sink) Sink // FR-016b
```

`Kind*` : `unreadable`, `missing`, `truncated`, `invalid`. Pour `invalid`, `Message` =
`uid=<uid>: <violation>; <violation>…`.

## Flux

```text
preuve (ReaderAt) ──Parse──▶ Validating(Sink) ──Event──▶ consommateur (encodeur, spec 005)
                                 └──Anomaly(invalid)──▶ consommateur
```
