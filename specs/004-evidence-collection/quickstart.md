# Quickstart: Collecte des preuves

Validation de bout en bout de la spec 004 (Linux ; adapter les chemins sous Windows).

## Préparation

```sh
go build -o bin/dfirflow ./cmd/dfirflow
T=$(mktemp -d); mkdir -p "$T/target/windows/System32/WINEVT/Logs" "$T/cases" "$T/empty"
printf 'sec' > "$T/target/windows/System32/WINEVT/Logs/Security.evtx"
printf 'sys' > "$T/target/windows/System32/WINEVT/Logs/System.evtx"
printf 'x'   > "$T/target/windows/System32/WINEVT/Logs/notes.txt"
touch -d 2026-10-01T08:00:00Z "$T/target/windows/System32/WINEVT/Logs/Security.evtx"
C=$(bin/dfirflow case init CASE-004 --host WIN-01 --analyst me --dir "$T/cases")
```

## Scénarios

| # | Commande | Attendu |
|---|---|---|
| 1 | `bin/dfirflow collect --case "$C" --target "$T/target"` | 2 lignes `COLLECTED` (pas `notes.txt`), code 0 ; chemins sous `evidence/windows/System32/WINEVT/Logs/` (US1-1, US1-2) |
| 2 | `bin/dfirflow case verify --case "$C"` | 2 `OK`, code 0 (US1-4, SC-001) |
| 3 | `grep Security "$C/hashes/manifest.jsonl"` | `origin.modified` = `2026-10-01T08:00:00Z` (US2-1) |
| 4 | relancer la commande 1 | 2 `ALREADY`, manifeste inchangé, code 0 (US4-1, SC-003) |
| 5 | `printf 'tampered' > …/Security.evtx` puis relancer 1 | `CONFLICT` sur `Security.evtx`, code 1 (US4-2) |
| 6 | `tail -1 "$C/case.log"` | entrée `collect` avec `target`, compteurs et `problems` (US3-1) |
| 7 | `collect --case "$C" --target "$T"` (le cas est sous la cible) | refus, code 1, aucune copie (FR-014) |
| 8 | `collect --case "$C" --target "$T/empty"` | `no artifact found`, code 1 (US1-3) |

Les mêmes scénarios sont couverts par les tests de `internal/collector` et `cmd/dfirflow`.
