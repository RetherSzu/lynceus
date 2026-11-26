# Quickstart: Chronologie consolidée du cas

Validation de bout en bout de la spec 006 (Linux ; adapter les chemins sous Windows).

## Préparation

```sh
go build -o bin/dfirflow ./cmd/dfirflow
T=$(mktemp -d); L="$T/target/Windows/System32/winevt/Logs"; mkdir -p "$L" "$T/cases"
cp internal/parser/evtx/testdata/Security.evtx "$L/"
cp internal/parser/evtx/testdata/Security.evtx "$L/Copy.evtx"   # seconde preuve, 739 événements
C=$(bin/dfirflow case init CASE-006 --host WIN-01 --analyst me --dir "$T/cases")
bin/dfirflow collect --case "$C" --target "$T/target"
```

## Scénarios

| # | Commande | Attendu |
|---|---|---|
| 1 | `bin/dfirflow timeline --case "$C"` | code 1, `run ingest first`, `timeline/` vide (US1-3) |
| 2 | `bin/dfirflow ingest --case "$C"` puis `bin/dfirflow timeline --case "$C"` | `2 files, 1478 events read, 1478 written`, code 0 (US1-1, SC-001) |
| 3 | relancer 2 et comparer les deux `timeline.jsonl` (`cmp`) | identiques (US1-2, SC-002) |
| 4 | `bin/dfirflow timeline --case "$C" --from 2019-02-07T00:00:00 --to 2019-02-07T12:00:00` | `954 written`, premier et dernier horodatages dans la fenêtre, bornes incluses (US2-1) |
| 5 | `bin/dfirflow timeline --case "$C" --source mft` | `0 written`, avertissement `no event from source mft`, fichier vide, code 0 (US2-3) |
| 6 | `bin/dfirflow timeline --case "$C" --from 2020-01-01T00:00:00Z --to 2019-01-01T00:00:00Z` | code 2, rien d'écrit (US2-4) |
| 7 | `tail -1 "$C/case.log"` | entrée `timeline` avec `filter`, compteurs et `sha256` égal à `sha256sum "$C/timeline/timeline.jsonl"` (US1-4) |
| 8 | `ls -a "$C/timeline"` | seulement `timeline.jsonl`, aucun `.partial` ni `.work-*` (SC-005) |
| 9 | `bin/dfirflow investigate --case "$(bin/dfirflow case init CASE-007 --host WIN-01 --analyst me --dir "$T/cases")" --target "$T/target"` | `detect: not implemented yet`, code 3, `timeline/timeline.jsonl` présent (US3-1) |

Le tri externe, l'interruption et le volume (SC-003, SC-005) sont couverts par les tests de
`internal/timeline` (`DFIRFLOW_LARGE=1` pour le test de 10 millions d'événements).
