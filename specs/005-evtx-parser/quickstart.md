# Quickstart: Parser EVTX et ingestion des journaux

Validation de bout en bout de la spec 005 (Linux ; adapter les chemins sous Windows).

## Préparation

```sh
go build -o bin/dfirflow ./cmd/dfirflow
T=$(mktemp -d); L="$T/target/Windows/System32/winevt/Logs"; mkdir -p "$L" "$T/cases"
cp internal/parser/evtx/testdata/Security.evtx "$L/"
printf 'x' > "$L/notes.evtx"                      # extension EVTX, contenu non EVTX
C=$(bin/dfirflow case init CASE-005 --host WIN-01 --analyst me --dir "$T/cases")
bin/dfirflow collect --case "$C" --target "$T/target"
```

## Scénarios

| # | Commande | Attendu |
|---|---|---|
| 1 | `bin/dfirflow ingest --case "$C"` | `INGESTED … Security.evtx  events=739 anomalies=0`, `SKIPPED … notes.evtx`, ligne `other`, code 0 (US1-1, US1-2, FR-018a) |
| 2 | `wc -l "$C/normalized/Windows/System32/winevt/Logs/Security.evtx.jsonl"` | 739 (SC-001) |
| 3 | relancer 1 puis comparer les deux versions du `.jsonl` (`cmp`) | identiques (US1-5, SC-005) |
| 4 | `bin/dfirflow ingest --case "$C" Windows/System32/winevt/Logs/Security.evtx` | une seule ligne `INGESTED` (US1-3) |
| 5 | `bin/dfirflow ingest --case "$C" absent.evtx` | `not in the case manifest`, code 1 (US1-4) |
| 6 | `chmod u+w` puis modifier un octet de la preuve sous `evidence/`, relancer 1 | `ALTERED`, code 4 (US4-2, SC-006) |
| 7 | `tail -1 "$C/case.log"` | entrée `ingest` avec `files`, compteurs et `top_other` (US4-1) |

Les journaux abîmés (US2) et la comparaison avec l'oracle (US3) sont couverts par les tests de
`internal/parser/evtx` ; ils ne demandent pas de manipulation manuelle.
