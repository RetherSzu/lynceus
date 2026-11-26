# Quickstart: Détection par règles mono-événement

Validation de bout en bout de la spec 012 (Linux ; adapter les chemins sous Windows).

## Préparation

```sh
go build -o bin/dfirflow ./cmd/dfirflow
T=$(mktemp -d); L="$T/target/Windows/System32/winevt/Logs"; mkdir -p "$L" "$T/cases" "$T/rules"
cp internal/parser/evtx/testdata/Security.evtx "$L/"
C=$(bin/dfirflow case init CASE-012 --host WIN-01 --analyst me --dir "$T/cases")
bin/dfirflow collect --case "$C" --target "$T/target"
cp internal/detection/rules/security_log_cleared.yml "$T/rules/"
printf 'title: agg\nid: x-agg\nlevel: low\nlogsource: {product: windows, service: security}\ndetection:\n  sel: {EventID: 4625}\n  condition: sel | count() > 5\n' > "$T/rules/agg.yml"
printf 'title: lin\nid: x-lin\nlevel: low\nlogsource: {product: linux, service: auth}\ndetection:\n  sel: {a: b}\n  condition: sel\n' > "$T/rules/linux.yml"
```

## Scénarios

| # | Commande | Attendu |
|---|---|---|
| 1 | `bin/dfirflow detect --case "$C"` | code 1, `run ingest first`, `detections/` vide (US1-3) |
| 2 | `bin/dfirflow ingest --case "$C"` puis `bin/dfirflow detect --case "$C"` | `7 rules applied, 0 skipped, 0 refused, 739 events read, 15 detections`, code 0 (US1-1, SC-001) |
| 3 | `jq -r .rule_id "$C/detections/detections.jsonl" \| sort \| uniq -c` | 1 × `8ad87a09-…` (1102), 14 × `16e98cfe-…` (4719) |
| 4 | relancer 2 et comparer les deux `detections.jsonl` (`cmp`) | identiques (US1-2, SC-003) |
| 5 | `bin/dfirflow detect --case "$C" --rules "$T/rules"` | `1 rules applied, 1 skipped, 1 refused, … 1 detections`, avertissement `rule refused: …/agg.yml: aggregation is not supported`, code 0 (US2-1 à US2-3) |
| 6 | `bin/dfirflow detect --case "$C" --rules "$T/absent"` | code 1, fichier de détections précédent inchangé (US2-4) |
| 7 | `cp "$T/rules/security_log_cleared.yml" "$T/rules/copy.yml"` puis scénario 5 | code 1, `duplicate rule id 8ad87a09-…` (US2-5) ; supprimer `copy.yml` ensuite |
| 8 | `tail -1 "$C/case.log"` après le scénario 2 | entrée `detect` avec `rules: embedded`, `ruleset_version`, comptes et `sha256` égal à `sha256sum "$C/detections/detections.jsonl"` (US1-5) |
| 9 | `ls -a "$C/detections"` | seulement `detections.jsonl`, aucun `.partial` ni `.work-*` (SC-006) |
| 10 | `bin/dfirflow investigate --case "$(bin/dfirflow case init CASE-013 --host WIN-01 --analyst me --dir "$T/cases")" --target "$T/target"` | `correlate: not implemented yet`, code 3, `detections/detections.jsonl` identique octet par octet à celui du scénario 2 (`uid` indépendant du cas) (US3-1, SC-007) |
| 11 | `bin/dfirflow detect --help` | l'aide indique qu'une détection est une piste, pas une preuve de compromission (FR-016) |

Les cas positifs et négatifs des règles embarquées, le sous-ensemble Sigma, l'interruption et le
volume (SC-002, SC-004, SC-006) sont couverts par les tests de `internal/detection`
(`DFIRFLOW_LARGE=1` pour le test de 10 millions d'événements).
