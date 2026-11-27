# Quickstart : valider les catégories et les modificateurs Sigma

Prérequis : binaire compilé (`make build`), cas de référence ingéré à partir du journal Security
de la spec 005 (`internal/parser/evtx/testdata/Security.evtx`, 739 événements dont 11 événements
4688 avec processus parent renseigné et ligne de commande vide), comme dans le quickstart de la
spec 012. Le dépôt ne contient pas de journal Sysmon : les scénarios Sysmon sont couverts par les
tests sur événements synthétiques (scénario 1).

```sh
B=./bin/dfirflow
C=<cas ingéré>
R=$(mktemp -d)
```

## 1. Tests automatiques

```sh
go test -race ./internal/detection/ ./cmd/dfirflow/
```

Attendu : succès. Couvre une règle par catégorie (positif, autre catégorie, autre journal, autre
EventID), chaque modificateur (positif, négatif), chaque combinaison refusée, les 12 règles
embarquées (SC-001, SC-004, SC-005).

## 2. Jeu embarqué inchangé sur la référence (SC-006)

```sh
$B detect --case $C
```

Attendu : `detect: 12 rules applied, 0 skipped, 0 refused, 739 events read, 15 detections: ...`,
aucun avertissement ; le fichier `detections/detections.jsonl` est identique octet par octet à
celui produit par la version 012.

## 3. `process_creation` sur Security 4688 avec renommage (US2, SC-003)

Règle `$R/parent.yml` : `category: process_creation`, sélection `ParentImage|endswith:
'\smss.exe'`.

```sh
$B detect --case $C --rules $R/parent.yml
```

Attendu : 7 détections (les 4688 dont le parent est `smss.exe`), aucun avertissement.

## 4. Garde 4688 (US2, FR-006, FR-015a)

Ajouter `$R/hash.yml` : `category: process_creation`, sélection `Image|endswith: '\smss.exe'`,
filtre `Hashes|contains: 'SHA256='`, condition `selection and not filter`.

```sh
$B detect --case $C --rules $R
```

Attendu : sortie d'erreur
`dfirflow: detect: warning: 1 rule not applied to Security 4688 (missing fields), see case.log` ;
toujours 7 détections (aucune de `hash.yml`) ; `case.log` : `rules_restricted` cite
`$R/hash.yml`, `security-4688`, `["Hashes"]`.

## 5. Refus de catégorie (US1, FR-001)

Ajouter `$R/web.yml` avec `category: webserver`.

Attendu : `warning: rule refused: $R/web.yml: unknown logsource category: webserver`, les autres
règles appliquées, code 0.

## 6. Catégorie et service (FR-007)

Règle `category: process_creation`, `service: sysmon`, sélection `ParentImage|endswith:
'\smss.exe'`.

Attendu : 0 détection sur la référence (seule la source Sysmon est retenue), aucun avertissement.
Avec `service: system` : refus `logsource category and service do not match`.

## 7. Modificateur invalide (FR-011)

Règle avec `CommandLine|re|windash: x`.

Attendu : refus `unsupported modifier: windash`.

## 8. Déterminisme et `case.log`

Relancer le scénario 4 : fichier identique octet par octet ; la dernière entrée `detect` porte
`categories_version` (16 caractères hexadécimaux), égal d'une exécution à l'autre.

## 9. Mesure sur SigmaHQ (SC-002, hors CI)

Avec l'accord de l'analyste, copier une release SigmaHQ hors du dépôt, puis :

```sh
DFIRFLOW_SIGMA_DIR=<release>/rules/windows go test -run TestSigmaCorpus -v ./internal/detection/
```

Attendu : part des règles des catégories couvertes chargées sans refus (objectif 90 %, non bloquant) ; raisons
des refus restants regroupées et comptées.

## 10. Volume (SC-007)

```sh
DFIRFLOW_LARGE=1 go test -run TestRunLarge -timeout 30m ./internal/detection/
```

Attendu : 10 millions d'événements mêlant Sysmon et Security, moins de 5 minutes, pic de mémoire
sous 256 Mio.
