# Implementation Plan: Catégories de sources et modificateurs Sigma

**Branch**: `feature/013-sigma-categories` | **Date**: 2026-11-27 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/013-sigma-categories/spec.md`

## Summary

Étendre `internal/detection` (spec 012) pour accepter les règles Sigma décrites par
`logsource.category`. Une table JSON embarquée et versionnée relie chaque catégorie à ses sources
(canal, EventID, contrainte `EventType`, renommage, champs fournis). À la compilation, une règle
devient une ou plusieurs entrées `(règle, source)` ; la garde écarte les sources partielles
(Security 4688) dont il manque un champ cité. L'index de la spec 012, désormais par canal et par EventID
(research R4), porte ces entrées ; à l'évaluation, les champs sont lus à travers le renommage de la source. Ajouter
les modificateurs `windash`, `cidr`, `base64`, `base64offset`, `wide`/`utf16le`, `utf16be`,
`exists`, `cased`, `fieldref`, cinq règles embarquées par catégorie, l'avertissement
récapitulatif de la garde et les clés `categories_version` et `rules_restricted` de `case.log`.
Les règles de service gardent exactement leur comportement.

## Technical Context

**Language/Version**: Go, `go 1.18` (`go.mod`)

**Primary Dependencies**: bibliothèque standard seulement pour les ajouts (`encoding/json`,
`encoding/base64`, `unicode/utf16`, `net/netip`, `embed`) ; `go.yaml.in/yaml/v3` déjà présent
(spec 012) ; aucune nouvelle dépendance

**Storage**: inchangé depuis la spec 012 (lecture de `normalized/`, écriture de `detections/` et
de `case.log`)

**Testing**: `go test -race` ; événements normalisés synthétiques Sysmon, PowerShell et 4688 ;
une règle par catégorie (positif, autre catégorie, autre journal, autre EventID) ; positif et
négatif par modificateur ; refus par combinaison ; journal Security de référence (SC-006 et
renommage 4688 sur des données réelles) ; test de volume sous `DFIRFLOW_LARGE=1` ; mesure du
corpus SigmaHQ sous `DFIRFLOW_SIGMA_DIR`, hors CI (R8)

**Target Platform**: Windows x64 et Linux x64

**Project Type**: CLI + packages internes

**Performance Goals**: comme la spec 012 : 10 millions d'événements en moins de 5 minutes,
mémoire au plus 256 Mio (SC-007)

**Constraints**: une règle compilée une seule fois quel que soit le nombre de ses sources ; coût
de `windash` borné (classes de caractères, pas d'expansion) ; sortie identique octet par octet ;
détections des règles de service inchangées

**Scale/Scope**: corpus fourni jusqu'à quelques milliers de règles (release SigmaHQ Windows) ;
16 catégories, 17 sources

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principe | Vérification | Statut |
|---|---|---|
| I. Binaire autonome | Table des catégories embarquée ; aucune dépendance ajoutée ; aucun réseau | Conforme |
| II. Natif d'abord | Aucun outil tiers lancé ; pySigma sert de référence documentaire, pas de code | Conforme |
| III. Chaîne de preuve | Détection inchangée (`uid` de l'événement) ; lecture seule du cas hors `detections/` ; restrictions consignées | Conforme |
| IV. Reproductibilité | Table versionnée par empreinte, consignée dans `case.log` (R1) ; évaluation indépendante de l'ordre des règles et des sources | Conforme |
| V. Traitement en flux | Inchangé ; mémoire par règle indépendante du nombre de sources (R4) | Conforme |
| VI. Tests d'abord et oracle | Positif et négatif par catégorie, par modificateur et par règle embarquée (Sysmon et 4688) ; mesure SigmaHQ hors CI en guise d'oracle d'interopérabilité (R8) | Conforme |
| VII. Licences | Règles SigmaHQ (DRL 1.1) ni embarquées ni copiées dans le dépôt ; règles ajoutées sous Apache-2.0 | Conforme |
| VIII. Détection | Règles déclaratives versionnées ; garde contre les faux positifs sur champ absent ; champs structurés seulement ; une détection reste une piste | Conforme |
| IX. Windows-first | Sources Sysmon, PowerShell et Security ; formats de champ Windows conservés tels quels (R3) | Conforme |

Aucune violation. Revérifié après la phase 1 (research, data-model, contrat) : inchangé.

## Project Structure

### Documentation (this feature)

```text
specs/013-sigma-categories/
├── spec.md
├── plan.md              # ce fichier
├── research.md          # R1 à R8
├── data-model.md        # table des catégories, garde, modificateurs, jeu embarqué, case.log
├── quickstart.md        # validation de bout en bout
├── contracts/
│   └── detect.md        # évolution du contrat de la spec 012
├── checklists/
│   └── requirements.md
└── tasks.md             # /speckit-tasks
```

### Source Code (repository root)

```text
internal/detection/
├── categories.json      # table des catégories (data-model.md)
├── categories.go        # Source, chargement et validation de la table, version (R1)
├── rule.go              # logsource : catégorie, service, intersection, champs cités (R5)
├── match.go             # lecture des champs à travers le renommage de la source ; exists, fieldref, cidr
├── modifiers.go         # windash (classes de caractères), base64, base64offset, encodages UTF-16, cased (R6)
├── ruleset.go           # entrées (règle, source), garde, restrictions, index par canal et par EventID (R4, R7)
├── detection.go         # Run : filtrage par EventID et EventType, puis condition
├── rules/*.yml          # + 5 règles par catégorie (data-model.md)
├── categories_test.go   # validité de la table, une règle par catégorie
├── match_test.go        # + modificateurs, positifs et négatifs
├── rule_test.go         # + refus de source et de combinaisons
├── ruleset_test.go      # + garde, restrictions, intersection service et catégorie
├── rules_test.go        # + cas Sysmon et 4688 des nouvelles règles
├── detection_test.go    # + sources mêlées, volume Sysmon et Security
├── sigma_test.go        # TestSigmaCorpus, sauté sans DFIRFLOW_SIGMA_DIR (R8)
└── fuzz_test.go         # + amorces avec catégories et nouveaux modificateurs

cmd/dfirflow/
├── commands.go          # avertissement de garde ; categories_version et rules_restricted dans case.log
└── main_test.go         # 12 règles ; renommage 4688 sur la référence ; garde ; journal

README.md                        # sous-ensemble Sigma, catégories, limites connues
docs/architecture-actuelle.md    # 013 marquée Codé, table des catégories
```

**Structure Decision**: tout reste dans `internal/detection`, qui possède déjà le chargement et
l'évaluation des règles ; la table des catégories est une donnée du moteur de règles, au même
titre que la table EVTX est une donnée du parser. `modifiers.go` sépare la construction des
motifs (transformations des valeurs de la règle) de leur évaluation sur l'événement (`match.go`).
Aucune modification du modèle 003 ni des autres packages.

## Complexity Tracking

Aucun écart à justifier : pas de nouvelle dépendance, pas de nouveau package.
