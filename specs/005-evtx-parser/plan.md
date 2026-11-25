# Implementation Plan: Parser EVTX et ingestion des journaux

**Branch**: `feature/005-evtx-parser` | **Date**: 2026-11-25 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/005-evtx-parser/spec.md`

## Summary

Intégrer un fork interne de `Velocidex/evtx` v0.2.0 (ADR-002, option B) dans
`internal/parser/evtx/binxml`, débarrassé de la résolution des messages et de toute dépendance
externe, puis le corriger : comptage des enregistrements par chunk et anomalies, bornes sur les
tailles, absence de panique, rendu `HexInt` et `MessageNumber`. Construire au-dessus le parser
`internal/parser/evtx` conforme au contrat de la spec 003, piloté par une table de correspondance
JSON embarquée, et brancher la commande `ingest` : vérification d'intégrité, écriture atomique des
événements et anomalies sous `normalized/`, résumé avec part des événements `other`, entrée dans
`case.log`.

## Technical Context

**Language/Version**: Go, `go 1.18` (`go.mod`)

**Primary Dependencies**: bibliothèque standard uniquement (`encoding/binary`, `encoding/json`,
`embed`, `unicode/utf16`, `crypto/sha256`) ; code d'origine Apache-2.0 intégré au dépôt

**Storage**: dossier de cas — lecture de `evidence/` et du manifeste, écriture de `normalized/` et
de `case.log`

**Testing**: `go test -race` ; tests oracle contre la sortie `evtx_dump` versionnée ; fixtures
malformées générées ; `go test -fuzz` sur le décodage d'un chunk

**Target Platform**: Windows x64 et Linux x64

**Project Type**: CLI + packages internes

**Performance Goals**: mémoire constante quelle que soit la taille du journal (SC-004) ; débit
mesuré mais non visé ici (DF-37, décodage parallèle reporté)

**Constraints**: décodage séquentiel en flux, sorties déterministes, aucune panique sur entrée
malformée, aucune écriture dans `evidence/`

**Scale/Scope**: journaux de quelques Ko à plusieurs Go ; table initiale de 15 EventID

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principe | Vérification | Statut |
|---|---|---|
| I. Binaire autonome | Bibliothèque standard uniquement ; fork sans dépendance (R2) ; aucun réseau | Conforme |
| II. Natif d'abord | Décodage EVTX en Go dans le dépôt ; aucun outil tiers exécuté (les oracles ne servent qu'aux tests) | Conforme |
| III. Chaîne de preuve | Empreinte vérifiée avant décodage (R10) ; `source_file`, `source_sha256`, `record_id`, `ingest` renseignés ; entrée `ingest` dans `case.log` | Conforme |
| IV. Reproductibilité | Ordre du journal, JSONL canonique, table versionnée, sortie et résumé triés ; même entrée → mêmes fichiers (SC-005) | Conforme |
| V. Traitement en flux | Un chunk de 64 Kio à la fois ; anomalie par enregistrement perdu, le décodage continue | Conforme |
| VI. Tests d'abord et oracle | Tests avant le code ; oracle `evtx_dump` versionné, EvtxECmd hors CI (R11) ; test de non-régression par défaut E1 à E5 | Conforme |
| VII. Licences | Code Apache-2.0 avec `LICENSE` et `NOTICE` ; dépendance MPL-2.0 retirée ; correspondances EvtxECmd sous MIT avec attribution | Conforme |
| VIII. Détection | Le type d'événement vient d'une table déclarative et versionnée ; aucune détection dans cette spec | Conforme |
| IX. Windows-first | Format Windows ; aucune API Windows requise, compilation identique sur les deux plateformes | Conforme |

Aucune violation.

**Re-check post-design** : conforme. Le design n'ajoute aucune dépendance et ne modifie pas le
modèle de la spec 003.

## Project Structure

### Documentation (this feature)

```text
specs/005-evtx-parser/
├── plan.md
├── research.md            # R1 à R13
├── data-model.md          # événement EVTX, entrée de table, anomalie écrite, résultat d'ingestion
├── quickstart.md
├── contracts/
│   ├── ingest.md          # sortie, fichiers, erreurs et codes de `ingest`
│   └── evtx-mapping.md    # format et couverture de la table de correspondance
└── tasks.md               # /speckit-tasks
```

### Source Code (repository root)

```text
internal/parser/evtx/
├── binxml/                # fork de Velocidex/evtx v0.2.0 (Apache-2.0)
│   ├── LICENSE
│   ├── NOTICE             # origine, version, liste des modifications
│   ├── evtx.go            # en-têtes, chunks, enregistrements, BinXML (corrigé)
│   ├── normalize.go       # aplatissement de l'arbre de l'événement
│   ├── odict.go           # remplace Velocidex/ordereddict (R2)
│   ├── debug.go
│   ├── binxml_test.go     # non-régression C12 et E1 à E5
│   └── fuzz_test.go       # fuzzing du décodage d'un chunk
├── parser.go              # Parser (Name, Match, Parse) : contrat spec 003
├── render.go            # rendu des valeurs BinXML (spec 003 FR-013)
├── mapping.go             # chargement et validation de mapping.json, application aux événements
├── mapping.json           # table de correspondance (FR-011, FR-012)
├── NOTICE                 # attribution des correspondances reprises d'EvtxECmd (MIT)
├── parser_test.go
├── mapping_test.go
└── testdata/
    ├── README.md          # origine et licence des fixtures
    ├── Security.evtx      # Apache-2.0, dépôt d'origine
    ├── Security_1_record.evtx
    └── oracle/            # sorties evtx_dump (et EvtxECmd) + README des écarts
internal/case/
└── case.go                # ajout de Evidence() : entrées du manifeste triées
internal/ingest/
├── ingest.go              # sélection des preuves, intégrité, écriture atomique, résumé
└── ingest_test.go
cmd/dfirflow/
├── commands.go            # exec de `ingest`
└── main_test.go
```

**Structure Decision** : le décodeur bas niveau (`binxml`) est séparé du parser (`evtx`) pour
isoler le code d'origine et ses modifications. `internal/ingest` orchestre les preuves et les
fichiers ; il choisit le parser par signature (`Match`) parmi une liste qui ne contient que le
parser EVTX dans cette spec. La table est embarquée dans le binaire, conformément au principe I.

## Complexity Tracking

Aucune violation à justifier.
