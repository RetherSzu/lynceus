# DFIRFlow

Pipeline d'investigation forensique Windows dans un binaire Go unique : collecte, décodage,
chronologie et détection sur les artefacts d'une machine, avec une chaîne de preuve vérifiable
de bout en bout.

> **Projet en développement.** La tranche EVTX (journaux d'événements Windows) fonctionne
> jusqu'à la détection. La corrélation, les rapports et les autres artefacts sont prévus ; voir
> [État du projet](#état-du-projet).

---

## Sommaire

- [Pourquoi DFIRFlow](#pourquoi-dfirflow)
- [Démarrage rapide](#démarrage-rapide)
- [Installation](#installation)
- [Les commandes](#les-commandes)
- [Le dossier de cas](#le-dossier-de-cas)
- [Les données produites](#les-données-produites)
- [Les règles de détection](#les-règles-de-détection)
- [Architecture](#architecture)
- [Principes de conception](#principes-de-conception)
- [État du projet](#état-du-projet)
- [Développement](#développement)
- [Licence](#licence)

---

## Pourquoi DFIRFlow

L'analyse d'une machine Windows compromise repose aujourd'hui sur une série d'outils spécialisés
(KAPE, outils d'Eric Zimmerman, Plaso, Hayabusa, Chainsaw…). Chacun est excellent dans son
domaine, mais l'analyste doit les enchaîner à la main, harmoniser des formats différents (CSV,
JSON, SQLite) et recouper les résultats lui-même. Ce travail est long, sujet aux erreurs et
difficile à rejouer à l'identique.

DFIRFlow réunit ces étapes dans un seul outil :

| Principe | Concrètement |
|---|---|
| Autonome | Un binaire statique, sans .NET, Python, Node ni Docker ; fonctionne hors ligne |
| En ligne de commande | Scriptable, utilisable sur un serveur sans interface ou un poste isolé du réseau |
| Unifié | Tous les artefacts sont convertis vers un seul modèle d'événement |
| Traçable | Chaque preuve est hachée en SHA-256 ; chaque détection remonte à l'enregistrement exact qui l'a produite |
| Reproductible | Même preuve, même version, mêmes règles : résultat identique à l'octet |
| Prudent | Une détection est une piste à examiner, jamais une preuve de compromission |

DFIRFlow ne remplace pas les outils de référence : il en reprend les meilleures idées (format de
règles Sigma, décodage natif des EVTX) dans une chaîne cohérente et vérifiable.

---

## Démarrage rapide

Deux commandes suffisent sur un volume monté ou une copie de disque :

```sh
dfirflow case init CASE-001 --host WIN-01 --analyst "Equipe IR" --dir ./cases
dfirflow investigate --case ./cases/CASE-001 --target /mnt/image
```

`investigate` collecte les journaux, les décode, construit la chronologie et applique les
règles. Il s'arrête ensuite avec le code 3 sur `correlate: not implemented yet` : c'est attendu
tant que la corrélation n'est pas livrée. Le résultat est le même que si l'on lançait chaque
étape à la main :

```sh
dfirflow collect  --case ./cases/CASE-001 --target /mnt/image
dfirflow ingest   --case ./cases/CASE-001
dfirflow timeline --case ./cases/CASE-001
dfirflow detect   --case ./cases/CASE-001
```

Exemple de sortie de `detect` :

```text
detect: 12 rules applied, 0 skipped, 0 refused, 739 events read, 15 detections: detections/detections.jsonl
```

---

## Installation

Depuis les sources (Go 1.18 ou plus récent) :

```sh
git clone <url-du-dépôt> dfirflow && cd dfirflow
make build            # bin/dfirflow pour le système courant
make build-windows    # bin/dfirflow-windows-x64.exe
make build-linux      # bin/dfirflow-linux-x64
```

Le binaire n'a besoin de rien d'autre pour fonctionner : les règles de détection et la table de
correspondance EVTX sont embarquées.

---

## Les commandes

`dfirflow --help` liste les commandes ; `dfirflow <commande> --help` détaille chacune.
L'option `--case` attend toujours le **chemin** du dossier de cas.

| Commande | Rôle | État |
|---|---|---|
| `case init <ID> --host --analyst [--dir]` | Crée le dossier de cas | Disponible |
| `case verify --case` | Recalcule les empreintes et signale toute altération | Disponible |
| `collect --case --target` | Copie les journaux EVTX d'un volume dans le cas | Disponible |
| `ingest --case [chemins…]` | Décode les preuves vers le modèle d'événement commun | Disponible |
| `timeline --case [--from --to --source]` | Chronologie triée, filtrable par période et par source | Disponible |
| `detect --case [--rules]` | Applique les règles de détection | Disponible |
| `investigate --case --target` | Enchaîne toutes les étapes | Jusqu'à `detect` |
| `import --case --tool <outil> <chemin>` | Lit les sorties d'outils tiers | Prévu |
| `correlate --case` | Reconstitue les chaînes d'attaque | Prévu |
| `report --case --format html,sqlite,jsonl` | Produit les livrables | Prévu |

### Pourquoi chaque étape existe

- **`case init`** isole chaque investigation dans un dossier propre, avec qui l'a ouverte, quand
  et sur quelle machine. Tout ce que produit DFIRFlow reste dans ce dossier.
- **`collect`** copie les journaux et calcule leur SHA-256 dans la même lecture, puis met la copie
  en lecture seule. Le chemin d'origine et les horodatages du fichier source sont relevés avant
  la copie. On travaille ensuite sur la copie, jamais sur l'original.
- **`ingest`** vérifie d'abord que chaque preuve a toujours son empreinte d'origine ; une preuve
  modifiée est refusée (code 4). Il décode ensuite les EVTX avec un parser natif et écrit des
  événements au format commun. Un enregistrement illisible n'est jamais ignoré en silence : il
  devient une *anomalie*, consignée à part.
- **`timeline`** fusionne les événements de toutes les preuves en une seule chronologie, dans un
  ordre total et stable. Le tri se fait sur disque par segments : la mémoire reste bornée même
  sur des dizaines de millions d'événements.
- **`detect`** applique des règles au format Sigma à tous les événements et écrit une détection
  par couple (règle, événement). Chaque détection garde l'identifiant de l'événement, celui de la
  règle et sa version exacte.
- **`case verify`** peut être lancé à tout moment : il signale une preuve modifiée, supprimée ou
  ajoutée hors outil.

### Codes de sortie

| Code | Sens |
|---|---|
| 0 | Succès |
| 1 | Échec d'exécution |
| 2 | Erreur d'usage (option manquante, invalide, répétée…) |
| 3 | Fonctionnalité pas encore disponible |
| 4 | Échec d'intégrité d'une preuve |

---

## Le dossier de cas

```text
cases/CASE-001/
├── case.json              qui, quand, quelle machine, quelle version de l'outil
├── case.log               une ligne par commande exécutée, en ajout seul
├── evidence/              copies des preuves, en lecture seule
├── hashes/manifest.jsonl  empreinte et origine de chaque preuve, en ajout seul
├── normalized/            événements et anomalies décodés, un fichier par preuve
├── timeline/              timeline.jsonl
├── detections/            detections.jsonl
└── reports/               livrables (prévu)
```

Garanties :

- le manifeste et le journal ne font qu'ajouter des lignes ; on peut rejouer l'historique complet
  d'un cas ;
- chaque entrée de `case.log` porte la commande, ses arguments, les heures de début et de fin, le
  code de sortie et un résumé (compteurs, empreinte du fichier produit, version du jeu de règles) ;
- un fichier produit n'est remplacé qu'une fois le nouveau complet : une commande interrompue
  laisse le résultat précédent intact.

---

## Les données produites

Tous les fichiers de sortie sont en **JSONL canonique** : un objet JSON par ligne, clés dans un
ordre fixe, horodatages en UTC à la microseconde. Deux exécutions sur les mêmes preuves donnent
des fichiers identiques, ce qui permet de les comparer ou de les hacher.

### Un événement (`normalized/`, `timeline/`)

```json
{"schema_version":1,"uid":"a6295a9cc8b313c1d19d4dc4f438dd5a","timestamp":"2019-02-06T14:17:53.317259Z",
 "timestamp_type":"logged","source":"evtx","event_type":"log_cleared","host":"TESTCOMPUTER",
 "channel":"Security","provider":"Microsoft-Windows-Eventlog","event_id":1102,
 "subject":{"domain":"TESTCOMPUTER","name":"test","sid":"S-1-5-21-…-1001"},
 "source_file":"Windows/System32/winevt/Logs/Security.evtx","source_sha256":"d04f923e…",
 "record_id":31878,"record_locator":"chunk:0/record:31878","ingest":"native",
 "metadata":{"SubjectUserName":"test","System.Computer":"TestComputer", "…":"…"}}
```

- `event_type` classe l'événement (`logon`, `logon_failed`, `process_creation`,
  `service_install`, `log_cleared`…, `other` sinon) ; la classification vient d'une table
  déclarative embarquée, pas du code.
- `metadata` conserve toutes les données de l'enregistrement d'origine : rien n'est perdu par
  la normalisation.
- `uid` est dérivé de l'empreinte de la preuve, de son chemin et de la position de
  l'enregistrement dans le fichier. Il est stable d'une exécution à l'autre et désigne un
  enregistrement unique, retrouvable dans la preuve d'origine.

### Une détection (`detections/`)

```json
{"schema_version":1,"id":"86a25cad8b924cb01e4d3655b4267a64","timestamp":"2019-02-06T14:17:53.317259Z",
 "rule_id":"8ad87a09-d977-4445-9e5a-962e9023846b","rule_version":"e0c454830084011d",
 "severity":"high","confidence":0.8,"mitre":"T1070.001","events":["a6295a9cc8b313c1d19d4dc4f438dd5a"]}
```

Le chemin de la preuve à l'alerte est complet : `events` désigne l'`uid` de l'événement, qui
porte `source_file`, `source_sha256` et `record_locator`, eux-mêmes vérifiables dans le
manifeste.

---

## Les règles de détection

### Le jeu embarqué

Sans option, `detect` applique douze règles intégrées au binaire :

| Règle | Événement | Sévérité | ATT&CK |
|---|---|---|---|
| Journal Security effacé | Security 1102 | high | T1070.001 |
| Journal effacé (vu par System) | System 104 | high | T1070.001 |
| Stratégie d'audit modifiée | Security 4719 | medium | T1562.002 |
| Compte utilisateur créé | Security 4720 | medium | T1136.001 |
| Membre ajouté à un groupe privilégié (identifié par SID) | Security 4728, 4732, 4756 | high | T1098 |
| Service installé | System 7045 | medium | T1543.003 |
| Tâche planifiée créée | Security 4698 | medium | T1053.005 |
| PowerShell lancé avec une commande encodée | `process_creation` | medium | T1059.001 |
| Clichés instantanés supprimés par vssadmin | `process_creation` | high | T1490 |
| Téléchargement de fichier par certutil | `process_creation` | medium | T1105 |
| Valeur de démarrage automatique (Run, RunOnce) écrite | `registry_set` | medium | T1547.001 |
| Script PowerShell qui télécharge puis exécute du code | `ps_script` | medium | T1059.001 |

Les groupes privilégiés sont reconnus par leur SID et non par leur nom, pour que la règle
fonctionne quelle que soit la langue du système. Les règles `process_creation` s'appliquent aux
journaux Sysmon et, sur une machine sans Sysmon, aux événements Security 4688.

### Utiliser ses propres règles

```sh
dfirflow detect --case ./cases/CASE-001 --rules ./mes-regles/
```

`--rules` accepte un fichier ou un dossier ; un dossier est parcouru récursivement (fichiers
`.yml` et `.yaml`, fichiers et dossiers cachés ignorés). Les règles fournies **remplacent** le
jeu embarqué : copiez-en les règles si vous voulez les conserver.

Chaque règle est examinée avant usage :

- une règle d'un autre produit que Windows est **écartée** et comptée (`skipped`) ;
- une règle qui sort du sous-ensemble pris en charge est **refusée**, avec la raison exacte :

  ```text
  dfirflow: detect: warning: rule refused: ./mes-regles/brute_force.yml: aggregation is not supported
  ```

- deux règles appliquées avec le même `id` font échouer la commande.

L'origine du jeu, sa version, la version de la table des catégories et la liste des refus sont
consignées dans `case.log`.

### Écrire et tester une règle

Une règle est un fichier Sigma classique :

```yaml
title: Compte utilisateur créé
id: 92be069d-0b8f-4ecd-a4c3-236eb494fa35
status: test
level: medium
tags:
    - attack.persistence
    - attack.t1136.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
    filter_machine:
        TargetUserName|endswith: '$'
    condition: selection and not filter_machine
```

Pour la tester, appliquez-la seule à un cas déjà ingéré :

```sh
dfirflow detect --case ./cases/CASE-001 --rules ./ma_regle.yml
```

Les champs disponibles sont ceux d'un événement de `normalized/` : `EventID`, `Channel`,
`Provider_Name`, `Computer`, puis toutes les clés de `metadata` (`TargetUserName`, `TargetSid`,
`CommandLine`…). La valeur d'un champ est comparée au texte tel qu'il apparaît dans l'événement,
jamais à un message rendu par Windows.

### Sources : services et catégories

Une règle désigne sa source par un service (`service: security`) ou par une catégorie
(`category: process_creation`), comme les règles publiques Sigma :

```yaml
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\vssadmin.exe'
        CommandLine|contains|all:
            - delete
            - shadows
    condition: selection
```

Services reconnus : `security`, `system`, `application`, `powershell`, `powershell-classic`,
`sysmon`, `taskscheduler`, `windefend`, `wmi`.

Catégories reconnues, et les événements auxquels elles s'appliquent :

| Catégorie | Événements |
|---|---|
| `process_creation` | Sysmon 1 ; Security 4688 (voir plus bas) |
| `network_connection` | Sysmon 3 |
| `driver_load`, `image_load` | Sysmon 6, Sysmon 7 |
| `create_remote_thread`, `process_access` | Sysmon 8, Sysmon 10 |
| `file_event` | Sysmon 11 |
| `registry_add`, `registry_delete` | Sysmon 12 (création, suppression) |
| `registry_set`, `registry_event` | Sysmon 13 ; Sysmon 12, 13 et 14 |
| `pipe_created`, `wmi_event`, `dns_query` | Sysmon 17-18, Sysmon 19-21, Sysmon 22 |
| `ps_module`, `ps_script` | PowerShell opérationnel 4103, 4104 |

Une règle qui déclare à la fois une catégorie et un service ne vise que les événements de la
catégorie présents dans le journal du service.

**Security 4688.** Sur une machine sans Sysmon, une règle `process_creation` s'applique aussi aux
événements 4688, avec `Image` lu dans `NewProcessName` et `ParentImage` dans `ParentProcessName`.
4688 ne fournit que `Image`, `ParentImage` et `CommandLine` (plus `EventID`, `Channel`,
`Provider_Name`, `Computer`) : une règle qui cite un autre champ, par exemple `Hashes` dans un
filtre, n'y est pas appliquée, sinon le filtre serait toujours faux et la règle produirait des
faux positifs. Un avertissement le signale, et `case.log` donne le détail par règle :

```text
dfirflow: detect: warning: 3 rules not applied to Security 4688 (missing fields), see case.log
```

Quand Sysmon et 4688 enregistrent le même lancement, une règle produit deux détections, une par
événement.

### Le sous-ensemble Sigma pris en charge

| Pris en charge | Refusé (raison affichée) |
|---|---|
| Sélection en table (ET) ou en liste de tables (OU) | Recherche par mots-clés |
| Valeurs multiples, jokers `*` et `?`, comparaison insensible à la casse | Agrégations (`\| count() > 5`) et `timeframe` |
| `contains`, `startswith`, `endswith`, `all`, `re`, `re\|i` | Comparaisons numériques (`gt`, `lt`…) et dates |
| `windash` (`-`, `/` et tirets typographiques), `cased` | `expand`, `utf16`, options `m` et `s` de `re` |
| `base64`, `base64offset`, précédés au besoin de `wide`, `utf16le`, `utf16be` | Combinaisons incohérentes (`re\|windash`, `base64\|cased`…) |
| `cidr` (IPv4 et IPv6), `exists`, `fieldref` | Catégories hors du tableau ci-dessus |
| `null` (champ absent ou vide) | |
| `and`, `or`, `not`, parenthèses, `1 of`, `all of`, `them` | |

Les règles portant sur plusieurs événements (seuils, fenêtres de temps, enchaînements) relèvent
de la future commande `correlate`.

### Version et confiance

- La **version d'une règle** est l'empreinte de son fichier : modifier une règle change sa
  version, donc l'identifiant de ses détections. On sait toujours quelle règle exacte a produit
  une alerte.
- La **confiance** vaut 0,8 pour une règle `stable`, 0,6 pour `test`, 0,4 pour `experimental` ;
  une règle peut la fixer elle-même. Les règles `deprecated` et `unsupported` sont écartées.
- **ATT&CK** : la première technique des étiquettes (`attack.t1070.001`) est reportée dans
  `mitre`.

---

## Architecture

```text
              volume monté, image, copie de disque
                              │
                    collect   │  copie + SHA-256 en une lecture, lecture seule
                              ▼
          evidence/ ── hashes/manifest.jsonl (empreinte, origine)
                              │
                    ingest    │  vérification d'empreinte, parser natif
                              ▼
                 Event + Anomaly ── validation centralisée
                              │
                              ▼
          normalized/  : un fichier d'événements par preuve
                 ┌────────────┴────────────┐
       timeline  │                         │  detect
                 ▼                         ▼
   timeline/timeline.jsonl     detections/detections.jsonl
                 └────────────┬────────────┘
                              ▼
                 correlate, report (prévu)
```

Le code est organisé en packages indépendants ; la ligne de commande ne contient aucune logique
métier, elle valide les arguments et appelle ces packages.

| Package | Rôle |
|---|---|
| `cmd/dfirflow` | Ligne de commande : analyse des arguments, aide, codes de sortie, journal |
| `internal/case` | Dossier de cas, manifeste, journal, vérification d'intégrité |
| `internal/collector` | Collecte des journaux EVTX et de leurs métadonnées d'origine |
| `internal/normalizer` | Modèle `Event` et `Detection`, identifiants, JSONL canonique |
| `internal/parser` | Contrat commun aux parsers, validation centralisée, anomalies |
| `internal/parser/evtx` | Parser EVTX natif et table de correspondance déclarative |
| `internal/ingest` | Vérification des preuves, choix du parser, écriture de `normalized/` |
| `internal/extsort` | Tri externe à mémoire bornée et écriture atomique, partagés |
| `internal/timeline` | Chronologie : filtres et clé d'ordre |
| `internal/detection` | Chargement des règles, évaluation, jeu embarqué |

### Choix techniques et leurs raisons

- **Go et un binaire statique** : un seul fichier à copier sur un poste d'analyse, Windows ou
  Linux, sans environnement d'exécution à installer.
- **Parsers natifs plutôt qu'orchestration d'outils** : DFIRFlow décode lui-même les artefacts
  du cœur. Les sorties d'outils tiers pourront être importées, mais DFIRFlow ne les exécute
  jamais. Le parser EVTX est un fork interne de `Velocidex/evtx` (Apache-2.0), corrigé pour ne
  rien perdre en silence et borner les lectures sur des fichiers corrompus.
- **Lecture en flux** : les événements sont traités un à un ; la mémoire ne dépend pas de la
  taille des preuves. Mesuré : 10 millions d'événements passés par `detect` en environ deux
  minutes, avec moins de 100 Mio de mémoire.
- **JSONL canonique** : lisible avec `jq` ou n'importe quel langage, comparable ligne à ligne,
  stable d'une exécution à l'autre.
- **Format Sigma** : le format ouvert de la communauté, pour réutiliser des règles existantes
  plutôt qu'inventer un langage.
- **Dépendances minimales** : bibliothèque standard Go, plus une seule bibliothèque en Go pur
  pour lire le YAML des règles (`go.yaml.in/yaml/v3`, MIT et Apache-2.0). Un test refuse toute
  autre dépendance.

---

## Principes de conception

1. **Binaire autonome**, hors ligne.
2. **Natif d'abord** : les outils tiers sont importés, jamais exécutés.
3. **Chaîne de preuve** : preuves hachées et en lecture seule, empreinte vérifiée avant chaque
   décodage, identifiants dérivés de l'empreinte.
4. **Reproductibilité** : sorties identiques à l'octet, ordre total, UTC.
5. **Aucune perte silencieuse** : tout enregistrement illisible devient une anomalie consignée.
6. **Tests d'abord** : chaque règle de détection a un cas positif et un cas négatif testés.
7. **Licences permissives** : Apache-2.0, MIT ou BSD uniquement.
8. **Détection déterministe** : règles versionnées, sans apprentissage automatique ; une
   détection est une piste.
9. **Windows d'abord** : artefacts Windows, valeurs rendues comme dans la vue XML de Windows.

---

## État du projet

| Étape | État |
|---|---|
| Ligne de commande, dossier de cas, intégrité | Disponible |
| Collecte et décodage des journaux EVTX | Disponible |
| Chronologie | Disponible |
| Détection mono-événement (Sigma) | Disponible |
| Corrélation : seuils, fenêtres de temps, chaînes d'attaque, déduplication | Prévu |
| Rapports HTML, SQLite, JSONL | Prévu |
| $MFT, USN, registre, Prefetch | Prévu |
| Import de sorties d'outils tiers | Prévu |

Limites connues :

- **Pas de collecte à chaud** : un journal verrouillé par un système en fonctionnement est
  signalé en échec ; travaillez sur un volume monté ou une image.
- **Catégories Sigma** : seules les catégories du tableau ci-dessus sont reconnues, à partir de
  Sysmon, de PowerShell et de Security 4688 ; les autres (`ps_classic_start`, pare-feu…) sont
  refusées avec la raison.
- **Pas de verrou de cas** : ne lancez pas deux commandes en même temps sur un même cas.
- **Enregistrements EVTX supprimés** (espace libre des fichiers) : non récupérés.

---

## Développement

```sh
make test     # tous les tests
make vet      # analyse statique
go test -race ./...
```

Un test de volume (10 millions d'événements) est désactivé par défaut :

```sh
DFIRFLOW_LARGE=1 go test -run TestRunLarge -timeout 30m ./internal/detection/
```

Le chargement des règles est testé par fuzzing, car une règle est une entrée non fiable :

```sh
go test -run '^$' -fuzz FuzzParseRule -fuzztime 60s ./internal/detection/
```

---

## Licence

DFIRFlow est distribué sous licence Apache-2.0 ; voir [LICENSE](LICENSE).
Le parser EVTX est dérivé de `Velocidex/evtx` (Apache-2.0).
