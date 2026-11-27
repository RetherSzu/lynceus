# Architecture de DFIRFlow — état au 2026-11-27

Ce document décrit le projet **tel qu'il est aujourd'hui** : ce qui est livré, ce qui est conçu
mais pas encore codé, et ce qui reste prévu. Il complète [Archi.md](Archi.md), qui décrit la
cible finale. Le sens de chaque donnée est détaillé dans
[dictionnaire-donnees.md](dictionnaire-donnees.md) ; les décisions d'architecture sont consignées
dans [adr/](adr/).

États utilisés : **Livré** (codé, testé, fusionné dans `dev`) · **Codé** (codé et testé sur sa
branche, pas encore fusionné) · **Conçu** (spec et plan validés,
pas encore codé) · **Prévu** (pas encore spécifié).

---

## 1. Vue d'ensemble

DFIRFlow est un binaire Go unique, sans runtime externe, qui fonctionne hors ligne sur une
station d'analyse Windows ou Linux. Il prend en entrée des artefacts Windows (journaux EVTX, $MFT,
registre…) et produit une chronologie, des détections et un rapport, en garantissant la chaîne de
preuve.

```text
             Poste Windows / image disque / sorties d'outils tiers
                                    │
          ┌─────────────────────────┴─────────────────────────┐
          ▼                                                   ▼
  collect (004, livré)                              import (011, prévu)
  copie + SHA-256 + origine                         lit KAPE, Hayabusa…
          │                                         (n'exécute jamais rien)
          ▼                                                   │
  ┌──────────────────── DOSSIER DE CAS (002, livré) ──────────┴────────┐
  │  evidence/  (lecture seule)  ◀── manifeste SHA-256, journal        │
  └───────────────────────────────┬────────────────────────────────────┘
                                  ▼
                    ingest (005, livré) : vérifie l'empreinte,
                    choisit le parser par signature
                                  ▼
                    Parser (contrat 003, livré) : EVTX 005 (livré),
                    USN 007, registre 008, $MFT 009, Prefetch 010 (prévus)
                                  │  Event + Anomaly
                                  ▼
                    Validation centralisée (003, livré)
                                  │  JSONL canonique
                                  ▼
                    normalized/  (005, livré) : événements + anomalies
                                  │
              ┌───────────────────┼────────────────────┐
              ▼                   ▼                    ▼
     timeline/ (006, livré)  detections/ (012, livré)   corrélation (prévu)
              └───────────────────┼────────────────────┘
                                  ▼
                     reports/ : HTML, SQLite, JSONL (prévu)
```

Tout passe par la **CLI** (spec 001), qui ne contient aucune logique métier : elle valide les
arguments et appelle les packages internes.

---

## 2. Ordre de développement (tranche verticale EVTX)

| Spec | Sujet | État |
|---|---|---|
| 001 | Grammaire de la CLI (10 commandes, aide, codes de sortie) | Livré |
| 002 | Dossier de cas, manifeste, vérification d'intégrité, journal | Livré |
| 003 | Modèle `Event`, `Detection`, contrat `Parser`, JSONL canonique | Livré |
| 004 | `collect` : copie des journaux EVTX dans le cas, métadonnées d'origine | Livré |
| 005 | Parser EVTX natif (fork interne, ADR-002) + `ingest` | Livré |
| 006 | `timeline` | Livré |
| 007–011 | USN, registre, $MFT, Prefetch, importers | Prévu |
| 012 | `detect` : règles Sigma mono-événement, jeu embarqué | Livré |
| 013 | Catégories de sources et modificateurs Sigma, garde 4688 | Codé |

---

## 3. Décisions d'architecture

| Décision | Date | Résumé | Référence |
|---|---|---|---|
| Approche hybride, natif d'abord | 2026-10 | Artefacts du cœur décodés en Go ; sorties d'outils tiers seulement importées, jamais exécutées | `etude-existant.md` §6–7, constitution II |
| ADR-002 : parsers natifs | 2026-11-25 | EVTX : fork interne de `Velocidex/evtx` v0.2.0 (Apache-2.0), sans la résolution des messages ni dépendance externe, corrigé (pertes silencieuses, bornes, types hexadécimaux) | [adr/ADR-002-parsers-natifs.md](adr/ADR-002-parsers-natifs.md) |
| Table de correspondance EVTX déclarative | 2026-11-25 | Le type d'événement et les champs extraits viennent d'un fichier JSON embarqué, pas du code | [guide-table-evtx.md](guide-table-evtx.md), spec 005 FR-011 |
| Collecte live NTFS (DF-13) | 2026-11-25 | Reportée ; un fichier verrouillé est rapporté `FAILED` | spec 004 FR-012 |
| Décodage EVTX parallèle (DF-18) | 2026-11-25 | Reporté à l'optimisation des performances (DF-37) | spec 005 FR-007 |

---

## 4. Code source

```text
cmd/dfirflow/              Livré : point d'entrée et CLI
├── main.go                   dispatch, codes de sortie, Ctrl+C (130)
├── commands.go               table des 10 commandes, options, exécution
└── flags.go                  analyse des options (une seule fois, listes, `--`)
internal/
├── case/       (casefile) Livré : dossier de cas
│   ├── case.go               Create, Open, Recorded, arborescence, case.json
│   ├── manifest.go           AddEvidence : copie + SHA-256 + origine + lecture seule
│   ├── verify.go             Verify : OK / MODIFIED / MISSING / UNTRACKED
│   └── journal.go            Log : une ligne JSON par commande
├── collector/             Livré : collecte (spec 004)
│   ├── collector.go          Collect : statuts COLLECTED / ALREADY / CONFLICT / FAILED / SKIPPED
│   ├── patterns.go           motifs d'artefacts, recherche sans casse, liens non suivis
│   ├── origin*.go            horodatages d'origine par plateforme (build tags)
│   └── locked*.go            fichier verrouillé sous Windows
├── normalizer/            Livré : modèle d'événement
│   ├── event.go              Event, Account, TimestampEntry, listes fermées
│   ├── time.go               Time : horodatage JSON à 6 décimales
│   ├── normalize.go          UID, NormalizeHost, NewAccount, FormatHex
│   ├── validate.go           Validate → []Violation
│   ├── detection.go          Detection, DetectionID
│   └── jsonl.go              Encoder, ReadEvents, ReadDetections, tri
├── parser/                Livré : contrat commun à tous les parsers et importers
│   ├── parser.go             Source, Anomaly, Sink, Parser, Validating
│   └── evtx/              Livré (spec 005)
│       ├── binxml/           fork de Velocidex/evtx (Apache-2.0, LICENSE + NOTICE)
│       ├── parser.go         Parser EVTX : contrat de la spec 003
│       ├── mapping.go        chargement et application de la table
│       └── mapping.json      table de correspondance EVTX (données)
├── ingest/                Livré (spec 005) : intégrité, choix du parser, écriture de normalized/
│   └── files.go              EventFiles : fichiers d'événements des preuves du manifeste (012)
├── extsort/               Codé (spec 012, extrait de 006) : tri externe borné, écriture atomique
├── timeline/              Livré (spec 006) : filtres, clé canonique ; s'appuie sur extsort
└── detection/             Livré (spec 012), étendu par la 013 (codé) : règles Sigma, catégories, détections
    ├── rule.go, match.go, condition.go   chargement, sélections et modificateurs, condition
    ├── modifiers.go          windash, base64, base64offset, encodages UTF-16 (013)
    ├── categories.go, categories.json   table des catégories et de leurs sources, version (013)
    ├── ruleset.go            jeu embarqué ou --rules, refus, garde, doublons, index, version
    └── rules/*.yml           jeu embarqué (12 règles, Apache-2.0)
specs/NNN-*/                  spec, plan, recherche, contrats, tâches de chaque fonctionnalité
docs/adr/                     décisions d'architecture
.specify/memory/constitution.md   9 principes non négociables
```

Dépendances : bibliothèque standard Go, plus **une seule dépendance de module**,
`go.yaml.in/yaml/v3` v3.0.6 (MIT et Apache-2.0, sans dépendance transitive), pour lire les règles
YAML (spec 012, plan, *Complexity Tracking*). `TestNoExternalDependency` refuse toute autre
dépendance. Le code d'origine Velocidex est intégré au dépôt, ce n'est pas une dépendance de
module.

Le dossier `spikes/` (code jetable des études) est ignoré par git.

---

## 5. La CLI (spec 001)

| Commande | Rôle | État |
|---|---|---|
| `case init <ID> --host --analyst [--dir]` | crée le dossier de cas | Livré |
| `case verify --case` | recalcule les SHA-256, détecte toute altération | Livré |
| `collect --case --target` | copie les journaux EVTX d'un volume dans le cas | Livré (004) |
| `ingest --case [chemins…]` | décode les preuves vers `normalized/` | Livré (005) |
| `import --case --tool <outil> <chemin>` | lit les sorties d'un outil tiers | Prévu (011) |
| `timeline --case [--from --to --source]` | chronologie filtrée vers `timeline/timeline.jsonl` | Livré (006) |
| `detect --case [--rules]` | applique les règles (jeu embarqué par défaut) vers `detections/detections.jsonl` | Livré (012), catégories (013, codé) |
| `correlate --case` | reconstitue les chaînes d'attaque | Prévu |
| `report --case --format html,sqlite,jsonl` | produit les livrables | Prévu |
| `investigate --case --target` | enchaîne les étapes, sans logique propre ; collecte, ingère, construit la chronologie, détecte, puis s'arrête à `correlate` | Partiel |

Les commandes non livrées répondent « not implemented yet », avec le code 3.

**Codes de sortie** : 0 succès · 1 échec d'exécution · 2 erreur d'usage · 3 non implémenté ·
4 échec d'intégrité (`case verify`, `ingest` sur une preuve altérée) · 130 interruption.

### `collect` (spec 004)

- Cherche `Windows/System32/winevt/Logs/*.evtx` sous la racine du volume, sans tenir compte de la
  casse, en conservant le chemin réel.
- Une ligne par fichier : `COLLECTED`, `ALREADY` (déjà au manifeste, même empreinte), `CONFLICT`
  (source différente, preuve existante intacte), `FAILED`, `SKIPPED` (lien ou fichier spécial).
- Refuse un cas situé sous la cible ; ne modifie jamais la cible.
- Entrée `collect` dans `case.log` : cible, compteurs, liste `problems`.

### `ingest` (spec 005, livré)

- Traite les preuves du manifeste (toutes, ou celles désignées) ; reconnaît un EVTX à sa signature.
- Vérifie l'empreinte de chaque preuve avant de la décoder : une preuve altérée est `ALTERED`
  (code 4) et n'est pas ingérée.
- Écrit `normalized/<chemin de la preuve>.jsonl` (événements) et `.anomalies.jsonl` (anomalies),
  de façon atomique ; une relance produit des fichiers identiques.
- Résumé : statut par preuve, nombres d'événements et d'anomalies, part des événements `other` et
  les dix (canal, EventID) non classés les plus fréquents.

### `timeline` (spec 006, livré)

- Lit `normalized/<preuve>.jsonl` des seules preuves du manifeste ; les anomalies et les fichiers
  `.partial` ne sont jamais lus ; un fichier sans preuve au manifeste est signalé.
- Filtres facultatifs : `--from`, `--to` (bornes incluses, UTC par défaut, à la microseconde),
  `--source` ; chaque événement apparaît une seule fois, à son horodatage principal.
- Écrit `timeline/timeline.jsonl` dans l'ordre canonique ; la précédente n'est remplacée qu'une fois
  la nouvelle complète ; l'entrée `case.log` porte les filtres, les compteurs et le SHA-256.

### `detect` (spec 012, livré ; 013, codé)

- Lit les mêmes fichiers d'événements que `timeline` (tous les événements, sans les filtres de la
  chronologie) et applique le jeu embarqué, ou à la place les règles de `--rules`.
- Une détection par couple (règle, événement) ; `detections/detections.jsonl` trié par `timestamp`
  puis `id`, écrit de façon atomique ; une détection est une piste, pas une preuve de compromission.
- Une règle hors du sous-ensemble Sigma est refusée avec sa raison ; une règle d'un autre produit
  que Windows est écartée et comptée ; l'entrée `case.log` porte l'origine et la version du jeu de
  règles, la version de la table des catégories, les refus, les restrictions de la garde
  (`rules_restricted`), les compteurs et le SHA-256.
- Un avertissement par source partielle signale les règles que la garde n'y applique pas (spec 013).

---

## 6. Le dossier de cas (spec 002)

```text
<dir>/<case_id>/
├── case.json              qui, quand, quelle machine, quelle version
├── case.log               une ligne par commande exécutée (ajout seul)
├── evidence/              copies des preuves, en lecture seule (alimenté par collect)
├── parsed/                réservé, non utilisé
├── normalized/            événements et anomalies JSONL (005, livré)
├── timeline/              timeline.jsonl, chronologie JSONL (006, livré)
├── detections/            detections.jsonl, détections JSONL (012, livré)
├── reports/               HTML / SQLite / JSONL (prévu)
└── hashes/manifest.jsonl  empreinte et origine de chaque preuve (ajout seul)
```

Garanties :
- une preuve est **copiée et hachée en une seule lecture**, puis vérifiée et mise en lecture seule ;
- chaque ligne du manifeste peut porter `origin` (spec 004) : chemin source et horodatages du
  fichier d'origine relevés avant la copie ;
- le manifeste et le journal ne font **qu'ajouter** des lignes ;
- `case verify` signale toute modification, suppression ou ajout hors outil.

---

## 7. Architecture du modèle d'événement (spec 003, livrée)

### 7.1 Structures et relations

```mermaid
classDiagram
    direction LR
    class Event {
        uid
        timestamp : Time
        timestamp_type
        timestamps : TimestampEntry[]
        source
        event_type
        host
        host_fqdn
        channel
        provider
        event_id
        subject : Account
        target : Account
        process
        process_id
        parent_process
        parent_process_id
        command_line
        file_path
        registry_path
        hashes : map
        source_file
        source_sha256
        record_id
        record_locator
        recovered
        ingest
        metadata : map
        Validate() Violation[]
    }
    class TimestampEntry {
        type
        time : Time
        origin
    }
    class Account {
        domain
        name
        sid
    }
    class Detection {
        id
        timestamp : Time
        rule_id
        rule_version
        severity
        confidence
        mitre
        events : uid[]
    }
    class ManifestEntry {
        file
        sha256
        size
        collected_at
    }
    class Source {
        File
        SHA256
        Host
    }
    class Anomaly {
        Locator
        Kind
        Message
    }
    class Parser {
        <<interface>>
        Name()
        Match(head)
        Parse(ctx, r, size, src, out)
    }
    class Sink {
        <<interface>>
        Event(Event)
        Anomaly(Anomaly)
    }
    Event "1" *-- "0..*" TimestampEntry
    Event "1" *-- "0..2" Account : subject / target
    Detection "1" --> "1..*" Event : events = uid
    ManifestEntry "1" ..> "1" Source : file, sha256
    Source ..> Event : source_file, source_sha256, host
    Parser ..> Sink : émet
    Sink ..> Event
    Sink ..> Anomaly
```

### 7.2 Comment les structures s'enchaînent

```text
case.json.hostname ─────────────┐
manifest.jsonl {file, sha256} ──┴─▶ Source ──▶ Parser.Parse(ctx, preuve, taille, Source, Sink)
                                                      │
                     ┌────────────────────────────────┴───────────────┐
                     ▼                                                ▼
              Sink.Event(Event)                              Sink.Anomaly(Anomaly)
                     │                                       unreadable / missing / truncated
                     ▼
        Validating : Event.Validate()
           ├─ valide   ─▶ consommateur ─▶ Encoder ─▶ normalized/*.jsonl
           └─ invalide ─▶ Anomaly{kind: invalid}  (jamais ignoré en silence)

normalized/*.jsonl ─▶ ReadEvents ─▶ filtre ─▶ tri externe ─▶ timeline/timeline.jsonl (006)
normalized/*.jsonl ─▶ ReadEvents ─▶ règles (canal, EventID) ─▶ Detection{events: [uid]} ─▶ tri externe
                                                         ─▶ detections/detections.jsonl
```

### 7.3 Les identifiants : qui pointe vers quoi

| Identifiant | Calcul | Relie |
|---|---|---|
| `source_sha256` | SHA-256 de la preuve (manifeste) | événement → preuve |
| `uid` | 32 hexa de SHA-256(`source_sha256` ‖ `source_file` ‖ `record_locator`) | détection → événement |
| `id` de détection | 32 hexa de SHA-256(`rule_id` ‖ `rule_version` ‖ `uid` triés) | rapport → détection |

Ces identifiants ne dépendent que de la preuve et de la position de l'enregistrement. Un correctif
de parseur ne change donc aucun `uid`, et deux exécutions donnent les mêmes identifiants.

### 7.4 Règles de format (JSONL canonique)

- un objet par ligne, terminé par `\n`, avec `schema_version` en premier ;
- les champs sont écrits dans un ordre fixe, les clés des maps sont triées et les champs vides sont omis ;
- les horodatages sont écrits `2020-09-09T13:18:23.627952Z` : en UTC, avec exactement 6 décimales ;
- l'ordre canonique des événements est `timestamp`, puis `source_file`, `record_id` et `uid` ;
- le décodeur est strict : il refuse tout champ inconnu, toute version inconnue et toute ligne
  invalide, en indiquant le numéro de la ligne.

Contrat normatif : [specs/003-event-model/contracts/event-model.md](../specs/003-event-model/contracts/event-model.md).

---

## 8. Parser EVTX et ingestion (spec 005, livré)

```text
evidence/…/Security.evtx
        │  ingest : SHA-256 recalculé = manifeste ?  non → ALTERED (code 4)
        ▼  oui
binxml (fork Velocidex)        en-tête de fichier → chunks de 64 Kio → enregistrements → BinXML
        │                      tailles bornées, pas de panique, comptage attendu / lu par chunk
        ▼  enregistrement décodé (System + EventData/UserData typés)
parser EVTX                    canal, fournisseur, EventID, Computer, TimeCreated, en-tête
        │  table de correspondance (mapping.json) → event_type, comptes, processus, empreintes…
        ▼  normalizer.Event  /  parser.Anomaly (enregistrement perdu, tronqué, illisible)
Validating (spec 003)          événement invalide → anomalie invalid
        ▼
normalized/…/Security.evtx.jsonl   +   normalized/…/Security.evtx.anomalies.jsonl
```

- **Aucune perte silencieuse** : pour chaque journal, événements + anomalies = enregistrements
  annoncés par les en-têtes de chunk.
- **Valeurs fidèles à Windows** : `HexInt` en `0x…`, horodatages à la microseconde, horodatage
  principal = instant de l'action (`UtcTime` Sysmon) sinon `TimeCreated`.
- **`event_type` = `other`** quand l'événement n'est pas dans la table : rien n'est perdu
  (`channel`, `provider`, `event_id` et `metadata` sont conservés), seul le classement manque. Pour
  ajouter un événement, voir [guide-table-evtx.md](guide-table-evtx.md).

---

## 9. Chronologie (spec 006, livré)

```text
manifeste ─▶ normalized/<preuve>.jsonl (preuves du manifeste, dans l'ordre du manifeste)
        │  ReadEvents : décodage strict, ligne refusée → échec (fichier, numéro de ligne)
        ▼  filtre --from / --to / --source
segments triés en mémoire (64 Mio au plus) ─▶ timeline/.work-*/seg-* si nécessaire
        │  fusion par tas, 128 segments au plus par passe, octets recopiés tels quels
        ▼
timeline/timeline.jsonl.partial ─▶ SHA-256 au fil de l'écriture ─▶ renommage en timeline.jsonl
```

- **Ordre total** : `timestamp` (µs), `source_file`, `record_id`, `uid` ; le résultat ne dépend ni
  du découpage en segments ni de l'ordre des fichiers.
- **Mémoire bornée** : seuls les segments en cours de tri sont en mémoire ; les fichiers de travail
  restent dans le cas et sont supprimés en succès, en échec ou à l'interruption.
- **Une seule chronologie par cas**, remplacée à chaque exécution ; les filtres de chaque version
  sont dans `case.log`.
- Le tri externe et l'écriture atomique sont dans `internal/extsort`, partagés avec `detect`.

---

## 10. Détection (spec 012, livrée ; spec 013, codée)

```text
jeu embarqué (rules/*.yml) ou --rules (fichier, ou .yml/.yaml d'un dossier, hors fichiers cachés)
        │  parseRule : produit windows sinon écartée ; champs, niveau, statut, confiance ;
        │  service → canal, ou catégorie → sources (categories.json) ; sélections et
        │  modificateurs ; condition (64 niveaux au plus) ; garde des sources partielles
        ▼  refus motivés · doublons d'id parmi les règles appliquées → échec · version du jeu
index canal → EventID → (règle, source) ─▶ normalized/<preuve>.jsonl ─▶ événements EVTX évalués
        │  par les entrées de leur (canal, EventID), puis par les règles de service de leur canal
        ▼
Detection (spec 003) ─▶ tri externe (timestamp, id) ─▶ detections/detections.jsonl
```

- **Sous-ensemble Sigma** : sélections (table = ET, liste de tables = OU), valeurs multiples,
  jokers `*` et `?`, `contains`, `startswith`, `endswith`, `all`, `re` et `re|i`, `null` ;
  `windash`, `cased`, `base64`, `base64offset`, `wide`/`utf16le`, `utf16be`, `cidr`, `exists`,
  `fieldref` (013) ; condition `and`, `or`, `not`, parenthèses, `1 of`, `all of`, `them`.
  Agrégations, `timeframe` et mots-clés sont refusés (relèvent de `correlate`).
- **Catégories (013)** : table embarquée `categories.json`, versionnée par empreinte
  (`categories_version`) : 16 catégories, 17 sources (Sysmon 1 à 22, PowerShell 4103 et 4104,
  Security 4688). Une source est un canal, des EventID, au besoin une contrainte `EventType`
  (opérations de registre Sysmon 12) et un renommage de champs.
- **Garde 4688 (013)** : Security 4688 est une source partielle de `process_creation` (`Image` ←
  `NewProcessName`, `ParentImage` ← `ParentProcessName`, `CommandLine`, plus les champs communs) ;
  une règle qui cite un autre champ, y compris par `fieldref`, n'y est pas évaluée et la
  restriction est consignée ; une règle sans source restante est refusée. Sysmon et 4688 décrivant
  le même lancement donnent deux détections ; leur rapprochement relève de `correlate` (DF-36).
- **Champs** : `EventID`, `Channel`, `Provider_Name`, `Computer`, puis les données de l'événement
  conservées par `ingest` (`metadata`) ; jamais un message rendu.
- **Versions** : `rule_version` = empreinte du fichier de la règle (fins de ligne ramenées à LF) ;
  version du jeu = empreinte des couples (id, version) triés, dans `case.log`.
- **Confiance** : déclarée par la règle, sinon 0,8 / 0,6 / 0,4 selon `stable` / `test` /
  `experimental` ; `mitre` = première technique ATT&CK des étiquettes (identifiant seul).
- **Jeu embarqué** (12 règles) : effacement des journaux Security et System, stratégie d'audit,
  création de compte, ajout à un groupe privilégié (par SID), installation de service, tâche
  planifiée ; PowerShell encodé, suppression des clichés par vssadmin, téléchargement par certutil
  (`process_creation`), clé Run (`registry_set`), script PowerShell qui télécharge et exécute
  (`ps_script`) ; chacune a un cas positif et un cas négatif testés, Sysmon et 4688 pour
  `process_creation`.

---

## 11. Principes qui contraignent l'architecture

| Principe | Effet concret |
|---|---|
| I. Binaire autonome | Go, bibliothèque standard et une dépendance YAML en Go pur, hors ligne ; code tiers intégré au dépôt plutôt qu'en dépendance ; règles embarquées |
| II. Natif d'abord | `import` lit les sorties d'outils tiers, ne les exécute jamais |
| III. Chaîne de preuve | manifeste SHA-256 et origine, preuves en lecture seule, empreinte vérifiée avant ingestion, `uid` dérivé de l'empreinte |
| IV. Reproductibilité | sorties identiques à l'octet, tri total, UTC, table de correspondance versionnée |
| V. Flux | lecture par `ReaderAt` et rappels ; anomalies obligatoires, aucune perte silencieuse |
| VI. Tests d'abord | tests et fichiers de référence avant le code ; oracles (evtx_dump, EvtxECmd) |
| VII. Licences | Apache-2.0 / MIT / BSD seulement ; projet sous Apache-2.0 ; dépendance MPL-2.0 de Velocidex retirée |
| VIII. Détection | règles Sigma déterministes et versionnées, champs structurés, sans apprentissage automatique ; une détection est une piste |
| IX. Windows-first | artefacts Windows ; rendu des valeurs aligné sur la vue XML Windows ; code propre à une plateforme isolé par build tags |

---

## 12. Points ouverts

- **Taxonomie des événements** : la liste fermée de la spec 003 compte dix types. Son
  élargissement (deux niveaux catégorie / type, alignés sur ECS ou OCSF) demandera une spec qui
  modifie le modèle 003.
- **Oracle EvtxECmd** : nécessite un environnement .NET ; ses sorties de référence seront produites
  hors CI (spec 005).
- **Collecte live** (DF-13) et **décodage parallèle** (DF-18) : reportés (cycles ultérieurs).
- **Exécutions simultanées sur un même cas** : non gérées (pas de verrou de cas) ; `ingest`,
  `timeline` et `detect` supposent une seule commande à la fois.
- **Récupération d'enregistrements EVTX supprimés** (espace libre des chunks, constat C13) : non
  planifiée.
- **Titres et tactiques ATT&CK** : seul l'identifiant de technique est conservé ; un référentiel
  embarqué (titres, tactiques, version d'ATT&CK) est prévu avec `report` ou `correlate`.
- **Catégories Sigma rares et sources hors Sysmon** (spec 013) : `ps_classic_*`, `file_delete`,
  `create_stream_hash`, pare-feu Windows 5156 pour `network_connection`, `ProcessId` hexadécimal
  de 4688 : non pris en charge. Mesure SC-002 du 2026-11-27 sur SigmaHQ (commit 876eb7b,
  `rules/windows`, hors du dépôt) : 2 047 règles des catégories couvertes sur 2 047 chargées ; sur
  tout le dossier, 2 304 règles appliquées et 123 refusées (74 services inconnus, 45 catégories
  hors table, 3 recherches par mots-clés, 1 sans source). La garde retire Security 4688 de 720
  des 1 193 règles `process_creation`, surtout pour `OriginalFileName` (588), `Description`,
  `ParentCommandLine`, `Product` et `Hashes`.
- **Champs pivots dans les règles** : non pris en charge.
- **Coût par règle sur un même EventID** (spec 013) : l'index par canal et EventID écarte les
  règles qui ne visent pas l'événement, mais un événement est évalué par toutes celles de son
  EventID (environ 57 ns par règle sur des motifs littéraux). 2 000 règles concentrées sur
  Sysmon 1, 4688 et Sysmon 13 font passer 10 millions d'événements de 2 à 7 min 41 s ; un
  préfiltre multi-motifs sur les littéraux des règles réduirait ce coût.