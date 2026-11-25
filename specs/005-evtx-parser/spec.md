# Feature Specification: Parser EVTX et ingestion des journaux

**Feature Branch**: `feature/005-evtx-parser`

**Created**: 2026-11-25

**Status**: Draft

**Clarification 2026-11-25**: décodage séquentiel ; le décodage parallèle par chunk (DF-18) est
reporté à l'optimisation des performances (DF-37) (FR-007).

**Input**: User description: "005-evtx-parser : parser EVTX natif et commande ingest pour les
journaux EVTX. Selon l'ADR-002 (option B), fork interne de Velocidex/evtx dans
internal/parser/evtx/ sans la partie messages (dépendance MPL), avec corrections : comptage des
enregistrements attendus par chunk et anomalies (pertes silencieuses), conservation du type HexInt,
MessageNumber, bornes sur les tailles et pas de panique sur entrée malformée. Parser conforme au
contrat parser.Parser de la 003 (Source, Sink, anomalies), normaliseur EVTX vers normalizer.Event
(Plane DF-16, DF-17, DF-28 ; DF-18 parsing parallèle par chunk à trancher). La commande ingest lit
les preuves EVTX du cas et écrit les événements normalisés en JSONL dans normalized/. Tests oracle
contre EvtxECmd / evtx_dump."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Ingérer les journaux EVTX collectés (Priority: P1)

L'analyste a collecté les journaux EVTX d'un poste dans son cas (spec 004). Il lance
`dfirflow ingest --case <cas>`. DFIRFlow décode chaque journal, transforme chaque enregistrement en
événement normalisé (spec 003) et écrit, pour chaque preuve, un fichier d'événements sous
`normalized/`. L'analyste dispose ensuite d'une base homogène pour la timeline (spec 006) et la
détection.

**Why this priority**: c'est la première étape qui transforme des preuves en données exploitables ;
elle termine la chaîne collecte → événements de la tranche verticale EVTX.

**Independent Test**: collecter un jeu de journaux de référence dans un cas, lancer `ingest`, puis
vérifier que chaque preuve EVTX a son fichier d'événements, que chaque ligne est un événement valide
du modèle 003 et que le nombre d'événements est égal au nombre d'enregistrements du journal.

**Acceptance Scenarios**:

1. **Given** un cas contenant `Security.evtx` (739 enregistrements sains), **When** l'analyste lance
   `ingest`, **Then** `normalized/` contient le fichier d'événements de cette preuve avec 739
   événements valides, dans l'ordre du journal, et la commande sort avec le code 0.
2. **Given** un cas contenant plusieurs journaux et un fichier sous `evidence/` qui n'est pas un
   EVTX, **When** l'analyste lance `ingest` sans chemin, **Then** tous les EVTX sont traités et le
   fichier non EVTX est signalé comme ignoré, sans erreur.
3. **Given** un cas, **When** l'analyste lance `ingest` avec le chemin d'une seule preuve, **Then**
   seule cette preuve est traitée.
4. **Given** un chemin qui ne désigne pas une preuve du manifeste, **When** l'analyste lance
   `ingest` avec ce chemin, **Then** la commande le refuse avant tout traitement, avec le code 1.
5. **Given** une ingestion déjà faite, **When** l'analyste relance `ingest`, **Then** les fichiers
   d'événements sont regénérés à l'identique.

---

### User Story 2 - Ne perdre aucun enregistrement en silence (Priority: P1)

Un journal EVTX peut être abîmé (chunk corrompu, fichier tronqué, enregistrement illisible).
L'analyste doit savoir exactement ce qui n'a pas pu être lu, où, et pourquoi, au lieu de découvrir
plus tard qu'une partie de la timeline manque.

**Why this priority**: le spike de la 003 a montré 78 enregistrements perdus sans aucune erreur
(C11) ; sans cette garantie, l'absence d'un événement dans la timeline ne prouve rien.

**Independent Test**: ingérer des journaux volontairement abîmés et vérifier que, pour chaque
journal, le nombre d'événements plus le nombre d'anomalies est égal au nombre d'enregistrements
annoncés par le fichier.

**Acceptance Scenarios**:

1. **Given** un journal dont un chunk est corrompu, **When** il est ingéré, **Then** les
   enregistrements lisibles des autres chunks sont émis, chaque enregistrement manquant ou illisible
   du chunk corrompu donne une anomalie localisée, et la somme événements + anomalies est égale au
   nombre d'enregistrements annoncés.
2. **Given** un journal tronqué au milieu d'un chunk, **When** il est ingéré, **Then** les
   enregistrements complets sont émis et une anomalie `truncated` signale la coupure.
3. **Given** un fichier dont les tailles internes sont incohérentes ou démesurées, **When** il est
   ingéré, **Then** DFIRFlow ne plante pas, ne consomme pas une mémoire disproportionnée et signale
   des anomalies ou une erreur fatale pour ce seul fichier.
4. **Given** des anomalies sur une preuve, **When** l'ingestion se termine, **Then** elles sont
   enregistrées dans le cas à côté des événements de cette preuve et comptées dans le résumé.

---

### User Story 3 - Des événements fidèles à Windows (Priority: P1)

Les règles de détection (Sigma) et la contre-expertise comparent les valeurs telles que Windows les
affiche. Un code d'état `0xc000006d` doit rester `0xc000006d`, un horodatage doit être exact à la
microseconde, et l'événement doit porter le bon type (`logon`, `process_creation`…), le bon compte
et le bon hôte.

**Why this priority**: une valeur mal rendue fait manquer une détection ou fausse une conclusion ;
le spike a relevé la perte du type hexadécimal (C14) et un défaut de décodage (C8).

**Independent Test**: comparer, champ par champ, les événements produits sur les journaux de
référence aux sorties des outils de référence.

**Acceptance Scenarios**:

1. **Given** un événement 4625 dont `Status` vaut `0xc000006d` dans Windows, **When** il est
   ingéré, **Then** les métadonnées de l'événement portent `Status = 0xc000006d`.
2. **Given** un événement 4104 (PowerShell), **When** il est ingéré, **Then** `MessageNumber` vaut
   `1`, comme dans Windows.
3. **Given** un événement Sysmon 1 portant `UtcTime`, **When** il est ingéré, **Then** l'horodatage
   principal est `UtcTime`, `TimeCreated` figure parmi les horodatages secondaires avec le type
   `logged`, et l'horodatage d'en-tête d'enregistrement avec le type `written`.
4. **Given** les journaux de référence, **When** leurs événements sont comparés aux outils de
   référence, **Then** `timestamp`, `event_id`, `channel`, `provider`, `record_id` et les valeurs
   des métadonnées concordent pour 100 % des enregistrements.
5. **Given** un événement 4624, **When** il est ingéré, **Then** `event_type = logon`, `subject` et
   `target` portent les comptes de l'événement, et un EventID sans correspondance donne
   `event_type = other`.

---

### User Story 4 - Tracer l'ingestion dans le cas (Priority: P2)

Un relecteur doit savoir quelles preuves ont été ingérées, avec quelle version de l'outil, combien
d'événements et d'anomalies chacune a produits, et si une preuve a été refusée.

**Why this priority**: chaîne de preuve (principe III) ; utile dès la première ingestion mais ne
bloque pas l'exploitation des événements.

**Independent Test**: ingérer un cas avec une preuve abîmée et une preuve altérée après collecte,
puis lire `case.log`.

**Acceptance Scenarios**:

1. **Given** une ingestion terminée, **When** l'analyste lit `case.log`, **Then** il trouve une
   entrée `ingest` avec, par preuve, le nombre d'événements et d'anomalies, et le code de sortie.
2. **Given** une preuve modifiée depuis sa collecte, **When** l'analyste lance `ingest`, **Then**
   cette preuve n'est pas ingérée, elle est signalée comme altérée, les autres sont traitées et la
   commande sort avec le code 4.

---

### Edge Cases

- Journal vide (en-tête seul, aucun enregistrement) : fichier d'événements vide, code 0.
- Fichier `.evtx` dont la signature n'est pas celle d'un EVTX : ignoré et signalé (la
  reconnaissance se fait sur le contenu, jamais sur l'extension).
- Enregistrement dont l'EventID n'est pas connu : émis avec `event_type = other`, jamais écarté.
- Enregistrement valide pour le décodeur mais invalide pour le modèle 003 (ex. hôte vide) :
  anomalie `invalid` avec les violations, aucun événement écrit.
- Numéros d'enregistrement d'en-tête et `EventRecordID` différents (journal exporté, C3) : le
  numéro d'en-tête identifie l'enregistrement.
- Interruption (Ctrl+C) : les fichiers d'événements déjà terminés restent valides, aucun fichier
  partiel ne subsiste, l'entrée de journal est écrite avec le code 130.
- Enregistrements récupérables dans l'espace libre des chunks (C13) : non traités dans cette spec.

## Requirements *(mandatory)*

### Functional Requirements

**Décodage EVTX**

- **FR-001**: DFIRFlow MUST décoder nativement le format EVTX (en-tête de fichier, chunks,
  enregistrements, BinXML et modèles), sans outil ni service externe.
- **FR-002**: La reconnaissance d'un journal EVTX MUST se faire sur la signature du fichier, jamais
  sur son extension.
- **FR-003**: Pour chaque chunk, le décodeur MUST comparer les enregistrements annoncés par
  l'en-tête du chunk aux enregistrements effectivement lus, et MUST signaler chaque écart par une
  anomalie (`missing`, `unreadable` ou `truncated`) portant sa localisation.
- **FR-004**: Le décodeur MUST conserver le type des valeurs : `HexInt32`/`HexInt64` rendus en
  `0x` + hexadécimal minuscule, et toutes les valeurs rendues selon les règles de la spec 003
  (FR-013), y compris `MessageNumber` des événements PowerShell.
- **FR-005**: Le décodeur MUST borner toute taille lue dans le fichier par la taille de son
  contenant (chunk ou fichier) et MUST NOT paniquer : une incohérence produit une anomalie, ou une
  erreur fatale pour ce seul fichier si la suite est illisible.
- **FR-006**: Le décodage MUST se faire en flux, chunk par chunk, avec une mémoire indépendante de
  la taille du journal.
- **FR-007**: Le décodage MUST être séquentiel, chunk après chunk. Le décodage parallèle par chunk
  (DF-18) est reporté à l'optimisation des performances (DF-37).

**Normalisation (contrat de la spec 003)**

- **FR-008**: Le parser EVTX MUST implémenter le contrat de parser de la spec 003 et émettre, dans
  l'ordre du journal, un événement par enregistrement lisible et une anomalie par enregistrement
  perdu, si bien que événements + anomalies = enregistrements annoncés.
- **FR-009**: Chaque événement MUST porter `source = evtx`, `channel`, `provider`, `event_id`,
  `host` (champ `Computer`), `record_id` (numéro d'en-tête de l'enregistrement), un
  `record_locator` qui localise l'enregistrement dans le fichier (chunk et enregistrement), et
  `ingest = native`.
- **FR-010**: L'horodatage principal MUST être l'instant de l'action quand l'événement le fournit
  (ex. `UtcTime` de Sysmon), sinon `TimeCreated` ; `TimeCreated` (`logged`) et l'horodatage d'en-tête
  (`written`) MUST figurer dans les horodatages secondaires quand ils diffèrent du principal.
- **FR-011**: `event_type` MUST être déterminé par une table de correspondance déclarative
  (données, et non code), intégrée au binaire et versionnée avec lui, indexée par (canal,
  fournisseur, EventID). Ajouter un EventID MUST se limiter à ajouter une entrée à cette table et son
  cas de test. La table MUST couvrir au minimum : 4624 `logon`, 4625 `logon_failed`, 4634 et 4647 `logoff`, 4688 et
  Sysmon 1 `process_creation`, 7045 et 4697 `service_install`, 4104 `script_execution`, 1102 et
  104 `log_cleared`, Defender 1116 et 1117 `malware_detected`, Defender 5001 et 5007
  `av_config_change` ; tout autre enregistrement MUST être `other`.
- **FR-012**: Les comptes (`subject`, `target`), le processus, le processus parent, la ligne de
  commande, le chemin de fichier et les empreintes MUST être renseignés à partir des champs de
  l'événement pour chaque EventID de FR-011 ; la correspondance entre champs de l'événement et champs
  normalisés MUST être décrite dans la même table déclarative que FR-011.
- **FR-012a**: Une entrée de table invalide (champ normalisé inconnu, type d'événement hors de la
  liste de la spec 003, doublon de clé) MUST être détectée par les tests et ne jamais atteindre une
  version publiée.
- **FR-013**: Toutes les données de l'événement (`EventData`, `UserData`) MUST être conservées dans
  `metadata` selon les règles de rendu de la spec 003.

**Commande `ingest`**

- **FR-014**: `ingest --case <cas> [chemins…]` MUST traiter les preuves EVTX du manifeste : toutes
  si aucun chemin n'est donné, sinon celles désignées (chemins relatifs à `evidence/`) ; un chemin
  hors manifeste MUST être refusé avant tout traitement.
- **FR-015**: Avant de décoder une preuve, `ingest` MUST vérifier que son empreinte est égale à
  celle du manifeste ; une preuve altérée MUST NOT être ingérée.
- **FR-016**: Pour chaque preuve, `ingest` MUST écrire les événements valides au format JSONL
  canonique de la spec 003 dans un fichier de `normalized/` qui reprend le chemin de la preuve, et
  les anomalies dans un fichier voisin ; une relance MUST remplacer ces fichiers par un résultat
  identique, sans jamais laisser de fichier partiel.
- **FR-017**: stdout MUST lister une ligne par preuve, triée par chemin, avec son statut
  (`INGESTED`, `SKIPPED`, `ALTERED`, `FAILED`), son nombre d'événements et d'anomalies, puis une
  ligne de résumé ; le format MUST être déterministe.
- **FR-018**: Chaque exécution MUST ajouter une entrée `ingest` à `case.log` avec, par preuve, le
  statut, les nombres d'événements et d'anomalies et la raison d'un échec.
- **FR-018a**: Le résumé de `ingest` (stdout et `case.log`) MUST indiquer la part des événements
  classés `other` et les dix couples (canal, EventID) non classés les plus fréquents, avec leur
  nombre, triés par nombre décroissant puis par canal et EventID.
- **FR-019**: Codes de sortie : 0 si toutes les preuves traitées sont `INGESTED` ou `SKIPPED`
  (les anomalies n'en font pas un échec) ; 4 si au moins une preuve est `ALTERED` ; 1 si au moins
  une preuve est `FAILED`, si un chemin est refusé ou si aucune preuve EVTX n'est trouvée ; 130 en
  cas d'interruption. `ALTERED` l'emporte sur `FAILED`.

**Validation**

- **FR-020**: Les événements produits sur les journaux de référence MUST être comparés, champ par
  champ, à au moins un outil de référence (EvtxECmd, et `evtx_dump` déjà recoupé par le spike) ;
  chaque écart connu MUST être documenté et justifié.
- **FR-021**: Chaque défaut relevé par le spike (C8, C11, C12, C14) et par l'ADR-002 (E1 à E5) MUST
  avoir un test de non-régression.

### Key Entities

- **Journal EVTX** : preuve du cas, découpée en chunks contenant des enregistrements.
- **Enregistrement** : unité du journal, identifiée par son numéro d'en-tête et sa position.
- **Événement normalisé** (spec 003) : un par enregistrement lisible et valide.
- **Anomalie** (spec 003) : un enregistrement perdu, tronqué, illisible ou invalide, localisé.
- **Table de correspondance EVTX** : données déclaratives versionnées ; (canal, fournisseur,
  EventID) → type d'événement et correspondance des champs à extraire.
- **Fichiers normalisés** : événements et anomalies d'une preuve, sous `normalized/`.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Sur les journaux de référence, 100 % des enregistrements produisent un événement ou
  une anomalie ; sur les journaux abîmés, événements + anomalies = enregistrements annoncés.
- **SC-002**: Sur les journaux de référence, les champs comparés concordent avec l'outil de
  référence pour 100 % des enregistrements, hors écarts documentés.
- **SC-003**: Aucun fichier du jeu de fichiers malformés (tailles incohérentes, signatures
  invalides, troncatures) ne provoque d'arrêt brutal ; chacun aboutit à des anomalies ou à un
  échec limité à ce fichier.
- **SC-004**: L'ingestion d'un journal de 1 Go s'effectue avec une consommation mémoire constante,
  indépendante de sa taille.
- **SC-005**: Deux ingestions du même cas produisent des fichiers normalisés identiques octet par
  octet.
- **SC-006**: Une preuve modifiée après collecte n'est jamais ingérée.
- **SC-007**: Ajouter la prise en charge d'un nouvel EventID ne demande qu'une entrée de table et
  son cas de test, sans modification du code du parser.

## Assumptions

- Le décodeur provient du fork interne de `Velocidex/evtx` décidé par l'ADR-002 (option B), sans la
  résolution des messages : le texte des messages Windows n'est pas produit.
- La timeline, le tri global et les filtres relèvent de la spec 006 ; `ingest` conserve l'ordre du
  journal.
- Les journaux de référence commités sont synthétiques ou sous licence compatible (journal de test
  Apache-2.0 de la bibliothèque d'origine) ; les échantillons GPL du spike restent hors dépôt.
- L'outil de référence EvtxECmd demande un environnement .NET ; ses sorties de référence sont
  produites hors CI et versionnées.
- Les enregistrements récupérables dans l'espace libre (C13) sont hors périmètre.
- La table de correspondance peut reprendre des correspondances des *Maps* d'EvtxECmd (licence
  MIT, compatible avec le principe VII), avec attribution.
- L'élargissement de la liste des types d'événement (taxonomie à deux niveaux alignée sur un
  standard) relève d'une spec ultérieure qui modifiera le modèle 003.
- Seules les preuves EVTX sont traitées ; les autres formats seront revendiqués par leurs parsers
  (specs 007 et suivantes).
