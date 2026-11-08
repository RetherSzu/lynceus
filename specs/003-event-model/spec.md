# Feature Specification: Modèle d'événement normalisé et contrat de parseur

**Feature Branch**: `feature/003-event-model`

**Created**: 2026-11-03

**Status**: Draft

**Input**: Spec 003 de la tranche verticale EVTX : modèle `Event` normalisé commun à tous les
parseurs et importers, structure `Detection`, identifiant d'événement, validation, contrat
`Parser`, JSONL canonique et politique d'évolution. Construite décision par décision
([decisions.md](decisions.md), D1–D11) à partir d'un spike sur de vrais artefacts
([spike-report.md](spike-report.md), constats C1–C14).

## User Scenarios & Testing *(mandatory)*

Les « utilisateurs » de cette spec sont les auteurs des specs suivantes (parseurs 005, 007–010,
importers 011, timeline 006, détection 012) et, à travers elles, l'analyste qui lit les fichiers
`normalized/`, `timeline/` et `detections/` d'un cas.

### User Story 1 - Représenter tout enregistrement d'artefact par un événement valide (Priority: P1)

L'auteur d'un parseur transforme chaque enregistrement d'un artefact (une entrée EVTX, une entrée
$MFT…) en un événement normalisé unique. Il dispose d'un modèle unique, d'une liste fermée de
valeurs et d'une validation qui lui dit précisément ce qui ne va pas.

**Why this priority**: tout le reste de l'outil (timeline, détection, corrélation, rapport) lit
ces événements ; un modèle flou se paierait dans chaque spec suivante.

**Independent Test**: construire des événements de test (valides et invalides) et vérifier que la
validation accepte les premiers et renvoie, pour les seconds, chaque violation nommée.

**Acceptance Scenarios**:

1. **Given** un événement EVTX 4624 complet (socle, `channel`, `provider`, `event_id`, `subject`,
   `target`), **When** il est validé, **Then** aucune violation n'est renvoyée.
2. **Given** un événement dont `timestamp` est nul, `source_sha256` fait 63 caractères et
   `event_type` vaut `persistence`, **When** il est validé, **Then** trois violations sont
   renvoyées, chacune nommant le champ et la règle.
3. **Given** un événement `source = evtx` sans `channel`, **When** il est validé, **Then** une
   violation est renvoyée ; **Given** un événement `source = mft` portant un `event_id`, **Then**
   une violation est renvoyée.
4. **Given** un enregistrement EVTX dont l'EventID n'est pas mappé, **When** le parseur l'émet avec
   `event_type = other`, **Then** il est valide et conservé.
5. **Given** les mêmes `source_sha256`, `source_file` et `record_locator`, **When** l'identifiant
   est calculé deux fois, y compris après un changement des champs décodés, **Then** le `uid` est
   identique.

---

### User Story 2 - Produire un JSONL canonique, identique à l'octet (Priority: P1)

L'analyste et les tests comparent les sorties d'un cas par empreinte. Deux exécutions sur les
mêmes preuves produisent des fichiers identiques octet par octet ; tout fichier peut être relu, et
une ligne corrompue est signalée avec son numéro.

**Why this priority**: c'est la garantie de reproductibilité (constitution, principe IV) et la base
des tests oracle (principe VI).

**Independent Test**: encoder un jeu d'événements de référence, comparer le résultat au fichier de
référence versionné, le relire, le réencoder et comparer à nouveau.

**Acceptance Scenarios**:

1. **Given** le jeu d'événements de référence, **When** il est encodé, **Then** la sortie est
   identique octet par octet au fichier de référence de `testdata/`.
2. **Given** un fichier encodé, **When** il est décodé puis réencodé, **Then** le résultat est
   identique au fichier d'origine.
3. **Given** des événements en désordre, **When** ils sont triés, **Then** l'ordre suit
   `timestamp`, `source_file`, `record_id`, `uid`, et deux tris du même ensemble donnent le même
   ordre.
4. **Given** un fichier dont la ligne 3 contient un champ inconnu, une ligne de `schema_version`
   non prise en charge, ou du JSON invalide, **When** il est décodé, **Then** le décodage échoue en
   indiquant la ligne 3 et la cause.
5. **Given** un événement dont `command_line` contient `<`, `>` et `&`, **When** il est encodé,
   **Then** ces caractères apparaissent tels quels.

---

### User Story 3 - Brancher un parseur sur un contrat commun (Priority: P1)

L'auteur d'un parseur implémente un contrat unique : il reçoit le fichier de preuve et sa
provenance, émet des événements et signale chaque anomalie non fatale au lieu de l'ignorer.
L'ingestion choisit le parseur d'après la signature du fichier.

**Why this priority**: le spike a montré 78 enregistrements perdus sans aucune erreur (C11) ; le
contrat est le seul endroit où l'on peut l'interdire pour tous les parseurs.

**Independent Test**: faire tourner un faux parseur de test à travers le contrat, sur une entrée
saine puis sur une entrée contenant des enregistrements illisibles, manquants et invalides.

**Acceptance Scenarios**:

1. **Given** le faux parseur et une entrée saine, **When** il est exécuté, **Then** il émet les
   événements dans l'ordre du fichier, tous valides, et ne renvoie aucune erreur.
2. **Given** une entrée contenant un enregistrement illisible, **When** le faux parseur est
   exécuté, **Then** une anomalie `unreadable` portant le `record_locator` est signalée et les
   enregistrements suivants sont émis.
3. **Given** un événement émis qui viole la validation, **When** il traverse la validation
   centralisée, **Then** il n'est pas transmis et une anomalie `invalid` nommant les violations est
   signalée à sa place.
4. **Given** une entrée de format inconnu, **When** la sélection est faite sur la signature,
   **Then** aucun parseur ne la revendique ; **Given** un parseur exécuté de force sur cette
   entrée, **Then** il renvoie une erreur fatale.
5. **Given** un contexte annulé pendant l'exécution, **When** le parseur le constate, **Then** il
   s'arrête et renvoie l'annulation ; les événements déjà émis restent valides.
6. **Given** un consommateur qui renvoie une erreur, **When** le parseur émet l'événement suivant,
   **Then** il s'arrête et renvoie cette erreur.

---

### User Story 4 - Enregistrer un résultat de détection (Priority: P2)

La future spec de détection (012) produit des résultats qui pointent vers les événements qui les
ont déclenchés, sans modifier ces événements.

**Why this priority**: la structure est nécessaire pour figer le format de `detections/` ; le
moteur viendra en spec 012.

**Independent Test**: construire, valider, encoder et relire des détections de test.

**Acceptance Scenarios**:

1. **Given** une détection valide, **When** elle est validée, **Then** aucune violation n'est
   renvoyée ; **Given** une sévérité `urgent`, une confiance de 1,5, une technique `T59` ou aucun
   événement, **Then** chaque cas produit une violation.
2. **Given** la même règle, la même version et les mêmes événements dans un ordre différent,
   **When** l'identifiant est calculé, **Then** il est identique.
3. **Given** des détections, **When** elles sont encodées, **Then** elles suivent les règles du
   JSONL canonique, triées par `timestamp` puis `id`.

---

### User Story 5 - Faire évoluer le modèle sans casser les cas existants (Priority: P3)

Une spec ultérieure ajoute un type d'événement ou un champ. Les cas produits avant restent
lisibles ; un binaire trop ancien refuse un fichier trop récent avec un message clair.

**Why this priority**: indispensable dès la spec 005, mais sans effet visible tant qu'une seule
version existe.

**Independent Test**: décoder un fichier de version supérieure à celle prise en charge et vérifier
le message ; vérifier que le contrat porte la version 1 dans son historique.

**Acceptance Scenarios**:

1. **Given** une ligne de `schema_version` 2 et un décodeur de version 1, **When** elle est
   décodée, **Then** l'erreur indique la version non prise en charge et invite à mettre à jour
   l'outil.
2. **Given** le contrat du modèle, **When** on le lit, **Then** il contient un tableau d'historique
   dont la première ligne est la version 1, introduite par la spec 003.

---

### Edge Cases

- Horodatage en-deçà de la microseconde (FILETIME à 100 ns) : tronqué, jamais arrondi.
- Horodatage dans un autre fuseau : converti en UTC avant encodage ; deux instants égaux dans des
  fuseaux différents s'encodent identiquement.
- `record_id = 0` (entrée 0 de la $MFT) : valide.
- `-`, chaîne vide ou SID `S-1-0-0` dans un compte : champ absent ; compte entièrement absent :
  objet omis.
- `Computer` en FQDN (`WIN-77LTAPHIQ1R.example.corp`) : `host = WIN-77LTAPHIQ1R`, `host_fqdn`
  conserve la valeur d'origine ; nom court : pas de `host_fqdn`.
- Artefact sans nom d'hôte ($MFT, Prefetch) : `host` = `hostname` du cas, normalisé de même.
- Valeur `%%2313` dans les données : conservée telle quelle.
- Chaîne non UTF-8 valide dans un champ ou dans `metadata` : violation, donc anomalie `invalid`.
- Deux événements de même `timestamp`, même fichier et même `record_id` (enregistrements
  récupérés) : départagés par `uid`.
- Fichier JSONL vide : décodé en zéro événement, sans erreur.
- Ligne terminée par `\r\n` à la lecture : refusée (ligne invalide).
- Empreintes Sysmon en majuscules (`SHA1=…,MD5=…`) : `hashes` exige des minuscules ; la mise en
  minuscules incombe au parseur (spec 005).

## Requirements *(mandatory)*

### Functional Requirements

**Événement : socle commun** (D5)

- **FR-001**: Tout événement MUST porter les champs suivants, avec ces règles :

  | Champ | Règle |
  |---|---|
  | `uid` | 32 caractères hexadécimaux minuscules (FR-008) |
  | `timestamp` | instant UTC non nul, horodatage principal (FR-005) |
  | `timestamp_type` | valeur de la liste FR-006 |
  | `source` | `evtx`, `mft`, `usnjrnl`, `registry`, `prefetch` ou `memory` (format d'artefact) |
  | `event_type` | valeur de la liste FR-007 |
  | `host` | non vide, normalisé selon FR-012 |
  | `source_file` | chemin relatif à `evidence/`, séparateur `/` |
  | `source_sha256` | 64 caractères hexadécimaux minuscules |
  | `record_id` | entier ≥ 0 |
  | `record_locator` | chaîne non vide, format fixé par chaque spec de parseur |
  | `ingest` | `native`, ou `import:<outil>@<version>` (outil et version non vides) |

- **FR-002**: Un événement MAY porter les champs facultatifs : `timestamps` (FR-005),
  `host_fqdn` (FR-012), `subject` et `target` (FR-011), `process`, `process_id`,
  `parent_process`, `parent_process_id`, `command_line`, `file_path`, `registry_path`, `hashes`
  (FR-003), `recovered` (booléen, faux par défaut), `metadata` (FR-013).
- **FR-003**: `hashes` MUST n'avoir que les clés `md5`, `sha1`, `sha256`, `imphash`, chacune de
  valeur hexadécimale minuscule de longueur respective 32, 40, 64, 32.
- **FR-004**: Si `source = evtx`, l'événement MUST porter `channel` (non vide), `provider`
  (non vide) et `event_id` (entier ≥ 0) ; sinon il MUST NOT porter ces trois champs.
- **FR-004a**: Le modèle MUST NOT porter de champ de détection (`severity`, `confidence`,
  `rule_id`, `mitre`) : ils appartiennent à la détection (FR-019).

**Horodatages** (D2, D5)

- **FR-005**: Un enregistrement d'artefact MUST produire un seul événement. Son horodatage
  principal MUST être l'instant de l'action décrite si la source le fournit, sinon l'instant
  d'écriture ; jamais l'horodatage d'en-tête d'enregistrement EVTX (C1). Les autres horodatages
  de l'enregistrement MAY figurer dans `timestamps`, chaque entrée portant `type` (FR-006),
  `time` (instant UTC non nul) et `origin` (nom du champ source, non vide, ex. `$SI`, `$FN`,
  `UtcTime`). Chaque spec de parseur documente l'application de cette règle à sa source.
- **FR-006**: Les types d'horodatage MUST être : `created`, `modified`, `accessed`, `changed`,
  `executed`, `logged` (EVTX `TimeCreated`), `written` (en-tête d'enregistrement EVTX),
  `last_write` (registre).

**Types d'événement** (D6)

- **FR-007**: `event_type` MUST appartenir à la liste fermée : `logon`, `logon_failed`, `logoff`,
  `process_creation`, `service_install`, `script_execution`, `log_cleared`,
  `malware_detected`, `av_config_change`, `other`. Un enregistrement sans type connu MUST être
  émis avec `other`, jamais écarté. Les specs de parseur ultérieures étendent la liste selon
  FR-024.

**Identifiant** (D4)

- **FR-008**: `uid` MUST valoir les 32 premiers caractères hexadécimaux minuscules du SHA-256 de
  `source_sha256`, `source_file` et `record_locator`, concaténés avec un octet nul comme
  séparateur. Il MUST NOT dépendre d'aucun champ décodé.

**Validation** (D5)

- **FR-009**: La validation MUST renvoyer la liste complète des violations d'un événement (champ et
  règle), vide si l'événement est valide. Elle couvre les règles vérifiables sur l'événement
  seul : FR-001 à FR-004a, FR-006, FR-007, la forme de `uid` (FR-008), FR-011, FR-012, et
  l'UTF-8 valide de toute chaîne. Le choix de l'horodatage principal (FR-005), la valeur exacte
  de `uid` et le rendu de `metadata` (FR-013) sont des obligations du parseur, vérifiées par ses
  tests oracle.
- **FR-010**: Un événement invalide MUST NOT être écrit ni ignoré en silence : il est remplacé par
  une anomalie `invalid` (FR-016) qui porte son `uid`, son `record_locator` et ses violations.

**Comptes et hôte** (D7)

- **FR-011**: `subject` (compte qui agit ou demande l'action) et `target` (compte sur lequel porte
  l'action) MUST avoir la forme `{sid, domain, name}`, chaque champ facultatif. `-`, la chaîne
  vide et `S-1-0-0` MUST être traités comme absents ; un objet sans aucun champ MUST être omis.
  `sid` MUST avoir la forme `S-1-<n>(-<n>)+` en majuscules. `domain` et `name` MUST conserver la
  casse d'origine. Aucune résolution SID → nom n'est faite.
- **FR-012**: `host` MUST être le nom court en majuscules (partie avant le premier `.`) de la
  valeur de l'artefact, ou à défaut du `hostname` du cas. Si cette valeur contient un `.`,
  `host_fqdn` MUST la conserver telle quelle ; sinon `host_fqdn` est absent.

**Métadonnées** (D8)

- **FR-013**: `metadata` MUST être une table de chaînes vers chaînes, suivant :
  - **rendu** : comme dans la vue XML Windows de l'événement — entier en décimal ; `HexInt32`/
    `HexInt64` en `0x` + hexadécimal minuscule sans zéro de tête ; booléen `true`/`false` ;
    flottant sous la forme la plus courte se relisant à l'identique ; GUID `{…}` majuscules ;
    SID `S-1-…` ; FILETIME/SYSTEMTIME au format horodatage de FR-017 ; binaire en hexadécimal
    minuscule ; `%%nnnn` conservé tel quel ;
  - **clés** : nom d'origine de `EventData`, casse conservée ; données sans nom `Data[1]`,
    `Data[2]`… ; `UserData` sans son élément racine, niveaux plus profonds joints par `.` ;
    champs `System` préfixés `System.` (ex. `System.EventRecordID`) ;
  - les champs promus au premier niveau MUST rester aussi dans `metadata` sous leur nom d'origine.

**Contrat de parseur** (D9)

- **FR-014**: Un parseur MUST recevoir : un contexte d'annulation, un accès en lecture à position
  arbitraire sur la preuve, sa taille, et sa provenance (chemin relatif, SHA-256 du manifeste,
  `hostname` du cas). Il MUST NOT ouvrir de fichier par lui-même.
- **FR-015**: Un parseur MUST exposer son nom (valeur de `source`, ou nom de l'outil pour un
  importer) et un test de reconnaissance sur les premiers octets de la preuve, sans se fier à
  l'extension.
- **FR-016**: Un parseur MUST émettre, de façon synchrone et dans l'ordre du fichier, des
  événements et des anomalies `{record_locator, kind, message}`, `kind` ∈ `unreadable`, `missing`,
  `truncated`, `invalid`. Après une anomalie, il MUST continuer. Il MUST s'arrêter dès que le
  consommateur renvoie une erreur, et renvoyer celle-ci.
- **FR-016a**: Un parseur MUST renvoyer une erreur fatale pour un format non reconnu, une erreur
  d'entrée/sortie ou une annulation ; les événements déjà émis restent valides.
- **FR-016b**: La spec MUST fournir un consommateur intermédiaire qui applique la validation
  (FR-009) à chaque événement, transmet les valides et convertit les autres selon FR-010.
- **FR-016c**: Un parseur MUST produire la même suite d'événements et d'anomalies pour la même
  entrée, et MUST NOT garder d'état entre deux exécutions. Un parseur et le décodeur MUST NOT
  paniquer sur une entrée malformée ; elle produit une anomalie ou une erreur.
- **FR-016d**: Les importers (spec 011) MUST implémenter le même contrat, avec
  `ingest = import:<outil>@<version>`.

**JSONL canonique** (D10)

- **FR-017**: Un horodatage MUST s'écrire en RFC 3339 UTC avec exactement 6 décimales et le
  suffixe `Z` (`2020-09-09T13:18:23.627952Z`), tronqué sous la microseconde.
- **FR-018**: L'encodage MUST produire un objet par ligne, en UTF-8 sans BOM, terminé par `\n` ;
  `schema_version` en premier champ puis les champs dans l'ordre du contrat ; clés de
  `metadata`, `hashes`, `subject`, `target` triées ; champs facultatifs vides omis ; aucun
  échappement HTML.
- **FR-018a**: L'ordre canonique des événements MUST être : `timestamp`, puis `source_file`
  (octet par octet), puis `record_id`, puis `uid`, tous croissants.
- **FR-018b**: Le décodage MUST refuser, en indiquant le numéro de ligne et la cause, toute ligne
  au JSON invalide, au `schema_version` non pris en charge, portant un champ inconnu, ou violant la validation (FR-009).

**Détection** (D3)

- **FR-019**: Une détection MUST porter : `id`, `timestamp` (plus ancien horodatage principal
  des événements concernés, fixé par le moteur, spec 012), `rule_id` (non vide), `rule_version` (non vide), `severity` (`info`,
  `low`, `medium`, `high`, `critical`), `confidence` (de 0 à 1 inclus), `mitre` (facultatif, forme
  `T####` ou `T####.###`), `events` (au moins un `uid`, triés, sans doublon).
- **FR-020**: `id` MUST valoir les 32 premiers caractères hexadécimaux minuscules du SHA-256 de
  `rule_id`, `rule_version` et des `uid` triés, séparés par un octet nul.
- **FR-021**: Les détections MUST suivre FR-017, FR-018 et FR-018b, triées par `timestamp` puis
  `id`.

**Évolution** (D11)

- **FR-022**: `schema_version` MUST valoir `1` pour cette spec. Toute modification du format ou
  d'une liste fermée MUST l'incrémenter de 1.
- **FR-023**: Le décodeur MUST lire toute version antérieure dont les évolutions sont additives, et
  MUST refuser une version inconnue en invitant à mettre à jour l'outil, ou une version antérieure
  à un changement cassant en invitant à réingérer le cas.
- **FR-024**: La formule du `uid` (FR-008), les règles de rendu (FR-013) et l'écriture des
  horodatages (FR-017) MUST NOT changer hors d'un changement cassant justifié dans la spec qui le
  porte.
- **FR-025**: Le contrat du modèle MUST tenir un historique des versions (version, spec,
  modifications, additive ou cassante). Toute spec qui modifie le modèle MUST, dans le même
  commit, mettre à jour ce contrat, le fichier de référence JSONL, et conserver le fichier de
  référence de la version précédente comme jeu de compatibilité.

**Amendement de la spec 001** (D5)

- **FR-026**: `timeline --source` MUST accepter la liste de FR-001 (`evtx`, `mft`, `usnjrnl`,
  `registry`, `prefetch`, `memory`) ; `powershell` et `defender` sont retirés, ces journaux étant
  des sources `evtx`.

### Key Entities

- **Événement** : représentation normalisée d'un enregistrement d'artefact ; socle commun, champs
  selon la source, métadonnées brutes ; identifié par `uid`.
- **Horodatage secondaire** : `{type, time, origin}` d'un même enregistrement.
- **Compte** : `{sid, domain, name}`, rôle `subject` ou `target`.
- **Provenance** : chemin relatif de la preuve, son SHA-256, `hostname` du cas.
- **Anomalie** : `{record_locator, kind, message}` signalée par un parseur ou par la validation.
- **Détection** : résultat d'une règle pointant vers un ou plusieurs événements.
- **Contrat du modèle** : document versionné décrivant le format et son historique.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Deux encodages du même jeu d'événements produisent des fichiers de même SHA-256
  dans 100 % des exécutions, sur Linux comme sur Windows.
- **SC-002**: Le cycle encodage → décodage → encodage reproduit le fichier à l'octet près pour
  100 % des événements du jeu de référence.
- **SC-003**: 100 % des événements invalides du jeu de test sont rejetés avec au moins une
  violation nommée, et 0 % des événements valides le sont.
- **SC-004**: 100 % des lignes corrompues du jeu de test sont refusées au décodage avec leur
  numéro de ligne exact.
- **SC-005**: Sur une entrée contenant des enregistrements illisibles, manquants et invalides, le
  nombre d'événements émis plus le nombre d'anomalies est égal au nombre d'enregistrements de
  l'entrée : aucun enregistrement n'est perdu en silence.
- **SC-006**: Le tri alphabétique des horodatages encodés donne le même ordre que leur tri
  chronologique pour 100 % des paires testées.

## Assumptions

- Le décodage EVTX, le mapping EventID → `event_type` et le format de `record_locator` EVTX
  relèvent de la spec 005 ; le choix de la bibliothèque EVTX (licence MPL-2.0, C12 ; perte du type
  hexadécimal, C14) doit être tranché avant elle.
- L'emplacement et le découpage des fichiers sous `normalized/`, l'étape où l'on trie et la
  persistance des anomalies relèvent des specs 004 à 006.
- La récupération d'enregistrements supprimés (C13) est hors périmètre ; `recovered` permet de les
  marquer quand une spec l'ajoutera.
- Le schéma SQLite (008), le format des règles et le moteur de détection (012) sont hors
  périmètre.
- Tout fichier importé est enregistré comme preuve avant lecture (spec 011), ce qui fournit le
  SHA-256 requis par `uid`.
- La présence de `source_file` au manifeste (D5) n'est pas vérifiable sur un événement isolé :
  elle est garantie par la construction de `Source` à partir du manifeste lors de l'ingestion
  (specs 004/005).
- Les noms de champ, les listes fermées et le format JSONL font partie du contrat lu par l'analyste
  et les outils tiers, pas de l'implémentation.
- Dépend de la spec 002 (manifeste, `hostname` du cas) et de la spec 001 (grammaire de
  `timeline`, amendée par FR-026).
