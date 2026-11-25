# Feature Specification: Collecte des preuves

**Feature Branch**: `feature/004-evidence-collection`

**Created**: 2026-11-25

**Status**: Draft

**Clarification 2026-11-25**: collecte limitée aux EVTX (FR-002) ; collecte live NTFS brute
(DF-13) reportée à une spec ultérieure, fichier verrouillé rapporté `FAILED` (FR-012).

**Input**: User description: "004-evidence-collection : collecte des preuves dans un cas DFIRFlow
(commande collect). Collecteur depuis un répertoire ou une image montée (DF-10), préservation des
métadonnées des fichiers collectés (DF-12), journal d'audit de la collecte / chaîne de conservation
(DF-14), en s'appuyant sur internal/case (AddEvidence, manifeste SHA-256, journal). Collecte live
NTFS brute des fichiers verrouillés (DF-13) à trancher en clarification. Tranche verticale EVTX : la
collecte doit au minimum couvrir les fichiers .evtx."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Collecter les journaux EVTX d'un volume (Priority: P1)

L'analyste a ouvert un cas (`case init`) et dispose d'un volume Windows accessible comme un
répertoire : copie d'un disque, image montée en lecture seule ou arborescence extraite. Il lance
`dfirflow collect --case <cas> --target <racine du volume>`. DFIRFlow repère les journaux
d'événements Windows sous la racine, les copie dans le cas en conservant leur chemin relatif, les
hache et les inscrit au manifeste. L'analyste peut ensuite passer au parsing (spec 005).

**Why this priority**: c'est la porte d'entrée de la tranche verticale EVTX ; sans preuves dans le
cas, `ingest`, `timeline` et `detect` n'ont rien à traiter.

**Independent Test**: créer un cas, préparer une arborescence de test contenant
`Windows/System32/winevt/Logs/*.evtx` et d'autres fichiers, lancer `collect`, puis vérifier que
seuls les `.evtx` sont sous `evidence/` avec le même chemin relatif, et que `case verify` rend `OK`
pour chacun.

**Acceptance Scenarios**:

1. **Given** un cas valide et une racine contenant `Windows/System32/winevt/Logs/Security.evtx` et
   `System.evtx`, **When** l'analyste lance `collect`, **Then** les deux fichiers sont copiés sous
   `evidence/Windows/System32/winevt/Logs/`, identiques octet par octet à la source, inscrits au
   manifeste, et la commande sort avec le code 0.
2. **Given** une racine dont la casse diffère (`windows/system32/WINEVT/logs/security.evtx`),
   **When** l'analyste lance `collect`, **Then** le fichier est trouvé et collecté sous son chemin
   tel qu'il existe dans la source.
3. **Given** une racine sans aucun artefact reconnu, **When** l'analyste lance `collect`, **Then**
   aucune preuve n'est ajoutée, un message indique qu'aucun artefact n'a été trouvé sous la cible et
   la commande sort avec le code 1.
4. **Given** une collecte terminée, **When** l'analyste lance `case verify`, **Then** chaque preuve
   collectée est `OK`.

---

### User Story 2 - Conserver les métadonnées d'origine (Priority: P1)

Pour l'analyse et la valeur probatoire, l'analyste doit pouvoir retrouver, pour chaque preuve, d'où
elle vient et quelles étaient ses métadonnées sur le volume source au moment de la collecte : chemin
d'origine, taille, horodatages du système de fichiers.

**Why this priority**: la copie modifie les horodatages du fichier copié ; sans relevé à la
collecte, ces informations sont perdues définitivement (DF-12).

**Independent Test**: collecter un fichier dont on a fixé les horodatages de modification et
d'accès, puis vérifier que l'entrée de la preuve restitue ces valeurs exactes, en UTC.

**Acceptance Scenarios**:

1. **Given** un fichier source dont la date de modification est `2026-10-01T08:00:00Z`, **When** il
   est collecté, **Then** l'entrée de la preuve indique son chemin dans la cible, sa taille et sa
   date de modification `2026-10-01T08:00:00Z`.
2. **Given** un horodatage que le système de fichiers source ne fournit pas (par exemple la date de
   création), **When** le fichier est collecté, **Then** ce champ est absent de l'entrée plutôt que
   renseigné par une valeur inventée.

---

### User Story 3 - Tracer la collecte dans le cas (Priority: P2)

Un relecteur (contre-expert, responsable d'équipe) ouvre le cas après coup et doit savoir qui a
collecté quoi, depuis quelle cible, quand, avec quelle version de l'outil, et ce qui a échoué.

**Why this priority**: chaîne de conservation (DF-14, principe III de la constitution) ; utile dès
que les preuves sont collectées mais ne bloque pas le parsing.

**Independent Test**: lancer une collecte avec un fichier illisible dans la cible, puis lire
`case.log` et vérifier que l'entrée de la collecte indique la cible, les compteurs et le fichier en
échec.

**Acceptance Scenarios**:

1. **Given** une collecte terminée, **When** l'analyste lit `case.log`, **Then** il trouve une
   entrée `collect` avec la cible, les dates de début et de fin, la version de l'outil, le code de
   sortie et le nombre de fichiers collectés, déjà présents et en échec.
2. **Given** un fichier source illisible, **When** l'analyste lance `collect`, **Then** les autres
   fichiers sont collectés, le fichier en échec est listé avec sa raison sur stdout et dans le
   journal, et la commande sort avec le code 1.

---

### User Story 4 - Relancer une collecte sans doublon (Priority: P2)

L'analyste relance `collect` sur la même cible (interruption, ajout d'une seconde cible, doute).
Les preuves déjà présentes ne doivent être ni dupliquées ni écrasées.

**Why this priority**: évite de corrompre un cas existant ; la manipulation est fréquente sur le
terrain.

**Independent Test**: lancer deux fois la même collecte et vérifier que la seconde n'ajoute rien au
manifeste et rapporte chaque fichier comme déjà présent.

**Acceptance Scenarios**:

1. **Given** une preuve déjà collectée et une source inchangée, **When** l'analyste relance
   `collect`, **Then** la preuve est rapportée `ALREADY`, rien n'est recopié et la commande sort
   avec le code 0.
2. **Given** une preuve déjà collectée dont la source a changé depuis, **When** l'analyste relance
   `collect`, **Then** la preuve existante n'est pas modifiée, le fichier est rapporté `CONFLICT`
   avec les deux empreintes, et la commande sort avec le code 1.

---

### Edge Cases

- Cible inexistante, non lisible ou qui n'est pas un répertoire : erreur explicite, code 1, aucune
  preuve ajoutée.
- Dossier du cas situé sous la cible : refusé avant toute copie (la collecte écrirait dans la
  source et pourrait se collecter elle-même).
- Lien symbolique ou point de jonction dans la cible : jamais suivi, signalé comme ignoré.
- Fichier verrouillé par le système (collecte sur un système en fonctionnement) : rapporté
  `FAILED`, collecte live hors périmètre (FR-012).
- Fichier de taille nulle : collecté comme les autres (un journal vide est une information).
- Interruption (Ctrl+C) : les preuves déjà enregistrées restent valides, aucune copie partielle ne
  subsiste, l'entrée du journal est écrite avec le code 130.
- Fichier modifié pendant sa copie : la vérification de la copie échoue, le fichier est en échec et
  aucune entrée n'est créée.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: `collect --case <chemin> --target <chemin>` MUST collecter dans le cas les artefacts
  reconnus présents sous la racine `--target`, qui est la racine d'un volume Windows accessible comme
  un répertoire (copie, image montée, arborescence extraite).
- **FR-002**: L'ensemble des artefacts reconnus MUST être défini par une liste de motifs, intégrée au binaire et donc versionnée avec lui (`tool_version`),
  de chemins relatifs à la racine du volume ; cette spec MUST couvrir au minimum les journaux
  d'événements (`Windows/System32/winevt/Logs/*.evtx`) et uniquement eux ; les autres artefacts
  (Registre, Prefetch…) s'ajouteront à la liste avec leurs parseurs.
- **FR-003**: La recherche des artefacts MUST ignorer la casse des chemins, et la preuve MUST être
  enregistrée sous son chemin relatif tel qu'il existe dans la source.
- **FR-004**: Chaque fichier MUST être enregistré par le mécanisme d'ajout de preuve de la spec 002 :
  copie hachée SHA-256, vérification de la copie, inscription au manifeste, passage en lecture seule,
  sans copie partielle ni entrée en cas d'échec.
- **FR-005**: La collecte MUST NOT modifier la cible : aucune écriture, aucun renommage, aucun
  changement de métadonnée initié par DFIRFlow.
- **FR-006**: Chaque preuve collectée MUST conserver ses métadonnées d'origine : chemin dans la
  cible, taille, et les horodatages fournis par le système de fichiers source (modification, accès,
  changement, création) en UTC ; un horodatage indisponible MUST être omis.
- **FR-007**: Ces métadonnées MUST être enregistrées avec l'entrée de manifeste de la preuve, de
  façon rétrocompatible : un manifeste de la spec 002 reste lisible et `case verify` inchangé.
- **FR-008**: Une preuve déjà inscrite au manifeste avec la même empreinte MUST être rapportée
  `ALREADY` sans être recopiée ; avec une empreinte différente, elle MUST être rapportée `CONFLICT`
  et laissée intacte.
- **FR-009**: Une erreur sur un fichier MUST être rapportée et MUST NOT interrompre la collecte des
  fichiers suivants.
- **FR-010**: stdout MUST lister une ligne par fichier, triée par chemin relatif, avec son statut
  (`COLLECTED`, `ALREADY`, `CONFLICT`, `FAILED`, `SKIPPED`) puis une ligne de résumé ; le format
  MUST être déterministe.
- **FR-011**: Chaque exécution de `collect` MUST ajouter une entrée au journal du cas avec la cible,
  les dates, la version de l'outil, le code de sortie, les compteurs par statut et la liste des
  fichiers en échec, en conflit ou ignorés avec leur raison.
- **FR-012**: La collecte live par lecture NTFS brute (DF-13) est hors périmètre : un fichier
  verrouillé ou dont la lecture est refusée MUST être rapporté `FAILED` avec une raison explicite
  indiquant que la collecte live n'est pas prise en charge.
- **FR-013**: Codes de sortie : 0 si au moins un fichier est `COLLECTED` ou `ALREADY` et qu'aucun n'est `FAILED` ni `CONFLICT` (les `SKIPPED` sont tolérés) ; 1 si au moins
  un fichier est `FAILED` ou `CONFLICT`, si aucun fichier régulier reconnu n'est trouvé (une cible ne contenant que des `SKIPPED` compte comme vide), ou si la cible ou le cas
  sont invalides ; 130 en cas d'interruption.
- **FR-014**: Le dossier du cas MUST NOT se trouver sous la cible ; la commande MUST le refuser
  avant toute copie.
- **FR-015**: Les liens symboliques et points de jonction de la cible MUST NOT être suivis ; ils
  sont rapportés `SKIPPED`.

### Key Entities

- **Cible** : racine d'un volume Windows accessible comme un répertoire, en lecture seule du point
  de vue de DFIRFlow.
- **Motif d'artefact** : chemin relatif à la racine, éventuellement avec joker, qui désigne un type
  d'artefact à collecter (ex. journaux EVTX).
- **Preuve** (spec 002) : copie sous `evidence/` décrite par une entrée du manifeste, enrichie ici
  des métadonnées d'origine.
- **Entrée de journal de collecte** : ligne de `case.log` résumant une exécution de `collect`.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100 % des fichiers `.evtx` présents sous `Windows/System32/winevt/Logs/` d'une cible
  de test sont collectés, et `case verify` rend `OK` pour chacun immédiatement après.
- **SC-002**: Pour chaque preuve, l'empreinte enregistrée est égale à celle du fichier source,
  calculée indépendamment.
- **SC-003**: Une seconde collecte sur une cible inchangée n'ajoute aucune entrée au manifeste et
  sort avec le code 0.
- **SC-004**: Après une collecte, la cible est identique à son état initial (contenu, liste des
  fichiers, dates de modification).
- **SC-005**: La collecte d'un jeu de 10 Go s'effectue avec une consommation mémoire constante,
  indépendante de la taille des fichiers.
- **SC-006**: Deux collectes de la même cible dans deux cas distincts produisent la même sortie
  stdout et les mêmes manifestes, aux dates de collecte et heures d'accès d'origine près.

## Assumptions

- La commande `collect` et ses options obligatoires existent déjà (spec 001) ; cette spec en fournit
  l'implémentation. `investigate` reste hors périmètre.
- Le mécanisme d'ajout de preuve, le manifeste et le journal de la spec 002 sont réutilisés tels
  quels ; seul le contenu de l'entrée de manifeste est enrichi (FR-007).
- L'analyste monte les images en lecture seule ; DFIRFlow ne monte pas d'image et ne lit pas de
  format d'image disque (E01, VMDK…) dans cette spec.
- L'horodatage d'accès de la source peut être modifié par le système d'exploitation lors de la
  lecture si le volume n'est pas monté en lecture seule ; DFIRFlow ne peut pas l'empêcher et
  enregistre la valeur lue avant la copie.
- Une seule cible par exécution ; plusieurs cibles s'obtiennent en relançant `collect`.
- Le nom d'hôte du cas (`case.json`) n'est pas contrôlé par rapport à la cible.
