# Feature Specification: Gestion des cas d'investigation

**Feature Branch**: `feature/002-case-management`

**Created**: 2026-11-03

**Status**: Draft

**Clarification 2026-11-03**: un échec d'intégrité sort avec le code dédié 4 (ajouté au contrat de
la spec 001).

**Input**: User description: "Spec 002 de la tranche verticale EVTX : gestion de cas — `case init`
crée un dossier de cas isolé (`case.json` + arborescence), un manifeste SHA-256 des preuves et un
journal des opérations ; `case verify` recalcule les empreintes et détecte toute altération. Fournit
aux specs suivantes (collecte, parsing) l'ajout d'une preuve au manifeste."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Ouvrir une investigation (Priority: P1)

Au début d'un incident, l'analyste crée un dossier de cas dédié à la machine examinée. Ce dossier
isole toutes les données de l'investigation et enregistre qui l'a ouverte, quand, sur quelle
machine et avec quelle version de l'outil.

**Why this priority**: toutes les autres commandes (`collect`, `ingest`, `detect`…) opèrent sur un
cas ; sans lui, rien ne peut être tracé (constitution, principe III).

**Independent Test**: lancer `dfirflow case init CASE-001 --host WIN-CLIENT01 --analyst dfir-team`
dans un dossier vide et vérifier l'arborescence et le contenu de `case.json`.

**Acceptance Scenarios**:

1. **Given** un dossier `./cases` inexistant, **When** l'analyste lance
   `dfirflow case init CASE-001 --host WIN-CLIENT01 --analyst dfir-team`, **Then** le dossier
   `./cases/CASE-001/` est créé avec `case.json`, un manifeste vide, un journal et les sous-dossiers
   `evidence/`, `parsed/`, `normalized/`, `timeline/`, `detections/`, `reports/`, `hashes/` ; la
   sortie standard affiche le chemin du cas ; le code de sortie est 0.
2. **Given** le cas créé, **When** l'analyste lit `case.json`, **Then** il contient l'identifiant,
   le nom d'hôte, l'analyste, la date de création en UTC, la version de l'outil et la version du
   format de cas.
3. **Given** `./cases/CASE-001/` existe déjà (même vide), **When** l'analyste relance
   `case init CASE-001`, **Then** la commande échoue avec le code 1, sans rien modifier dans le
   dossier existant.
4. **Given** l'option `--dir /mnt/usb/cases`, **When** l'analyste crée un cas, **Then** le cas est
   créé dans `/mnt/usb/cases/CASE-001/`, le dossier parent étant créé au besoin.

---

### User Story 2 - Vérifier l'intégrité des preuves (Priority: P1)

À tout moment (avant un rapport, avant une contre-expertise, après un transfert), l'analyste
vérifie qu'aucune preuve du cas n'a été modifiée, supprimée ou ajoutée hors outil depuis son
enregistrement.

**Why this priority**: c'est la garantie probatoire de DFIRFlow (exigence E8) ; un cas dont
l'intégrité ne peut pas être démontrée n'a pas de valeur.

**Independent Test**: créer un cas, y enregistrer des preuves de test, puis modifier, supprimer et
ajouter un fichier sous `evidence/` et vérifier le rapport de `case verify`.

**Acceptance Scenarios**:

1. **Given** un cas dont toutes les preuves sont intactes, **When** l'analyste lance
   `dfirflow case verify --case ./cases/CASE-001`, **Then** chaque preuve est listée `OK` avec son
   empreinte, un résumé indique le nombre de preuves vérifiées, et le code de sortie est 0.
2. **Given** une preuve dont le contenu a changé, **When** l'analyste lance `case verify`,
   **Then** elle est listée `MODIFIED` avec l'empreinte attendue et l'empreinte obtenue, et le code
   de sortie signale l'échec d'intégrité.
3. **Given** une preuve supprimée, **When** l'analyste lance `case verify`, **Then** elle est
   listée `MISSING` et le code de sortie signale l'échec d'intégrité.
4. **Given** un fichier présent sous `evidence/` mais absent du manifeste, **When** l'analyste
   lance `case verify`, **Then** il est listé `UNTRACKED` et le code de sortie signale l'échec
   d'intégrité.
5. **Given** un cas sans aucune preuve, **When** l'analyste lance `case verify`, **Then** le
   résumé indique 0 preuve et le code de sortie est 0.
6. **Given** un chemin `--case` qui n'est pas un dossier de cas valide, **When** l'analyste lance
   `case verify`, **Then** la commande échoue avec le code 1 et un message explicite.

---

### User Story 3 - Enregistrer une preuve dans le cas (Priority: P2)

Les fonctionnalités de collecte et d'ingestion (specs 004 et suivantes) doivent pouvoir enregistrer
une preuve dans le cas : la copier sous `evidence/`, calculer son empreinte, l'ajouter au manifeste
et la protéger contre l'écriture.

**Why this priority**: capacité interne requise par la spec 004 ; sans commande utilisateur dédiée
dans cette spec, elle est testée directement.

**Independent Test**: enregistrer un fichier de test dans un cas, puis vérifier sa présence sous
`evidence/`, son entrée dans le manifeste, sa protection en écriture et un `case verify` à `OK`.

**Acceptance Scenarios**:

1. **Given** un cas et un fichier source, **When** la preuve est enregistrée, **Then** une copie
   identique octet par octet existe sous `evidence/`, le manifeste contient son chemin relatif,
   son empreinte SHA-256, sa taille et la date d'enregistrement UTC, et la copie est en lecture
   seule.
2. **Given** une preuve déjà enregistrée sous le même chemin relatif, **When** on tente de
   l'enregistrer à nouveau, **Then** l'opération est refusée sans modifier la preuve existante.
3. **Given** un fichier source illisible, **When** on tente de l'enregistrer, **Then** l'opération
   échoue sans laisser de copie partielle sous `evidence/` ni d'entrée dans le manifeste.

---

### User Story 4 - Retracer les opérations du cas (Priority: P3)

Lors de la rédaction du rapport ou d'une contre-expertise, l'analyste consulte l'historique des
opérations effectuées sur le cas : quelle commande, avec quels arguments, quand, avec quel résultat.

**Why this priority**: exigé par la constitution (« les opérations importantes MUST être
journalisées »), mais utile surtout une fois plusieurs commandes fonctionnelles livrées.

**Independent Test**: lancer `case init` puis `case verify`, et vérifier deux entrées dans le
journal du cas.

**Acceptance Scenarios**:

1. **Given** un cas créé, **When** l'analyste lit le journal, **Then** il contient une entrée pour
   `case init` avec les arguments, l'heure UTC de début et de fin, la version de l'outil et le code
   de sortie 0.
2. **Given** un `case verify` en échec d'intégrité, **When** l'analyste lit le journal, **Then** une
   entrée `case verify` est ajoutée avec le code de sortie correspondant et le nombre de preuves
   par statut.
3. **Given** un journal existant, **When** une nouvelle commande s'exécute, **Then** les entrées
   précédentes sont conservées à l'identique (ajout uniquement).

---

### Edge Cases

- `--dir` désigne un fichier et non un dossier : échec code 1, rien n'est créé.
- Droits insuffisants pour créer le dossier du cas : échec code 1 avec le chemin en cause ; aucun
  cas partiellement créé ne doit rester (pas de `case.json` sans arborescence).
- Interruption (Ctrl+C) pendant `case verify` : arrêt avec code 130, entrée de journal indiquant
  l'interruption.
- Preuve volumineuse (plusieurs Go) : la vérification ne charge jamais le fichier entier en mémoire.
- `case.json` absent, illisible ou d'une version de format inconnue : `case verify` échoue (code 1)
  en nommant le fichier.
- Manifeste corrompu (ligne illisible) : `case verify` échoue (code 1) en indiquant la ligne.
- Preuve dont le chemin relatif sortirait de `evidence/` (`../`) : refusée à l'enregistrement et
  signalée à la vérification.
- Lien symbolique sous `evidence/` : signalé `UNTRACKED`, jamais suivi.
- Noms de fichiers avec espaces, accents ou caractères spéciaux Windows : conservés tels quels.

## Requirements *(mandatory)*

### Functional Requirements

**Création du cas**

- **FR-001**: `case init <ID>` MUST créer le dossier `<dir>/<ID>/` (avec `<dir>` = `--dir`, défaut
  `./cases`) contenant `case.json`, `case.log`, `hashes/manifest.jsonl` (vide) et les
  sous-dossiers `evidence/`, `parsed/`, `normalized/`, `timeline/`, `detections/`, `reports/`,
  `hashes/`.
- **FR-002**: `case.json` MUST contenir `case_id`, `hostname`, `analyst`, `created_at` (UTC,
  RFC 3339), `tool_version` et `schema_version` (version du format de dossier de cas, `1`).
- **FR-003**: `case init` MUST échouer (code 1) sans rien modifier si `<dir>/<ID>` existe déjà,
  quel que soit son contenu.
- **FR-004**: La création MUST être atomique du point de vue de l'utilisateur : en cas d'échec,
  aucun dossier de cas partiel ne subsiste.
- **FR-005**: En cas de succès, `case init` MUST écrire le chemin du dossier du cas sur la sortie
  standard (une ligne).

**Manifeste et preuves**

- **FR-006**: Le manifeste MUST lister chaque preuve avec : chemin relatif à `evidence/`, SHA-256
  (hexadécimal minuscule), taille en octets, date d'enregistrement UTC. Il MUST être en ajout
  seul : aucune entrée n'est modifiée ou supprimée.
- **FR-007**: L'enregistrement d'une preuve MUST : copier la source sous `evidence/` en calculant
  l'empreinte pendant la copie (lecture unique, en flux), vérifier que la copie a la même empreinte
  et la même taille, ajouter l'entrée au manifeste, puis passer la copie en lecture seule.
- **FR-008**: L'enregistrement MUST refuser un chemin relatif déjà présent dans le manifeste ou
  sortant de `evidence/`, et MUST NOT laisser de copie partielle ni d'entrée en cas d'échec.
- **FR-009**: Aucune opération de cette spec MUST NOT modifier ou supprimer un fichier déjà présent
  sous `evidence/`.

**Vérification**

- **FR-010**: `case verify` MUST recalculer en flux l'empreinte SHA-256 de chaque preuve du
  manifeste et lui attribuer un statut : `OK`, `MODIFIED` (empreinte ou taille différente),
  `MISSING` (fichier absent).
- **FR-011**: `case verify` MUST lister comme `UNTRACKED` tout fichier ou lien sous `evidence/`
  absent du manifeste, sans suivre les liens symboliques.
- **FR-012**: `case verify` MUST écrire sur la sortie standard une ligne par preuve (statut, chemin
  relatif, empreinte attendue et, si différente, obtenue), triée par chemin, puis une ligne de
  résumé avec le nombre de preuves par statut.
- **FR-013**: `case verify` MUST sortir avec le code 0 si toutes les preuves sont `OK` (ou s'il n'y
  en a aucune), et avec le code 4 (échec d'intégrité) si au moins une preuve est `MODIFIED`, `MISSING`
  ou `UNTRACKED`.
- **FR-014**: `case verify` MUST échouer avec le code 1 si `--case` ne désigne pas un dossier de cas
  valide (`case.json` absent, illisible ou de `schema_version` inconnue, manifeste illisible).
- **FR-015**: `case verify` MUST NOT modifier le cas, à l'exception de l'ajout de son entrée au
  journal.

**Journal**

- **FR-016**: Chaque commande opérant sur un cas existant ou créé (ici `case init` et
  `case verify`) MUST ajouter au journal `case.log` une entrée contenant : nom de la commande,
  arguments, heure UTC de début et de fin, version de l'outil, code de sortie, et un résumé propre
  à la commande (ex. décompte des statuts pour `case verify`).
- **FR-017**: Le journal MUST être en ajout seul ; une entrée MUST être écrite même quand la
  commande échoue après l'ouverture du cas, y compris en cas d'interruption.

### Key Entities

- **Cas** : dossier isolé d'une investigation, identifié par `case_id` ; métadonnées dans
  `case.json` ; contient preuves, données dérivées, manifeste et journal.
- **Preuve** : fichier copié sous `evidence/`, en lecture seule, décrit par une entrée du manifeste.
- **Entrée de manifeste** : chemin relatif, SHA-256, taille, date d'enregistrement UTC.
- **Résultat de vérification** : statut par preuve (`OK`, `MODIFIED`, `MISSING`, `UNTRACKED`) et
  résumé.
- **Entrée de journal** : commande, arguments, début, fin, version, code de sortie, résumé.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Un analyste crée un cas complet en une seule commande, en moins de 1 seconde.
- **SC-002**: 100 % des altérations testées (modification d'un octet, troncature, suppression,
  ajout d'un fichier, remplacement par un lien) sont détectées par `case verify`.
- **SC-003**: Sur un cas sans altération, `case verify` ne produit aucun faux positif sur 100 %
  des exécutions répétées.
- **SC-004**: La vérification de 10 Go de preuves s'effectue avec une consommation mémoire
  inférieure à 100 Mo, indépendamment de la taille des fichiers.
- **SC-005**: Deux exécutions de `case verify` sur le même cas intact produisent une sortie
  standard identique.
- **SC-006**: Toute exécution de `case init` ou `case verify` (réussie, en échec ou interrompue)
  laisse exactement une entrée supplémentaire dans le journal du cas, dès lors que le cas existe.

## Assumptions

- L'enregistrement d'une preuve n'a pas de commande utilisateur dans cette spec : `collect`
  (spec 004) l'utilisera. Il est livré et testé comme capacité interne.
- La protection en lecture seule est une protection contre les erreurs, pas contre un attaquant
  ayant les droits sur le disque ; la détection d'altération repose sur `case verify`.
- L'intégrité du manifeste lui-même (signature, horodatage qualifié) est hors périmètre de cette
  spec et pourra faire l'objet d'une spec ultérieure.
- Les formats `manifest.jsonl` et `case.log` sont des lignes JSON (une entrée par ligne), lisibles
  et ajoutables sans réécriture du fichier.
- La date de création et les dates du journal sont prises sur l'horloge de la station d'analyse,
  convertie en UTC.
- `case info` (affichage des métadonnées) n'est pas requis ; `case.json` est lisible directement.
- Dépend de la spec 001 (grammaire de `case init` et `case verify`, codes de sortie).
