# Feature Specification: Chronologie consolidée du cas

**Feature Branch**: `feature/006-timeline`

**Created**: 2026-11-26

**Status**: Draft

**Clarification 2026-11-26**: un événement apparaît une seule fois, à son horodatage principal ;
une vue « super-chronologie » (une ligne par horodatage) est hors périmètre (FR-009).

**Input**: User description: "006-timeline : commande timeline qui fusionne les événements
normalisés du cas (normalized/**/*.jsonl produits par ingest, spec 005) en une chronologie unique
triée selon l'ordre canonique de la spec 003 (FR-018a : timestamp, source_file, record_id, uid),
écrite en JSONL canonique sous timeline/. Filtres --from, --to (ISO 8601, UTC par défaut) et
--source (liste de la spec 003 FR-026), grammaire déjà fixée par la spec 001 (FR-011). Traitement
en flux et mémoire bornée sur de gros volumes (constitution V), sortie déterministe octet par octet
(IV), écriture atomique, entrée timeline dans case.log, codes de sortie cohérents avec 001.
investigate enchaîne collect, ingest puis timeline. Dernière spec de la tranche verticale EVTX."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Obtenir la chronologie complète du cas (Priority: P1)

L'analyste a ingéré les journaux d'un poste (spec 005). Il lance `dfirflow timeline --case <cas>`.
DFIRFlow rassemble les événements de toutes les preuves ingérées et écrit une chronologie unique,
du plus ancien au plus récent, dans `timeline/` du cas. L'analyste lit les faits de toutes les
sources dans l'ordre où ils se sont produits, sans avoir à croiser les fichiers à la main.

**Why this priority**: la chronologie est le premier livrable lu par l'analyste et l'entrée de la
détection (spec 012) ; elle termine la tranche verticale EVTX (collecte, ingestion, chronologie).

**Independent Test**: ingérer deux journaux de référence dans un cas, lancer `timeline`, puis
vérifier que le fichier produit contient exactement la réunion des événements des deux preuves,
chaque ligne valide au sens du modèle 003, dans l'ordre canonique.

**Acceptance Scenarios**:

1. **Given** un cas avec deux preuves ingérées de 739 événements chacune, **When** l'analyste lance
   `timeline --case <cas>`, **Then** `timeline/timeline.jsonl` contient 1478 événements dans
   l'ordre canonique, la sortie standard affiche le nombre d'événements et le chemin du fichier, et
   le code de sortie est 0.
2. **Given** la même commande relancée sans changement du cas, **When** elle se termine, **Then**
   le fichier produit est identique octet par octet au précédent.
3. **Given** un cas dont aucune preuve n'a été ingérée, **When** l'analyste lance `timeline`,
   **Then** la commande indique qu'il faut d'abord lancer `ingest`, n'écrit rien et sort avec le
   code 1.
4. **Given** une exécution réussie, **When** l'analyste lit `case.log`, **Then** une entrée
   `timeline` indique les filtres appliqués, le nombre de fichiers lus, le nombre d'événements écrits
   et l'empreinte SHA-256 du fichier produit.

---

### User Story 2 - Restreindre la chronologie à une fenêtre et à des sources (Priority: P2)

L'analyste sait que l'incident s'est produit dans une plage de temps donnée. Il lance
`timeline --case <cas> --from 2026-11-01T08:00:00 --to 2026-11-01T18:00:00 --source evtx` et
n'obtient que les événements de cette plage et de ces sources.

**Why this priority**: sur un poste réel la chronologie complète compte des millions de lignes ;
la fenêtre temporelle est le premier geste de tri de l'analyste.

**Independent Test**: sur un cas de référence, lancer `timeline` avec une fenêtre connue et
vérifier que le fichier contient exactement les événements dont l'horodatage principal est dans la
fenêtre, et seulement ceux des sources demandées.

**Acceptance Scenarios**:

1. **Given** `--from` et `--to` donnés sans fuseau, **When** la commande s'exécute, **Then** les
   bornes sont interprétées en UTC et seuls les événements dont l'horodatage principal est compris
   entre les deux bornes, incluses, sont écrits.
2. **Given** `--from` seul, **When** la commande s'exécute, **Then** tous les événements à partir
   de cette borne sont écrits ; de même pour `--to` seul.
3. **Given** `--source mft` sur un cas qui ne contient que des journaux EVTX, **When** la commande
   s'exécute, **Then** la chronologie est vide, un avertissement sur la sortie d'erreur indique
   qu'aucun événement de la source `mft` n'a été trouvé, et le code de sortie est 0.
4. **Given** `--from` postérieur à `--to`, **When** la commande est lancée, **Then** elle échoue en
   erreur d'usage (code 2) sans rien lire ni écrire (spec 001).
5. **Given** des filtres qui n'excluent aucun événement, **When** la commande s'exécute, **Then**
   le fichier produit est identique à celui obtenu sans filtre.

---

### User Story 3 - Enchaîner l'investigation jusqu'à la chronologie (Priority: P3)

L'analyste lance `dfirflow investigate --case <cas> --target <source>`. DFIRFlow collecte, ingère,
puis construit la chronologie, et s'arrête à l'étape suivante, `detect`, non encore livrée.

**Why this priority**: c'est le parcours de bout en bout de la tranche verticale ; il n'ajoute pas
de comportement propre (spec 001, FR-015).

**Independent Test**: lancer `investigate` sur un dossier de journaux de référence et vérifier que
`timeline/timeline.jsonl` existe et que la commande s'arrête sur `detect: not implemented yet`
avec le code 3.

**Acceptance Scenarios**:

1. **Given** un dossier source contenant des journaux EVTX, **When** l'analyste lance
   `investigate`, **Then** la collecte, l'ingestion et la chronologie réussissent, puis la commande
   affiche `dfirflow: detect: not implemented yet` et sort avec le code 3.
2. **Given** une étape `timeline` en échec, **When** `investigate` s'exécute, **Then** elle
   s'arrête à cette étape et renvoie son code de sortie.

---

### Edge Cases

- Fichier d'événements illisible (JSON invalide, champ inconnu, version de modèle non prise en
  charge, événement invalide) : la commande échoue (code 1) en citant le fichier et le numéro de
  ligne (spec 003, FR-018b) ; aucune chronologie partielle n'est laissée.
- Fichiers d'anomalies (`*.anomalies.jsonl`) et fichiers temporaires d'une ingestion interrompue
  (`*.partial`) : ils ne sont jamais lus comme des événements.
- Fichier d'événements sans preuve correspondante dans le manifeste : ignoré, avec un avertissement
  qui cite son chemin.
- Preuve du manifeste sans fichier d'événements (non EVTX, en échec, non encore ingérée) : ignorée
  sans erreur ; le résumé indique le nombre de preuves lues.
- Fichier d'événements vide (journal vide) : lu sans erreur, aucun événement.
- Événements de même horodatage : départagés par `source_file`, `record_id` puis `uid`
  (spec 003, FR-018a) ; l'ordre ne dépend jamais de l'ordre de lecture des fichiers.
- Interruption (Ctrl+C) : la chronologie précédente, s'il y en a une, reste intacte ; aucun
  fichier temporaire n'est laissé ; code 130.
- Espace disque insuffisant pendant l'écriture : échec (code 1), chronologie précédente intacte.
- Chronologie précédente présente : elle est remplacée seulement quand la nouvelle est complète.
- Fenêtre qui exclut tout : chronologie vide (fichier de zéro octet), code 0.

## Requirements *(mandatory)*

### Functional Requirements

**Entrées**

- **FR-001**: `timeline` MUST lire les fichiers d'événements de `normalized/` produits par
  `ingest` pour les preuves du manifeste du cas, et eux seuls ; les fichiers d'anomalies et les
  fichiers temporaires MUST être exclus.
- **FR-002**: Un fichier d'événements sans preuve correspondante dans le manifeste MUST être
  ignoré avec un avertissement sur la sortie d'erreur citant son chemin.
- **FR-003**: Si aucun fichier d'événements n'est disponible, la commande MUST échouer (code 1)
  avec un message invitant à lancer `ingest`, sans rien écrire.
- **FR-004**: Chaque ligne lue MUST être décodée et validée selon le modèle 003 (FR-018b) ; une
  ligne refusée MUST faire échouer la commande (code 1) avec le fichier, le numéro de ligne et la
  cause.

**Filtres**

- **FR-005**: `--from` et `--to` MUST suivre la grammaire de la spec 001 (FR-011) : date-heure
  ISO 8601, UTC si aucun fuseau n'est donné ; `--from` postérieur à `--to` est une erreur d'usage
  (code 2) vérifiée avant toute lecture.
- **FR-006**: Un événement MUST être retenu si et seulement si son horodatage principal est
  supérieur ou égal à `--from` (si donné) et inférieur ou égal à `--to` (si donné), comparés à la
  microseconde.
- **FR-007**: `--source` MUST accepter une ou plusieurs valeurs de la liste de la spec 003
  (FR-026) ; un événement MUST être retenu si et seulement si sa source est dans la liste. Sans
  `--source`, toutes les sources sont retenues.
- **FR-008**: Une source demandée par `--source` dont aucun événement n'a été lu MUST produire un
  avertissement sur la sortie d'erreur, sans changer le code de sortie.
- **FR-009**: Chaque événement MUST apparaître une seule fois, placé et filtré selon son
  horodatage principal ; ses horodatages secondaires restent dans son champ `timestamps`, sans
  produire de ligne supplémentaire.

**Sortie**

- **FR-010**: La chronologie MUST être écrite dans `timeline/timeline.jsonl`, au format JSONL
  canonique de la spec 003 (FR-017, FR-018), chaque événement repris sans modification.
- **FR-011**: Les événements MUST être écrits dans l'ordre canonique de la spec 003 (FR-018a).
- **FR-012**: Pour un même cas et les mêmes arguments, la chronologie MUST être identique octet par
  octet d'une exécution à l'autre, quels que soient l'ordre des fichiers sur le disque et la
  machine.
- **FR-013**: La chronologie MUST remplacer la précédente seulement une fois écrite en entier ; en
  cas d'échec ou d'interruption, la précédente MUST rester intacte et aucun fichier temporaire
  MUST NOT subsister.
- **FR-014**: La sortie standard MUST afficher une ligne de résumé : nombre de fichiers d'événements
  lus, nombre d'événements lus, nombre d'événements écrits et chemin de la chronologie, relatif au
  cas. Les avertissements MUST aller sur la sortie d'erreur (spec 001, FR-022).

**Volume**

- **FR-015**: La mémoire utilisée MUST rester bornée, indépendante du nombre total d'événements du
  cas (constitution V) ; un cas plus grand que la mémoire disponible MUST être traité.
- **FR-016**: Les fichiers de travail nécessaires au tri MUST être créés dans le cas et supprimés à
  la fin de la commande, en succès comme en échec.

**Traçabilité**

- **FR-017**: Chaque exécution qui a ouvert le cas, réussie ou non, MUST ajouter une entrée
  `timeline` à `case.log` (spec 002) avec : les filtres appliqués, le nombre de fichiers lus, le
  nombre d'événements lus et écrits, l'empreinte SHA-256 de la chronologie produite (en cas de
  succès), les avertissements (sources absentes, fichiers hors manifeste) et la cause de l'échec
  (sinon).
- **FR-018**: `timeline` MUST NOT modifier `evidence/`, `normalized/` ni le manifeste.

**Codes de sortie** (spec 001, FR-020)

- **FR-019**: `0` succès (chronologie vide comprise) ; `1` échec d'exécution (aucun fichier
  d'événements, ligne refusée, erreur d'écriture) ; `2` erreur d'usage ; `130` interruption.

**Enchaînement**

- **FR-020**: `investigate` MUST enchaîner `collect`, `ingest` puis `timeline` sans filtre, et
  s'arrêter à `detect` tant que cette commande n'est pas livrée (spec 001, FR-015 et FR-021).

### Key Entities

- **Chronologie** : fichier unique `timeline/timeline.jsonl` du cas ; suite ordonnée d'événements
  du modèle 003, produite pour un jeu de filtres donné.
- **Filtre** : bornes temporelles facultatives (`from`, `to`) et liste facultative de sources ;
  enregistré dans `case.log` avec chaque chronologie.
- **Fichier d'événements** : sortie de `ingest` pour une preuve (`normalized/<preuve>.jsonl`) ;
  entrée de la chronologie.
- **Entrée `timeline` de `case.log`** : filtres, comptes, empreinte de la chronologie ou cause de
  l'échec.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Sur les journaux de référence, la chronologie contient 100 % des événements ingérés,
  sans doublon ni perte, et 100 % de ses lignes sont valides au sens du modèle 003.
- **SC-002**: Deux exécutions successives, et deux exécutions sur des machines différentes, sur le
  même cas avec les mêmes arguments produisent une chronologie identique octet par octet.
- **SC-003**: Sur un cas de 10 millions d'événements, la mémoire utilisée ne dépasse pas 256 Mio
  et la chronologie est produite en moins de 5 minutes sur le poste de référence.
- **SC-004**: Pour 100 % des fenêtres de test, la chronologie filtrée est égale à la chronologie
  complète restreinte à la fenêtre et aux sources demandées.
- **SC-005**: Après une interruption ou une erreur à n'importe quel moment, la chronologie
  précédente est intacte et aucun fichier temporaire ne subsiste dans le cas.
- **SC-006**: `investigate` sur un dossier de journaux de référence produit la même chronologie que
  l'enchaînement manuel `collect`, `ingest`, `timeline`.

## Assumptions

- Les fichiers d'événements de `normalized/` ne sont pas triés par horodatage (`ingest` les écrit
  dans l'ordre du journal) ; la chronologie doit donc trier, pas seulement fusionner.
- `timeline` ne revérifie pas l'empreinte des preuves : c'est le rôle de `case verify` (spec 002)
  et de `ingest`. Une preuve trouvée altérée par une ingestion ultérieure peut garder un fichier
  d'événements d'une ingestion antérieure ; ce cas relève de `ingest` et n'est pas traité ici.
- Une seule chronologie existe par cas : chaque exécution remplace la précédente ; les filtres de
  chaque version sont retrouvés dans `case.log`. Plusieurs chronologies nommées sont hors
  périmètre.
- Les anomalies (`*.anomalies.jsonl`) ne figurent pas dans la chronologie ; leur nombre est déjà
  rapporté par `ingest`.
- Aucun dédoublonnage : deux preuves distinctes au contenu identique donnent des événements
  distincts (leur `uid` diffère par `source_file`).
- Les formats de rapport (HTML, SQLite) sont l'objet de la spec `report` ; la chronologie est
  uniquement le JSONL canonique.
- Le poste de référence de SC-003 est celui de la spec 005 (SC-004).
- Dépendances : specs 001 (grammaire, codes de sortie), 002 (cas, `case.log`), 003 (modèle,
  ordre canonique), 005 (fichiers d'événements).
