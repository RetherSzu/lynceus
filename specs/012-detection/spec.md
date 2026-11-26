# Feature Specification: Détection par règles mono-événement

**Feature Branch**: `feature/012-detection`

**Created**: 2026-11-26

**Status**: Draft

**Input**: User description: "012-detection : commande detect qui applique des règles de
détection déterministes (sous-ensemble Sigma, mono-événement) aux événements normalisés de toutes
les preuves du manifeste (normalized/, pas la timeline), et écrit les détections au format
Detection de la spec 003 (FR-019 à FR-021) en JSONL canonique sous detections/. Jeu de règles
maison embarqué par défaut, remplacé entièrement par --rules (fichier ou dossier). Seuils,
agrégations et déduplication (DF-36) laissés à correlate. Constitution VIII (règles versionnées,
id, sévérité, MITRE, champs structurés, pas de preuve de compromission), IV (déterminisme, version
des règles enregistrée), V (flux), VI (cas positif et négatif par règle). Entrée detect dans
case.log, écriture atomique, codes de sortie de la 001. investigate enchaîne jusqu'à detect puis
s'arrête à correlate."

## Clarifications

### Session 2026-11-26

- Q: Sur quels événements les règles s'appliquent-elles ? → A: tous les événements normalisés des
  preuves du manifeste (`normalized/`), indépendamment de la chronologie et de ses filtres (FR-001).
- Q: Quelles règles s'appliquent quand `--rules` est absent ? → A: un jeu embarqué dans le binaire,
  que `--rules` remplace entièrement (FR-003, FR-017).
- Q: Quelle portée pour les règles ? → A: mono-événement seulement ; seuils, agrégations, fenêtres
  de temps et déduplication (DF-36) relèvent de `correlate` (FR-006, Assumptions).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Repérer les événements suspects avec les règles fournies (Priority: P1)

L'analyste a ingéré les journaux d'un poste (spec 005). Il lance `dfirflow detect --case <cas>`
sans autre option. DFIRFlow applique son jeu de règles embarqué à tous les événements du cas et
écrit, dans `detections/` du cas, une détection par événement qui satisfait une règle. Chaque
détection indique la règle, sa version, la sévérité, la confiance, la technique MITRE ATT&CK et
l'événement concerné. L'analyste sait par où commencer son examen, sans relire des milliers
d'événements.

**Why this priority**: c'est la première valeur analytique de l'outil, au-delà de la mise en
forme des journaux ; elle fonctionne sans que l'analyste ait à écrire ni fournir de règles.

**Independent Test**: ingérer le journal Security de référence, lancer `detect`, puis vérifier
que chaque détection pointe vers un événement existant du cas qui satisfait la règle citée, et
qu'aucun autre événement ne satisfait une règle du jeu.

**Acceptance Scenarios**:

1. **Given** un cas où le journal Security de référence est ingéré, **When** l'analyste lance
   `detect --case <cas>`, **Then** `detections/detections.jsonl` contient une détection pour
   l'effacement du journal (1102) et une par modification de la stratégie d'audit (4719), chacune
   valide au sens du modèle 003, la sortie standard affiche le nombre de règles appliquées,
   d'événements lus et de détections, et le code de sortie est 0.
2. **Given** la même commande relancée sans changement du cas, **When** elle se termine, **Then**
   le fichier produit est identique octet par octet au précédent.
3. **Given** un cas dont aucune preuve n'a été ingérée, **When** l'analyste lance `detect`,
   **Then** la commande indique qu'il faut d'abord lancer `ingest`, n'écrit rien et sort avec le
   code 1.
4. **Given** un cas dont aucun événement ne satisfait une règle, **When** l'analyste lance
   `detect`, **Then** le fichier de détections est vide et le code de sortie est 0.
5. **Given** une exécution réussie, **When** l'analyste lit `case.log`, **Then** une entrée
   `detect` indique l'origine des règles (embarquées), la version du jeu de règles, le nombre de
   règles appliquées, d'événements lus et de détections, et l'empreinte SHA-256 du fichier produit.

---

### User Story 2 - Appliquer ses propres règles (Priority: P2)

L'analyste dispose de règles au format Sigma, écrites par son équipe ou reprises d'un corpus
public. Il lance `detect --case <cas> --rules ./regles` (un fichier ou un dossier). DFIRFlow
applique ces règles à la place du jeu embarqué. Les règles qu'il ne sait pas appliquer sont
signalées une par une avec la raison, sans bloquer les autres.

**Why this priority**: chaque incident appelle des règles propres (indicateurs connus, outils de
l'attaquant) ; la réutilisation du format Sigma évite de tout réécrire.

**Independent Test**: lancer `detect` avec un dossier contenant des règles valides, une règle
utilisant une fonction non prise en charge et une règle pour un autre système que Windows, puis
vérifier que seules les règles valides produisent des détections et que les deux autres sont
signalées avec leur raison.

**Acceptance Scenarios**:

1. **Given** `--rules` désignant un dossier de règles valides, **When** la commande s'exécute,
   **Then** seules ces règles sont appliquées, le jeu embarqué ne l'est pas, et `case.log` indique
   le chemin des règles et la version du jeu.
2. **Given** une règle qui utilise une fonction hors du sous-ensemble pris en charge (agrégation,
   recherche par mot-clé, modificateur inconnu), **When** la commande s'exécute, **Then** cette
   règle est refusée avec un avertissement qui cite son fichier et la raison, les autres règles
   sont appliquées et le code de sortie est 0.
3. **Given** une règle qui vise un autre système que Windows, **When** la commande s'exécute,
   **Then** elle est écartée comme non applicable, comptée à part, sans avertissement d'erreur.
4. **Given** `--rules` désignant un chemin inexistant, ou un ensemble où aucune règle n'est
   applicable, **When** la commande s'exécute, **Then** elle échoue (code 1) sans rien écrire.
5. **Given** deux règles appliquées portant le même identifiant, **When** la commande s'exécute, **Then**
   elle échoue (code 1) en citant l'identifiant et les deux fichiers, sans rien écrire.
6. **Given** une règle modifiée entre deux exécutions, **When** l'analyste compare les deux
   fichiers de détections, **Then** la version de la règle diffère dans les détections qu'elle
   produit.

---

### User Story 3 - Enchaîner l'investigation jusqu'à la détection (Priority: P3)

L'analyste lance `dfirflow investigate --case <cas> --target <source>`. DFIRFlow collecte,
ingère, construit la chronologie, applique le jeu de règles embarqué, puis s'arrête à l'étape
suivante, `correlate`, non encore livrée.

**Why this priority**: c'est le parcours de bout en bout ; il n'ajoute pas de comportement propre
(spec 001, FR-015).

**Independent Test**: lancer `investigate` sur un dossier de journaux de référence et vérifier que
`detections/detections.jsonl` existe et que la commande s'arrête sur
`correlate: not implemented yet` avec le code 3.

**Acceptance Scenarios**:

1. **Given** un dossier source contenant des journaux EVTX, **When** l'analyste lance
   `investigate`, **Then** les étapes jusqu'à `detect` réussissent, puis la commande affiche
   `dfirflow: correlate: not implemented yet` et sort avec le code 3.
2. **Given** une étape `detect` en échec, **When** `investigate` s'exécute, **Then** elle
   s'arrête à cette étape et renvoie son code de sortie.

---

### Edge Cases

- Fichier d'événements illisible (JSON invalide, champ inconnu, version de modèle non prise en
  charge, événement invalide) : échec (code 1) citant le fichier et le numéro de ligne ; aucun
  fichier de détections partiel n'est laissé.
- Fichiers d'anomalies, fichiers temporaires et fichiers sans preuve au manifeste : jamais lus,
  comme pour `timeline` (spec 006, FR-001 et FR-002).
- Un même événement satisfait plusieurs règles : une détection par règle.
- Deux preuves au contenu identique : chaque copie produit sa propre détection (`uid` distincts) ;
  le rapprochement relève de `correlate` (DF-36).
- Champ cité par une règle absent de l'événement : la condition sur ce champ est fausse, sauf si
  la règle teste explicitement l'absence du champ.
- Règle sans condition satisfaisable sur aucun événement du cas : aucune détection, sans erreur.
- Règle au statut `deprecated` ou `unsupported` : écartée comme non applicable.
- Fichier de règles illisible (syntaxe invalide, plusieurs règles dans un fichier, champ
  obligatoire manquant) : règle refusée avec la raison, comme une fonction non prise en charge.
- Fichiers du dossier `--rules` qui ne sont pas des règles (extension autre que `.yml` ou
  `.yaml`) et fichiers ou dossiers cachés (`.github/` d'un clone SigmaHQ, par exemple) : ignorés.
- Interruption (Ctrl+C) : le fichier de détections précédent, s'il existe, reste intact ; aucun
  fichier temporaire n'est laissé ; code 130.
- Espace disque insuffisant pendant l'écriture : échec (code 1), fichier précédent intact.

## Requirements *(mandatory)*

### Functional Requirements

**Entrées**

- **FR-001**: `detect` MUST lire les événements des fichiers de `normalized/` des preuves du
  manifeste, et eux seuls, avec les mêmes règles de sélection que `timeline` (spec 006, FR-001 à
  FR-004) ; elle MUST NOT dépendre de la présence ni des filtres d'une chronologie.
- **FR-002**: Si aucun fichier d'événements n'est disponible, la commande MUST échouer (code 1)
  avec un message invitant à lancer `ingest`, sans rien écrire.

**Règles**

- **FR-003**: Sans `--rules`, la commande MUST appliquer le jeu de règles embarqué dans le binaire.
  Avec `--rules`, elle MUST appliquer uniquement les règles du fichier désigné ou des fichiers
  `.yml` et `.yaml` du dossier désigné et de ses sous-dossiers, hors fichiers et dossiers cachés
  (nom commençant par `.`).
- **FR-004**: Les règles MUST être au format Sigma, une règle par fichier, restreint à la
  détection sur un seul événement : sélections nommées de conditions sur des champs, valeurs
  multiples (l'une ou l'autre), jokers `*` et `?`, modificateurs `contains`, `startswith`,
  `endswith`, `all` et `re` (avec son option `i`, insensible à la casse), test d'absence d'un champ, comparaison insensible à la casse par
  défaut, et condition combinant les sélections par `and`, `or`, `not`, parenthèses, `1 of` et
  `all of` (motifs de noms et `them` compris).
- **FR-005**: Une règle MUST porter un identifiant, un titre, un niveau et une description de la
  source visée (produit et service) ; elle MAY porter des étiquettes MITRE ATT&CK et une confiance.
- **FR-006**: Une règle MUST être refusée, avec un avertissement citant son fichier et la raison,
  si elle est illisible, incomplète, ou utilise une fonction hors de FR-004 : agrégation ou seuil,
  fenêtre de temps, recherche par mot-clé hors champ, modificateur inconnu, source décrite par
  catégorie plutôt que par service, service inconnu, condition imbriquée au-delà de 64 niveaux.
  Les autres règles MUST être appliquées.
- **FR-007**: Une règle visant un autre produit que Windows, ou au statut `deprecated` ou
  `unsupported`, MUST être écartée comme non applicable, comptée à part, sans avertissement.
- **FR-008**: La commande MUST échouer (code 1) sans rien écrire si le chemin de `--rules`
  n'existe pas, si aucune règle n'est applicable, ou si deux règles appliquées portent le même
  identifiant (message citant l'identifiant et les fichiers) ; une règle écartée ou refusée n'entre
  pas dans ce contrôle.
- **FR-009**: Une règle MUST s'appuyer sur les champs structurés de l'événement : identifiant
  d'événement, canal, fournisseur et données de l'événement telles que conservées par l'ingestion
  (constitution VIII) ; elle MUST NOT s'appuyer sur un message rendu.
- **FR-010**: Le service visé par une règle MUST désigner un canal EVTX ; la règle MUST
  s'appliquer seulement aux événements EVTX de ce canal.

**Détections**

- **FR-011**: Pour chaque couple (règle applicable, événement) où l'événement satisfait la
  condition de la règle, la commande MUST produire exactement une détection au format de la
  spec 003 (FR-019, FR-020), avec :
  - `rule_id` : l'identifiant de la règle ;
  - `rule_version` : une empreinte du contenu du fichier de la règle, qui change dès que la règle
    change ;
  - `severity` : le niveau de la règle (`informational` devient `info`, les autres niveaux sont
    repris tels quels) ;
  - `confidence` : la confiance déclarée par la règle, ou à défaut une valeur fixée par son statut
    (table de `data-model.md`) ;
  - `mitre` : la première technique ATT&CK citée par les étiquettes de la règle, si elle en a une ;
  - `events` : l'`uid` de l'événement ;
  - `timestamp` : l'horodatage principal de l'événement.
- **FR-012**: Les détections MUST être écrites dans `detections/detections.jsonl`, au format JSONL
  canonique, triées par `timestamp` puis `id` (spec 003, FR-021) ; chaque ligne MUST être valide
  au sens du modèle 003.
- **FR-013**: Pour un même cas et les mêmes règles, le fichier de détections MUST être identique
  octet par octet d'une exécution à l'autre, quels que soient l'ordre des fichiers sur le disque,
  l'ordre des règles et la machine.
- **FR-014**: Le fichier de détections MUST remplacer le précédent seulement une fois écrit en
  entier ; en cas d'échec ou d'interruption, le précédent MUST rester intact et aucun fichier
  temporaire MUST NOT subsister.
- **FR-015**: La sortie standard MUST afficher une ligne de résumé : nombre de règles appliquées,
  écartées et refusées, nombre d'événements lus, nombre de détections et chemin du fichier, relatif au cas. Les
  avertissements MUST aller sur la sortie d'erreur (spec 001, FR-022).
- **FR-016**: Ni la sortie ni l'aide MUST NOT présenter une détection comme une preuve de
  compromission ; l'aide de `detect` MUST indiquer qu'une détection est une piste à examiner
  (constitution VIII).

**Jeu embarqué**

- **FR-017**: Le jeu embarqué MUST couvrir au moins : effacement du journal Security, effacement
  du journal System, modification de la stratégie d'audit, création d'un compte utilisateur, ajout
  d'un membre à un groupe privilégié, installation d'un service, création d'une tâche planifiée.
- **FR-018**: Chaque règle du jeu embarqué MUST porter un identifiant, une sévérité, une technique
  MITRE ATT&CK, et disposer d'au moins un cas positif et un cas négatif testés (constitution VI) ;
  le jeu embarqué MUST se charger sans aucun refus.

**Volume**

- **FR-019**: La mémoire utilisée MUST rester bornée, indépendante du nombre d'événements du cas et
  du nombre de détections (constitution V).

**Traçabilité**

- **FR-020**: Chaque exécution qui a ouvert le cas, réussie ou non, MUST ajouter une entrée
  `detect` à `case.log` (spec 002) avec : l'origine des règles (embarquées ou chemin), la version
  du jeu de règles (empreinte de la liste triée des couples identifiant et version), le nombre de
  règles appliquées, écartées et refusées avec, pour ces dernières, le fichier et la raison, le
  nombre d'événements lus, le nombre de détections, l'empreinte SHA-256 du fichier produit (en cas
  de succès) et la cause de l'échec (sinon).
- **FR-021**: `detect` MUST NOT modifier `evidence/`, `normalized/`, `timeline/` ni le manifeste.

**Codes de sortie** (spec 001, FR-020)

- **FR-022**: `0` succès (aucune détection ou règles refusées comprises) ; `1` échec d'exécution
  (aucun fichier d'événements, ligne refusée, règles inutilisables, identifiants en double, erreur
  d'écriture) ; `2` erreur d'usage ; `130` interruption.

**Enchaînement**

- **FR-023**: `investigate` MUST enchaîner `collect`, `ingest`, `timeline` puis `detect` avec le
  jeu embarqué, et s'arrêter à `correlate` tant que cette commande n'est pas livrée (spec 001,
  FR-015 et FR-021).

### Key Entities

- **Règle** : fichier Sigma mono-événement ; identifiant, titre, niveau, statut, source visée
  (produit, service), étiquettes ATT&CK, confiance facultative, sélections et condition ; sa
  version est l'empreinte de son contenu.
- **Jeu de règles** : ensemble des règles appliquées lors d'une exécution (embarqué ou `--rules`) ;
  sa version est l'empreinte de la liste triée des couples identifiant et version.
- **Détection** : structure de la spec 003 (FR-019) ; un résultat par couple règle et événement.
- **Fichier de détections** : `detections/detections.jsonl` du cas, remplacé à chaque exécution.
- **Entrée `detect` de `case.log`** : origine et version des règles, comptes, refus, empreinte du
  fichier ou cause de l'échec.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Sur le journal Security de référence, le jeu embarqué produit exactement les
  détections attendues (une pour l'effacement du journal, une par modification de la stratégie
  d'audit), et 100 % des lignes produites sont valides au sens du modèle 003.
- **SC-002**: 100 % des règles du jeu embarqué détectent leur cas positif et aucune ne détecte son
  cas négatif.
- **SC-003**: Deux exécutions successives, et deux exécutions sur des machines différentes, sur le
  même cas avec les mêmes règles produisent un fichier de détections identique octet par octet.
- **SC-004**: Sur un cas de 10 millions d'événements avec le jeu embarqué, la mémoire utilisée ne
  dépasse pas 256 Mio et les détections sont produites en moins de 5 minutes sur le poste de
  référence.
- **SC-005**: Pour 100 % des règles de test refusées, l'analyste trouve dans la sortie d'erreur et
  `case.log` le fichier de la règle et la raison, sans lire le code ; les règles écartées sont
  comptées.
- **SC-006**: Après une interruption ou une erreur à n'importe quel moment, le fichier de
  détections précédent est intact et aucun fichier temporaire ne subsiste dans le cas.
- **SC-007**: `investigate` sur un dossier de journaux de référence produit les mêmes détections
  que l'enchaînement manuel `collect`, `ingest`, `timeline`, `detect`.

## Assumptions

- Les seuils, agrégations, fenêtres de temps et le rapprochement d'un même enregistrement présent
  dans plusieurs preuves (DF-36) relèvent de `correlate` ; `detect` ne compte rien.
- Le sous-ensemble Sigma exclut les sources décrites par catégorie (`process_creation`, par
  exemple), qui supposent une table de correspondance vers plusieurs canaux ; une grande partie du
  corpus public SigmaHQ sera donc refusée avec la raison. L'ajout des catégories est une évolution
  ultérieure.
- La table des services pris en charge (au moins `security`, `system`, `application`,
  `powershell`, `sysmon`, `taskscheduler`) et la table de confiance par statut sont fixées dans
  `data-model.md`, au plan.
- Une seule exécution de `detect` à la fois sur un cas, comme pour `timeline` ; un seul fichier de
  détections par cas, remplacé à chaque exécution ; les versions précédentes se retrouvent dans
  `case.log`.
- `detect` ne revérifie pas l'empreinte des preuves (rôle de `case verify` et de `ingest`).
- Le jeu embarqué est écrit pour DFIRFlow sous licence Apache-2.0 ; l'enrichissement à 10 à 15
  règles qualifiées (`docs/MoSCoW.md`) est une étape ultérieure.
- `investigate` n'a pas d'option `--rules` (spec 001, FR-015) et utilise toujours le jeu embarqué.
- Le poste de référence de SC-004 est celui des specs 005 et 006.
- Dépendances : specs 001 (grammaire, codes de sortie), 002 (cas, `case.log`), 003 (structure
  `Detection`, JSONL canonique), 005 (fichiers d'événements, données d'événement conservées), 006
  (sélection des fichiers d'événements, écriture atomique).
