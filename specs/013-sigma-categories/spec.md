# Feature Specification: Catégories de sources et modificateurs Sigma

**Feature Branch**: `feature/013-sigma-categories`

**Created**: 2026-11-27

**Status**: Draft

**Input**: User description: "013-sigma-categories : étendre detect (spec 012) aux règles Sigma qui
déclarent une catégorie de source (logsource.category) au lieu d'un service. Catégories couvertes :
noyau Sysmon + PowerShell (process_creation, network_connection, file_event, image_load,
driver_load, dns_query, registry_add/set/delete/event, process_access, create_remote_thread,
pipe_created, wmi_event, ps_script, ps_module), via une table de correspondance déclarative
embarquée catégorie → (canal, EventID, renommage de champs). process_creation s'applique aussi à
Security 4688 avec renommage (NewProcessName → Image, ParentProcessName → ParentImage…) et garde :
une règle qui utilise un champ absent de 4688 n'est pas appliquée à 4688. Ajout des modificateurs
windash, cidr, base64, base64offset, exists, fieldref, cased, utf16le/utf16be/wide (et
contains|all). Ajout de 3 à 5 règles embarquées par catégorie avec cas positif et négatif. Mêmes
garanties que la 012 : déterminisme, versions, refus motivés, constitution VI et VIII."

## Clarifications

### Session 2026-11-27

- Q: Comment l'analyste est-il prévenu qu'une règle n'est pas appliquée à Security 4688 faute de
  champ ? → A: un avertissement récapitulatif par source partielle (une seule aujourd'hui : Security 4688)
  sur la sortie d'erreur (nombre de règles
  concernées, renvoi à `case.log`), le détail par règle dans `case.log`.
- Q: Un même lancement de processus enregistré par Sysmon et par 4688 et détecté par une même
  règle donne-t-il une ou deux détections ? → A: deux, une par événement ; le rapprochement des
  deux enregistrements relève de `correlate` (DF-36). **Révisée le 2026-11-27** : une seule
  détection portant les deux événements ; le doublon naît de la source 4688 ajoutée par cette
  spec, il est donc corrigé ici et `correlate` n'en dépend pas (DF-36 sort de son périmètre).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Appliquer les règles Sigma publiques décrites par catégorie (Priority: P1)

L'analyste dispose de règles Sigma publiques ou internes écrites pour une catégorie d'activité
(création de processus, connexion réseau, écriture de clé de registre, bloc de script
PowerShell…) plutôt que pour un journal précis. Il les passe à `detect --rules` sur un cas dont
les journaux Sysmon et PowerShell ont été ingérés. DFIRFlow sait quels journaux et quels
événements correspondent à chaque catégorie, applique les règles aux seuls événements concernés
et produit des détections au même format que celles de la spec 012.

**Why this priority**: la majorité des règles Windows publiques sont décrites par catégorie ;
tant qu'elles sont refusées, `detect` n'exploite qu'une petite partie de la connaissance de
détection disponible. C'est le gain de valeur principal de la fonctionnalité.

**Independent Test**: sur un cas contenant des événements Sysmon de chaque catégorie couverte,
appliquer une règle par catégorie avec `--rules`, puis vérifier qu'une détection est produite
pour l'événement attendu et aucune pour un événement d'une autre catégorie ou d'un autre journal.

**Acceptance Scenarios**:

1. **Given** un cas contenant un événement Sysmon de création de processus dont la ligne de
   commande contient `-EncodedCommand`, **When** l'analyste applique une règle
   `category: process_creation` qui recherche ce motif, **Then** une détection est produite pour
   cet événement.
2. **Given** le même cas et une règle `category: network_connection`, **When** la commande
   s'exécute, **Then** la règle n'est évaluée que sur les événements Sysmon de connexion réseau,
   jamais sur ceux de création de processus, même s'ils portent les mêmes champs.
3. **Given** une règle `category: registry_set`, **When** la commande s'exécute, **Then** seuls
   les événements Sysmon d'écriture de valeur de registre sont évalués, et non ceux de création ou
   de suppression de clé.
4. **Given** une règle `category: ps_script`, **When** la commande s'exécute, **Then** elle est
   évaluée sur les blocs de script du journal PowerShell opérationnel.
5. **Given** une règle déclarant une catégorie non couverte (par exemple `webserver`), **When** la
   commande s'exécute, **Then** la règle est refusée avec un avertissement citant son fichier et
   la catégorie, et les autres règles sont appliquées.

---

### User Story 2 - Détecter les créations de processus sans Sysmon (Priority: P1)

Beaucoup de machines n'ont pas Sysmon mais journalisent les créations de processus dans le
journal Security (événement 4688). L'analyste applique les mêmes règles `process_creation` : elles
s'appliquent aussi aux événements 4688, dont les champs sont présentés sous les noms attendus par
les règles. Une règle qui s'appuie sur une information que l'événement 4688 ne contient pas (par
exemple l'empreinte du binaire) n'est pas appliquée à 4688, pour ne pas produire de fausses
détections ; l'analyste le voit dans le journal du cas.

**Why this priority**: sans ce comportement, les règles de création de processus ne détectent rien
sur la plupart des machines examinées ; et sans la garde, une règle du type « processus X sauf si
signé par Y » détecterait à tort tous les processus X, faute de champ de signature dans 4688.

**Independent Test**: sur un cas contenant un événement 4688 et un événement Sysmon équivalents,
appliquer une règle portant sur l'image et la ligne de commande (une détection portant les deux
événements), puis une règle
qui exclut un champ absent de 4688 (une seule détection, sur l'événement Sysmon).

**Acceptance Scenarios**:

1. **Given** un événement 4688 dont le nouveau processus est `C:\Windows\System32\vssadmin.exe`
   avec la ligne de commande `vssadmin delete shadows /all`, **When** une règle
   `process_creation` portant sur `Image` et `CommandLine` est appliquée, **Then** une détection
   est produite pour cet événement.
2. **Given** une règle `process_creation` dont un filtre porte sur `Hashes` ou
   `OriginalFileName`, **When** la commande s'exécute, **Then** la règle n'est évaluée que sur les
   événements Sysmon ; un avertissement récapitulatif sur la sortie d'erreur indique combien de
   règles n'ont pas été appliquées à 4688, et l'entrée `case.log` cite cette règle et les champs
   manquants.
3. **Given** une règle `process_creation` portant sur `ParentImage`, **When** elle est appliquée à
   un événement 4688, **Then** la valeur comparée est celle du processus parent enregistré par
   l'événement.

---

### User Story 3 - Utiliser les modificateurs Sigma courants (Priority: P2)

Les règles publiques utilisent des modificateurs absents de la spec 012 : variantes de tirets
d'option (`windash`), plages d'adresses (`cidr`), chaînes encodées en base64 éventuellement en
UTF-16 (`base64`, `base64offset`, `wide`, `utf16le`, `utf16be`), présence d'un champ (`exists`),
comparaison sensible à la casse (`cased`) et comparaison avec un autre champ (`fieldref`).
L'analyste peut appliquer ces règles sans les réécrire.

**Why this priority**: ces modificateurs sont fréquents dans les règles de création de processus
et de connexion réseau ; sans eux, une partie des règles des catégories ajoutées reste refusée.
Ils ne servent qu'une fois les catégories prises en charge, d'où le rang P2.

**Independent Test**: pour chaque modificateur, appliquer une règle qui l'utilise à un événement
qui la satisfait et à un événement qui ne la satisfait pas, et vérifier une détection pour le
premier seulement.

**Acceptance Scenarios**:

1. **Given** une règle `CommandLine|windash|contains: '-enc '`, **When** elle est évaluée sur des
   lignes de commande contenant `-enc `, `/enc ` et `–enc ` (tiret demi-cadratin), **Then** les
   trois sont détectées.
2. **Given** une règle `DestinationIp|cidr: '10.0.0.0/8'`, **When** elle est évaluée sur
   `10.1.2.3` et `192.168.1.1`, **Then** seul le premier est détecté ; une valeur qui n'est pas
   une adresse IP n'est jamais détectée.
3. **Given** une règle `CommandLine|wide|base64offset|contains: 'IEX'`, **When** elle est évaluée
   sur une ligne de commande PowerShell contenant `IEX` encodé en UTF-16LE puis en base64, quel
   que soit son décalage, **Then** elle est détectée.
4. **Given** une règle `ParentImage|exists: false`, **When** elle est évaluée sur un événement
   sans ce champ et sur un événement qui le porte, **Then** seul le premier est détecté.
5. **Given** une règle `TargetFilename|cased|endswith: '.EXE'`, **When** elle est évaluée sur
   `a.EXE` et `a.exe`, **Then** seul le premier est détecté.
6. **Given** une règle `SourceUser|fieldref: TargetUser`, **When** elle est évaluée sur un
   événement où les deux champs sont égaux et un où ils diffèrent, **Then** seul le premier est
   détecté.

---

### User Story 4 - Disposer de règles par catégorie dans le jeu embarqué (Priority: P3)

Sans fournir de règles, l'analyste bénéficie de quelques détections maison sur les catégories
ajoutées : commande PowerShell encodée, suppression des clichés instantanés, téléchargement par
`certutil`, persistance par clé de démarrage du registre, bloc de script de téléchargement et
d'exécution.

**Why this priority**: elle rend la fonctionnalité visible avec `investigate`, qui n'a pas
d'option `--rules`, mais l'essentiel de la valeur vient des règles fournies (US1).

**Independent Test**: lancer `detect` sans `--rules` sur un cas contenant un cas positif et un cas
négatif de chaque nouvelle règle, et vérifier exactement une détection par cas positif.

**Acceptance Scenarios**:

1. **Given** un cas de référence de la spec 012 (journal Security seul), **When** `detect` est
   lancé sans `--rules`, **Then** les détections produites sont identiques à celles de la
   spec 012, à l'exception de la ligne de résumé qui compte les nouvelles règles.
2. **Given** un événement 4688 `vssadmin delete shadows /all`, **When** `detect` est lancé sans
   `--rules`, **Then** une détection est produite avec la technique ATT&CK de la règle.

---

### Edge Cases

- **Catégorie et service à la fois** : la règle s'applique aux seules sources de la catégorie qui
  appartiennent au journal du service ; si aucune ne correspond, la règle est refusée.
- **Catégorie connue sans journal dans le cas** (par exemple Sysmon absent) : la règle est
  appliquée et ne produit rien ; ce n'est ni un refus ni une erreur.
- **Règle `process_creation` dont tous les champs existent dans 4688 mais avec un format
  différent** (identifiant de processus en hexadécimal dans 4688, en décimal dans Sysmon) : un
  champ dont le format n'est pas équivalent est considéré comme absent de 4688 (garde).
- **Règle `process_creation` restreinte à Sysmon par la garde, sur un cas sans Sysmon** : aucune
  détection ; l'entrée `case.log` montre la restriction.
- **Même lancement de processus enregistré par Sysmon et par 4688** : une règle qui les satisfait
  tous deux produit une seule détection, qui porte les deux événements (FR-005a). Deux lancements
  distincts (PID, PID parent ou image différents, ou horodatages à plus de 2 secondes) restent
  deux détections.
- **Règle qui teste l'`EventID` explicitement** avec une catégorie : la condition est évaluée
  telle quelle ; un test `EventID: 1` ne peut donc pas être satisfait par un événement 4688.
- **`fieldref` vers un champ absent** : la condition est fausse. Avec la garde 4688, le champ
  référencé compte comme un champ utilisé.
- **`exists` avec une valeur qui n'est pas `true` ou `false`** : la règle est refusée.
- **`cidr` avec une plage invalide** : la règle est refusée ; **valeur d'événement non IP** : pas
  de correspondance.
- **`base64` sur une valeur de l'événement qui n'est pas du base64** : la comparaison se fait sur
  le texte tel qu'il est (le modificateur encode la valeur de la règle, il ne décode pas
  l'événement).
- **Combinaisons incohérentes de modificateurs** (`re` avec `windash` ou `base64`, `cidr` avec
  `contains`, `exists` avec un autre modificateur, `fieldref` avec `re`, `wide` sans `base64` ni
  `base64offset`, plusieurs encodages) : la règle est refusée avec le modificateur en cause.
- **Modificateurs restés hors périmètre** (`expand`, `gt`, `lt`, `gte`, `lte`, `minute`…, options
  `m` et `s` de `re`, `utf16`) : la règle est refusée comme en spec 012.
- **Table de correspondance modifiée entre deux versions de l'outil** : les résultats peuvent
  différer ; la version de la table est consignée dans `case.log` pour l'expliquer.

## Requirements *(mandatory)*

### Functional Requirements

**Catégories de sources**

- **FR-001**: Une règle dont la source est décrite par `category` MUST être acceptée si la
  catégorie fait partie de la liste couverte : `process_creation`, `network_connection`,
  `file_event`, `image_load`, `driver_load`, `dns_query`, `registry_add`, `registry_set`,
  `registry_delete`, `registry_event`, `process_access`, `create_remote_thread`,
  `pipe_created`, `wmi_event`, `ps_script`, `ps_module`. Une autre catégorie MUST être refusée
  avec un avertissement citant le fichier et la catégorie (spec 012, FR-006).
- **FR-002**: Chaque catégorie MUST correspondre à une ou plusieurs **sources**, chacune définie
  par un canal EVTX, un ou plusieurs identifiants d'événement et, au besoin, une valeur imposée
  d'un champ de l'événement (par exemple le type d'opération de registre). Une règle de catégorie
  MUST être évaluée seulement sur les événements EVTX de ses sources.
- **FR-003**: La correspondance des catégories vers les sources, et pour chaque source le
  renommage des champs, MUST être décrite par une table déclarative embarquée dans le binaire, et
  non dans le code ; la table MUST porter une version.
- **FR-004**: `process_creation` MUST avoir pour sources l'événement Sysmon de création de
  processus et l'événement Security 4688.
- **FR-005**: Pour une source, la table MAY renommer des champs : un champ cité par la règle est
  alors lu sous le nom qu'il porte dans l'événement de cette source (pour 4688 au moins : `Image`
  depuis `NewProcessName`, `ParentImage` depuis `ParentProcessName`, `CommandLine` depuis
  `CommandLine`). Un champ ne MUST être renommé que si sa signification et son format sont
  équivalents à ceux de la source de référence.
- **FR-005a**: Quand une même règle est satisfaite par un événement Sysmon 1 et par un événement
  Security 4688 du même lancement de processus (même hôte, même PID, même PID parent, même image
  sans tenir compte de la casse, horodatages à 2 secondes au plus l'un de l'autre), `detect` MUST
  produire une seule détection portant les deux événements, à l'horodatage du plus ancien. Tout
  autre couple (règle, événement) MUST produire sa propre détection. Le nombre de rapprochements
  MUST être consigné dans `case.log`.
- **FR-006**: Une source MAY être déclarée **partielle** par la table, avec la liste des champs
  qu'elle fournit. Une règle qui cite un champ hors de cette liste (y compris par `fieldref`)
  MUST NOT être évaluée sur cette source ; elle reste évaluée sur les autres sources de sa
  catégorie. Security 4688 MUST être déclarée partielle.
- **FR-007**: Si une règle porte à la fois une catégorie et un service, elle MUST être évaluée
  seulement sur les sources de la catégorie qui appartiennent au canal du service ; si aucune ne
  correspond, elle MUST être refusée.
- **FR-008**: Une règle de catégorie restreinte par la garde sur toutes ses sources MUST être refusée
  avec la liste des champs non disponibles.
- **FR-009**: Les règles décrites par service (spec 012) MUST conserver exactement leur
  comportement ; une détection produite par une telle règle MUST rester identique octet par octet.

**Modificateurs**

- **FR-010**: Les modificateurs suivants MUST être pris en charge, en plus de ceux de la spec 012
  (dont `contains|all`) :
  - `windash` : chaque tiret ou barre oblique en tête d'option de la valeur peut être remplacé
    par `-`, `/`, `–` (demi-cadratin), `—` (cadratin) ou `―` (barre horizontale) ;
  - `cidr` : la valeur de l'événement est une adresse IPv4 ou IPv6 comprise dans la plage ;
  - `base64` : la valeur de la règle est comparée sous sa forme encodée en base64 ;
  - `base64offset` : la valeur est recherchée sous ses trois encodages base64 possibles selon sa
    position dans le texte encodé ;
  - `utf16le` (ou `wide`) et `utf16be` : la valeur est convertie dans cet encodage avant
    `base64` ou `base64offset` ;
  - `exists` : la valeur de la règle (`true` ou `false`) indique si le champ doit être présent ;
  - `cased` : la comparaison est sensible à la casse ;
  - `fieldref` : la valeur de la règle est le nom d'un autre champ de l'événement, dont la
    valeur est comparée.
- **FR-011**: Une combinaison de modificateurs sans sens défini (Edge Cases) MUST être refusée
  avec le modificateur en cause ; tout modificateur hors de FR-010 et de la spec 012 MUST rester
  refusé.
- **FR-012**: Les modificateurs de comparaison de texte (`windash`, `base64`, `base64offset`,
  encodages, `cased`) MUST se combiner avec les jokers, les listes de valeurs et `all` comme dans
  la spec 012 ; `cidr`, `exists` et `fieldref` suivent les règles de valeurs de `data-model.md`.

**Jeu embarqué**

- **FR-013**: Le jeu embarqué MUST être complété de 5 règles décrites par catégorie au total,
  couvrant : commande PowerShell encodée, suppression des clichés instantanés, téléchargement par
  `certutil`, persistance par clé de démarrage du registre et bloc de script PowerShell de
  téléchargement et d'exécution. Chacune MUST porter un identifiant, une sévérité, une technique
  ATT&CK, et disposer d'au moins un cas positif et un cas négatif testés, y compris sur 4688
  quand elle relève de `process_creation` (constitution VI).
- **FR-014**: Le jeu embarqué MUST toujours se charger sans aucun refus, et ses règles de la
  spec 012 MUST rester inchangées.

**Traçabilité et garanties**

- **FR-015**: L'entrée `detect` de `case.log` MUST porter en plus la version de la table des
  catégories et, pour chaque règle restreinte par la garde, le fichier de la règle, la
  source et les champs non disponibles.
- **FR-015a**: Si au moins une règle est restreinte par la garde, la commande MUST écrire
  sur la sortie d'erreur un seul avertissement par source concernée, donnant le nombre de règles
  restreintes et renvoyant à `case.log` ; elle MUST NOT écrire un avertissement par règle. Une
  restriction n'est pas un refus : elle ne change pas le compte des règles refusées.
- **FR-016**: Les garanties de la spec 012 MUST s'appliquer sans changement aux règles de
  catégorie : déterminisme octet par octet (FR-013), écriture atomique (FR-014), mémoire bornée
  (FR-019), refus motivés (FR-006), champs structurés uniquement (FR-009), format et ordre des
  détections (FR-011, FR-012), codes de sortie (FR-022).
- **FR-017**: La ligne de résumé de la sortie standard MUST garder le format de la spec 012.

### Key Entities

- **Catégorie** : nom Sigma d'une famille d'activité (`process_creation`…) ; désigne une ou
  plusieurs sources.
- **Source** : canal EVTX, identifiants d'événement, valeur imposée éventuelle d'un champ, table
  de renommage des champs, et liste des champs fournis si la source est partielle.
- **Table des catégories** : ensemble versionné des catégories et de leurs sources, embarqué dans
  le binaire.
- **Restriction par la garde** : couple (règle, source partielle) écarté par la garde, avec les
  champs non disponibles ; consigné dans `case.log`.
- **Règle**, **Jeu de règles**, **Détection** : inchangés depuis la spec 012 ; la source d'une
  règle peut désormais être une catégorie.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Pour chaque catégorie couverte, une règle de test détecte son événement positif et
  aucun événement d'une autre catégorie, d'un autre journal ou d'un autre identifiant d'événement
  (100 % des catégories).
- **SC-002**: Sur un instantané fixé des règles Windows publiques de SigmaHQ appartenant aux
  catégories couvertes, au moins 90 % se chargent sans refus ; chaque refus restant porte une
  raison lisible.
- **SC-003**: Une règle `process_creation` portant seulement sur l'image, le parent et la ligne de
  commande détecte un même lancement de processus enregistré par Sysmon et par 4688 ; une règle
  qui s'appuie sur un champ absent de 4688 ne produit aucune détection sur 4688.
- **SC-004**: 100 % des modificateurs de FR-010 ont un cas positif et un cas négatif testés, et
  100 % des combinaisons refusées listées en Edge Cases produisent un refus avec le modificateur
  en cause.
- **SC-005**: 100 % des règles ajoutées au jeu embarqué détectent leur cas positif et aucune ne
  détecte son cas négatif.
- **SC-006**: Sur le journal Security de référence, les détections des règles de la spec 012 sont
  identiques octet par octet avant et après la fonctionnalité.
- **SC-007**: Sur un cas de 10 millions d'événements mêlant Sysmon et Security, avec le jeu
  embarqué, la mémoire utilisée reste sous 256 Mio et les détections sont produites en moins de
  5 minutes sur le poste de référence (spec 012, SC-004) ; avec en plus 2 000 règles de catégorie,
  dont 1 800 sur des EventID absents du flux et 200 sur des EventID présents, la durée reste
  au plus le double. Le coût d'une règle se paie sur chaque événement de ses EventID (environ
  57 ns par règle et par événement) : il n'est pas borné quand un corpus concentre ses règles
  sur un EventID fréquent.

## Assumptions

- Les noms de champs des règles Sigma sont ceux des données d'événement Sysmon ; la source Sysmon
  d'une catégorie ne renomme donc aucun champ. Les données d'événement Sysmon et PowerShell sont
  conservées par l'ingestion (spec 005), comme pour Security.
- La liste exacte des sources de chaque catégorie (identifiants d'événement Sysmon, événements
  PowerShell 4103 et 4104, valeurs du type d'opération de registre) et le renommage complet
  pour 4688 sont fixés dans `data-model.md`, au plan, d'après la documentation de Sysmon et de
  Sigma.
- Les règles publiques de SigmaHQ sont distribuées sous Detection Rule License 1.1, qui n'est pas
  une licence autorisée par la constitution (principe VII) : elles ne sont ni embarquées ni
  copiées dans le dépôt. SC-002 est mesuré sur une copie locale, hors du dépôt et de la CI, comme
  l'oracle EvtxECmd de la spec 005 ; le seuil de 90 % est un objectif non bloquant, mesuré à
  l'implémentation (research R8).
- Les règles ajoutées au jeu embarqué sont écrites pour DFIRFlow sous licence Apache-2.0.
- Les tests reposent sur des événements normalisés synthétiques de Sysmon et de 4688 ; le dépôt
  ne contient pas de journal Sysmon de référence sous licence compatible.
- La corrélation (seuils, fenêtres de temps) reste hors périmètre, comme en spec 012. Le
  rapprochement d'un même lancement enregistré par Sysmon et par 4688 (DF-36) est traité ici
  (FR-005a), puisque le doublon vient de cette spec.
- Les catégories rares (`clipboard_capture`, `raw_access_thread`, `sysmon_status`, `registry_rename`,
  `file_delete`…) et les sources autres que Sysmon, PowerShell et 4688 pour une catégorie
  (par exemple les journaux de pare-feu pour `network_connection`) sont des évolutions
  ultérieures.
- Dépendances : spec 012 (moteur de règles, refus, jeu embarqué, `case.log`), spec 005 (données
  d'événement conservées), spec 003 (structure `Detection`).
