# Recherche : catégories de sources et modificateurs Sigma

Décisions prises pour la spec 013. Chaque point suit le format décision, raison, alternatives.
Références externes : spécification Sigma (modificateurs, taxonomie des sources), schéma Sysmon,
documentation de l'événement Security 4688, pipeline Windows de pySigma (correspondance des
catégories, utilisée comme référence et non comme code).

## R1. Format et version de la table des catégories

- **Décision** : fichier JSON `internal/detection/categories.json`, embarqué par `embed`, lu et
  validé au chargement du jeu de règles. Sa version est les 16 premiers caractères hexadécimaux du
  SHA-256 de son contenu, comme `rule_version` (spec 012, R4) ; elle est consignée dans `case.log`
  sous `categories_version`.
- **Raison** : même approche que la table EVTX de la spec 005 (données déclaratives embarquées,
  pas de code) ; une empreinte ne peut pas être oubliée lors d'une modification, contrairement à
  un numéro de version tenu à la main. Le JSON est lu par la bibliothèque standard.
- **Alternatives** : table en Go (modifiable seulement en recompilant le code, moins lisible pour
  un analyste) ; YAML (aucun gain, la table n'est pas écrite par les utilisateurs) ; numéro de
  version manuel (risque d'oubli).

## R2. Sources de chaque catégorie

- **Décision** : table de `data-model.md`. Une source est un canal, un ensemble d'EventID et, au
  besoin, une contrainte sur le champ `EventType` (opérations de registre Sysmon 12). Sources
  retenues d'après le schéma Sysmon et le pipeline Windows de pySigma : Sysmon 1, 3, 6, 7, 8, 10,
  11, 12, 13, 14, 17, 18, 19, 20, 21, 22 ; PowerShell opérationnel 4103 (`ps_module`) et 4104
  (`ps_script`) ; Security 4688 (`process_creation`, partielle).
- **Raison** : ce sont les correspondances admises par les outils de référence ; les reprendre
  garantit qu'une règle SigmaHQ vise les mêmes événements chez nous et ailleurs. Sysmon 12
  regroupe création et suppression : sans la contrainte `EventType`, `registry_add` et
  `registry_delete` seraient indiscernables.
- **Alternatives** : `ps_module` étendu à Windows PowerShell 800 (relève de `ps_classic_script`
  dans la taxonomie Sigma, catégorie hors périmètre) ; `network_connection` étendu au journal du
  pare-feu Windows 5156 (champs et formats différents, reporté).

## R3. Renommage et garde pour Security 4688

- **Décision** : 4688 renomme `Image` → `NewProcessName`, `ParentImage` → `ParentProcessName` ;
  `CommandLine` garde son nom. Ses champs fournis sont ces trois-là plus les champs communs à tout
  événement (`EventID`, `Channel`, `Provider_Name`, `Computer`). Une règle qui cite un autre champ
  n'est pas évaluée sur 4688. Les champs cités comprennent les clés des sélections et les cibles
  de `fieldref`.
- **Raison** : seuls ces champs ont une signification et un format équivalents à Sysmon (FR-005).
  `ProcessId` et `ParentProcessId` existent dans 4688 mais en hexadécimal (`0x1a4`), contre le
  décimal dans Sysmon ; `User` est `DOMAINE\nom` dans Sysmon et réparti sur deux champs dans
  4688 ; `IntegrityLevel` est un libellé dans Sysmon et un SID dans 4688. Les renommer ferait
  échouer en silence les comparaisons, et les filtres `not` deviendraient des faux positifs.
- **Alternatives** : renommer aussi `ProcessId` et convertir l'hexadécimal (transformation de
  valeur, hors du principe d'une table de renommage ; reporté) ; appliquer toute règle à 4688
  sans garde (faux positifs dès qu'un filtre porte sur un champ absent, comportement refusé à la
  spécification).

## R4. Évaluation par source

- **Décision** : une règle est compilée une seule fois. L'index par canal de la spec 012 devient
  `canal → EventID → entrées`, plus une liste `canal → entrées sans EventID` pour les règles de
  service ; une **entrée** est un couple `(règle, source)`. Une règle de service donne une entrée
  sans contrainte d'EventID ni renommage ; une règle de catégorie donne une entrée par source
  retenue après la garde, rangée sous chacun des EventID de la source. Pour un événement EVTX, on
  examine les entrées de son couple (canal, EventID), puis celles de son canal sans EventID :
  contrainte `EventType` satisfaite, puis condition de la règle, les champs étant lus à travers le
  renommage de la source. Le coût par événement dépend ainsi des seules règles qui peuvent le
  concerner, et non de la taille du corpus.
- **Raison** : un événement ne peut appartenir qu'à une source d'une catégorie donnée, donc une
  règle ne produit jamais deux détections pour le même événement (FR-011 de la spec 012) ; un
  index par canal seul ferait examiner à chaque événement Sysmon toutes les règles Sysmon d'un
  corpus (environ 2 000 pour SigmaHQ), alors que seules celles de son EventID peuvent le
  concerner. Limite mesurée : un événement est évalué par toutes les règles de son EventID
  (environ 57 ns par règle sur des motifs littéraux) ; 1 000 règles `process_creation` sur un
  flux où Sysmon 1 et 4688 font un tiers des événements quadruplent la durée. Un préfiltre
  multi-motifs sur les littéraux des règles est reporté à une évolution ultérieure.
- **Alternatives** : index par canal seul (coût proportionnel au corpus, voir ci-dessus) ;
  réécrire la règle en ajoutant `EventID` et `Channel` à sa condition (fausse
  la garde et la traçabilité par source) ; une copie compilée de la règle par source (mémoire
  multipliée pour les corpus de milliers de règles).

## R5. Catégorie et service ensemble

- **Décision** : si une règle déclare `category` et `service`, les sources retenues sont celles de
  la catégorie dont le canal est celui du service ; aucune → refus
  `logsource category and service do not match`. Sans `service`, la catégorie seule décide.
- **Raison** : lecture la plus stricte de la source déclarée, sans jamais élargir ce que la règle
  vise (FR-007).
- **Alternatives** : ignorer le service (élargit la règle) ; refuser toute règle qui déclare les
  deux (refuse des règles valides du corpus, par exemple `category: ps_script` avec
  `service: powershell`).

## R6. Sémantique des modificateurs

Les modificateurs se lisent de gauche à droite : encodage (`wide`, `utf16le`, `utf16be`), puis
`base64` ou `base64offset`, puis la position (`contains`, `startswith`, `endswith`), avec `all`,
`cased` et `windash` à toute place. Combinaisons valides et refusées : `data-model.md`.

- **`windash`** — **Décision** : dans chaque valeur, un `-` ou un `/` placé en début de mot
  (précédé d'un début de texte ou d'un caractère qui n'est ni lettre, ni chiffre, ni `_`, et suivi
  d'une lettre ou d'un chiffre) devient une classe de caractères `- / – — ―` dans le motif. **Raison** :
  même positions que pySigma, sans générer 5ⁿ variantes de la valeur : le motif reste une seule
  chaîne avec des classes, ce qui borne le coût quelle que soit la règle. **Alternative** :
  expansion en liste de variantes (explosion combinatoire sur une ligne de commande à options
  multiples).
- **`base64`** — **Décision** : la valeur, après encodage éventuel, est encodée en base64
  standard avec remplissage ; le motif obtenu est comparé **sensible à la casse**. **Raison** : en
  base64, la casse est porteuse de sens ; une comparaison insensible à la casse ferait
  correspondre des contenus différents. **Alternative** : décoder la valeur de l'événement (coût
  à chaque événement, faux négatifs sur un base64 tronqué ou entouré d'autre texte).
- **`base64offset`** — **Décision** : pour une valeur `v` de `n` octets et pour `i` = 0, 1, 2,
  encoder `i` octets de bourrage suivis de `v`, retirer les `[0, 2, 3][i]` premiers caractères et,
  selon `(n + i) mod 3`, les `[0, 3, 2]` derniers ; les trois motifs sont reliés par OU et
  comparés sensibles à la casse. Avec `all`, chaque valeur doit être satisfaite par l'un de ses
  trois motifs. **Raison** : définition de la spécification Sigma, qui couvre les trois
  alignements possibles d'une sous-chaîne dans un texte encodé. **Alternative** : aucune autre
  définition n'est interopérable.
- **`utf16le`, `wide`, `utf16be`** — **Décision** : conversion de la valeur en UTF-16 sans
  marque d'ordre des octets, avant `base64` ou `base64offset` ; seules ou après le modificateur
  base64, refus. **Raison** : ces encodages n'ont de sens que pour produire les octets à encoder ;
  `utf16` (avec marque d'ordre) reste refusé (FR-011).
- **`cidr`** — **Décision** : chaque valeur est un préfixe IPv4 ou IPv6 (`net/netip`, Go 1.18) ;
  la valeur de l'événement correspond si c'est une adresse dans l'un des préfixes ; une valeur
  d'événement qui n'est pas une adresse ne correspond jamais ; un préfixe invalide est refusé.
  **Raison** : comparaison exacte, sans réécriture en jokers.
- **`exists`** — **Décision** : valeur YAML booléenne unique `true` ou `false` ; vrai si le
  champ est présent (même vide) selon la valeur. **Raison** : se distingue de `null` (absent ou
  vide, spec 012) comme dans la spécification Sigma.
- **`cased`** — **Décision** : désactive la mise en minuscules du motif et de la valeur, pour les
  comparaisons par motif (y compris `windash`). Refusé avec `re`, qui a son option `i`.
- **`fieldref`** — **Décision** : la valeur est le nom d'un champ ; la condition est vraie si les
  deux champs sont présents et égaux, insensible à la casse sauf avec `cased`. Combinable seulement
  avec `cased` et `all` ; refusé avec tout autre modificateur. **Raison** : seule forme utilisée
  par le corpus Windows ; les variantes `fieldref|startswith` ne sont pas interopérables.

## R7. Signalement des règles exclues d'une source

- **Décision** : sortie d'erreur, un avertissement par source partielle ayant exclu au moins une
  règle :
  `dfirflow: detect: warning: 42 rules not applied to Security 4688 (missing fields), see case.log`.
  `case.log` porte `rules_restricted`, liste triée par fichier de `{file, source, missing}`.
  Une règle exclue de toutes ses sources est refusée (FR-008) avec
  `fields not available in any source: <champs>` et n'apparaît pas dans `rules_restricted`.
- **Raison** : clarification de la spec (réponse B) ; l'avertissement unique signale le problème
  sans noyer la sortie quand un corpus en compte des centaines.

## R8. Jeu embarqué et mesure sur SigmaHQ

- **Décision** : cinq règles ajoutées (`data-model.md`), écrites pour DFIRFlow sous Apache-2.0,
  avec des cas positifs et négatifs Sysmon et, pour `process_creation`, 4688. Aucune ne cite de
  champ hors de 4688 : le jeu embarqué ne produit aucun avertissement de garde. Sur le journal
  Security de référence, les 11 événements 4688 ont une ligne de commande vide : les nouvelles
  règles n'y détectent rien, ce qui préserve SC-006.
- **Décision (SC-002)** : la mesure se fait avec un utilitaire de test lancé à la main
  (`DFIRFLOW_SIGMA_DIR=<dossier>`) qui charge les règles Windows des catégories couvertes d'une
  release SigmaHQ copiée hors du dépôt et affiche la part chargée et les raisons de refus
  regroupées. La release est téléchargée par l'analyste ou avec son accord, jamais par la CI.
  Le seuil de 90 % reste l'objectif mais n'est pas bloquant : il n'a jamais été mesuré.
  L'utilitaire journalise le taux et les raisons de refus sans échouer ; un écart au seuil est
  consigné dans les points ouverts de `docs/architecture-actuelle.md` et oriente la prochaine
  évolution. Mesure du 2026-11-27 (SigmaHQ 876eb7b) : 2 047 règles sur 2 047, soit 100 %.
- **Raison** : la licence DRL 1.1 interdit d'embarquer ces règles (constitution VII) ; un
  utilitaire hors CI reproduit le principe de l'oracle EvtxECmd de la spec 005.
