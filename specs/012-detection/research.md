# Research: Détection par règles mono-événement

Décisions techniques de la spec 012. Les trois choix de périmètre ont été tranchés par
l'utilisateur avant la spec ; aucune question n'est restée ouverte.

## R1. Lecture des règles YAML

- **Decision**: `go.yaml.in/yaml/v3` v3.0.6, décodage en `yaml.Node` pour connaître le type de
  chaque valeur (scalaire, liste, table) et refuser un fichier qui contient plus d'un document.
  Taille d'un fichier de règle limitée à 1 Mio (refus au-delà, avant décodage).
- **Rationale**: c'est le successeur maintenu par l'organisation YAML de `gopkg.in/yaml.v3`
  (même code, versions `v3.0.0` et `v3.0.1` du nouveau chemin retirées) ; licence MIT et
  Apache-2.0 ; aucune dépendance transitive ; `go 1.16`, compatible avec `go 1.18`. Il protège
  contre l'expansion d'alias abusive. Le décodage en nœuds évite les conversions implicites (un
  `EventID: 4688` reste le texte `4688`).
- **Alternatives considered**: `gopkg.in/yaml.v3` (non maintenu, même code) ; lecteur YAML maison
  (trop risqué sur une entrée non fiable) ; imposer JSON (incompatible avec Sigma et SigmaHQ).

## R2. Sous-ensemble Sigma et sémantique

- **Decision**:
  - `detection` contient des sélections nommées et `condition` (une chaîne). Une sélection est
    une table (toutes ses conditions de champ, ET) ou une liste de tables (l'une ou l'autre, OU).
    Une liste de valeurs nues (mots-clés), `timeframe`, une `condition` en liste ou contenant `|`
    (agrégation) sont refusées.
  - Condition de champ `Champ|mod1|mod2: valeur ou liste`. Liste : l'une des valeurs (OU), ou
    toutes avec `all`. Modificateurs acceptés : `contains`, `startswith`, `endswith`, `all`, `re`, et `i`
    seulement juste après `re` (`re|i`).
    Tout autre modificateur est refusé. `re` est exclusif des trois premiers.
  - Valeurs : scalaires YAML comparés comme texte. Sans `re`, comparaison insensible à la casse
    (repli Unicode simple), `*` (suite quelconque) et `?` (un caractère) sont des jokers, `\*`,
    `\?` et `\\` les échappent. `contains`, `startswith`, `endswith` reviennent à entourer la
    valeur de `*`. `null` est vrai si le champ est absent ou vide.
  - `re` : expression régulière RE2 (`regexp`), sensible à la casse, recherchée n'importe où dans
    la valeur ; `re|i` la rend insensible à la casse (préfixe `(?i)`) ; les autres options de
    Sigma (`m`, `s`) sont refusées ; une expression invalide refuse la règle.
  - `condition` : identifiants de sélection, `and`, `or`, `not`, parenthèses, `1 of <motif>`,
    `all of <motif>` où le motif est un nom, un nom terminé par `*`, ou `them` (toutes les
    sélections sauf celles dont le nom commence par `_`). Priorité : `not` > `and` > `or`. Un
    identifiant ou un motif qui ne désigne aucune sélection refuse la règle. L'imbrication
    (parenthèses et `not`) est limitée à 64 niveaux : au-delà, refus, pour qu'une condition
    malveillante ne puisse pas épuiser la pile (le YAML est déjà limité à 10 000 niveaux par la
    bibliothèque). `re` combiné à `contains`, `startswith` ou `endswith` est refusé.
- **Rationale**: c'est la partie de la spécification Sigma utilisée par les règles
  mono-événement Windows ; tout le reste (agrégations, corrélations, `timeframe`) relève de
  `correlate`. RE2 garantit un temps linéaire sur une expression fournie par un tiers. Refuser
  plutôt qu'ignorer un élément inconnu évite une règle silencieusement plus large que prévu.
- **Alternatives considered**: accepter et ignorer les modificateurs inconnus (faux positifs ou
  négatifs silencieux) ; jokers par traduction en expressions régulières (inutile, un filtrage
  glob itératif suffit).

## R3. Accès aux champs de l'événement

- **Decision**: `EventID` → `event_id` (texte décimal), `Channel` → `channel`, `Provider_Name` →
  `provider`, `Computer` → `metadata["System.Computer"]` ; tout autre nom → la clé de même nom de
  `metadata` (données de l'événement EVTX conservées par `ingest`, spec 005), comparaison du nom
  exacte. Un champ absent rend fausse toute condition sauf `null`.
- **Rationale**: ce sont les noms des règles Sigma Windows sur les journaux natifs (sans
  `process_creation` ni table de correspondance). Les champs structurés de `metadata` sont ceux
  de l'enregistrement, jamais un message rendu (constitution VIII).
- **Alternatives considered**: exposer aussi les champs pivots (`command_line`, `subject`…) sous
  des noms DFIRFlow : utile pour des règles multi-sources, reporté avec les catégories.

## R4. Identité, version et confiance des règles

- **Decision**:
  - Champs obligatoires : `id`, `title`, `level` (`informational`, `low`, `medium`, `high`,
    `critical`), `logsource` (`product` et `service`), `detection`. Champs facultatifs lus :
    `status`, `tags`, `confidence` (nombre de 0 à 1, extension DFIRFlow). Les autres champs
    (`author`, `references`, `falsepositives`, `date`…) sont ignorés.
  - `rule_version` : 16 premiers caractères hexadécimaux du SHA-256 du fichier, fins de ligne
    `\r\n` ramenées à `\n`.
  - Version du jeu : 16 premiers caractères hexadécimaux du SHA-256 des lignes
    `<rule_id>\x00<rule_version>\n` triées.
  - `confidence` par défaut selon `status` : `stable` 0,8 ; `test` 0,6 ; `experimental` ou absent
    0,4. `deprecated` et `unsupported` : règle écartée (FR-007).
  - `mitre` : la première étiquette de la forme `attack.tNNNN` ou `attack.tNNNN.NNN`, dans l'ordre
    du fichier, en majuscules (`T1070.001`).
- **Rationale**: l'empreinte change à toute modification de la règle sans exiger de numéro de
  version que Sigma n'a pas ; la normalisation des fins de ligne rend l'empreinte identique sur
  un poste Windows qui convertit les fichiers à l'extraction. La table de confiance exprime la
  maturité déclarée de la règle ; elle est publiée dans le contrat.
- **Alternatives considered**: `modified` de Sigma comme version (souvent absent, pas modifié à
  chaque changement) ; confiance obligatoire (bloque la reprise du corpus public).

## R5. Sélection des fichiers d'événements

- **Decision**: déplacer dans `ingest` la sélection écrite pour la 006 (R1 de la 006) sous la
  forme `ingest.EventFiles(c) (files, unknown []string, err)` ; `timeline` et `detection`
  l'appellent. Les fichiers inconnus produisent le même avertissement.
- **Rationale**: `ingest` fixe le nom `normalized/<preuve>.jsonl` ; une seule définition évite que
  `timeline` et `detect` divergent sur les fichiers lus.
- **Alternatives considered**: exporter la fonction depuis `timeline` (`detection` dépendrait de
  `timeline` pour une règle qui n'est pas la sienne) ; la dupliquer.

## R6. Tri des détections et écriture

- **Decision**: déplacer `sorter` et `writeAtomic` de `internal/timeline` vers `internal/extsort`
  avec une clé générique `(entier, texte, entier, texte)` et un décodeur de clé fourni par
  l'appelant pour relire les segments. `timeline` garde sa clé `(timestamp, source_file,
  record_id, uid)` ; `detection` utilise `(timestamp µs, id, 0, "")`. Budget de segment et fan-in
  inchangés (64 Mio, 128). Un dossier de travail `detections/.work-*` et un
  `detections.jsonl.partial` laissés par un arrêt brutal sont supprimés au démarrage.
- **Rationale**: le nombre de détections n'est pas borné (une règle large sur des millions
  d'événements) ; le tri de la 006 est déjà mesuré (10 millions de lignes, 139 Mio). Déplacer sans
  changer le comportement garde ses tests valides, avec le test de volume de la 006 comme garde.
- **Alternatives considered**: trier les détections en mémoire (contraire à FR-019) ; écrire les
  détections dans l'ordre des événements de la chronologie (dépendrait de `timeline`, exclu par
  FR-001, et l'ordre `(timestamp, id)` n'est pas celui des événements).

## R7. Tests des règles embarquées

- **Decision**: une table de tests associe à chaque fichier de `rules/` au moins un événement
  positif et un négatif (synthétiques, construits en Go). Un test vérifie que chaque règle
  embarquée a une entrée dans la table et que le jeu embarqué se charge sans refus ni écart.
  SC-001 est vérifié sur le journal Security de référence : 1 détection 1102 et 14 détections
  4719, aucune autre.
- **Rationale**: constitution VI (positif et négatif par règle) ; la vérification d'exhaustivité
  empêche d'ajouter une règle sans ses cas.
- **Alternatives considered**: cas de test dans le YAML de la règle (champ non Sigma) ; fixtures
  EVTX par règle (pas de journal de laboratoire pour 4720, 4732, 7045, 4698 dans le dépôt).

## R8. Performance

- **Decision**: les règles sont indexées par canal (minuscules) au chargement ; un événement non
  EVTX ou d'un canal sans règle n'est pas évalué. Conditions compilées une fois (jokers découpés,
  expressions régulières compilées). Pas de parallélisme.
- **Rationale**: le coût dominant est le décodage des lignes, déjà mesuré par la 006 ; l'index
  rend le coût des règles proportionnel aux seules règles du canal. Le parallélisme compliquerait
  l'ordre sans nécessité pour SC-004.
- **Alternatives considered**: évaluer toutes les règles sur tous les événements (coût en
  nombre de règles × événements avec un corpus de milliers de règles).
