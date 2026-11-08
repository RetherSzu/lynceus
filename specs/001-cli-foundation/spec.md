# Feature Specification: Fondation de la CLI DFIRFlow

**Feature Branch**: `001-cli-foundation`

**Created**: 2026-11-02

**Status**: Draft

**Amendement 2026-11-03**: l'option outil de `import` est `--tool` (et non `--from`, réservé aux
bornes de `timeline`).

**Input**: User description: "Fondation de la CLI DFIRFlow : grammaire des sous-commandes. Le cas est
toujours désigné par --case. Commandes : `case init <ID> --host --analyst [--dir]`, `case verify --case`,
`collect --case --target`, `ingest --case [chemins…]`, `import --case --from <outil> <chemin>`,
`timeline --case [--from --to --source]`, `detect --case [--rules]`, `correlate --case`,
`report --case --format html,sqlite,jsonl`, `investigate --case --target`. Conserver --help/-h et
--version existants. Cette spec couvre la grammaire, l'aide, la validation des arguments, les codes
de sortie et la journalisation ; chaque sous-commande renvoie une erreur explicite « non
implémenté » tant que sa spec fonctionnelle n'est pas livrée."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Découvrir les commandes disponibles (Priority: P1)

Un analyste DFIR lance `dfirflow` sur une station d'analyse ou un poste compromis, sans
documentation sous la main. Il doit comprendre en quelques secondes quelles commandes existent,
dans quel ordre les enchaîner et quelles options chacune attend.

**Why this priority**: c'est le point d'entrée de tout le pipeline ; sans grammaire stable et
découvrable, aucune spec fonctionnelle (cas, collecte, parsing…) ne peut s'y brancher.

**Independent Test**: exécuter `dfirflow --help`, puis `dfirflow <commande> --help` pour chaque
commande, et vérifier que chaque aide liste les options et arguments décrits dans cette spec.

**Acceptance Scenarios**:

1. **Given** le binaire installé, **When** l'analyste lance `dfirflow --help` ou `dfirflow -h`,
   **Then** l'aide générale liste les 10 commandes (`case init`, `case verify`, `collect`, `ingest`,
   `import`, `timeline`, `detect`, `correlate`, `report`, `investigate`) dans l'ordre du pipeline,
   chacune avec une description d'une ligne, et le code de sortie est 0.
2. **Given** le binaire installé, **When** l'analyste lance `dfirflow` sans argument, **Then**
   l'aide générale est affichée et le code de sortie est 0.
3. **Given** le binaire installé, **When** l'analyste lance `dfirflow detect --help`, **Then** l'aide
   de `detect` décrit `--case` (obligatoire) et `--rules` (optionnel), et le code de sortie est 0.
4. **Given** le binaire installé, **When** l'analyste lance `dfirflow --version`, **Then** la sortie
   est `DFIRFlow <version>` et le code de sortie est 0 (comportement actuel conservé).

---

### User Story 2 - Être arrêté net par une commande mal formée (Priority: P1)

L'analyste tape une commande incomplète ou erronée (option obligatoire oubliée, valeur invalide,
commande inconnue). L'outil doit refuser avant toute action, avec un message qui dit précisément
ce qui ne va pas, et un code de sortie qu'un script peut tester.

**Why this priority**: en situation de crise, une commande mal comprise ne doit jamais toucher aux
preuves ; la validation stricte en amont protège la chaîne de preuve (constitution, principe III).

**Independent Test**: exécuter un jeu de commandes invalides et vérifier pour chacune le message
d'erreur sur la sortie d'erreur, la sortie standard vide et le code de sortie d'erreur d'usage.

**Acceptance Scenarios**:

1. **Given** le binaire, **When** l'analyste lance `dfirflow detect` sans `--case`, **Then** le
   message indique que `--case` est obligatoire pour `detect` et le code de sortie est 2.
2. **Given** le binaire, **When** l'analyste lance `dfirflow analyze`, **Then** le message indique
   que la commande est inconnue, renvoie vers `dfirflow --help`, et le code de sortie est 2.
3. **Given** le binaire, **When** l'analyste lance `dfirflow import --case ./cases/C1 --tool foo ./x`,
   **Then** le message liste les valeurs acceptées pour `--tool` et le code de sortie est 2.
4. **Given** le binaire, **When** l'analyste lance `dfirflow report --case ./cases/C1 --format pdf`,
   **Then** le message liste les formats acceptés et le code de sortie est 2.
5. **Given** le binaire, **When** l'analyste lance `dfirflow case init ../evil --host H --analyst A`,
   **Then** l'identifiant est refusé (caractères non autorisés) et le code de sortie est 2.

---

### User Story 3 - Savoir qu'une commande valide n'est pas encore disponible (Priority: P2)

Pendant le développement, l'analyste (ou un script de test) lance une commande correctement
formée dont la fonctionnalité n'est pas encore livrée. L'outil doit le dire explicitement, sans
rien écrire sur le disque, avec un code de sortie distinct d'une erreur d'usage ou d'exécution.

**Why this priority**: permet de livrer la grammaire complète maintenant et de brancher chaque
fonctionnalité ensuite, spec par spec, sans jamais laisser croire qu'une commande a réussi.

**Independent Test**: lancer chaque commande avec des arguments valides et vérifier le message
« non implémenté », l'absence de création ou modification de fichier et le code de sortie dédié.

**Acceptance Scenarios**:

1. **Given** la fonctionnalité de détection non livrée, **When** l'analyste lance
   `dfirflow detect --case ./cases/CASE-001`, **Then** le message indique que `detect` n'est pas encore
   implémentée, aucun fichier n'est créé ni modifié, et le code de sortie est 3.
2. **Given** aucune étape du pipeline livrée, **When** l'analyste lance
   `dfirflow investigate --case ./cases/CASE-001 --target ./evidence`, **Then** l'outil s'arrête à la
   première étape non implémentée (`collect`), la nomme dans le message, et le code de sortie est 3.

---

### User Story 4 - Enchaîner le pipeline dans un script (Priority: P3)

Un analyste automatise une investigation dans un script shell. Il doit pouvoir distinguer, par le
seul code de sortie, le succès, une erreur d'usage, un échec d'exécution et une fonctionnalité
absente, et récupérer les résultats sur la sortie standard sans qu'ils soient mêlés aux messages.

**Why this priority**: l'usage headless et scriptable est une exigence de la constitution
(principe I), mais il n'apporte de la valeur qu'une fois les commandes fonctionnelles livrées.

**Independent Test**: dans un script, enchaîner des commandes valides, invalides et non
implémentées, et vérifier codes de sortie et séparation sortie standard / sortie d'erreur.

**Acceptance Scenarios**:

1. **Given** un script, **When** une commande échoue pour une raison quelconque, **Then** rien
   n'est écrit sur la sortie standard et le diagnostic est écrit sur la sortie d'erreur, préfixé
   par `dfirflow:` et le nom de la commande.
2. **Given** un script, **When** les options sont placées après les arguments positionnels
   (`dfirflow ingest ./logs --case ./cases/CASE-001`), **Then** la commande est interprétée comme si les
   options étaient placées avant.

---

### Edge Cases

- Option répétée (`--case A --case B`) : erreur d'usage (code 2), sauf pour les options
  explicitement multivaluées.
- Argument `--` : tout ce qui suit est traité comme argument positionnel (chemins commençant par `-`).
- `--help` combiné à des arguments invalides : l'aide l'emporte, code 0.
- `--version` combiné à une commande : erreur d'usage (code 2) ; `--version` est global uniquement.
- `--from` postérieur à `--to` dans `timeline` : erreur d'usage (code 2).
- Date `--from`/`--to` non conforme au format attendu : erreur d'usage, le message rappelle le format.
- `--format` contenant un doublon (`html,html`) ou une valeur vide (`html,`) : erreur d'usage.
- `case init` sans identifiant, ou avec un identifiant vide : erreur d'usage.
- `ingest` sans chemin : accepté (signifie « tout ce qui est sous `evidence/` du cas »).
- Chemins contenant des espaces ou des caractères non ASCII : acceptés tels quels.
- Interruption (Ctrl+C) : sortie avec code 130, sans message d'erreur supplémentaire.

## Requirements *(mandatory)*

### Functional Requirements

**Grammaire générale**

- **FR-001**: La CLI MUST exposer exactement les commandes suivantes : `case init`, `case verify`,
  `collect`, `ingest`, `import`, `timeline`, `detect`, `correlate`, `report`, `investigate`.
- **FR-002**: Toute commande opérant sur un cas existant MUST désigner ce cas par l'option `--case`,
  obligatoire ; seule `case init` reçoit l'identifiant du cas en argument positionnel.
- **FR-003**: La valeur de `--case` MUST être un chemin (relatif ou absolu) vers le dossier du cas ;
  aucune résolution implicite par identifiant n'est effectuée. Une valeur vide MUST être refusée
  (code 2).
- **FR-004**: Les options MUST être acceptées sous les formes `-x`/`--long` et `--long valeur` /
  `--long=valeur`, avant ou après les arguments positionnels ; `--` MUST terminer les options.
- **FR-005**: Les options globales `-h`/`--help` et `--version` MUST conserver leur comportement
  actuel (aide générale ; sortie `DFIRFlow <version>`), avec code de sortie 0.

**Commandes et arguments**

- **FR-006**: `case init <ID>` MUST exiger `--host` et `--analyst`, et accepter `--dir` (dossier
  racine des cas, par défaut `./cases`). `<ID>` MUST ne contenir que lettres, chiffres, `-` et `_`,
  sans séparateur de chemin, longueur 1 à 64.
- **FR-007**: `case verify` MUST exiger `--case`.
- **FR-008**: `collect` MUST exiger `--case` et `--target` (fichier ou dossier source des preuves).
- **FR-009**: `ingest` MUST exiger `--case` et accepter zéro ou plusieurs chemins positionnels.
- **FR-010**: `import` MUST exiger `--case`, `--tool` et exactement un chemin positionnel ; `--tool`
  MUST être l'une des valeurs `kape`, `orc`, `eztools`, `hayabusa`, `plaso`, `volatility`.
- **FR-011**: `timeline` MUST exiger `--case` et accepter `--from` et `--to` (date-heure ISO 8601,
  interprétée en UTC si aucun fuseau n'est donné) et `--source` (une ou plusieurs valeurs parmi
  `evtx`, `mft`, `usnjrnl`, `registry`, `prefetch`, `memory`) — amendé par la spec 003 (FR-026).
- **FR-012**: `detect` MUST exiger `--case` et accepter `--rules` (fichier ou dossier de règles).
- **FR-013**: `correlate` MUST exiger `--case`.
- **FR-014**: `report` MUST exiger `--case` et accepter `--format`, liste séparée par des virgules
  parmi `html`, `sqlite`, `jsonl` ; en l'absence de `--format`, les trois formats sont produits.
- **FR-015**: `investigate` MUST exiger `--case` et `--target`, et MUST enchaîner, dans l'ordre,
  `collect` → `ingest` → `timeline` → `detect` → `correlate` → `report`, sans comportement propre :
  elle s'arrête à la première étape en échec et renvoie le code de sortie de cette étape.
- **FR-016**: `import` MUST seulement lire les fichiers désignés ; aucune commande MUST NOT lancer
  un programme tiers (constitution, principe II).

**Aide**

- **FR-017**: `dfirflow <commande> --help` MUST afficher l'usage de la commande, ses arguments, ses
  options (obligatoire / optionnelle, valeurs acceptées, valeur par défaut) et un exemple.
- **FR-018**: L'aide générale et les aides par commande MUST être écrites sur la sortie standard.

**Validation et codes de sortie**

- **FR-019**: Toute validation de syntaxe (commande connue, options obligatoires, valeurs
  énumérées, formats de date, identifiant de cas) MUST être effectuée avant toute lecture ou
  écriture sur le disque.
- **FR-020**: La CLI MUST utiliser les codes de sortie suivants :
  `0` succès ; `1` échec d'exécution ; `2` erreur d'usage ; `3` fonctionnalité non implémentée ;
  `4` échec d'intégrité des preuves (ajouté par la spec 002) ; `130` interruption par l'utilisateur.
- **FR-021**: Tant que la spec fonctionnelle d'une commande n'est pas livrée, cette commande, une
  fois ses arguments validés, MUST afficher `dfirflow: <commande>: not implemented yet` sur la sortie
  d'erreur, ne rien écrire sur le disque et sortir avec le code 3.

**Sorties et journalisation**

- **FR-022**: La sortie standard MUST être réservée aux résultats et à l'aide ; tout diagnostic
  (erreur, avertissement, progression) MUST aller sur la sortie d'erreur.
- **FR-023**: Chaque message d'erreur MUST être préfixé par `dfirflow:` suivi du nom de la commande
  concernée, et MUST indiquer l'option ou l'argument en cause.
- **FR-024**: Une commande qui n'a pas modifié de cas MUST NOT écrire de journal sur le disque. Le
  journal des opérations d'un cas (constitution, principe III) est défini par la spec de gestion de
  cas ; cette spec impose seulement que toute commande fonctionnelle future y enregistre son nom,
  ses arguments, l'heure UTC de début et de fin, et son code de sortie.

### Key Entities

- **Commande** : nom (éventuellement en deux mots, ex. `case init`), arguments positionnels, options
  (obligatoires ou non, valeurs acceptées, défaut), statut (implémentée / non implémentée).
- **Référence de cas** : valeur de `--case`, chemin vers un dossier de cas unique.
- **Code de sortie** : contrat entre la CLI et les scripts appelants (FR-020).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100 % des 10 commandes sont listées dans l'aide générale et disposent d'une aide
  dédiée contenant au moins un exemple.
- **SC-002**: 100 % des cas invalides listés dans les scénarios et cas limites produisent le code 2,
  une sortie standard vide et un message nommant l'option ou l'argument en cause.
- **SC-003**: 100 % des commandes valides non encore implémentées produisent le code 3 sans aucune
  création ou modification de fichier (vérifié par comparaison du système de fichiers avant/après).
- **SC-004**: Un analyste découvrant l'outil identifie la commande et les options nécessaires pour
  une étape donnée du pipeline en moins de 1 minute, à l'aide de l'aide intégrée uniquement.
- **SC-005**: Toute réponse de la CLI (aide, erreur d'usage, non implémenté) est obtenue en moins de
  1 seconde sur une station d'analyse standard.
- **SC-006**: Les tests existants de `--help` et `--version` continuent de passer sans modification
  de leur résultat attendu.

## Assumptions

- Les messages de la CLI restent en anglais, comme le code existant ; la documentation reste en
  français.
- Aucune option de verbosité (`--verbose`, `--quiet`) ni de format de sortie machine (`--json`) n'est
  ajoutée à ce stade ; elles pourront l'être par une spec ultérieure.
- La validation se limite à la syntaxe : l'existence du cas, de `--target`, des chemins ou des
  règles est vérifiée par les specs fonctionnelles correspondantes (code 1 en cas d'échec).
- Le dossier racine des cas par défaut est `./cases`, conformément à `docs/Archi.md` §5.
- La liste des valeurs de `--tool` (import) et `--source` (timeline) suit `docs/etude-existant.md`
  §9.1 et les constantes de source du modèle `Event` ; elle évoluera avec les specs d'import et de
  parsing.
- Le code de sortie actuel (2 pour toute erreur) est remplacé par le contrat FR-020 ; les erreurs
  d'usage gardent le code 2.
- Dépendances : les specs fonctionnelles (gestion de cas, collecte, parsing, timeline, détection,
  corrélation, rapport, import) remplaceront chacune la réponse « non implémenté » de leur commande.
