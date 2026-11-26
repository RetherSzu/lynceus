# Research: Chronologie consolidée du cas

Décisions techniques de la spec 006. Aucune question n'est restée ouverte après la clarification
du 2026-11-26 (FR-009).

## R1. Sélection des fichiers d'événements

- **Decision**: parcourir le manifeste (`Case.Evidence()`, trié par chemin) et ouvrir, pour chaque
  preuve, `normalized/<preuve>.jsonl` s'il existe. Un parcours de `normalized/` sert seulement à
  signaler les fichiers inconnus : un fichier est connu s'il vaut `<preuve>.jsonl` ou
  `<preuve>.anomalies.jsonl` pour une preuve du manifeste ; les `*.partial` sont ignorés sans
  avertissement ; tout autre fichier produit l'avertissement de FR-002.
- **Rationale**: le nom du fichier d'événements est dérivé du manifeste, comme dans `ingest` ; on
  n'a jamais à deviner, à partir d'un nom, s'il s'agit d'événements ou d'anomalies (une preuve
  nommée `x.anomalies` reste sans ambiguïté). L'ordre de lecture est celui du manifeste, stable.
- **Alternatives considered**: lister `normalized/` et exclure par suffixe — ambigu pour certains
  noms de preuve et dépendant de l'ordre du système de fichiers.

## R2. Tri externe

- **Decision**: chaque événement lu, décodé et validé par `normalizer.ReadEvents`, puis retenu par
  le filtre, est réencodé en ligne canonique (`normalizer.NewEncoder`) et conservé avec sa clé de
  tri. Quand la taille cumulée (lignes et clés) dépasse un budget de 64 Mio, le segment est trié
  et écrit dans un dossier de travail. À la fin, les segments sont fusionnés par un tas
  (`container/heap`) ; la fusion lit chaque ligne, n'en décode que la clé et recopie les octets
  tels quels. Au-delà de 128 segments, la fusion se fait en plusieurs passes de 128 segments au
  plus. Si un seul segment suffit, il est écrit directement dans la chronologie, sans fichier de
  travail.
- **Rationale**: les fichiers de `normalized/` sont dans l'ordre du journal (R5 de la spec 005),
  il faut donc trier et non seulement fusionner. Le budget en octets borne la mémoire quelle que
  soit la taille des événements (un 4104 PowerShell peut peser plusieurs Kio). La limite de
  segments ouverts tient sous la limite de descripteurs courante de Linux (1024). Recopier les
  octets garantit que la chronologie est l'encodage canonique sans second réencodage.
- **Alternatives considered**: tri en mémoire de tous les événements (contraire au principe V) ;
  base SQLite temporaire (dépendance et non nécessaire pour un tri) ; budget en nombre
  d'événements (mémoire non bornée si les événements sont gros).

## R3. Clé et ordre

- **Decision**: clé `(timestamp en microsecondes UTC, source_file, record_id, uid)`, comparée dans
  cet ordre, `source_file` et `uid` octet par octet. La même fonction de comparaison sert au tri
  des segments et à la fusion.
- **Rationale**: c'est l'ordre FR-018a de la spec 003, identique à `normalizer.SortEvents`
  (horodatage tronqué à la microseconde, comme il est écrit). L'`uid` étant unique par
  enregistrement, l'ordre est total : la sortie ne dépend ni du budget, ni du nombre de segments,
  ni de l'ordre des fichiers.
- **Alternatives considered**: comparer l'horodatage comme chaîne — exact pour le format canonique,
  mais la comparaison d'entiers ne suppose rien sur la largeur des années.

## R4. Filtres

- **Decision**: `from` et `to`, déjà validés par la CLI (spec 001), sont tronqués à la
  microseconde ; un événement est retenu si `from <= t <= to`, `t` étant son horodatage principal
  tronqué. `--source` est un ensemble ; sans option, toutes les sources passent. Les sources
  rencontrées sont relevées avant le filtre temporel, pour l'avertissement de FR-008.
- **Rationale**: bornes incluses (spec, US2-1) ; même précision que l'écriture (FR-017 de la
  spec 003), donc ce que l'analyste lit dans la chronologie est ce qui a été filtré.
- **Alternatives considered**: borne `to` exclue — plus commode pour des fenêtres contiguës mais
  contre-intuitive pour `--to 2026-11-01T18:00:00`.

## R5. Écriture atomique et nettoyage

- **Decision**: la chronologie est écrite dans `timeline/timeline.jsonl.partial` à travers un
  `io.MultiWriter` vers le fichier et un SHA-256, puis synchronisée, fermée et renommée en
  `timeline/timeline.jsonl`. Le dossier de travail est créé par `os.MkdirTemp` sous `timeline/`
  (préfixe `.work-`). Un `defer` supprime le dossier de travail et le `.partial` en succès comme en
  échec ou interruption. Au démarrage, un `.partial` ou des `.work-*` laissés par un arrêt brutal
  sont supprimés. Le contexte est vérifié entre deux lignes.
- **Rationale**: même schéma que `ingest` (`.partial` puis renommage) ; `os.Rename` remplace le
  fichier existant sous Windows comme sous Linux. Créer le dossier de travail dans le cas évite de
  remplir un disque système et garde les données sur le support de l'investigation (FR-016).
- **Alternatives considered**: dossier temporaire du système — données d'enquête hors du cas,
  volume parfois trop petit.

## R6. Oracle

- **Decision**: l'oracle de l'ordre est `normalizer.SortEvents` appliqué en mémoire au même jeu
  d'événements, filtré par une fonction de test indépendante. Le tri externe est vérifié en forçant
  un budget de quelques Kio (plusieurs segments, plusieurs passes) et en comparant au résultat à
  segment unique.
- **Rationale**: aucun outil de référence ne produit cette chronologie JSONL ; la spec 003 fixe
  l'ordre et `SortEvents` en est déjà l'implémentation testée.
- **Alternatives considered**: comparer à `psort` de plaso — format, champs et ordre différents,
  et exécution d'outil tiers.

## R7. Intégration CLI

- **Decision**: `timelineCmd` ouvre le cas, appelle `timeline.Run`, écrit les avertissements sur la
  sortie d'erreur, la ligne de résumé sur la sortie standard, et journalise l'entrée `timeline`
  via `logOperation` (le champ `error` du résumé porte la cause d'un échec). `investigate` est
  inchangée : elle appelle déjà les étapes dans l'ordre et s'arrêtera à `detect` (code 3).
- **Rationale**: même structure que `ingestCmd` ; aucune logique propre dans `investigate`
  (spec 001, FR-015).
- **Alternatives considered**: aucune.
