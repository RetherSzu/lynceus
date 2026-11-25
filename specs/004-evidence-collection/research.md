# Research: Collecte des preuves

Choix d'implémentation de la spec 004. Aucune dépendance externe : bibliothèque standard Go 1.18
(`go.mod`).

## R1 — Repérage des EVTX sans parcourir tout le volume

- **Decision** : résoudre le motif `Windows/System32/winevt/Logs/*.evtx` composant par composant :
  à chaque niveau, `os.ReadDir` puis comparaison `strings.EqualFold` ; au dernier niveau, garder
  les entrées dont l'extension est `.evtx` (sans casse). Plusieurs répertoires ne différant que par
  la casse (possible sous Linux) sont tous explorés.
- **Rationale** : FR-003 (casse ignorée, chemin réel conservé) ; quelques `ReadDir` au lieu d'un
  `WalkDir` de millions de fichiers ; la liste de motifs reste une simple table (FR-002).
- **Alternatives** : `filepath.Glob` (sensible à la casse sous Linux) ; `WalkDir` complet (lent sur
  un volume entier, et suit des chemins inutiles).

## R2 — Métadonnées d'origine (FR-006)

- **Decision** : `os.Lstat` avant la copie ; `ModTime` partout ; horodatages complémentaires lus via
  `Sys()` dans des fichiers à build tag :
  - `windows` : `*syscall.Win32FileAttributeData` → création, accès, modification (pas de
    changement d'inode sous Windows) ;
  - `linux` : `*syscall.Stat_t` → accès (`Atim`), changement (`Ctim`) ; création omise (`statx`
    hors stdlib en 1.18) ;
  - autres OS : modification seule.
- **Rationale** : principe IX (isolation par build tags, compilation Linux intacte) ; un champ
  indisponible est omis, jamais inventé (US2-2).
- **Alternatives** : `golang.org/x/sys` pour `statx` — dépendance ajoutée pour un seul champ sous
  Linux, rejetée.

## R3 — Stockage des métadonnées (FR-007)

- **Decision** : nouveau champ optionnel `origin` (objet, `omitempty`) dans `ManifestEntry`. Les
  manifestes de la spec 002 se relisent sans changement ; `case verify` n'utilise pas ce champ.
- **Rationale** : une ligne de manifeste = toute l'information de custody d'une preuve ; pas de
  second fichier à garder cohérent.
- **Alternatives** : fichier `hashes/origins.jsonl` séparé (deux fichiers append-only à
  synchroniser) ; métadonnées seulement dans `case.log` (non rattachées à la preuve).

## R4 — API de `internal/case`

- **Decision** :
  - `AddEvidence(ctx, src, rel string, origin *Origin)` : ajout du contexte (lecture via le
    `ctxReader` existant, interruption → `.partial` supprimé) et de l'origine ;
  - `Case.Recorded(file) (sha256 string, ok bool)` : `entries` passe de `map[string]bool` à
    `map[string]string` (fichier → empreinte).
- **Rationale** : FR-008 (`ALREADY`/`CONFLICT` sans relire le manifeste) et interruption propre ;
  les seuls appelants actuels d'`AddEvidence` sont les tests du package.
- **Alternatives** : nouvelle fonction à côté d'`AddEvidence` (deux chemins d'écriture à maintenir).

## R5 — Fichier verrouillé (FR-012)

- **Decision** : l'erreur d'ouverture est rapportée `FAILED`. Sous Windows, `ERROR_SHARING_VIOLATION`
  (32) et `ERROR_LOCK_VIOLATION` (33) sont reconnus (fichier à build tag) et la raison devient
  `locked by the system: live collection is not supported`.
- **Rationale** : clarification Q2 (DF-13 reporté) ; message actionnable pour l'analyste.

## R6 — Garde-fous sur la cible

- **Decision** : chemins absolus via `filepath.Abs` + `filepath.EvalSymlinks` ; refus si le dossier
  du cas est égal à la cible ou sous elle (`filepath.Rel` ne commence pas par `..`). Pendant la
  résolution, toute entrée `Lstat` non régulière (lien, point de jonction, périphérique) est
  rapportée `SKIPPED` et jamais suivie.
- **Rationale** : FR-005, FR-014, FR-015. En Go 1.18, un point de jonction Windows est vu comme
  `ModeSymlink`.

## R7 — Source déjà collectée

- **Decision** : pour un chemin déjà au manifeste, la source est hachée en flux puis comparée :
  égale → `ALREADY`, différente → `CONFLICT` (attendu/obtenu), sans écrire dans le cas.
- **Rationale** : FR-008, SC-003 ; le coût d'un hachage est acceptable pour une relance.
