# Research: Gestion des cas d'investigation

## R1 — Création atomique du cas

- **Decision**: `os.Mkdir(<dir>/<ID>)` (échoue si le dossier existe : test d'existence atomique),
  puis création du contenu ; en cas d'erreur, `os.RemoveAll` du dossier qu'on vient de créer.
- **Rationale**: FR-003 et FR-004 ; on ne supprime que ce que la commande a elle-même créé.
- **Alternatives considered**: dossier temporaire + `os.Rename` — sous Linux `rename` remplace un
  dossier cible vide, ce qui violerait FR-003.

## R2 — Enregistrement d'une preuve

- **Decision**: écriture dans `<final>.partial` ouvert en `O_EXCL`, via
  `io.Copy(io.MultiWriter(fichier, sha256), source)` ; `Sync` ; relecture et re-hachage de la copie ;
  `Rename` vers le nom final ; ajout au manifeste ; `Chmod 0o444`. En cas d'échec : suppression du
  `.partial` (ou du fichier final si l'ajout au manifeste échoue).
- **Rationale**: FR-007/FR-008 ; le hachage pendant la copie évite une lecture supplémentaire de la
  source (qui peut être lente ou volatile) ; la relecture prouve que la copie sur disque est fidèle.
- **Alternatives considered**: hacher la source puis copier (deux lectures de la source).

## R3 — Chemins des preuves

- **Decision**: chemin relatif nettoyé (`filepath.Clean`), refusé s'il est absolu, vide, `.`, ou
  commence par `..` ; stocké dans le manifeste avec des `/` (`filepath.ToSlash`).
- **Rationale**: cas limite « chemin sortant de `evidence/` » ; manifeste portable entre Windows et
  Linux (principe IX). `filepath.IsLocal` (Go 1.20) n'est pas disponible avec `go 1.18`.

## R4 — Formats de fichiers

- **Decision**: `case.json` indenté ; `manifest.jsonl` et `case.log` en JSON Lines, ouverts en
  `O_APPEND`, une écriture `Write` par ligne suivie de `Sync`.
- **Rationale**: ajout seul sans réécriture (FR-006, FR-017) ; lisible à l'œil et par `jq`.

## R5 — Vérification

- **Decision**: pour chaque entrée du manifeste, `Lstat` puis hachage en flux (lecteur qui vérifie
  `ctx` à chaque lecture) ; `filepath.WalkDir` sur `evidence/` (ne suit pas les liens) pour
  repérer les `UNTRACKED` ; résultats triés par chemin. Une entrée de manifeste qui sort de
  `evidence/` rend le manifeste invalide (code 1).
- **Rationale**: FR-010 à FR-012, SC-004, SC-005 ; interruption → code 130.

## R6 — Codes de sortie et journal

- **Decision**: `errIntegrity` (sentinelle) → code 4. Les `exec` de `case init` et `case verify`
  écrivent leur entrée de journal via `defer`, avec le code calculé par `exitCode`. Les arguments
  journalisés sont ceux de la ligne de commande après le nom de la commande.
- **Rationale**: FR-013, FR-016, FR-017 ; un seul point de calcul des codes (spec 001, R4).
