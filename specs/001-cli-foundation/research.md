# Research: Fondation de la CLI DFIRFlow

Aucun `NEEDS CLARIFICATION` ne restait dans le Technical Context ; cette phase tranche les choix
techniques ouverts par la spec.

## R1 — Bibliothèque de parsing CLI

- **Decision**: package standard `flag`, un `flag.FlagSet` par commande.
- **Rationale**: principe I (aucune dépendance) et VII (aucune licence à auditer) ; `flag` accepte
  déjà `-x`, `--x`, `--x valeur` et `--x=valeur` (FR-004) ; le code existant l'utilise.
- **Alternatives considered**: `spf13/cobra` (Apache-2.0, sous-commandes et aide générées, mais
  ~10 dépendances transitives pour 10 commandes) ; `urfave/cli` (MIT, même constat). Rejetées :
  coût en dépendances supérieur au code à écrire.

## R2 — Options après les arguments positionnels

- **Decision**: boucle de parsing : `fs.Parse(args)`, puis si des arguments restent, le premier
  est un positionnel ; on le mémorise et on relance `fs.Parse` sur la suite. Si l'argument qui a
  arrêté le parsing est `--`, tout le reste est positionnel sans nouveau parsing.
- **Rationale**: `flag` s'arrête au premier non-option ; cette boucle de quelques lignes donne le
  comportement de FR-004 / User Story 4 sans dépendance.
- **Alternatives considered**: réordonner `args` à la main (doit connaître les options booléennes
  vs à valeur, fragile) ; bibliothèque `pflag` (dépendance pour un seul comportement).

## R3 — Option répétée

- **Decision**: type `flag.Value` « valeur unique » dont `Set` renvoie une erreur s'il est appelé
  deux fois ; utilisé pour toutes les options à valeur.
- **Rationale**: `flag` accepte silencieusement les répétitions (la dernière gagne) ; le cas limite
  `--case A --case B` doit être une erreur d'usage.
- **Alternatives considered**: compter via `fs.Visit` (ne voit pas les répétitions).

## R4 — Codes de sortie

- **Decision**: `run` renvoie une `error` ; `main` la convertit :
  erreur d'usage (type dédié, ou erreur de `flag`) → 2 ; `errNotImplemented` → 3 ;
  contexte annulé par signal → 130 ; toute autre erreur → 1 ; `nil` → 0.
- **Rationale**: un seul point de mapping, testable via `run` sans `os.Exit`.
- **Alternatives considered**: `run` renvoie directement un `int` (perd le message d'erreur pour
  les tests).

## R5 — Interruption (Ctrl+C)

- **Decision**: `signal.NotifyContext(ctx, os.Interrupt)` dans `main` (Go ≥ 1.16, compatible
  `go 1.18`), contexte passé aux commandes ; sortie 130 si le contexte est annulé.
- **Rationale**: portable Windows/Linux (principe IX) ; les commandes longues futures n'auront
  qu'à respecter `ctx`.
- **Alternatives considered**: `syscall.SIGTERM` en plus (absent sous Windows, inutile ici).

## R6 — Formats de valeurs

- **Decision**:
  - identifiant de cas : `^[A-Za-z0-9_-]{1,64}$` ;
  - dates : `2006-01-02T15:04:05Z07:00` (RFC 3339) ou `2006-01-02T15:04:05` (interprétée UTC) ;
  - listes (`--format`, `--source`) : séparées par des virgules, sans doublon ni élément vide,
    valeurs comparées en minuscules exactes ;
  - `--format` absent → `html,sqlite,jsonl`.
- **Rationale**: correspond aux FR-006, FR-011, FR-014 et aux cas limites ; une seule syntaxe de
  liste pour toute la CLI.
- **Alternatives considered**: option répétable (`--source evtx --source mft`) — rejetée car en
  conflit avec la règle « option répétée = erreur ».

## R7 — Commande `investigate`

- **Decision**: exécute séquentiellement les fonctions des commandes `collect`, `ingest`,
  `timeline`, `detect`, `correlate`, `report` avec les options pertinentes ; s'arrête et renvoie la
  première erreur, préfixée du nom de l'étape.
- **Rationale**: FR-015 — aucune logique propre ; aujourd'hui s'arrête à `collect` (code 3).
- **Alternatives considered**: relancer le binaire pour chaque étape (inutilement lourd).

## R8 — Langue et format des messages

- **Decision**: messages en anglais, préfixe `dfirflow: <commande>: ` ; erreur d'usage suivie de
  `Run 'dfirflow <commande> --help' for usage.`
- **Rationale**: cohérent avec le code existant et l'hypothèse de la spec.
