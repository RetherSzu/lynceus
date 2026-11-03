# Contrat CLI : dfirflow

Contrat public de la ligne de commande. Toute modification incompatible (nom de commande ou
d'option, valeur acceptée, code de sortie) est une rupture et doit passer par une spec.

## Invocation globale

```text
dfirflow [-h | --help]
dfirflow --version
dfirflow <commande> [options] [arguments]
dfirflow <commande> -h | --help
```

- Sans argument : aide générale, code 0.
- `--version` : `DFIRFlow <version>\n` sur stdout, code 0 ; combiné à une commande → code 2.
- Options : `-nom`, `--nom`, `--nom valeur`, `--nom=valeur` ; avant ou après les positionnels ;
  `--` termine les options.

## Commandes

| Commande | Positionnels | Options obligatoires | Options facultatives |
|---|---|---|---|
| `case init` | `<ID>` (exactement 1) | `--host`, `--analyst` | `--dir` (défaut `./cases`) |
| `case verify` | aucun | `--case` | — |
| `collect` | aucun | `--case`, `--target` | — |
| `ingest` | `[chemin…]` (0..n) | `--case` | — |
| `import` | `<chemin>` (exactement 1) | `--case`, `--tool` | — |
| `timeline` | aucun | `--case` | `--from`, `--to`, `--source` |
| `detect` | aucun | `--case` | `--rules` |
| `correlate` | aucun | `--case` | — |
| `report` | aucun | `--case` | `--format` (défaut `html,sqlite,jsonl`) |
| `investigate` | aucun | `--case`, `--target` | — |

## Valeurs acceptées

| Option | Format |
|---|---|
| `<ID>` | `^[A-Za-z0-9_-]{1,64}$` |
| `--case`, `--target`, `--dir`, `--rules`, chemins | chemin non vide |
| `import --tool` | `kape`, `orc`, `eztools`, `hayabusa`, `plaso`, `volatility` |
| `timeline --from`, `--to` | RFC 3339 (`2026-11-02T09:00:00Z`, `…+01:00`) ou sans fuseau (UTC) ; `--from` ≤ `--to` |
| `timeline --source` | liste séparée par virgules parmi `evtx`, `mft`, `usnjrnl`, `registry`, `prefetch`, `powershell`, `defender`, `memory` |
| `report --format` | liste séparée par virgules parmi `html`, `sqlite`, `jsonl` |

Listes : pas de doublon, pas d'élément vide.

## Sorties

- **stdout** : aide et résultats uniquement.
- **stderr** : diagnostics, format `dfirflow: <commande>: <message>`.
  - Erreur d'usage : message nommant l'option/argument en cause, puis
    `Run 'dfirflow <commande> --help' for usage.`
  - Non implémenté : `dfirflow: <commande>: not implemented yet`.
  - `investigate` : `dfirflow: investigate: <étape>: not implemented yet`.

## Codes de sortie

| Code | Signification |
|---|---|
| 0 | succès |
| 1 | échec d'exécution |
| 2 | erreur d'usage |
| 3 | fonctionnalité non implémentée |
| 130 | interruption utilisateur |
