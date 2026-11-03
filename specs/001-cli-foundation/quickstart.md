# Quickstart: valider la fondation de la CLI

## Prérequis

- Go installé (version de `go.mod` ou plus récente).
- Depuis la racine du dépôt : `make build` (produit `bin/dfirflow`).

## 1. Tests automatisés

```bash
go test ./cmd/dfirflow/ -race -v
```

Attendu : tous les tests passent, y compris `TestRunVersion` et `TestRunHelp` inchangés (SC-006).

## 2. Aide (User Story 1)

```bash
bin/dfirflow;          echo "exit=$?"   # aide générale, exit=0
bin/dfirflow --help;   echo "exit=$?"   # 10 commandes dans l'ordre du pipeline, exit=0
bin/dfirflow detect -h; echo "exit=$?"  # --case (obligatoire), --rules, un exemple, exit=0
bin/dfirflow --version                  # DFIRFlow <version>
```

## 3. Erreurs d'usage (User Story 2) — attendu : exit=2, stdout vide

```bash
bin/dfirflow detect                                        # --case manquant
bin/dfirflow analyze                                       # commande inconnue
bin/dfirflow import --case ./cases/C1 --tool foo ./x       # valeurs --tool listées
bin/dfirflow report --case ./cases/C1 --format pdf         # formats listés
bin/dfirflow case init ../evil --host H --analyst A        # ID refusé
bin/dfirflow detect --case A --case B                      # option répétée
bin/dfirflow timeline --case C --from 2026-11-02T10:00:00Z --to 2026-11-01T00:00:00Z
```

Vérifier chaque code : `bin/dfirflow detect >/dev/null; echo $?` → `2`.

## 4. Non implémenté (User Story 3) — attendu : exit=3, aucun fichier créé

```bash
tmp=$(mktemp -d) && cd "$tmp"
/chemin/vers/bin/dfirflow case init CASE-001 --host H --analyst A; echo "exit=$?"
/chemin/vers/bin/dfirflow investigate --case ./cases/CASE-001 --target ./evidence; echo "exit=$?"
ls -A "$tmp"   # doit être vide
```

Le second message doit nommer l'étape `collect`.

## 5. Script (User Story 4)

```bash
bin/dfirflow ingest ./logs --case ./cases/CASE-001; echo "exit=$?"   # options après positionnel → 3
bin/dfirflow ingest --case ./cases/CASE-001 -- -fichier.evtx          # '--' accepté → 3
```
