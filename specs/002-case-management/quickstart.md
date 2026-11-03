# Quickstart: valider la gestion des cas

## Prérequis

`make build` depuis la racine (produit `bin/dfirflow`), puis travailler dans un dossier vide :

```bash
B=$PWD/bin/dfirflow; cd "$(mktemp -d)"
```

## 1. Tests automatisés

```bash
go test ./internal/case/ ./cmd/dfirflow/ -race -v
```

## 2. Création (User Story 1)

```bash
$B case init CASE-001 --host WIN-CLIENT01 --analyst dfir-team   # affiche cases/CASE-001, exit 0
ls cases/CASE-001                                               # case.json case.log detections evidence hashes normalized parsed reports timeline
cat cases/CASE-001/case.json                                    # schema_version 1, created_at en UTC
$B case init CASE-001 --host X --analyst Y; echo $?             # 1, dossier inchangé
```

## 3. Vérification (User Story 2)

```bash
$B case verify --case ./cases/CASE-001; echo $?                 # "0 evidence files…", 0
echo test > cases/CASE-001/evidence/notes.txt
$B case verify --case ./cases/CASE-001; echo $?                 # UNTRACKED notes.txt, 4
$B case verify --case ./nope; echo $?                           # 1
```

Les statuts `MODIFIED` et `MISSING` (preuves enregistrées puis altérées) sont couverts par les
tests du package, l'enregistrement n'ayant pas de commande avant la spec 004.

## 4. Journal (User Story 4)

```bash
cat cases/CASE-001/case.log    # une ligne par commande : case init (0), case verify (0), case verify (4)
```
