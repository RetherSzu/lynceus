# Quickstart: valider le modèle d'événement

Pas de commande utilisateur dans cette spec (hors FR-026) : la validation passe par les tests.

## 1. Tests automatisés

```bash
go test ./internal/normalizer/ ./internal/parser/ ./cmd/dfirflow/ -race -v
```

Couvre US1 (validation, `uid`), US2 (fichier de référence, aller-retour, tri, décodage strict),
US3 (faux parseur, anomalies, annulation), US4 (détections), US5 (version non prise en charge).

## 2. Déterminisme du fichier de référence (SC-001)

```bash
for i in 1 2; do go test ./internal/normalizer/ -run Golden -count=1 -update && sha256sum internal/normalizer/testdata/events.v1.jsonl; done
# deux régénérations, même empreinte et git diff vide ; Windows : TestGolden compare les octets (job test-windows)
```

## 3. Lisibilité par un outil tiers

```bash
jq -c 'select(.event_type=="logon") | {timestamp, host, target}' \
  internal/normalizer/testdata/events.v1.jsonl
```

Chaque ligne est un objet autonome (`schema_version` inclus).

## 4. Amendement CLI (FR-026)

```bash
make build
bin/dfirflow timeline --case ./cases/CASE-001 --source evtx,mft; echo $?   # 3 (non implémenté)
bin/dfirflow timeline --case ./cases/CASE-001 --source powershell; echo $? # 2 (valeur refusée)
```
