# Data Model: Détection par règles mono-événement

Aucune modification du modèle de la spec 003 : les détections suivent la structure `Detection`
(FR-019 à FR-021) et le JSONL canonique, `schema_version` 1.

## Règle (fichier Sigma)

| Champ | Obligatoire | Règle |
|---|---|---|
| `id` | oui | texte non vide, unique dans le jeu ; devient `rule_id` |
| `title` | oui | texte non vide |
| `status` | non | `stable`, `test`, `experimental` ; `deprecated` et `unsupported` écartent la règle ; autre valeur : refus |
| `level` | oui | `informational`, `low`, `medium`, `high`, `critical` ; devient `severity` (`informational` → `info`) |
| `logsource.product` | oui | `windows` (casse indifférente), sinon règle écartée |
| `logsource.service` | oui | une clé de la table des services ; `logsource.category` présent : refus |
| `tags` | non | la première `attack.tNNNN[.NNN]` devient `mitre` |
| `confidence` | non | nombre de 0 à 1 (extension DFIRFlow) ; sinon table par statut |
| `detection` | oui | sélections nommées et `condition` (research R2) |

Version : `rule_version` = 16 hexa du SHA-256 du fichier (fins de ligne ramenées à `\n`).
Fichier de plus de 1 Mio, plus d'un document YAML, YAML invalide : refus.

### Table des services

| `service` | Canal EVTX |
|---|---|
| `security` | `Security` |
| `system` | `System` |
| `application` | `Application` |
| `powershell` | `Microsoft-Windows-PowerShell/Operational` |
| `powershell-classic` | `Windows PowerShell` |
| `sysmon` | `Microsoft-Windows-Sysmon/Operational` |
| `taskscheduler` | `Microsoft-Windows-TaskScheduler/Operational` |
| `windefend` | `Microsoft-Windows-Windows Defender/Operational` |
| `wmi` | `Microsoft-Windows-WMI-Activity/Operational` |

Le canal de l'événement est comparé sans tenir compte de la casse. Le produit est examiné
avant tout autre champ : une règle d'un autre produit est écartée même si elle serait refusée.

### Table de confiance par statut

| `status` | `confidence` |
|---|---|
| `stable` | 0.8 |
| `test` | 0.6 |
| `experimental` ou absent | 0.4 |

### Champs accessibles (research R3)

| Nom dans la règle | Valeur de l'événement |
|---|---|
| `EventID` | `event_id`, en décimal |
| `Channel` | `channel` |
| `Provider_Name` | `provider` |
| `Computer` | `metadata["System.Computer"]` |
| tout autre nom | `metadata[<nom>]` |

## Issue du chargement d'une règle

```text
fichier
  ├─ produit autre que windows, statut deprecated/unsupported ──► écartée (comptée, sans avertissement)
  ├─ illisible, incomplète, fonction hors sous-ensemble ────────► refusée (avertissement : fichier, raison)
  └─ sinon ─────────────────────────────────────────────────────► appliquée
```

Jeu de règles : aucune règle appliquée → échec (code 1) ; deux règles appliquées de même `id` →
échec (code 1) ; une règle écartée ou refusée n'entre pas dans le contrôle des doublons. Version du jeu : 16 hexa du SHA-256 des lignes `<id>\x00<rule_version>\n` triées.

## Jeu embarqué

| Fichier | `id` | Canal | Condition | `level` | `status` | `mitre` |
|---|---|---|---|---|---|---|
| `security_log_cleared.yml` | `8ad87a09-d977-4445-9e5a-962e9023846b` | Security | `EventID` 1102, `Provider_Name` Microsoft-Windows-Eventlog | high | stable | T1070.001 |
| `system_log_cleared.yml` | `7f021602-7eb2-46cc-bd9c-8791ff6b80c6` | System | `EventID` 104, `Provider_Name` Microsoft-Windows-Eventlog | high | stable | T1070.001 |
| `audit_policy_changed.yml` | `16e98cfe-8ffe-44bc-8353-804570a5f7b3` | Security | `EventID` 4719 | medium | test | T1562.002 |
| `user_account_created.yml` | `92be069d-0b8f-4ecd-a4c3-236eb494fa35` | Security | `EventID` 4720 | medium | test | T1136.001 |
| `privileged_group_member_added.yml` | `c45e29cd-cdb3-495e-9bb4-596a96da98bb` | Security | `EventID` 4728, 4732 ou 4756 et `TargetSid` égal à `S-1-5-32-544` ou finissant par `-512`, `-518`, `-519` | high | test | T1098 |
| `service_installed.yml` | `937be0a0-b743-4102-83e6-25f8c5eed60b` | System | `EventID` 7045, `Provider_Name` Service Control Manager | medium | test | T1543.003 |
| `scheduled_task_created.yml` | `5f1c65f2-02d2-4919-abcd-8f4b6066b681` | Security | `EventID` 4698 | medium | test | T1053.005 |

Le groupe est identifié par son SID et non par son nom, qui dépend de la langue du système.

## Détection produite

| Champ (spec 003) | Valeur |
|---|---|
| `id` | `DetectionID(rule_id, rule_version, [uid])` (FR-020) |
| `timestamp` | horodatage principal de l'événement |
| `rule_id`, `rule_version` | de la règle |
| `severity`, `confidence`, `mitre` | de la règle (tables ci-dessus) |
| `events` | `[uid]` de l'événement |

Clé de tri : `(timestamp µs, id)`, ordre croissant (spec 003, FR-021).

## Résumé d'exécution

| Champ | Sens |
|---|---|
| `rules` | `embedded` ou chemin donné à `--rules` |
| `ruleset_version` | version du jeu appliqué |
| `rules_applied`, `rules_skipped` | règles appliquées, écartées |
| `rules_refused` | liste `{file, reason}`, triée par fichier |
| `files` | fichiers d'événements lus |
| `events_read` | événements lus |
| `detections` | détections écrites |
| `sha256` | empreinte de `detections/detections.jsonl` (succès seulement) |
| `unknown_files` | fichiers de `normalized/` hors manifeste |

## Entrée `detect` de `case.log`

```json
{"command":"detect", "...":"champs communs (spec 002)",
 "summary":{"rules":"embedded","ruleset_version":"<16 hex>",
  "rules_applied":7,"rules_skipped":0,
  "rules_refused":[{"file":"rules/agg.yml","reason":"aggregation is not supported"}],
  "files":1,"events_read":739,"detections":15,"sha256":"<64 hex>"}}
```

`rules_refused` et `unknown_files` sont omis quand ils sont vides. En cas d'échec, `sha256` est
omis et `error` porte la cause. Si le jeu de règles est inutilisable (aucune règle applicable,
identifiants en double), `ruleset_version` est omis mais les comptes et `rules_refused` restent ;
si le chemin de `--rules` est introuvable, les comptes sont omis aussi. `files`, `events_read` et
`detections` sont omis si aucun événement n'a été lu.

## États du fichier de détections

```text
absent ou précédent
  ├─ aucun fichier d'événements, règles inutilisables ──► inchangé (code 1)
  ├─ ligne refusée / erreur d'écriture ─────────────────► inchangé, temporaires supprimés (code 1)
  ├─ interruption ──────────────────────────────────────► inchangé, temporaires supprimés (code 130)
  └─ succès ────────────────────────────────────────────► remplacé par le nouveau (code 0)
```
