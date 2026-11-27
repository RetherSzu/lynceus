# Modèle de données : catégories de sources et modificateurs Sigma

Complète le modèle de la spec 012 (`specs/012-detection/data-model.md`) ; ce qui n'est pas
repris ici est inchangé.

## Table des catégories (`internal/detection/categories.json`)

Tableau JSON d'objets `{category, sources}` ; chaque source :

| Champ | Type | Règle |
|---|---|---|
| `name` | texte | identifiant de la source, unique dans la table, cité par `case.log` et la sortie d'erreur |
| `label` | texte | libellé lisible pour l'avertissement (`Security 4688`) |
| `channel` | texte | canal EVTX, comparé sans tenir compte de la casse |
| `event_ids` | entiers | au moins un |
| `event_type` | textes | facultatif : valeurs admises du champ `EventType`, comparées sans tenir compte de la casse |
| `rename` | table | facultatif : nom du champ dans la règle → nom du champ dans l'événement |
| `fields` | textes | facultatif : présent seulement pour une source **partielle**, liste des champs de la règle qu'elle fournit, en plus des champs communs |

Champs communs, toujours fournis : `EventID`, `Channel`, `Provider_Name`, `Computer`.

Validation au chargement (une table invalide est une erreur de construction, détectée par les
tests, jamais par l'utilisateur) : catégories et noms de sources uniques, `event_ids` non vide,
`rename` et `fields` cohérents (tout champ renommé d'une source partielle figure dans `fields`).

Version : 16 premiers caractères hexadécimaux du SHA-256 du fichier (research R1).

### Contenu

| Catégorie | Source (`name`) | Canal | EventID | Contrainte `EventType` |
|---|---|---|---|---|
| `process_creation` | `sysmon-1` | Microsoft-Windows-Sysmon/Operational | 1 | |
| `process_creation` | `security-4688` | Security | 4688 | |
| `network_connection` | `sysmon-3` | Sysmon | 3 | |
| `driver_load` | `sysmon-6` | Sysmon | 6 | |
| `image_load` | `sysmon-7` | Sysmon | 7 | |
| `create_remote_thread` | `sysmon-8` | Sysmon | 8 | |
| `process_access` | `sysmon-10` | Sysmon | 10 | |
| `file_event` | `sysmon-11` | Sysmon | 11 | |
| `registry_add` | `sysmon-12-add` | Sysmon | 12 | `CreateKey` |
| `registry_delete` | `sysmon-12-delete` | Sysmon | 12 | `DeleteKey`, `DeleteValue` |
| `registry_set` | `sysmon-13` | Sysmon | 13 | `SetValue` |
| `registry_event` | `sysmon-12-14` | Sysmon | 12, 13, 14 | |
| `pipe_created` | `sysmon-17-18` | Sysmon | 17, 18 | |
| `wmi_event` | `sysmon-19-21` | Sysmon | 19, 20, 21 | |
| `dns_query` | `sysmon-22` | Sysmon | 22 | |
| `ps_module` | `powershell-4103` | Microsoft-Windows-PowerShell/Operational | 4103 | |
| `ps_script` | `powershell-4104` | Microsoft-Windows-PowerShell/Operational | 4104 | |

`security-4688` est la seule source partielle :

- `label` : `Security 4688` ;
- `rename` : `Image` → `NewProcessName`, `ParentImage` → `ParentProcessName` ;
- `fields` : `Image`, `ParentImage`, `CommandLine`.

Les sources Sysmon et PowerShell n'ont ni `rename` ni `fields` : les noms des règles sont ceux des
données d'événement (research R2).

## Règle (ajouts à la spec 012)

| Attribut | Règle |
|---|---|
| Source déclarée | `logsource.service` (spec 012) ou `logsource.category`, ou les deux (research R5) |
| Champs cités | clés des sélections et cibles de `fieldref`, calculés à la compilation |
| Entrées | une ou plusieurs `(règle, source)` après la garde (research R4) |
| Restrictions | sources partielles exclues par la garde, avec les champs manquants |

Ordre des contrôles de `logsource` :

1. `product` absent → refus `missing logsource.product` ; autre que `windows` → écartée (inchangé).
2. Ni `service` ni `category` → refus `missing logsource.service or logsource.category`.
3. `category` hors de la table → refus `unknown logsource category: <c>`.
4. `service` inconnu → refus `unknown logsource service: <s>` (inchangé).
5. Les deux : sources de la catégorie sur le canal du service ; aucune → refus
   `logsource category and service do not match`.
6. Après compilation de la détection : garde ; aucune source restante → refus
   `fields not available in any source: <champs triés, séparés par des virgules>`.

La raison `logsource category is not supported` de la spec 012 disparaît.

## Modificateurs (ajouts à la spec 012)

| Modificateur | Place | Valeurs | Combinable avec |
|---|---|---|---|
| `windash` | toute place | textes | position, `all`, `cased` |
| `cidr` | seul (avec `all`) | préfixes IPv4 ou IPv6 | `all` |
| `base64`, `base64offset` | avant la position | textes | encodage avant, position après, `all` |
| `wide`, `utf16le`, `utf16be` | avant `base64` ou `base64offset` | textes | `base64`, `base64offset` |
| `exists` | seul | un booléen `true` ou `false` | aucun |
| `cased` | toute place | textes | position, `all`, `windash`, `fieldref` |
| `fieldref` | seul (avec `cased`, `all`) | noms de champs | `cased`, `all` |

Refus `unsupported modifier: <mod>` pour : `re` avec un modificateur de cette table ; deux
modificateurs base64 ; deux encodages ; un encodage absent avant un base64 ou placé après ;
`base64*` avec `windash` ou `cased` (comparaison base64 toujours sensible à la casse) ; `cidr`,
`exists` ou `fieldref` avec un modificateur non listé ; un modificateur répété.

Refus de valeur : `invalid selection <nom>: field <champ>: <cause>` pour un préfixe `cidr`
invalide, une valeur `exists` non booléenne ou multiple, une cible `fieldref` vide.

Modificateurs toujours refusés : `expand`, `gt`, `gte`, `lt`, `lte`, `minute`, `hour`, `day`,
`week`, `month`, `year`, `utf16`, options `m` et `s` de `re`, tout nom inconnu.

## Jeu embarqué (ajouts)

| Fichier | Titre | Catégorie | Sélection | Niveau, statut | ATT&CK |
|---|---|---|---|---|---|
| `proc_creation_powershell_encoded.yml` | PowerShell encoded command | `process_creation` | `Image` finit par `\powershell.exe` ou `\pwsh.exe` ; `CommandLine\|windash\|contains` ` -enc`, ` -encodedcommand`, ` -ec ` | medium, test | T1059.001 |
| `proc_creation_vssadmin_delete_shadows.yml` | Shadow copies deleted with vssadmin | `process_creation` | `Image` finit par `\vssadmin.exe` ; `CommandLine\|contains\|all` `delete`, `shadows` | high, test | T1490 |
| `proc_creation_certutil_download.yml` | File download with certutil | `process_creation` | `Image` finit par `\certutil.exe` ; `CommandLine\|windash\|contains` ` -urlcache`, ` -verifyctl` | medium, test | T1105 |
| `registry_set_run_key.yml` | Autorun registry value set | `registry_set` | `TargetObject\|contains` `\Software\Microsoft\Windows\CurrentVersion\Run\`, `\Software\Microsoft\Windows\CurrentVersion\RunOnce\` | medium, test | T1547.001 |
| `ps_script_download_execute.yml` | PowerShell script downloads and executes code | `ps_script` | `ScriptBlockText\|contains` `DownloadString(`, `DownloadFile(`, `Invoke-WebRequest` ; et `ScriptBlockText\|contains` `IEX`, `Invoke-Expression` ; condition `all of selection_*` | medium, test | T1059.001 |

Identifiants UUID v4 : `proc_creation_powershell_encoded.yml` 94b506b2-9a79-4e99-9e7c-8de7ec0280c5,
`proc_creation_vssadmin_delete_shadows.yml` 640e0339-c6ec-44c6-ac37-cf83d4d59f37,
`proc_creation_certutil_download.yml` fd6c81ea-7967-4928-8a61-fcd5af347728,
`registry_set_run_key.yml` 33591d7c-fcc9-4365-83e7-4bd5e79976fc,
`ps_script_download_execute.yml` 5aa5ae5e-ab5b-4d44-85ad-7fde1a9291b3 ; en-têtes `author: DFIRFlow`,
`license: Apache-2.0`, description en anglais, comme en spec 012.

Cas de test, en plus d'un positif et d'un négatif Sysmon par règle : les trois règles
`process_creation` ont un positif et un négatif 4688 ; `registry_set_run_key` a un négatif
Sysmon 12 de même chemin (création de clé) ; `ps_script_download_execute` a un négatif qui
télécharge sans exécuter.

Après l'ajout : 12 règles embarquées, 0 refus, 0 restriction ; sur le journal Security de
référence, toujours 15 détections (SC-006).

## Entrée `detect` de `case.log` (ajouts)

| Clé | Contenu |
|---|---|
| `categories_version` | version de la table des catégories (toujours présente dès que le jeu de règles est chargé) |
| `rules_restricted` | liste triée par fichier puis source de `{file, source, missing}` (`missing` : champs triés) ; omise si vide |

La ligne de résumé et les autres clés sont inchangées.
