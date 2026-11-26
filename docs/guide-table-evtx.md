# Guide : maintenir la table de correspondance EVTX

Ce guide s'adresse à toute personne qui veut faire reconnaître un nouvel événement Windows par
DFIRFlow, ou corriger la façon dont un événement est interprété. Il ne demande aucune connaissance
du code Go du parser.

- **Fichier concerné** : `internal/parser/evtx/mapping.json`
- **Applicable à partir de** : spec 005 (parser EVTX)
- **Contrat normatif** : [specs/005-evtx-parser/contracts/evtx-mapping.md](../specs/005-evtx-parser/contracts/evtx-mapping.md)

---

## 1. À quoi sert la table

Chaque enregistrement d'un journal EVTX devient un événement normalisé (modèle de la spec 003).
Le parser remplit toujours les champs communs : horodatage, canal, fournisseur, EventID, hôte,
provenance, et toutes les données de l'événement dans `metadata`.

La table ajoute, pour les événements qu'elle connaît :

- le **type d'événement** (`event_type`) : `logon`, `process_creation`… ;
- l'**extraction des champs normalisés** : compte qui agit (`subject`), compte visé (`target`),
  processus, ligne de commande, empreintes… ;
- au besoin, le champ qui porte l'**instant réel de l'action** (ex. `UtcTime` de Sysmon).

Un événement absent de la table n'est pas perdu : il est écrit avec `event_type = other`, et toutes
ses données restent dans `metadata`. Les règles de détection qui portent sur le canal, l'EventID ou
les champs de `metadata` continuent de fonctionner. La table améliore le classement et la
recherche, elle ne conditionne pas la conservation des données.

## 2. Repérer les événements à ajouter

À la fin de chaque ingestion, `dfirflow ingest` affiche la part des événements classés `other` et
les dix couples (canal, EventID) non classés les plus fréquents :

```text
other: 41.2% (608 events); top: Security/4672=210, System/7036=95, ...
```

Ces informations figurent aussi dans `case.log` (champ `top_other` de l'entrée `ingest`). Elles
indiquent les ajouts qui auront le plus d'effet.

## 3. Structure d'une entrée

```json
{
  "channel": "Security",
  "provider": "Microsoft-Windows-Security-Auditing",
  "event_id": 4720,
  "event_type": "...",
  "fields": {
    "subject.sid": "SubjectUserSid",
    "subject.domain": "SubjectDomainName",
    "subject.name": "SubjectUserName",
    "target.sid": "TargetSid",
    "target.domain": "TargetDomainName",
    "target.name": "TargetUserName"
  }
}
```

| Champ | Obligatoire | Contenu |
|---|---|---|
| `channel` | oui | nom du journal tel qu'il apparaît dans `System/Channel` (ex. `Security`) |
| `provider` | oui | fournisseur tel qu'il apparaît dans `System/Provider/@Name` |
| `event_id` | oui | numéro de l'événement (`System/EventID`) |
| `event_type` | oui | une valeur de la liste du §4 ; jamais `other` |
| `action_time` | non | nom du champ de `EventData` qui porte l'instant de l'action |
| `action_time_type` | si `action_time` | type de cet horodatage : `created`, `modified`, `accessed`, `changed`, `executed`, `logged` |
| `fields` | oui (peut être vide) | champ normalisé → nom du champ source dans `EventData` ou `UserData` |

Le triplet (`channel`, `provider`, `event_id`) identifie l'entrée : il doit être unique dans la
table. Les comparaisons de chaînes ignorent la casse.

Champs normalisés utilisables dans `fields` :

| Clé | Signification |
|---|---|
| `subject.sid`, `subject.domain`, `subject.name` | compte qui agit ou demande l'action |
| `target.sid`, `target.domain`, `target.name` | compte sur lequel porte l'action |
| `process`, `process_id` | processus à l'origine de l'événement |
| `parent_process`, `parent_process_id` | processus parent |
| `command_line` | ligne de commande |
| `file_path` | fichier concerné |
| `registry_path` | clé ou valeur de registre concernée |
| `hashes` | chaîne d'empreintes au format Sysmon (`SHA1=…,MD5=…`) |

Règles de conversion appliquées automatiquement :

- une valeur `-`, vide ou `S-1-0-0` est traitée comme absente ;
- une valeur `DOMAINE\nom` placée dans `subject.domain` ou `target.domain` est découpée en domaine
  et nom ;
- `process_id` et `parent_process_id` acceptent le décimal et l'hexadécimal (`0x…`) ;
- un champ source absent de l'événement laisse le champ normalisé vide, sans erreur.

## 4. Types d'événement disponibles

La liste est fermée (spec 003, FR-007) :

| Valeur | Sens |
|---|---|
| `logon` | ouverture de session réussie |
| `logon_failed` | échec d'ouverture de session |
| `logoff` | fermeture de session |
| `process_creation` | création de processus |
| `service_install` | installation de service |
| `script_execution` | exécution de script (PowerShell…) |
| `log_cleared` | effacement d'un journal |
| `malware_detected` | détection par l'antivirus |
| `av_config_change` | modification de la configuration de l'antivirus |

Si aucun type ne convient, ne pas ajouter d'entrée : l'événement reste `other`. Ajouter un nouveau
type modifie le modèle d'événement partagé par tous les parsers ; cela passe par une spec dédiée
(voir §7), pas par une simple modification de la table.

## 5. Procédure d'ajout ou de modification

1. **Identifier l'événement** : relever le canal, le fournisseur et l'EventID exacts dans un
   enregistrement réel (vue XML de l'Observateur d'événements, ou fichier normalisé produit par
   `ingest`, champs `channel`, `provider`, `event_id`).
2. **Relever les noms des champs** : ce sont les clés de `metadata` dans le fichier normalisé, ou
   les attributs `Name` de `EventData/Data` dans la vue XML. Respecter leur orthographe exacte.
3. **Ajouter l'entrée** dans `mapping.json`, en conservant l'ordre du fichier : par canal, puis
   fournisseur, puis EventID croissant.
4. **Ajouter un cas de test** : un enregistrement de référence de cet événement et le résultat
   attendu (type et champs normalisés), selon les conventions des tests de
   `internal/parser/evtx/` (voir `mapping_test.go`). Les journaux de test doivent être synthétiques
   ou sous licence compatible ; aucun journal issu d'un système réel de personne ou d'organisation.
5. **Lancer les tests** : `go test ./internal/parser/evtx/...`. Ils refusent une table invalide :
   triplet en double, type hors liste ou égal à `other`, champ normalisé inconnu, `action_time`
   sans `action_time_type`.
6. **Indiquer la source** : si la correspondance est reprise des *Maps* d'EvtxECmd (licence MIT),
   le mentionner dans `internal/parser/evtx/NOTICE`.

La table est intégrée au binaire : une modification prend effet à la compilation suivante et est
datée par la version de l'outil enregistrée dans chaque cas (`tool_version`).

## 6. Exemple complet : exécution PowerShell (4104)

Enregistrement (extrait de la vue XML Windows) :

```xml
<System>
  <Provider Name="Microsoft-Windows-PowerShell" />
  <EventID>4104</EventID>
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
</System>
<EventData>
  <Data Name="MessageNumber">1</Data>
  <Data Name="ScriptBlockText">Get-Process</Data>
  <Data Name="Path">C:\temp\a.ps1</Data>
</EventData>
```

Entrée de table :

```json
{
  "channel": "Microsoft-Windows-PowerShell/Operational",
  "provider": "Microsoft-Windows-PowerShell",
  "event_id": 4104,
  "event_type": "script_execution",
  "fields": {
    "file_path": "Path"
  }
}
```

Résultat : `event_type = script_execution`, `file_path = C:\temp\a.ps1`. `ScriptBlockText` et
`MessageNumber` restent disponibles dans `metadata`.

## 7. Ce que la table ne permet pas

| Besoin | Démarche |
|---|---|
| Nouveau type d'événement | spec modifiant le modèle 003 (liste fermée, historique des versions du contrat) |
| Nouveau champ normalisé | idem : le modèle `Event` est un contrat partagé |
| Calcul ou combinaison de valeurs | évolution du parser EVTX, par spec |
| Classement selon le contenu d'un champ (ex. type d'ouverture de session) | évolution du format de la table, par spec |
| Détection d'un comportement malveillant | règles de détection (spec 012), pas la table |
