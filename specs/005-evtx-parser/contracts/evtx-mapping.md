# Contrat : table de correspondance EVTX (`mapping.json`)

Fichier `internal/parser/evtx/mapping.json`, embarqué dans le binaire. Toute modification est
versionnée avec l'outil (`tool_version`) et accompagnée d'un cas de test.

## Format

Tableau JSON d'entrées ; décodage strict (champ inconnu = erreur).

```json
[
  {
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
    "event_id": 4624,
    "event_type": "logon",
    "fields": {
      "subject.sid": "SubjectUserSid",
      "subject.domain": "SubjectDomainName",
      "subject.name": "SubjectUserName",
      "target.sid": "TargetUserSid",
      "target.domain": "TargetDomainName",
      "target.name": "TargetUserName",
      "process": "ProcessName",
      "process_id": "ProcessId"
    }
  },
  {
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": 1,
    "event_type": "process_creation",
    "action_time": "UtcTime",
    "action_time_type": "executed",
    "fields": {
      "subject.domain": "User",
      "process": "Image",
      "process_id": "ProcessId",
      "parent_process": "ParentImage",
      "parent_process_id": "ParentProcessId",
      "command_line": "CommandLine",
      "hashes": "Hashes"
    }
  }
]
```

## Règles

- Clé d'entrée : (`channel`, `provider`, `event_id`), comparés sans casse pour les chaînes ; unique.
- `event_type` : liste de la spec 003 FR-007, `other` interdit (c'est la valeur par défaut).
- `fields` : clés de la liste du data-model ; valeur = nom d'un champ de `EventData` ou `UserData`.
  Un champ source absent de l'événement laisse le champ normalisé vide.
- `subject.domain` sur une valeur `DOMAINE\nom` (Sysmon `User`) : découpée en `domain` et `name`.
- `process_id`, `parent_process_id` : décimal ou `0x…` acceptés.
- `hashes` : chaîne Sysmon `SHA1=…,MD5=…,SHA256=…,IMPHASH=…`, découpée et passée en minuscules
  (spec 003 C9).

## Couverture initiale (spec 005, FR-011)

| Canal | Fournisseur | EventID | event_type |
|---|---|---|---|
| Security | Microsoft-Windows-Security-Auditing | 4624 | logon |
| Security | Microsoft-Windows-Security-Auditing | 4625 | logon_failed |
| Security | Microsoft-Windows-Security-Auditing | 4634, 4647 | logoff |
| Security | Microsoft-Windows-Security-Auditing | 4688 | process_creation |
| Security | Microsoft-Windows-Security-Auditing | 4697 | service_install |
| Security | Microsoft-Windows-Eventlog | 1102 | log_cleared |
| System | Service Control Manager | 7045 | service_install |
| System | Microsoft-Windows-Eventlog | 104 | log_cleared |
| Microsoft-Windows-Sysmon/Operational | Microsoft-Windows-Sysmon | 1 | process_creation |
| Microsoft-Windows-PowerShell/Operational | Microsoft-Windows-PowerShell | 4104 | script_execution |
| Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender | 1116, 1117 | malware_detected |
| Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender | 5001, 5007 | av_config_change |

Les correspondances de champs reprises des *Maps* d'EvtxECmd (MIT) citent leur origine dans
`internal/parser/evtx/NOTICE`.
