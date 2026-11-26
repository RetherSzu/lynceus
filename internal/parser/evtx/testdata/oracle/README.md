# Sorties de référence (oracle)

| Fichier | Outil | Version | Commande | Date |
|---|---|---|---|---|
| `Security.evtx_dump.jsonl` | `evtx_dump` (omerbenamram/evtx, MIT/Apache-2.0) | 0.12.3, binaire `x86_64-unknown-linux-gnu`, SHA-256 `a64220cd31e006b4d37c90adb6cca776120f463953b59de71a8089563307b937` | `evtx_dump -o jsonl ../Security.evtx` | 2026-11-25 |

Le binaire n'est pas versionné ; il n'est exécuté que pour produire ce fichier, jamais par DFIRFlow
(constitution, principe II).

## Champs comparés

`TestOracleEvtxDump` compare, pour chacun des 739 enregistrements : `TimeCreated` (horodatage
principal), `EventID`, `Channel`, `Provider/@Name`, et chaque valeur de `EventData` ou de `UserData`
(élément racine omis).

## Écarts connus

| Écart | DFIRFlow | evtx_dump | Justification |
|---|---|---|---|
| GUID de substitution | `{54849625-5478-4994-A5BA-3E3B0328C30D}` | `54849625-5478-4994-A5BA-3E3B0328C30D` | spec 003 FR-013 : rendu de la vue XML Windows, entre accolades |

Aucun autre écart. La sortie EvtxECmd, produite hors CI (environnement .NET), sera ajoutée à ce
dossier avec ses propres écarts.
