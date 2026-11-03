# Rapport de spike — modèle Event (spec 003)

**Date** : 2026-11-03 · **Code** : `spikes/003-model/` (module Go séparé, jetable, hors binaire)

## Objet

Confronter la struct `Event` et l'interface `Parser` actuelles à de vrais artefacts avant de
spécifier, pour ne pas rouvrir la 003 pendant les specs 005 (EVTX) et 009 ($MFT).

## Matériel

| Élément | Source | Licence | Usage |
|---|---|---|---|
| `www.velocidex.com/golang/evtx` v0.2.0 | Velocidex | Apache-2.0 | parsing EVTX |
| `www.velocidex.com/golang/go-ntfs` v0.2.1 | Velocidex | Apache-2.0 | parsing NTFS / $MFT |
| 6 fichiers EVTX (`EVTX-ATTACK-SAMPLES`) | sbousseaden | **GPL** | local uniquement (scratchpad), non commités |
| `testdata/Security.evtx` | dépôt `evtx` | Apache-2.0 | 739 enregistrements |
| `parser/test_data/test.ntfs.dd` | dépôt `go-ntfs` | Apache-2.0 | image NTFS 10 Mo |

Volume : **768 enregistrements EVTX** (Security, System, PowerShell/Operational,
Sysmon/Operational) dont les 6 EventID visés (4624, 4625, 4688, 7045, 4104, Sysmon 1) ;
**39 entrées $MFT**. Pas de comparaison EvtxECmd (non disponible) : voir « Vérifications restantes ».

## Constats

### C1 — L'horodatage d'en-tête d'enregistrement n'est pas fiable → D5, D10

L'en-tête binaire de chaque enregistrement EVTX porte un FILETIME distinct de
`System/TimeCreated`. Écart observé jusqu'à **289 s**, et l'en-tête vaut **0** sur certains
enregistrements (fichiers exportés). `TimeCreated` est le seul horodatage d'événement fiable.

### C2 — Précision de l'horodatage → D10

La bibliothèque expose `TimeCreated` en secondes flottantes (`1599657503.627952`), soit une
précision effective de la **microseconde**, contre 100 ns pour le FILETIME d'origine. Les
horodatages $MFT de `go-ntfs` sortent aussi à la microseconde sur l'échantillon.

### C3 — Deux numéros d'enregistrement → D4

Le numéro d'en-tête (`RecordID`) et `System/EventRecordID` diffèrent sur **29/768**
enregistrements (fichiers exportés, renumérotés). Le premier est unique dans le fichier ; le
second est celui que voient l'Observateur d'événements et les autres outils. Il faut garder les
deux et choisir lequel entre dans l'identifiant.

### C4 — Plusieurs horodatages sémantiques dans un même enregistrement EVTX → D2

Sysmon porte `EventData/UtcTime` (instant de l'action) en plus de `TimeCreated` (écriture du
journal) : écart observé jusqu'à **58 s**. La question de la granularité ne concerne donc pas
que $MFT.

### C5 — $MFT : 8 horodatages par entrée, mais 1,4 valeur distincte en moyenne → D2

Sur l'image de test, 39 entrées produisent 56 horodatages distincts (**1,4 par entrée** au lieu
de 8). Un événement « par horodatage distinct, avec la liste des types qu'il couvre » (style
MACB / bodyfile) coûterait ~1,4× au lieu de 8×. Échantillon synthétique : sur un vrai système
(accès désactivés, timestomping) la moyenne sera plus élevée, à mesurer en spec 009.

### C6 — Plusieurs utilisateurs par événement, sous plusieurs formes → D7

| Événement | Champs utilisateur présents |
|---|---|
| 4624/4625 | `Subject*` (demandeur) **et** `Target*` (compte connecté), chacun SID + domaine + nom |
| 4688 | `Subject*` (créateur) et `Target*` (compte du nouveau processus) |
| 4104, 7045 | seulement `System/Security/UserID` (SID, sans nom) |
| Sysmon 1 | `User` = `NT AUTHORITY\SYSTEM` (nom, sans SID) |
| 1102 | `UserData/LogFileCleared/Subject*` |

Un seul champ `User` texte ne suffit pas : il faut au minimum distinguer **SID et nom**, et
décider s'il y a un ou deux acteurs (sujet / cible). Les valeurs `-` signifient « absent ».

### C7 — `Host` non homogène → D7

`Computer` vaut tantôt un nom court (`MSEDGEWIN10`), tantôt un FQDN
(`WIN-77LTAPHIQ1R.example.corp`).

### C8 — `EventData` n'est pas plat ni toujours présent → D8

- Types des valeurs : `str` 7 828, `int` 2 795, `bool` 21, `float` 15, `dict` 1.
  Une `map[string]string` impose une règle de conversion (ex. `Status` = 3221225581 se lit
  `0xC000006D` chez les analystes).
- Données sans nom : `5038` renvoie `{"Data": {"Name": "param1", "Value": …}}`.
- **`UserData` au lieu de `EventData`** pour 1102 (effacement du journal Security) et 1101 :
  événements clés de détection (« suppression des journaux »).
- Valeurs non résolues hors ligne : `%%2313`, `%%1833` (chaînes de message).
- Artefact de décodage : `MessageNumber` = `"\u0001"` (octet brut rendu en caractère).

### C9 — Champs dérivés à normaliser → D8

Sysmon `Hashes` = `"SHA1=…,MD5=…,SHA256=…,IMPHASH=…"` (une chaîne, hexa majuscules) :
le champ `Hashes map[string]string` fonctionne après découpage et passage en minuscules.

### C10 — Contrat d'entrée des bibliothèques → D9

| Bibliothèque | Entrée | Sortie |
|---|---|---|
| `evtx` | `io.ReadSeeker` (chunks de 64 Ko) | slice d'enregistrements par chunk |
| `go-ntfs` (`ParseMFTFile`) | `context.Context`, `io.ReaderAt`, taille | channel |

L'interface actuelle `Parse(io.Reader)` ne convient à aucune des deux. Un `io.ReaderAt` + taille
(ex. `*os.File`, `io.SectionReader`) couvre les deux cas.

### C11 — Pertes silencieuses sur fichier corrompu → D9 (principe V)

| Fichier | Résultat | Erreur remontée |
|---|---|---|
| Intact | 739 enregistrements | — |
| 200 octets inversés dans le 1er chunk | 661 (**78 perdus**) | **aucune** |
| Tronqué au milieu | 628 | `unexpected EOF` sur le dernier chunk |
| Signature invalide | 0 | `wrong magic` |

`go-ntfs` ignore aussi les entrées illisibles (`continue`). Le contrat `Parser` doit donc imposer
la **remontée des anomalies non fatales** ; pour EVTX, l'en-tête de chunk
(`FirstEventRecID`/`LastEventRecID`) permet de compter les enregistrements attendus et de
signaler les manques.

### C12 — Licence : dépendance MPL-2.0 → constitution, principe VII

`evtx` importe `hashicorp/golang-lru` (**MPL-2.0**) dans `messages_windows.go` uniquement : il
entre donc dans le **binaire Windows**, pas dans le binaire Linux. Le principe VII n'autorise que
Apache-2.0, MIT et BSD. Autres dépendances transitives : Apache-2.0, MIT, BSD, ISC (compatibles).
À trancher avant la spec 005 : amender le principe VII (MPL-2.0 non modifié accepté) ou écarter
ce fichier (fork / vendoring).

## Recoupement avec deux implémentations indépendantes

Outils : `evtx_dump` v0.12.3 (Rust, `omerbenamram/evtx`, MIT/Apache-2.0, binaire de release
vérifié par SHA-256) et `evtxinfo`/`evtxexport` 20181227 (C, `libevtx`, LGPL, paquet Ubuntu
`libevtx-utils`). Utilisés comme oracles externes uniquement.

| Point | Velocidex (Go) | evtx_dump (Rust) | libevtx (C) | Conclusion |
|---|---|---|---|---|
| Nombre d'enregistrements (8 fichiers) | 768 | 768 | 739 (Security.evtx) | Identique |
| Numéro d'enregistrement | en-tête | en-tête (`Record N`) | en-tête (`Event number`) | **C3 confirmé** : les 3 outils exposent le numéro d'en-tête ; `EventRecordID` identique partout |
| `TimeCreated` | float s | ISO, 6 décimales | — | Identique à la µs sur 768/768 ; **C2 confirmé** |
| Horodatage d'en-tête | `FileTime` | — | `Written time` | **C1 précisé** : c'est l'heure d'**écriture** dans le journal, pas de l'événement |
| Champs typés `HexInt` (`Status`, `*LogonId`, `ProcessId`…) | **entier décimal** | `"0xc000006d"` | `0xc000006d` | **C14** : Velocidex perd le type hexadécimal (1 701 valeurs sur 8 champs) |
| Dates dans `EventData` (`ClientCreationTime`…) | float s | ISO 8601 | — | Velocidex perd le type date |
| `MessageNumber` (4104) | `"\u0001"` | `1` | — | **Bug de décodage Velocidex** (C8 confirmé) |
| Données sans nom (5038) | `{"Data":{"Name","Value"}}` | clé `param1` | `String: 1` | Formes divergentes : la normalisation doit fixer la sienne |
| Fichier abîmé (chunk 0) | 661, **aucune erreur** | 661, erreur `chunk 0` | 661 + **116 récupérés** | **C11 confirmé** ; seul libevtx récupère |
| Fichier tronqué | 628, erreur EOF | 628, **aucune erreur** | 628 | Aucun outil ne signale tout |
| Enregistrements récupérables (zone libre) | non exposés | non exposés | **39** sur le fichier intact | **C13** |

### C13 — Enregistrements récupérables hors des enregistrements « vivants »

`libevtx` récupère des enregistrements dans l'espace libre des chunks (39 sur un fichier intact,
116 sur le fichier abîmé). Les bibliothèques Go et Rust les ignorent. Valeur forensique réelle
(événements effacés ou écrasés) ; hors périmètre de la 003, mais le modèle doit pouvoir marquer
un événement comme **récupéré** (provenance) si une spec ultérieure l'ajoute.

### C14 — Perte du type hexadécimal par Velocidex

Windows rend les `HexInt32/HexInt64` en hexadécimal (`0xc000006d`, `0x3e7`), et les règles
Sigma comparent ces chaînes telles quelles (ex. `Status: '0xc000006d'`). Velocidex les convertit
en entiers décimaux sans conserver le type : impossible de savoir après coup qu'un `999` était
`0x3e7`. Conséquence pour D8 (rendu canonique des valeurs) et **risque pour le choix de la
bibliothèque en spec 005** (correctif, fork, ou table de champs hexadécimaux connus).

## Impact sur les décisions de la spec 003

| Décision | Ce que le spike apporte |
|---|---|
| D2 Granularité | Question réelle pour EVTX (C4) et $MFT (C5) ; option « un événement par horodatage distinct » chiffrée à ~1,4× |
| D4 Identifiant | Deux numéros d'enregistrement (C3) ; le choix conditionne la stabilité de l'ID |
| D5 Champs obligatoires | `Timestamp` = `TimeCreated`, jamais l'en-tête (C1) |
| D7 User / Host | Sujet vs cible, SID vs nom, FQDN vs nom court (C6, C7) |
| D8 Metadata | Types non textuels, rendu hexadécimal Windows, `UserData`, données sans nom, valeurs non résolues (C8, C9, C14) |
| D9 Parser | `io.ReaderAt` + taille + `context` ; anomalies non fatales obligatoires (C10, C11) |
| D10 Sérialisation | Précision microseconde effective (C2) |
| Provenance | Marquage possible d'un événement récupéré (C13) |
| Constitution VII | MPL-2.0 dans le binaire Windows (C12) |
| Choix de bibliothèque (spec 005) | Perte du type hexadécimal et bug `MessageNumber` chez Velocidex (C14, C8) |

## Vérifications restantes

- Comparaison avec EvtxECmd (oracle de la constitution) : à faire en spec 005 via le runtime
  `dotnet`, les trois implémentations recoupées ici concordant déjà.
- Mesure de C5 sur un $MFT réel (spec 009).
