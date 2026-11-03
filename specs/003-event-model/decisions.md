# Décisions — spec 003 (modèle Event)

Journal des décisions validées une à une avant la rédaction de `spec.md`.
Références `Cn` : constats de [spike-report.md](spike-report.md).

## D1 — Périmètre (validée le 2026-11-03)

**Dans la 003** :
- définition et sémantique de `Event` ;
- type `Detection` (structure de données uniquement, pas de moteur) ;
- identifiant d'événement ;
- validation d'un événement ;
- contrat `Parser` et contrat de sortie commun aux importers ;
- encodeur / décodeur JSONL canonique et ordre de tri ;
- champ de provenance capable de marquer un événement **récupéré** (C13) ;
- règle de rendu canonique des valeurs, dont l'hexadécimal Windows (C14).

**Hors de la 003** :
- décodage EVTX et mapping EventID → `EventType` (005) ;
- écriture dans `normalized/` : nommage, découpage (005 / 006) ;
- schéma SQLite (008) ; format des règles et moteur (012) ; importers concrets (011) ;
- récupération d'enregistrements supprimés (spec ultérieure) ;
- **à trancher avant la 005** : choix de la bibliothèque EVTX (C12 licence MPL, C14 hexa).

**Livrables** : code `internal/normalizer`, `internal/parser`, faux parseur de test, fichier
JSONL de référence, tests. Aucune commande CLI modifiée.

## D2 — Granularité (validée le 2026-11-03)

**Option D** : un enregistrement d'artefact produit **un seul `Event`**, portant :
- un **horodatage principal** (`Timestamp` + `TimestampType`) ;
- une **liste typée des horodatages secondaires** (`Timestamps: [{type, time}]`).

La timeline (spec 006) déplie la liste en une ligne par valeur distincte ; la détection évalue
chaque événement une seule fois ; le timestomping se détecte dans un même événement ($SI vs $FN).

**Règle de l'horodatage principal** : l'heure à laquelle l'action décrite s'est produite si la
source la fournit (ex. Sysmon 1 → `UtcTime`) ; sinon l'heure d'écriture (EVTX → `TimeCreated`).
Chaque spec de parseur (005, 007, 009, 010) applique et documente cette règle pour sa source.

Motifs : C4, C5 ; évite les alertes dupliquées et un dédoublonnage en spec 012.

## D3 — Résultats de détection (validée le 2026-11-03)

**Option B** : struct `Detection` séparée ; `Event` ne contient plus aucun champ de détection
(`Severity`, `Confidence`, `RuleID`, `MITRE` retirés).

| Champ | Contenu | Règle |
|---|---|---|
| `id` | identifiant de la détection | déterministe : hash de `rule_id` + `rule_version` + identifiants des événements |
| `rule_id` | ex. `DFIR-PS-001` | obligatoire |
| `rule_version` | version de la règle | obligatoire (E9) |
| `severity` | `info`, `low`, `medium`, `high`, `critical` | liste fermée |
| `confidence` | 0.0 à 1.0 | confiance attribuée par la règle |
| `mitre` | ex. `T1059.001` | `T####` ou `T####.###`, peut être vide |
| `events` | identifiants des événements concernés | au moins 1, triés |
| `timestamp` | horodatage principal du premier événement | placement dans la timeline |

Hors 003 (spec 012) : format des règles, moteur, message à l'analyste, faux positifs.
L'identifiant unique d'un `Event` ne s'appelle pas `EventID` (réservé à l'EventID Windows) : voir D4.

## D4 — Identifiant d'événement (validée le 2026-11-03)

**Option B — identifiant de provenance** :

```
uid = 32 premiers caractères hexa (minuscules) de
      SHA-256( source_sha256 + "\x00" + source_file + "\x00" + record_locator )
```

- `source_sha256` : empreinte de l'artefact (manifeste) ; `source_file` : chemin relatif à
  `evidence/`, immuable (manifeste en ajout seul, spec 002).
- `record_locator` : chaîne désignant l'enregistrement dans le fichier, format fixé par chaque
  spec de parseur. Exemples : EVTX `record=1234` ; EVTX récupéré `offset=0x1a2b0` (C13) ;
  $MFT `entry=46,seq=5` ; import CSV/JSONL `line=812`.
- 128 bits : collision négligeable, deux fois plus compact qu'un SHA-256 complet.
- Ne dépend d'aucun champ décodé : un correctif de parseur ne change pas les `uid`.

**Changements de `Event`** : ajout de `uid` et `record_locator` ; `record_id` (numérique,
affiché à l'analyste, utilisé pour le tri) conservé ; l'`EventRecordID` Windows ira dans
`Metadata` (spec 005, C3).

**Conséquence spec 011** : tout fichier importé est d'abord enregistré comme preuve
(manifeste + SHA-256) avant d'être lu.

## D5 — Champs obligatoires et validation (validée le 2026-11-03)

**Socle commun (obligatoire pour tout événement)** :

| Champ | Règle |
|---|---|
| `uid` | 32 hexa minuscules, formule D4 |
| `timestamp` | UTC, non nul ; règle D2, jamais l'en-tête EVTX (C1) |
| `timestamp_type` | liste fermée des types d'horodatage (ci-dessous) |
| `timestamps` | facultatif ; entrées `{type, time, origin}`, `time` UTC non nul |
| `source` | liste fermée des formats d'artefact (ci-dessous) |
| `event_type` | taxonomie fermée (D6) |
| `host` | non vide |
| `source_file` | chemin relatif à `evidence/`, présent au manifeste |
| `source_sha256` | 64 hexa minuscules |
| `record_id` | entier ≥ 0 (0 valide, ex. entrée `$MFT`) |
| `record_locator` | non vide |
| `ingest` | `native` ou `import:<outil>@<version>` |
| `recovered` | booléen, faux par défaut, omis si faux (C13) |

**Champs selon la source** :
- `provider`, `event_id` : obligatoires si `source = evtx`, absents sinon ;
- champs utilisateur : D7 ;
- `process`, `process_id`, `parent_process`, `parent_process_id`, `command_line`, `file_path`,
  `registry_path` : facultatifs ;
- `hashes` : facultatif ; clés `md5`, `sha1`, `sha256`, `imphash` uniquement ; valeurs hexa
  minuscules de longueur 32, 40, 64, 32 (C9) ;
- `metadata` : D8.

**Retirés** : `severity`, `confidence`, `rule_id`, `mitre` (D3).

**Événement invalide** : la validation renvoie la liste des violations ; l'événement est rejeté et
compté comme anomalie (avec `uid`, `record_locator`, raison), jamais ignoré en silence (C11).

**Sous-décision 1 — `source` = format d'artefact (option a)** : `evtx`, `mft`, `usnjrnl`,
`registry`, `prefetch`, `memory`. PowerShell et Defender se distinguent par `provider` / canal.
Conséquence : amender la spec 001 (`timeline --source` perd `powershell` et `defender`) ; un
filtre par canal ou fournisseur pourra être ajouté plus tard.

**Sous-décision 2 — types d'horodatage** : liste fermée `created`, `modified`, `accessed`,
`changed` (ex-`mft_modified`, le « C » de MACB), `executed`, `logged` (EVTX `TimeCreated`),
`written` (en-tête d'enregistrement EVTX, C1), `last_write` (registre). Chaque entrée de
`timestamps` porte `origin`, le nom du champ source (`$SI`, `$FN`, `UtcTime`, `TimeCreated`…) :
le timestomping compare `created`/`$SI` et `created`/`$FN` dans un même événement.

**Sous-décision 3 — `host`** : valeur de l'artefact si présente, sinon `hostname` du cas
(`case.json`, spec 002). Normalisation (nom court / FQDN) : D7.

## D6 — Taxonomie `event_type` (validée le 2026-11-03)

**Forme (option a)** : liste plate, fermée, propre à DFIRFlow, en `snake_case` ; noms de catégorie
Sigma repris quand ils existent. Une valeur hors liste est une violation de validation (D5).

**Repli (option i)** : un enregistrement sans type connu reçoit `other` ; il est conservé, apparaît
dans la timeline, et ses données restent dans `metadata` (C11, principe V).

**Liste initiale (minimale, tranche verticale EVTX, Defender compris ; amendée le 2026-11-03)** :

| `event_type` | Exemples EVTX (mapping fixé par la spec 005) |
|---|---|
| `logon` | 4624 |
| `logon_failed` | 4625 |
| `logoff` | 4634, 4647 |
| `process_creation` | 4688, Sysmon 1 |
| `service_install` | 7045, 4697 |
| `script_execution` | 4104 |
| `log_cleared` | 1102, 104 |
| `malware_detected` | Defender 1116, 1117 |
| `av_config_change` | Defender 5001, 5007 |
| `other` | tout le reste |

Defender est un journal EVTX (D5, `source` = format) : ses types entrent donc dès la 005.
Chaque spec de parseur ultérieure (007–010) ajoute ses types (évolution mineure, D11).
`persistence` et autres conclusions ne sont pas des `event_type` : elles relèvent d'une
`Detection` (D3).

## D7 — Utilisateurs et hôte (validée le 2026-11-03)

**Comptes (option b)** : deux objets facultatifs `subject` et `target`, chacun `{sid, domain, name}`.
- `subject` : compte qui agit ou demande l'action ;
- `target` : compte sur lequel porte l'action (session ouverte, compte du nouveau processus) ;
- mapping par EventID fixé par la spec 005 (ex. 4104 `UserID` → `subject.sid` ; Sysmon 1 `User`
  → `subject` après découpage `domaine\nom`). Remplace le champ texte `user`.

**Normalisation des comptes** :
- `-`, vide et le SID nul `S-1-0-0` = absent, champ omis ; objet sans aucun champ omis ;
- `sid` de forme `S-1-<n>(-<n>)+`, majuscules ; SID invalide = violation (D5) ;
- `domain`, `name` : casse d'origine conservée (preuve) ; la comparaison insensible à la casse
  relève des règles (spec 012) ;
- pas de résolution SID → nom dans la 003 (nécessite SAM / registre).

**Hôte (option b)** : `host` = nom court en majuscules (avant le premier `.`) ; `host_fqdn`
facultatif = valeur d'origine si elle contenait un point. Même règle pour le repli sur
`hostname` du cas (D5). Hôte / IP distants (`IpAddress`, `WorkstationName`) : `metadata` (D8) ;
un champ dédié pourra venir avec la corrélation (D11).

## D8 — `metadata` et rendu canonique des valeurs (validée le 2026-11-03)

**Type (option a)** : `metadata` reste `map[string]string` ; chaque valeur suit une règle de rendu
canonique unique.

**Règle de rendu** : une valeur s'écrit comme Windows l'écrit dans la vue XML de l'événement ;
oracle de test : `evtx_dump`.

| Type d'origine | Rendu | Exemple |
|---|---|---|
| Entier | décimal | `4624` |
| `HexInt32` / `HexInt64` | `0x` + hexa minuscules, sans zéros de tête (C14) | `0xc000006d` |
| Booléen | `true` / `false` | |
| Flottant | forme la plus courte se relisant à l'identique | `0.5` |
| GUID | `{…}` en majuscules | `{54849625-5478-4994-A5BA-3E3B0328C30D}` |
| SID | `S-1-…` | |
| FILETIME / SYSTEMTIME | RFC 3339 UTC, microseconde (D10) | `2020-09-09T13:18:23.627952Z` |
| Binaire | hexa minuscules | `0a1b…` |
| `%%nnnn` non résolu | conservé tel quel (résolution hors ligne hors périmètre) | `%%2313` |
| Chaîne non UTF-8 valide | violation (D5) | |

**Nommage des clés** :
- `EventData` : nom d'origine, casse conservée (`TargetUserName`) ;
- données sans nom : `Data[1]`, `Data[2]`… (base 1, comme `%1`) ;
- `UserData` : élément racine retiré (`LogFileCleared`), niveaux plus profonds joints par `.` ;
- champs `System` : préfixe `System.` (`System.EventRecordID`, `System.Level`, `System.Task`,
  `System.Opcode`, `System.Keywords`, `System.Execution.ProcessID`…) ;
- champs promus (`process`, `command_line`…) : conservés aussi dans `metadata` sous leur nom
  d'origine (preuve brute, compatibilité Sigma).

**Complément à D5** : `channel` devient un champ de premier niveau, obligatoire si
`source = evtx` (avec `provider` et `event_id`).

## D9 — Contrat `Parser` (validée le 2026-11-03)

```go
type Source struct{ File, SHA256, Host string }
type Anomaly struct{ Locator, Kind, Message string }
type Sink interface {
    Event(normalizer.Event) error
    Anomaly(Anomaly) error
}
type Parser interface {
    Name() string            // = valeur de `source` (evtx, mft…)
    Match(head []byte) bool
    Parse(ctx context.Context, r io.ReaderAt, size int64, src Source, out Sink) error
}
```

- **Entrée (option b)** : `ctx`, `io.ReaderAt` + taille (C10), `Source` = chemin relatif à
  `evidence/`, SHA-256 du manifeste, `hostname` du cas (D4, D5). Pas de chemin : le parseur
  n'ouvre aucun fichier.
- **Sortie (option b)** : rappels synchrones `out.Event` / `out.Anomaly` ; une erreur renvoyée par
  le `Sink` arrête le parseur.
- **Erreur fatale** = retour de `Parse` : format non reconnu, erreur d'E/S, annulation. Les
  événements déjà émis restent valides.
- **Anomalie non fatale** : `out.Anomaly`, puis le parseur continue. `kind` ∈ `unreadable`,
  `missing` (ex. EVTX `FirstEventRecID`/`LastEventRecID`, C11), `truncated`, `invalid` (D5).
  Chaque spec de parseur documente sa détection des manques. Persistance des anomalies : spec
  d'ingestion (004/005).
- **Validation centralisée** : `Sink` intermédiaire fourni par la 003, qui valide (D5), transmet
  les événements valides et convertit les autres en anomalies `invalid`.
- **Sélection** : `Match` sur la signature des premiers octets (EVTX `ElfFile\x00`), jamais
  l'extension.
- **Garanties** : émission dans l'ordre du fichier ; sortie identique à entrée identique
  (principe IV) ; aucun état entre deux appels (utilisable en parallèle sur des fichiers
  distincts).
- **Importers (011)** : même interface ; `Name()` = outil ; `ingest` = `import:<outil>@<version>`.

## D10 — JSONL canonique (validée le 2026-11-03)

- **Ligne** : un objet par ligne, UTF-8 sans BOM, terminateur `\n` (jamais `\r\n`) ; champs dans
  l'ordre fixé par la spec ; clés de `metadata`, `hashes`, `subject`/`target` triées ; champs
  facultatifs vides omis (ni `null` ni `""`) ; pas d'échappement HTML (`<`, `>`, `&` littéraux).
- **Horodatages (option a)** : RFC 3339 UTC, 6 décimales fixes
  (`2020-09-09T13:18:23.627952Z`), troncature sous la microseconde (C2).
- **Tri** : `timestamp` ↑, `source_file` ↑, `record_id` ↑, `uid` ↑ (ordre total). La 003 fournit
  le comparateur ; les specs 005/006 fixent l'étape où l'on trie.
- **Version (option a)** : `schema_version` sur chaque ligne, premier champ.
- **Décodeur strict** : refus d'un `schema_version` non pris en charge, d'un champ inconnu ou
  d'une ligne invalide, avec le numéro de ligne.
- **`Detection`** : mêmes règles ; tri `timestamp` ↑ puis `id` ↑.
- **Vérification** : fichier de référence JSONL dans `testdata/`, comparé octet par octet à la
  sortie du faux parseur.

## D11 — Politique d'évolution du modèle (validée le 2026-11-03)

- **Version (option a)** : `schema_version` entier, +1 à chaque changement du format ou d'une
  liste fermée, ajout compris. Un binaire refuse une version qu'il ne connaît pas, avec un message
  invitant à mettre à jour.
- **Compatibilité** :
  - additif (champ facultatif, `event_type`, type d'horodatage, `kind` d'anomalie) : le décodeur
    lit obligatoirement toutes les versions additives antérieures ;
  - cassant (renommage, suppression, changement de sens ou de rendu) : refus avec « réingérer le
    cas » ; `normalized/` est dérivé de preuves immuables (spec 002), on régénère sans migrer.
- **Gelés** : formule du `uid` (D4), règles de rendu des valeurs (D8), écriture des horodatages
  (D10). Modifiables seulement par un changement cassant justifié dans la spec qui le porte
  (pourquoi inévitable, impact sur les cas existants).
- **Procédure** : contrat unique `specs/003-event-model/contracts/event-model.md` avec tableau
  d'historique (version, spec, ajouts, additif/cassant). Toute spec qui modifie le modèle, dans un
  même commit : amende le contrat et incrémente `schema_version`, met à jour le fichier de
  référence JSONL, conserve celui de la version précédente comme jeu de compatibilité.
- `case.json` garde son propre `schema_version` (spec 002).

## Compléments validés à la rédaction (2026-11-03)

- **`id` de détection (précise D3)** : 32 premiers hexa minuscules de
  SHA-256(`rule_id` \x00 `rule_version` \x00 `uid` triés séparés par \x00).
- **Amendement CLI dans la 003 (déroge à D1)** : `timeline --source` accepte `evtx`, `mft`,
  `usnjrnl`, `registry`, `prefetch`, `memory` (FR-026).
