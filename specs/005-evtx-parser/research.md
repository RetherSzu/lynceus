# Research: Parser EVTX et ingestion des journaux

Choix d'implémentation de la spec 005. Références : ADR-002 (option B), rapport de spike de la
spec 003 (constats C1 à C14), code de `www.velocidex.com/golang/evtx` v0.2.0.

## R1 — Périmètre du fork

- **Decision** : copier dans `internal/parser/evtx/binxml/` les fichiers `evtx.go` (856 lignes),
  `normalize.go` et `debug.go` ; ne pas reprendre `messages*.go`, `resolver*.go`, `utils.go`,
  `cmd/`, `fixtures/`. Conserver le fichier `LICENSE` (Apache-2.0) et ajouter un fichier `NOTICE`
  indiquant l'origine, la version et les modifications.
- **Rationale** : la résolution des messages est hors périmètre (étude de l'existant §5.1) et porte
  la seule dépendance MPL-2.0 (E1) ; `utils.go` n'apporte qu'une fonction de débogage dépendant de
  `go-spew`.
- **Alternatives** : dépendance directe (écartée par l'ADR-002).

## R2 — Aucune dépendance externe

- **Decision** :
  - `github.com/pkg/errors` remplacé par `fmt.Errorf` avec `%w` ;
  - `github.com/Velocidex/ordereddict` remplacé par un type interne minimal (liste de paires
    clé/valeur ordonnée, accès par clé) ;
  - le module reste en bibliothèque standard Go 1.18.
- **Rationale** : `ordereddict` entraîne trois modules transitifs (`Velocidex/json`,
  `Velocidex/yaml`, `alecthomas/repr`) pour un usage limité à la construction de l'arbre de
  l'événement ; les specs 001 à 004 n'ont aucune dépendance et le principe I privilégie un binaire
  minimal.
- **Alternatives** : conserver `ordereddict` (licence compatible, mais trois dépendances de plus).

## R3 — Comptage par chunk et anomalies (E2, FR-003)

- **Decision** : l'en-tête de chunk fournit `FirstEventRecNumber` et `LastEventRecNumber`.
  `Chunk.Parse` est modifié pour ne plus renvoyer silencieusement le résultat partiel (le code
  d'origine fait `return result, nil` sur erreur) : il renvoie les enregistrements lus et la liste
  des numéros attendus non lus. Le parser émet une anomalie par numéro manquant :
  `unreadable` si l'en-tête d'enregistrement est invalide, `missing` pour les numéros suivants du
  même chunk, `truncated` si le fichier se termine avant la fin du chunk.
- **Rationale** : satisfait l'égalité événements + anomalies = enregistrements annoncés (SC-001).
- **Alternatives** : reprise après erreur par recherche de la signature d'enregistrement suivante
  (`**\0\0`) ; reportée (proche de la récupération C13).

## R4 — Bornes et absence de panique (E5, FR-005)

- **Decision** :
  - `ConsumeBytes`, `ReadPrefixedUnicodeString`, `ReadName` et la lecture des tailles
    d'enregistrement vérifient la place restante dans le chunk (64 Kio) ; dépassement → erreur de
    décodage de l'enregistrement, jamais d'allocation de la taille lue ;
  - taille d'enregistrement hors de `[24, 65024]` octets → enregistrement illisible ;
  - nombre de chunks lu dans l'en-tête de fichier borné par `taille / 65536` ;
  - décodage de chaque enregistrement protégé par `recover`, converti en anomalie `unreadable`
    (filet de sécurité ; tout cas rencontré donne un test et une correction).
- **Rationale** : contraintes de sécurité de la constitution (« MUST NOT paniquer ») et FR-016c de
  la spec 003.

## R5 — Rendu des valeurs (E3, E4, FR-004)

- **Decision** : le décodeur produit des valeurs typées ; le rendu en chaînes suit la spec 003
  FR-013 via `normalizer.FormatHex` pour `HexInt32`/`HexInt64` (types BinXML `0x14` et `0x15`).
  `MessageNumber` (E4) : correction du décodage du type concerné, vérifiée sur un enregistrement
  4104 de référence.
- **Rationale** : C14 et C8 ; la valeur rendue doit être celle de la vue XML Windows.

## R6 — Table de correspondance déclarative (FR-011, FR-012, FR-012a)

- **Decision** : fichier `internal/parser/evtx/mapping.json`, embarqué par `//go:embed`, lu une fois
  au démarrage avec `encoding/json` (décodage strict, champs inconnus refusés). Une entrée par
  (canal, fournisseur, EventID) : `event_type`, puis pour chaque champ normalisé le nom du champ
  `EventData`/`UserData` source (voir `contracts/evtx-mapping.md`). Un test charge la table et
  vérifie : clés uniques, `event_type` dans la liste de la spec 003, champs normalisés connus, et un
  cas positif par entrée.
- **Rationale** : ajout d'un EventID sans code (SC-007) ; JSON est lu par la bibliothèque standard
  (R2).
- **Alternatives** : YAML (plus lisible, mais dépendance `gopkg.in/yaml.v3`) ; code Go (contraire à
  FR-011).

## R7 — Horodatages (FR-010)

- **Decision** : horodatage principal = `EventData/UtcTime` si l'entrée de table le désigne comme
  instant de l'action (Sysmon), sinon `System/TimeCreated`. Secondaires : `logged`
  (`TimeCreated`, origine `TimeCreated`) et `written` (en-tête d'enregistrement, origine
  `RecordHeader`) lorsqu'ils diffèrent du principal ; un horodatage d'en-tête nul est omis (C1).
  Précision : microseconde (spec 003).
- **Rationale** : spec 003 FR-005, FR-006 ; constats C1, C2, C4.

## R8 — Localisation et identifiant

- **Decision** : `record_locator` = `chunk:<index du chunk>/record:<numéro d'en-tête>` ;
  `record_id` = numéro d'en-tête (C3) ; anomalie de niveau fichier : `file`. `uid` calculé par
  `normalizer.UID` (spec 003 FR-008).
- **Rationale** : unique dans le fichier, lisible, stable entre deux ingestions.

## R9 — Fichiers de sortie et atomicité (FR-016)

- **Decision** : pour la preuve `evidence/<rel>`, événements dans `normalized/<rel>.jsonl` et
  anomalies dans `normalized/<rel>.anomalies.jsonl` (JSONL, une anomalie
  `{record_locator, kind, message}` par ligne). Écriture dans `<fichier>.partial` puis renommage
  après succès ; en cas d'échec ou d'interruption, les `.partial` sont supprimés et les anciens
  fichiers restent en place.
- **Rationale** : relance idempotente (SC-005), aucun fichier partiel.

## R10 — Vérification d'intégrité avant décodage (FR-015)

- **Decision** : `ingest` recalcule le SHA-256 de la preuve en flux et le compare au manifeste avant
  de la décoder (deux lectures du fichier). Écart → statut `ALTERED`, pas de décodage.
- **Rationale** : un événement porte `source_sha256` ; décoder un fichier altéré produirait des
  événements dont la provenance est fausse.
- **Alternatives** : hachage pendant le décodage (une seule lecture) ; impossible à garantir car le
  décodeur lit par positions et peut ne pas lire tous les octets.

## R11 — Oracle (FR-020)

- **Decision** :
  - fixture commitée : `testdata/Security.evtx` du dépôt d'origine (Apache-2.0, 739
    enregistrements) ;
  - sortie de référence `evtx_dump` v0.12.3 (`-o jsonl`) commitée dans `testdata/oracle/` ; le test
    compare, par enregistrement, `TimeCreated`, `EventID`, `Channel`, `Provider`, `EventRecordID` et
    chaque valeur de `EventData` ;
  - sortie EvtxECmd produite hors CI et ajoutée au même dossier quand elle est disponible ; écarts
    documentés dans `testdata/oracle/README.md`.
- **Rationale** : principe VI ; `evtx_dump` concorde déjà avec deux autres implémentations (spike).

## R12 — Fixtures malformées (SC-003)

- **Decision** : générées dans les tests à partir de `Security.evtx` : octets inversés dans un
  chunk, troncature au milieu d'un chunk, signature de fichier invalide, taille d'enregistrement
  démesurée, nombre de chunks démesuré. Un test de fuzzing (`go test -fuzz`, Go 1.18) sur le
  décodage d'un chunk complète ce jeu.
- **Rationale** : aucun fichier binaire de plus dans le dépôt ; couvre E2 et E5.

## R13 — Résumé des types non classés (FR-018a)

- **Decision** : `ingest` compte les événements par (canal, EventID) quand `event_type = other`, et
  affiche la part de `other` et les dix couples les plus fréquents (tri : nombre décroissant, puis
  canal, puis EventID).
