# ADR-002 — Parsers natifs : bibliothèque Go existante, fork ou réimplémentation

- **Statut** : Accepté (2026-11-25), option B
- **Ticket** : DF-04
- **Concerne** : spec 005 (parser EVTX) en priorité ; même question pour `go-ntfs` en specs 007/009
- **Références** : `docs/etude-existant.md` §5, `specs/003-event-model/spike-report.md` (C8, C10–C14),
  constitution principes I, II, V, VI, VII

## Contexte

L'étude de l'existant retient « natif, via `Velocidex/evtx` » (§5.1). Le spike de la spec 003 a
exercé cette bibliothèque (v0.2.0, Apache-2.0) sur 8 fichiers et l'a recoupée avec `evtx_dump`
(Rust) et `libevtx` (C) : décodage concordant sur 768/768 enregistrements, mais cinq écarts avec
la constitution ou les besoins de DFIRFlow.

| # | Constat | Principe |
|---|---|---|
| E1 | `messages_windows.go` importe `hashicorp/golang-lru` (**MPL-2.0**), présent dans le binaire Windows | VII |
| E2 | Perte silencieuse d'enregistrements sur un chunk abîmé (78 perdus, aucune erreur) | V |
| E3 | `HexInt32/64` rendus en décimal : `0xc000006d` → `3221225581`, incompatible avec les règles Sigma | VIII |
| E4 | `MessageNumber` mal décodé (`"\u0001"` au lieu de `1`) | VI |
| E5 | `ConsumeBytes` alloue une taille lue dans le fichier sans borne ; aucun `recover` | contraintes de sécurité (« MUST NOT paniquer ») |

Autres faits : ~1 500 lignes de Go, pas de CGO, `go.mod` en go 1.13 ; API par chunk de 64 Ko sur
`io.ReadSeeker` (C10) ; enregistrements récupérables dans l'espace libre non exposés (C13).

## Options

### A — Dépendance directe `www.velocidex.com/golang/evtx`

- Avantage : Effort minimal ; décodage BinXML éprouvé (Velociraptor).
- Inconvénient : E1 viole le principe VII (amendement de la constitution nécessaire, ou build tag pour
  exclure le fichier, impossible sans fork).
- Inconvénient : E2–E5 à corriger en amont (PR à un projet peu actif) ou à contourner après coup ; E3 n'est
  pas réparable après coup (le type est perdu).

### B — Fork interne dans `internal/parser/evtx/` (recommandée)

Copie du code Apache-2.0 (attribution et `LICENSE` conservés dans le dossier), puis :

- suppression de `messages*.go` et `resolver*.go` (résolution des messages hors périmètre,
  étude §5.1) → E1 disparaît, aucune dépendance MPL ;
- conservation du type des `HexInt` (E3) et correction de `MessageNumber` (E4) ;
- bornes sur toutes les tailles lues et `recover` par chunk converti en anomalie (E5) ;
- comptage attendu/obtenu par chunk via `FirstEventRecID`/`LastEventRecID` → anomalie (E2) ;
- API alignée sur le contrat `parser.Parser` de la 003 (`io.ReaderAt` + taille + `context`).

- Avantage : Respecte I, II, V, VII sans amendement ; corrige les cinq écarts à la source.
- Avantage : Effort borné (~1 500 lignes déjà écrites et validées sur 768 enregistrements).
- Inconvénient : Maintenance à notre charge ; divergence avec l'amont (acceptable : bibliothèque peu active).

### C — Réimplémentation complète

- Avantage : Maîtrise totale, code conçu pour le flux et les anomalies dès le départ.
- Inconvénient : BinXML (templates, substitutions, 20+ types de valeurs) : plusieurs semaines ; incompatible
  avec l'échéance du 15/12 (Gantt tâche 6) ; risque de précision plus élevé.

## Décision

**Option B**, retenue le 2026-11-25. Le fork est le seul moyen de respecter le principe VII sans amender la
constitution tout en corrigeant E2–E5, pour un coût proche de l'option A.

## Conséquences

- La spec 005 inclut l'import du fork, ses correctifs et leurs tests (chaque écart E2–E5 devient
  un test de non-régression), puis le parser et le normaliseur EVTX.
- Tests oracle (principe VI) : EvtxECmd reste la référence de la constitution ; `evtx_dump` sert
  de second oracle déjà recoupé.
- Les fixtures GPL du spike (`EVTX-ATTACK-SAMPLES`) restent hors dépôt ; les fixtures commitées
  sont synthétiques ou Apache-2.0 (`testdata/Security.evtx` de l'amont).
- Récupération des enregistrements dans l'espace libre (C13) : hors spec 005, possible plus tard
  dans le fork.
- `go-ntfs` (Apache-2.0, sans dépendance MPL constatée) : décision reportée aux specs NTFS, sur
  les mêmes critères.
