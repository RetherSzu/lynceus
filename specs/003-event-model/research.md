# Research: Modèle d'événement normalisé et contrat de parseur

Les choix de fond sont tranchés dans [decisions.md](decisions.md) (D1–D11) à partir du
[spike](spike-report.md). Ce document ne couvre que les choix d'implémentation restants, vérifiés
sur Go 1.22 en restant compatibles `go 1.18` (pas de `slices`, `maps`, `cmp`, `min`).

## R1 — JSONL déterministe avec `encoding/json`

- **Decision**: `json.Encoder` avec `SetEscapeHTML(false)` ; une ligne par `Encode` (il ajoute
  `\n`). Ordre des champs = ordre de déclaration du struct ; les clés de map sont triées par la
  bibliothèque. `schema_version` en tête via un struct d'enveloppe
  `struct{ SchemaVersion int; Event }` (le champ externe précède les champs promus — vérifié).
- **Rationale**: aucun code de sérialisation à écrire ; ordre garanti par la bibliothèque.
- **Alternatives considered**: `MarshalJSON` écrit à la main (plus de code, plus de risques) ;
  champ `SchemaVersion` dans `Event` (le parseur devrait le renseigner).

## R2 — Horodatage à 6 décimales fixes

- **Decision**: type `normalizer.Time struct{ time.Time }` avec `MarshalJSON` =
  `UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.000000Z")` et `UnmarshalJSON`
  par `time.Parse` du même gabarit.
- **Rationale**: `time.Time` s'encode en `RFC3339Nano` à décimales variables (tri faux, FR-017).
  Vérifié : le gabarit refuse 5 ou 7 décimales, l'absence de décimales et tout décalage autre que
  `Z` ; le décodeur est donc strict sans code supplémentaire. `Truncate` tronque (1,999 µs → 1 µs).
- **Alternatives considered**: chaîne brute dans le struct (perte du type pour le tri et la
  validation).

## R3 — Décodage strict ligne par ligne

- **Decision**: lecture par `bufio.Reader.ReadBytes('\n')` (pas de limite de longueur : un
  script 4104 peut dépasser 1 Mo) ; numéro de ligne compté ; refus d'une ligne contenant `\r`
  final ou non UTF-8 (`utf8.Valid`) ; `json.Decoder` + `DisallowUnknownFields` ; refus de tout
  contenu après l'objet ; contrôle de `schema_version` ; puis validation (FR-009) de l'objet lu.
- **Rationale**: `encoding/json` remplace silencieusement l'UTF-8 invalide par U+FFFD (vérifié) :
  la vérification doit précéder le décodage. Valider après lecture détecte aussi une ligne
  syntaxiquement correcte mais corrompue.
- **Alternatives considered**: `bufio.Scanner` (limite de jeton à configurer, échec sur ligne
  longue) ; `json.Unmarshal` (pas de `DisallowUnknownFields`).
- **Limite connue**: une clé JSON dupliquée n'est pas détectée (la bibliothèque garde la
  dernière) ; à documenter en commentaire `shortcut:`.

## R4 — Champs facultatifs et valeur zéro

- **Decision**: `omitempty` sur les champs facultatifs ; `event_id` en `*uint32` (l'EventID 0
  existe et doit rester présent pour `source = evtx`, FR-004) ; `subject`/`target` en `*Account` ;
  `record_id` sans `omitempty` (0 valide). `process_id = 0` équivaut à absent (PID 0 = processus
  inactif, jamais acteur).
- **Rationale**: le seul champ où 0 est une valeur réelle et obligatoire est `event_id`.
- **Alternatives considered**: pointeurs partout (lourd pour les parseurs).

## R5 — Validation

- **Decision**: `func (e Event) Validate() []Violation`, `Violation{Field, Rule string}` ; liste
  complète, ordre fixe (ordre des champs). L'encodeur valide aussi et refuse un événement invalide
  (FR-010) ; le décodeur valide chaque ligne lue.
- **Rationale**: une seule fonction utilisée par le `Sink` de validation, l'encodeur et le
  décodeur ; violations comparables dans les tests.

## R6 — Aides de normalisation fournies aux parseurs

- **Decision**: `NormalizeHost(raw) (host, fqdn string)`, `NewAccount(sid, domain, name) *Account`
  (applique `-`, vide, `S-1-0-0` → absent, SID en majuscules, `nil` si tout est absent),
  `FormatHex(uint64) string`, `UID(sha256, file, locator) string`.
- **Rationale**: les règles D7/D8 deviennent du code commun au lieu d'être réimplémentées par
  chaque parseur. Les autres rendus D8 sont déjà dans la bibliothèque standard
  (`strconv.FormatInt`, `strconv.FormatFloat(f, 'g', -1, 64)`, `strconv.FormatBool`,
  `hex.EncodeToString`) ; le rendu GUID dépend du type de la bibliothèque EVTX (spec 005).

## R7 — Faux parseur

- **Decision**: parseur de test dans `internal/parser/fake_test.go`, format texte : signature
  `FAKE1\n`, une ligne par enregistrement `numéro|horodatage|event_type|commande` ; ligne `!` =
  illisible, saut de numéro = manquant, horodatage vide = invalide.
- **Rationale**: exerce tout le contrat (FR-014 à FR-016c) sans dépendance ni artefact sous
  licence ; non exporté, il ne grossit pas le binaire.

## R8 — Tri

- **Decision**: `SortEvents([]Event)` et `SortDetections([]Detection)` par `sort.Slice` sur la
  clé FR-018a / FR-021 ; l'ordre est total (dernier critère unique), la stabilité est inutile.
