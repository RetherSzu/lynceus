# Architecture Logicielle — DFIRFlow

## 1. Architecture Générale

```text
                         ┌──────────────────────┐
                         │    Windows Host      │
                         │    ou image disque   │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │       COLLECTOR      │
                         └──────────┬───────────┘
                                    │
                  ┌─────────────────┼─────────────────┐
                  │                 │                 │
                  ▼                 ▼                 ▼
               EVTX             Registry            MFT
                  │                 │                 │
                  ▼                 ▼                 ▼
              Parser             Parser             Parser
                  │                 │                 │
                  └─────────────────┼─────────────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │     NORMALIZER       │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   EVENT MODEL        │
                         └──────────┬───────────┘
                                    │
                    ┌───────────────┼────────────────┐
                    │               │                │
                    ▼               ▼                ▼
                Timeline        Detection        Correlation
                    │               │                │
                    └───────────────┼────────────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │      REPORTING       │
                         └──────────┬───────────┘
                                    │
                         ┌──────────┼──────────┐
                         ▼          ▼          ▼
                       JSON      SQLite      HTML

```

## 2. Decoupage en Couches Logicielles

Le projet est organisé selon les packages standards de l'écosystème Go :

```text
cmd/
internal/
    collector/      # Ingestion des fichiers et gestion de l'intégrité
    parser/         # Décodage spécifique des artefacts (EVTX, $MFT, Registre, etc.)
    normalizer/     # Mapping vers le modèle d'événement commun
    detection/      # Moteur d'évaluation des règles
    correlation/    # Reconstitution des chaînes d'attaque
    timeline/       # Tri et gestion chronologique des événements
    reporting/      # Génération des livrables d'investigation (JSON, SQLite, HTML)
    case/           # Gestion du contexte d'investigation (Case Management)
pkg/
rules/              # Règles de détection YAML
tests/              # Fixtures, scénarios et tests d'intégration
docs/               # Spécifications et documentation d'architecture
examples/           # Cas d'exemples d'incidents

```

## 3. Arborescence du Dépôt (Repository Structure)

```text
dfirflow/
│
├── cmd/
│   └── dfirflow/
│       └── main.go
│
├── internal/
│   ├── collector/
│   │   ├── collector.go
│   │   ├── filesystem.go
│   │   └── metadata.go
│   │
│   ├── parser/
│   │   ├── evtx/
│   │   ├── registry/
│   │   ├── mft/
│   │   ├── usnjrnl/
│   │   └── prefetch/
│   │
│   ├── normalizer/
│   │   ├── event.go
│   │   └── normalize.go
│   │
│   ├── detection/
│   │   ├── engine.go
│   │   ├── rule.go
│   │   └── matcher.go
│   │
│   ├── correlation/
│   │   ├── correlation.go
│   │   └── attack_chain.go
│   │
│   ├── timeline/
│   │   ├── timeline.go
│   │   └── sort.go
│   │
│   ├── reporting/
│   │   ├── json.go
│   │   ├── sqlite.go
│   │   └── html.go
│   │
│   └── case/
│       ├── case.go
│       └── manifest.go
│
├── rules/
│   ├── detection/
│   └── mitre/
│
├── tests/
│   ├── fixtures/
│   ├── integration/
│   └── scenarios/
│
├── examples/
│   ├── compromised-host/
│   └── ransomware/
│
├── docs/
│   ├── architecture.md
│   ├── methodology.md
│   ├── detections.md
│   └── benchmarks.md
│
├── scripts/
│
├── go.mod
├── go.sum
├── Makefile
├── LICENSE
└── README.md

```

## 4. Modèle de Données Pivot (`Event Struct`)

Toutes les sources d'artefacts (EVTX, Registre, $MFT, USN Journal, Prefetch,
PowerShell, Defender) sont converties vers une structure Go d'événement unique
:

```go
type Event struct {
    Timestamp     time.Time         `json:"timestamp"`
    Source        string            `json:"source"`
    Host          string            `json:"host"`
    User          string            `json:"user"`
    EventType     string            `json:"event_type"`

    Process       string            `json:"process"`
    ParentProcess string            `json:"parent_process"`
    CommandLine   string            `json:"command_line"`

    FilePath      string            `json:"file_path"`
    RegistryPath  string            `json:"registry_path"`

    Severity      string            `json:"severity"`
    Confidence    float64           `json:"confidence"`

    RuleID        string            `json:"rule_id"`
    MITRE         []string          `json:"mitre"`

    Metadata      map[string]string `json:"metadata"`
}

```

## 5. Modèle de Gestion des Investigations (`Case Management`)

Chaque session d'analyse est isolée au sein d'une structure **`Case`**
organisée comme suit :

```text
cases/
└── CASE-2027-001/
    ├── case.json         # Métadonnées de l'investigation
    ├── evidence/          # Artefacts bruts collectés
    ├── parsed/            # Données intermédiaires décodées
    ├── normalized/        # Événements au format pivot
    ├── timeline/          # Timeline chronologique consolidée
    ├── detections/        # Alertes et détections identifiées
    ├── reports/           # Exports HTML / SQLite / JSON
    └── hashes/            # Manifestes de hachage SHA-256 (traçabilité)

```

Structure du manifeste `case.json` :

```json
{
  "case_id": "CASE-2027-001",
  "hostname": "WIN-CLIENT01",
  "analyst": "dfir-team",
  "created_at": "2027-04-12T09:00:00Z",
  "tool_version": "0.8.0"
}
```

## 6. Choix de Stack Technique

- **Langage principal :** **Go** (binaire compilé statique, exécution portable
  sans dépendances runtime, concurrence native via goroutines/channels).
- **Base de données embarquée :** **SQLite** (indexation de la timeline, des
  détections et des chaînes de corrélation).
- **Formats de sortie & restitution :** JSON, JSONL, SQLite, HTML.
- **Automation & Outillage :** Git, Make, `go test`, Docker (pour les tests de
  laboratoire), GitHub Actions / CI/CD (cross-compilation vers Windows x64 et
  Linux x64).
