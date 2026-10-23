// Package normalizer définit le modèle d'événement pivot de DFIRFlow.
// Toutes les sources (parseurs natifs et importers) produisent des Event.
package normalizer

import "time"

// Event est le modèle pivot commun à tous les artefacts
// (EVTX, $MFT, $UsnJrnl, Registre, Prefetch, PowerShell, Defender, imports tiers).
type Event struct {
	// --- Temporalité ---
	Timestamp     time.Time `json:"timestamp"`      // Toujours en UTC
	TimestampType string    `json:"timestamp_type"` // Voir constantes TS*

	// --- Origine de l'événement ---
	Source    string `json:"source"`             // Voir constantes Source*
	Provider  string `json:"provider,omitempty"` // Fournisseur EVTX (ex. Microsoft-Windows-Security-Auditing)
	EventID   int    `json:"event_id,omitempty"` // Identifiant EVTX (ex. 4688)
	Host      string `json:"host"`
	User      string `json:"user,omitempty"`
	EventType string `json:"event_type"` // Catégorie normalisée (process_creation, logon, file_create, persistence…)

	// --- Processus ---
	Process         string            `json:"process,omitempty"`
	ProcessID       uint32            `json:"process_id,omitempty"`
	ParentProcess   string            `json:"parent_process,omitempty"`
	ParentProcessID uint32            `json:"parent_process_id,omitempty"`
	CommandLine     string            `json:"command_line,omitempty"`
	Hashes          map[string]string `json:"hashes,omitempty"` // Binaire concerné : md5, sha1, sha256 (Amcache, Sysmon EID 1)

	// --- Objets du système ---
	FilePath     string `json:"file_path,omitempty"`
	RegistryPath string `json:"registry_path,omitempty"`

	// --- Détection ---
	// Renseignés par le moteur de détection, vides à la normalisation.
	Severity   string   `json:"severity,omitempty"`   // info, low, medium, high, critical
	Confidence float64  `json:"confidence,omitempty"` // 0.0 à 1.0
	RuleID     string   `json:"rule_id,omitempty"`
	MITRE      []string `json:"mitre,omitempty"` // Ex. T1059.001

	// --- Traçabilité (chaîne de preuve) ---
	SourceFile string `json:"source_file"`   // Chemin de l'artefact dans evidence/
	SourceHash string `json:"source_sha256"` // SHA-256 de l'artefact source
	RecordID   uint64 `json:"record_id"`     // N° d'enregistrement EVTX, entrée MFT, USN…
	Ingest     string `json:"ingest"`        // "native" ou "import:<outil>@<version>"

	// --- Données spécifiques à l'artefact ---
	// EventData EVTX brut, 4 horodatages SI/FN du $MFT, reason flags USN, etc.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Valeurs de Source.
const (
	SourceEVTX       = "evtx"
	SourceMFT        = "mft"
	SourceUSN        = "usnjrnl"
	SourceRegistry   = "registry"
	SourcePrefetch   = "prefetch"
	SourcePowerShell = "powershell"
	SourceDefender   = "defender"
	SourceMemory     = "memory" // Uniquement via import Volatility
)

// Valeurs de TimestampType.
const (
	TSCreated     = "created"
	TSModified    = "modified"
	TSAccessed    = "accessed"
	TSMFTModified = "mft_modified" // Modification de l'entrée MFT ($SI/$FN)
	TSExecuted    = "executed"     // Prefetch, Amcache, BAM
	TSLogged      = "logged"       // Horodatage d'écriture d'un journal (EVTX, USN)
	TSLastWrite   = "last_write"   // LastWrite d'une clé de registre
)

// Valeur de Ingest pour le parsing natif.
const IngestNative = "native"
