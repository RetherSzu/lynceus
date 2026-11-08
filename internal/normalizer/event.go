// Package normalizer définit le modèle d'événement pivot de DFIRFlow.
// Toutes les sources (parseurs natifs et importers) produisent des Event.
package normalizer

// SchemaVersion est la version du format JSONL écrit et accepté.
const SchemaVersion = 1

// Event est le modèle pivot commun à tous les artefacts. L'ordre des champs
// est l'ordre de sérialisation (contracts/event-model.md, FR-018).
type Event struct {
	UID           string           `json:"uid"`
	Timestamp     Time             `json:"timestamp"`      // Toujours en UTC
	TimestampType string           `json:"timestamp_type"` // Voir constantes TS*
	Timestamps    []TimestampEntry `json:"timestamps,omitempty"`

	Source    string `json:"source"`     // Voir constantes Source*
	EventType string `json:"event_type"` // Voir constantes Type*
	Host      string `json:"host"`       // Nom court en majuscules
	HostFQDN  string `json:"host_fqdn,omitempty"`

	// Requis si et seulement si Source = evtx.
	Channel  string  `json:"channel,omitempty"`
	Provider string  `json:"provider,omitempty"`
	EventID  *uint32 `json:"event_id,omitempty"` // Pointeur : 0 est un identifiant valide

	Subject *Account `json:"subject,omitempty"` // Compte qui agit
	Target  *Account `json:"target,omitempty"`  // Compte visé

	Process         string            `json:"process,omitempty"`
	ProcessID       uint32            `json:"process_id,omitempty"` // 0 = absent
	ParentProcess   string            `json:"parent_process,omitempty"`
	ParentProcessID uint32            `json:"parent_process_id,omitempty"` // 0 = absent
	CommandLine     string            `json:"command_line,omitempty"`
	FilePath        string            `json:"file_path,omitempty"`
	RegistryPath    string            `json:"registry_path,omitempty"`
	Hashes          map[string]string `json:"hashes,omitempty"` // md5, sha1, sha256, imphash

	// Traçabilité (chaîne de preuve).
	SourceFile    string `json:"source_file"`    // Chemin relatif à evidence/, séparateur "/"
	SourceHash    string `json:"source_sha256"`  // SHA-256 de l'artefact source
	RecordID      uint64 `json:"record_id"`      // Toujours écrit, 0 compris
	RecordLocator string `json:"record_locator"` // Position de l'enregistrement dans l'artefact
	Recovered     bool   `json:"recovered,omitempty"`
	Ingest        string `json:"ingest"` // "native" ou "import:<outil>@<version>"

	// Données propres à l'artefact (EventData EVTX, horodatages SI/FN, flags USN…).
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Account identifie un compte ; les champs absents sont omis.
type Account struct {
	Domain string `json:"domain,omitempty"`
	Name   string `json:"name,omitempty"`
	SID    string `json:"sid,omitempty"`
}

// TimestampEntry est un horodatage secondaire de l'enregistrement.
type TimestampEntry struct {
	Type   string `json:"type"` // Voir constantes TS*
	Time   Time   `json:"time"`
	Origin string `json:"origin"` // Attribut d'origine (ex. $SI, $FN)
}

// Valeurs de Source.
const (
	SourceEVTX     = "evtx"
	SourceMFT      = "mft"
	SourceUSN      = "usnjrnl"
	SourceRegistry = "registry"
	SourcePrefetch = "prefetch"
	SourceMemory   = "memory" // Uniquement via import Volatility
)

// Valeurs de TimestampType.
const (
	TSCreated   = "created"
	TSModified  = "modified"
	TSAccessed  = "accessed"
	TSChanged   = "changed"    // Modification de l'entrée MFT ($SI/$FN)
	TSExecuted  = "executed"   // Prefetch, Amcache, BAM
	TSLogged    = "logged"     // EVTX TimeCreated, USN
	TSWritten   = "written"    // En-tête d'enregistrement EVTX
	TSLastWrite = "last_write" // LastWrite d'une clé de registre
)

// Valeurs de EventType.
const (
	TypeLogon           = "logon"
	TypeLogonFailed     = "logon_failed"
	TypeLogoff          = "logoff"
	TypeProcessCreation = "process_creation"
	TypeServiceInstall  = "service_install"
	TypeScriptExecution = "script_execution"
	TypeLogCleared      = "log_cleared"
	TypeMalwareDetected = "malware_detected"
	TypeAVConfigChange  = "av_config_change"
	TypeOther           = "other"
)

// Valeur de Ingest pour le parsing natif.
const IngestNative = "native"
