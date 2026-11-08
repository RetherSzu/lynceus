package normalizer

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Violation est une règle du modèle non respectée par un champ.
type Violation struct {
	Field string
	Rule  string
}

func (v Violation) String() string { return v.Field + ": " + v.Rule }

var (
	sources = set(SourceEVTX, SourceMFT, SourceUSN, SourceRegistry, SourcePrefetch, SourceMemory)
	tsTypes = set(TSCreated, TSModified, TSAccessed, TSChanged, TSExecuted, TSLogged, TSWritten, TSLastWrite)
	evTypes = set(TypeLogon, TypeLogonFailed, TypeLogoff, TypeProcessCreation, TypeServiceInstall,
		TypeScriptExecution, TypeLogCleared, TypeMalwareDetected, TypeAVConfigChange, TypeOther)
	hashLen  = map[string]int{"md5": 32, "sha1": 40, "sha256": 64, "imphash": 32}
	sidRegex = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+)+$`)
)

func set(vs ...string) map[string]bool {
	m := make(map[string]bool, len(vs))
	for _, v := range vs {
		m[v] = true
	}
	return m
}

const notUTF8 = "must be valid UTF-8"

// Validate renvoie toutes les violations de l'événement, dans l'ordre des
// champs, au plus une par champ ; nil si l'événement est valide (FR-009).
func (e Event) Validate() []Violation {
	var vs []Violation
	add := func(field, rule string) { vs = append(vs, Violation{field, rule}) }
	text := func(field, s string) {
		if !utf8.ValidString(s) {
			add(field, notUTF8)
		}
	}

	if !isLowerHex(e.UID, 32) {
		add("uid", "must be 32 lowercase hex characters")
	}
	if e.Timestamp.IsZero() {
		add("timestamp", "must not be zero")
	}
	if !tsTypes[e.TimestampType] {
		add("timestamp_type", fmt.Sprintf("unknown value %q", e.TimestampType))
	}
	for i, ts := range e.Timestamps {
		f := fmt.Sprintf("timestamps[%d].", i)
		if !tsTypes[ts.Type] {
			add(f+"type", fmt.Sprintf("unknown value %q", ts.Type))
		}
		if ts.Time.IsZero() {
			add(f+"time", "must not be zero")
		}
		if ts.Origin == "" {
			add(f+"origin", "must not be empty")
		} else {
			text(f+"origin", ts.Origin)
		}
	}
	if !sources[e.Source] {
		add("source", fmt.Sprintf("unknown value %q", e.Source))
	}
	if !evTypes[e.EventType] {
		add("event_type", fmt.Sprintf("unknown value %q", e.EventType))
	}
	switch {
	case e.Host == "":
		add("host", "must not be empty")
	case !utf8.ValidString(e.Host):
		add("host", notUTF8)
	case strings.Contains(e.Host, "."):
		add("host", "must be the short name, without '.'")
	case strings.IndexFunc(e.Host, unicode.IsSpace) >= 0:
		add("host", "must not contain spaces")
	case e.Host != strings.ToUpper(e.Host):
		add("host", "must be uppercase")
	}
	if e.HostFQDN != "" {
		if !utf8.ValidString(e.HostFQDN) {
			add("host_fqdn", notUTF8)
		} else if !strings.Contains(e.HostFQDN, ".") {
			add("host_fqdn", "must contain '.'")
		}
	}

	// FR-004 : champs EVTX requis pour evtx, interdits pour les autres sources
	// connues (une source inconnue est déjà signalée).
	if e.Source == SourceEVTX {
		if e.Channel == "" {
			add("channel", "required when source is evtx")
		} else {
			text("channel", e.Channel)
		}
		if e.Provider == "" {
			add("provider", "required when source is evtx")
		} else {
			text("provider", e.Provider)
		}
		if e.EventID == nil {
			add("event_id", "required when source is evtx")
		}
	} else if sources[e.Source] {
		if e.Channel != "" {
			add("channel", "only allowed when source is evtx")
		}
		if e.Provider != "" {
			add("provider", "only allowed when source is evtx")
		}
		if e.EventID != nil {
			add("event_id", "only allowed when source is evtx")
		}
	}

	account(add, "subject", e.Subject)
	account(add, "target", e.Target)

	text("process", e.Process)
	text("parent_process", e.ParentProcess)
	text("command_line", e.CommandLine)
	text("file_path", e.FilePath)
	text("registry_path", e.RegistryPath)
	for _, k := range sortedKeys(e.Hashes) {
		n, ok := hashLen[k]
		if !ok {
			add("hashes", fmt.Sprintf("unknown key %q", k))
		} else if !isLowerHex(e.Hashes[k], n) {
			add("hashes["+k+"]", fmt.Sprintf("must be %d lowercase hex characters", n))
		}
	}

	if rule := sourceFileRule(e.SourceFile); rule != "" {
		add("source_file", rule)
	}
	if !isLowerHex(e.SourceHash, 64) {
		add("source_sha256", "must be 64 lowercase hex characters")
	}
	if e.RecordLocator == "" {
		add("record_locator", "must not be empty")
	} else {
		text("record_locator", e.RecordLocator)
	}
	if !validIngest(e.Ingest) {
		add("ingest", `must be "native" or "import:<tool>@<version>"`)
	}
	for _, k := range sortedKeys(e.Metadata) {
		if !utf8.ValidString(k) {
			add("metadata", "key "+notUTF8)
		} else if !utf8.ValidString(e.Metadata[k]) {
			add("metadata", fmt.Sprintf("value of %q %s", k, notUTF8))
		}
	}
	return vs
}

// account vérifie un compte : jamais vide, jamais de valeur « absente »
// laissée en place, SID canonique (FR-011).
func account(add func(field, rule string), field string, a *Account) {
	if a == nil {
		return
	}
	if *a == (Account{}) {
		add(field, "must be omitted when empty")
		return
	}
	for _, f := range []struct{ name, v string }{{"domain", a.Domain}, {"name", a.Name}} {
		switch {
		case !utf8.ValidString(f.v):
			add(field+"."+f.name, notUTF8)
		case f.v == "-":
			add(field+"."+f.name, `"-" means absent and must be omitted`)
		}
	}
	switch {
	case a.SID == "":
	case !sidRegex.MatchString(a.SID):
		add(field+".sid", "must match S-1-<n>(-<n>)+ in uppercase")
	case a.SID == nullSID:
		add(field+".sid", nullSID+" means absent and must be omitted")
	}
}

// sourceFileRule renvoie la règle violée par un chemin de preuve, ou "".
func sourceFileRule(p string) string {
	switch {
	case p == "":
		return "must not be empty"
	case !utf8.ValidString(p):
		return notUTF8
	case strings.Contains(p, `\`):
		return `must use "/" as separator`
	case strings.HasPrefix(p, "/"), len(p) >= 2 && p[1] == ':':
		return "must be relative to evidence/"
	case path.Clean(p) != p:
		return "must be a clean path"
	case p == ".." || strings.HasPrefix(p, "../"):
		return "must stay inside evidence/"
	}
	return ""
}

func validIngest(s string) bool {
	if s == IngestNative {
		return true
	}
	rest := strings.TrimPrefix(s, "import:")
	tool, version, ok := strings.Cut(rest, "@")
	return rest != s && ok && tool != "" && version != "" && utf8.ValidString(s)
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
