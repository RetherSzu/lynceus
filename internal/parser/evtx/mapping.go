package evtx

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"DFIRFlow/internal/normalizer"
)

// Entry est une entrée de la table de correspondance (contracts/evtx-mapping.md).
type Entry struct {
	Channel        string            `json:"channel"`
	Provider       string            `json:"provider"`
	EventID        *uint32           `json:"event_id"`
	EventType      string            `json:"event_type"`
	ActionTime     string            `json:"action_time,omitempty"`
	ActionTimeType string            `json:"action_time_type,omitempty"`
	Fields         map[string]string `json:"fields"`
}

// Table indexe les entrées par (canal, fournisseur, EventID), sans casse.
type Table map[string]Entry

//go:embed mapping.json
var mappingJSON []byte

var (
	tableOnce sync.Once
	table     Table
	tableErr  error
)

// defaultTable charge une seule fois la table embarquée ; une table invalide
// est une erreur renvoyée par Parse, jamais une panique.
func defaultTable() (Table, error) {
	tableOnce.Do(func() { table, tableErr = LoadTable(mappingJSON) })
	return table, tableErr
}

func key(channel, provider string, id uint32) string {
	return strings.ToLower(channel) + "\x00" + strings.ToLower(provider) + "\x00" + strconv.FormatUint(uint64(id), 10)
}

var (
	eventTypes = map[string]bool{
		normalizer.TypeLogon: true, normalizer.TypeLogonFailed: true, normalizer.TypeLogoff: true,
		normalizer.TypeProcessCreation: true, normalizer.TypeServiceInstall: true,
		normalizer.TypeScriptExecution: true, normalizer.TypeLogCleared: true,
		normalizer.TypeMalwareDetected: true, normalizer.TypeAVConfigChange: true,
	}
	timestampTypes = map[string]bool{
		normalizer.TSCreated: true, normalizer.TSModified: true, normalizer.TSAccessed: true,
		normalizer.TSChanged: true, normalizer.TSExecuted: true, normalizer.TSLogged: true,
	}
	fieldNames = map[string]bool{
		"subject.sid": true, "subject.domain": true, "subject.name": true,
		"target.sid": true, "target.domain": true, "target.name": true,
		"process": true, "process_id": true, "parent_process": true, "parent_process_id": true,
		"command_line": true, "file_path": true, "registry_path": true, "hashes": true,
	}
)

// LoadTable décode strictement une table et la valide (FR-012a).
func LoadTable(data []byte) (Table, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var entries []Entry
	if err := dec.Decode(&entries); err != nil {
		return nil, fmt.Errorf("mapping table: %w", err)
	}
	t := Table{}
	for i, e := range entries {
		name := fmt.Sprintf("mapping table: entry %d (%s/%s/%v)", i, e.Channel, e.Provider, e.EventID)
		switch {
		case e.Channel == "" || e.Provider == "" || e.EventID == nil:
			return nil, fmt.Errorf("%s: channel, provider and event_id are required", name)
		case !eventTypes[e.EventType]:
			return nil, fmt.Errorf("%s: invalid event_type %q", name, e.EventType)
		case e.Fields == nil:
			return nil, fmt.Errorf("%s: fields is required", name)
		case (e.ActionTime == "") != (e.ActionTimeType == ""):
			return nil, fmt.Errorf("%s: action_time and action_time_type go together", name)
		case e.ActionTimeType != "" && !timestampTypes[e.ActionTimeType]:
			return nil, fmt.Errorf("%s: invalid action_time_type %q", name, e.ActionTimeType)
		}
		for f := range e.Fields {
			if !fieldNames[f] {
				return nil, fmt.Errorf("%s: unknown normalized field %q", name, f)
			}
		}
		k := key(e.Channel, e.Provider, *e.EventID)
		if _, dup := t[k]; dup {
			return nil, fmt.Errorf("%s: duplicate entry", name)
		}
		t[k] = e
	}
	return t, nil
}

// lookup renvoie l'entrée de l'événement, s'il est dans la table.
func (t Table) lookup(channel, provider string, id uint32) (Entry, bool) {
	e, ok := t[key(channel, provider, id)]
	return e, ok
}

// apply remplit event_type et les champs normalisés à partir de metadata ;
// il renvoie l'instant de l'action désigné par l'entrée, s'il existe.
func (e Entry) apply(ev *normalizer.Event, data map[string]interface{}) (action time.Time, ok bool) {
	ev.EventType = e.EventType
	get := func(f string) string {
		src, mapped := e.Fields[f]
		if !mapped {
			return ""
		}
		v := strings.TrimSpace(render(data[src]))
		if v == "-" { // valeur vide de Windows
			return ""
		}
		return v
	}
	account := func(prefix string) *normalizer.Account {
		domain, name := get(prefix+".domain"), get(prefix+".name")
		if d, n, split := strings.Cut(domain, `\`); split && name == "" {
			domain, name = d, n
		}
		return normalizer.NewAccount(get(prefix+".sid"), domain, name)
	}
	ev.Subject = account("subject")
	ev.Target = account("target")
	ev.Process = get("process")
	ev.ProcessID = parseID(get("process_id"))
	ev.ParentProcess = get("parent_process")
	ev.ParentProcessID = parseID(get("parent_process_id"))
	ev.CommandLine = get("command_line")
	ev.FilePath = get("file_path")
	ev.RegistryPath = get("registry_path")
	ev.Hashes = parseHashes(get("hashes"))
	if e.ActionTime != "" {
		return timeOf(data[e.ActionTime])
	}
	return time.Time{}, false
}

// parseID lit un identifiant décimal ou 0x… ; 0 signifie absent.
func parseID(s string) uint32 {
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s, base = s[2:], 16
	}
	v, err := strconv.ParseUint(s, base, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}

// parseHashes découpe la chaîne Sysmon « SHA1=…,MD5=… » (spec 003, C9).
func parseHashes(s string) map[string]string {
	known := map[string]bool{"md5": true, "sha1": true, "sha256": true, "imphash": true}
	var h map[string]string
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		k = strings.ToLower(k)
		if !ok || !known[k] || v == "" {
			continue
		}
		if h == nil {
			h = map[string]string{}
		}
		h[k] = strings.ToLower(v)
	}
	return h
}
