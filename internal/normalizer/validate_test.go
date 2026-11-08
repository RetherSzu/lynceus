package normalizer

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func u32(v uint32) *uint32 { return &v }

// valid4624 renvoie un 4624 complet et valide ; chaque appel est une copie neuve.
func valid4624() Event {
	return Event{
		UID:           UID(testSHA, testFile, testLoc),
		Timestamp:     Time{time.Date(2020, 9, 9, 13, 18, 23, 627952000, time.UTC)},
		TimestampType: TSLogged,
		Timestamps:    []TimestampEntry{{Type: TSWritten, Time: Time{time.Date(2020, 9, 9, 13, 18, 23, 0, time.UTC)}, Origin: "Header"}},
		Source:        SourceEVTX,
		EventType:     TypeLogon,
		Host:          "WIN-77LTAPHIQ1R",
		HostFQDN:      "WIN-77LTAPHIQ1R.example.corp",
		Channel:       "Security",
		Provider:      "Microsoft-Windows-Security-Auditing",
		EventID:       u32(4624),
		Subject:       &Account{Domain: "EXAMPLE", Name: "WIN-77LTAPHIQ1R$", SID: "S-1-5-18"},
		Target:        &Account{Domain: "EXAMPLE", Name: "alice", SID: "S-1-5-21-1-2-3-1104"},
		Process:       `C:\Windows\System32\lsass.exe`,
		ProcessID:     620,
		Hashes:        map[string]string{"md5": strings.Repeat("a", 32), "sha256": strings.Repeat("b", 64)},
		SourceFile:    testFile,
		SourceHash:    testSHA,
		RecordID:      1234,
		RecordLocator: testLoc,
		Ingest:        IngestNative,
		Metadata:      map[string]string{"LogonType": "3", "Status": "0x0"},
	}
}

func fields(vs []Violation) []string {
	out := []string{}
	for _, v := range vs {
		out = append(out, v.Field)
	}
	return out
}

func TestValidate(t *testing.T) {
	if vs := valid4624().Validate(); len(vs) != 0 {
		t.Fatalf("valid event: %v", vs)
	}

	const bad = "\xff"
	cases := []struct {
		name string
		mut  func(*Event)
		want []string
	}{
		{"uid short", func(e *Event) { e.UID = e.UID[:31] }, []string{"uid"}},
		{"uid upper", func(e *Event) { e.UID = strings.ToUpper(e.UID) }, []string{"uid"}},
		{"timestamp zero", func(e *Event) { e.Timestamp = Time{} }, []string{"timestamp"}},
		{"timestamp_type unknown", func(e *Event) { e.TimestampType = "mft_modified" }, []string{"timestamp_type"}},
		{"timestamps time zero", func(e *Event) { e.Timestamps[0].Time = Time{} }, []string{"timestamps[0].time"}},
		{"timestamps type unknown", func(e *Event) { e.Timestamps[0].Type = "header" }, []string{"timestamps[0].type"}},
		{"timestamps origin empty", func(e *Event) { e.Timestamps[0].Origin = "" }, []string{"timestamps[0].origin"}},
		{"source unknown", func(e *Event) { e.Source = "powershell" }, []string{"source"}},
		{"event_type unknown", func(e *Event) { e.EventType = "persistence" }, []string{"event_type"}},
		{"host empty", func(e *Event) { e.Host = "" }, []string{"host"}},
		{"host dotted", func(e *Event) { e.Host = "WIN.EXAMPLE" }, []string{"host"}},
		{"host lowercase", func(e *Event) { e.Host = "win-77ltaphiq1r" }, []string{"host"}},
		{"host space", func(e *Event) { e.Host = "WIN-01 " }, []string{"host"}},
		{"host_fqdn without dot", func(e *Event) { e.HostFQDN = "WIN-77LTAPHIQ1R" }, []string{"host_fqdn"}},
		{"source_file absolute", func(e *Event) { e.SourceFile = "/Logs/Security.evtx" }, []string{"source_file"}},
		{"source_file backslash", func(e *Event) { e.SourceFile = `Logs\Security.evtx` }, []string{"source_file"}},
		{"source_file dotdot", func(e *Event) { e.SourceFile = "../Security.evtx" }, []string{"source_file"}},
		{"source_file unclean", func(e *Event) { e.SourceFile = "Logs/./Security.evtx" }, []string{"source_file"}},
		{"source_file drive", func(e *Event) { e.SourceFile = "C:/Logs/Security.evtx" }, []string{"source_file"}},
		{"source_file empty", func(e *Event) { e.SourceFile = "" }, []string{"source_file"}},
		{"source_sha256 63", func(e *Event) { e.SourceHash = e.SourceHash[:63] }, []string{"source_sha256"}},
		{"source_sha256 upper", func(e *Event) { e.SourceHash = strings.ToUpper(e.SourceHash) }, []string{"source_sha256"}},
		{"record_locator empty", func(e *Event) { e.RecordLocator = "" }, []string{"record_locator"}},
		{"ingest unknown", func(e *Event) { e.Ingest = "manual" }, []string{"ingest"}},
		{"ingest no version", func(e *Event) { e.Ingest = "import:hayabusa@" }, []string{"ingest"}},
		{"ingest no tool", func(e *Event) { e.Ingest = "import:@2.0" }, []string{"ingest"}},
		{"ingest no at", func(e *Event) { e.Ingest = "import:hayabusa" }, []string{"ingest"}},
		{"evtx without channel", func(e *Event) { e.Channel = "" }, []string{"channel"}},
		{"evtx without provider", func(e *Event) { e.Provider = "" }, []string{"provider"}},
		{"evtx without event_id", func(e *Event) { e.EventID = nil }, []string{"event_id"}},
		{"mft with event_id", func(e *Event) { e.Source, e.Channel, e.Provider = SourceMFT, "", "" }, []string{"event_id"}},
		{"mft with channel", func(e *Event) { e.Source, e.Provider, e.EventID = SourceMFT, "", nil }, []string{"channel"}},
		{"hashes unknown key", func(e *Event) { e.Hashes["crc32"] = "abcd1234" }, []string{"hashes"}},
		{"hashes bad length", func(e *Event) { e.Hashes["sha1"] = strings.Repeat("c", 32) }, []string{"hashes[sha1]"}},
		{"hashes upper", func(e *Event) { e.Hashes["md5"] = strings.Repeat("A", 32) }, []string{"hashes[md5]"}},
		{"sid malformed", func(e *Event) { e.Subject.SID = "S-1-5" }, []string{"subject.sid"}},
		{"sid lowercase", func(e *Event) { e.Subject.SID = "s-1-5-18" }, []string{"subject.sid"}},
		{"sid dash", func(e *Event) { e.Target.SID = "-" }, []string{"target.sid"}},
		{"sid null", func(e *Event) { e.Target.SID = nullSID }, []string{"target.sid"}},
		{"name dash", func(e *Event) { e.Target.Name = "-" }, []string{"target.name"}},
		{"account empty", func(e *Event) { e.Subject = &Account{} }, []string{"subject"}},
		{"utf8 command_line", func(e *Event) { e.CommandLine = "cmd " + bad }, []string{"command_line"}},
		{"utf8 account", func(e *Event) { e.Target.Name = bad }, []string{"target.name"}},
		{"utf8 metadata key", func(e *Event) { e.Metadata[bad] = "x" }, []string{"metadata"}},
		{"utf8 metadata value", func(e *Event) { e.Metadata["Status"] = bad }, []string{"metadata"}},
		{"record_id zero valid", func(e *Event) { e.RecordID = 0 }, []string{}},
		{"event_type other valid", func(e *Event) { e.EventType = TypeOther }, []string{}},
		{"event_id zero valid", func(e *Event) { e.EventID = u32(0) }, []string{}},
		{"three defects", func(e *Event) { e.UID, e.Host, e.Ingest = "", "", "" }, []string{"uid", "host", "ingest"}},
	}
	for _, c := range cases {
		e := valid4624()
		c.mut(&e)
		vs := e.Validate()
		if got := fields(vs); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: fields = %v, want %v (%v)", c.name, got, c.want, vs)
		}
		for _, v := range vs {
			if v.String() != v.Field+": "+v.Rule {
				t.Errorf("%s: String() = %q", c.name, v.String())
			}
		}
	}
}
