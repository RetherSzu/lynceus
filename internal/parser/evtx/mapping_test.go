package evtx

import (
	"strings"
	"testing"
	"time"

	"DFIRFlow/internal/normalizer"
	"DFIRFlow/internal/parser/evtx/binxml"
)

func TestMappingTable(t *testing.T) {
	tbl, err := LoadTable(mappingJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl) != 15 {
		t.Fatalf("%d entries, want 15 (contracts/evtx-mapping.md)", len(tbl))
	}
	valid := `{"channel":"Security","provider":"P","event_id":1,"event_type":"logon","fields":{}}`
	bad := map[string]string{
		"duplicate (case-insensitive)": `[` + valid + `,{"channel":"SECURITY","provider":"p","event_id":1,"event_type":"logoff","fields":{}}]`,
		"event_type other":             `[{"channel":"S","provider":"P","event_id":1,"event_type":"other","fields":{}}]`,
		"unknown event_type":           `[{"channel":"S","provider":"P","event_id":1,"event_type":"login","fields":{}}]`,
		"unknown normalized field":     `[{"channel":"S","provider":"P","event_id":1,"event_type":"logon","fields":{"user":"X"}}]`,
		"unknown JSON field":           `[{"channel":"S","provider":"P","event_id":1,"event_type":"logon","fields":{},"severity":"high"}]`,
		"action_time without type":     `[{"channel":"S","provider":"P","event_id":1,"event_type":"logon","action_time":"UtcTime","fields":{}}]`,
		"invalid action_time_type":     `[{"channel":"S","provider":"P","event_id":1,"event_type":"logon","action_time":"UtcTime","action_time_type":"written","fields":{}}]`,
		"missing event_id":             `[{"channel":"S","provider":"P","event_type":"logon","fields":{}}]`,
		"missing fields":               `[{"channel":"S","provider":"P","event_id":1,"event_type":"logon"}]`,
	}
	for name, data := range bad {
		if _, err := LoadTable([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(name, "JSON") == false && !strings.Contains(err.Error(), "entry") {
			t.Errorf("%s: error does not name the entry: %v", name, err)
		}
	}
	if _, err := LoadTable([]byte(`[` + valid + `]`)); err != nil {
		t.Fatal(err)
	}
}

// record construit un enregistrement décodé ; data est l'EventData.
func record(channel, provider string, id uint16, data ...interface{}) *binxml.EventRecord {
	sys := binxml.NewDict()
	sys.Set("Provider", dict("Name", provider))
	sys.Set("EventID", id)
	sys.Set("TimeCreated", dict("SystemTime", binxml.FileTime(131939362733172597)))
	sys.Set("Channel", channel)
	sys.Set("Computer", "host.example.org")
	ev := dict("System", sys, "EventData", dict(data...))
	rec := &binxml.EventRecord{Event: dict("Event", ev)}
	rec.Header.RecordID = 1
	rec.Header.FileTime = 131939362733172597
	return rec
}

func convert(t *testing.T, rec *binxml.EventRecord) normalizer.Event {
	t.Helper()
	tbl, err := defaultTable()
	if err != nil {
		t.Fatal(err)
	}
	ev, err := toEvent(rec, 0, testSrc, tbl)
	if err != nil {
		t.Fatal(err)
	}
	if vs := ev.Validate(); len(vs) > 0 {
		t.Fatalf("invalid event: %v", vs)
	}
	return ev
}

const (
	sec      = "Security"
	auditing = "Microsoft-Windows-Security-Auditing"
	sysmon   = "Microsoft-Windows-Sysmon"
	defender = "Microsoft-Windows-Windows Defender"
	defChan  = "Microsoft-Windows-Windows Defender/Operational"
)

func TestMappingApply(t *testing.T) {
	sid := binxml.SID("S-1-5-21-1-2-3-1001")
	subject := []interface{}{"SubjectUserSid", sid, "SubjectDomainName", "CORP", "SubjectUserName", "alice"}
	target := []interface{}{"TargetUserSid", sid, "TargetDomainName", "CORP", "TargetUserName", "bob"}
	cat := func(parts ...[]interface{}) []interface{} {
		var out []interface{}
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	proc := []interface{}{"ProcessName", `C:\Windows\System32\lsass.exe`, "ProcessId", binxml.HexInt64(0x1a4)}
	cases := []struct {
		channel, provider string
		id                uint16
		data              []interface{}
		want              string
		check             func(normalizer.Event) bool
	}{
		{sec, auditing, 4624, cat(subject, target, proc), "logon", func(e normalizer.Event) bool {
			return e.Subject.Name == "alice" && e.Target.Name == "bob" && e.ProcessID == 420 && e.Process != ""
		}},
		{sec, auditing, 4625, cat(subject, target, proc), "logon_failed", func(e normalizer.Event) bool { return e.Target.SID == string(sid) }},
		{sec, auditing, 4634, target, "logoff", func(e normalizer.Event) bool { return e.Target.Domain == "CORP" }},
		{sec, auditing, 4647, target, "logoff", func(e normalizer.Event) bool { return e.Target.Name == "bob" }},
		{sec, auditing, 4688, cat(subject, []interface{}{"NewProcessName", `C:\x.exe`, "NewProcessId", binxml.HexInt64(8), "ParentProcessName", `C:\p.exe`, "ProcessId", binxml.HexInt64(4), "CommandLine", "x /y"}), "process_creation",
			func(e normalizer.Event) bool {
				return e.Process == `C:\x.exe` && e.ProcessID == 8 && e.ParentProcess == `C:\p.exe` && e.ParentProcessID == 4 && e.CommandLine == "x /y"
			}},
		{sec, auditing, 4697, cat(subject, []interface{}{"ServiceFileName", `C:\svc.exe`}), "service_install", func(e normalizer.Event) bool { return e.FilePath == `C:\svc.exe` }},
		{sec, "Microsoft-Windows-Eventlog", 1102, subject, "log_cleared", func(e normalizer.Event) bool { return e.Subject.Name == "alice" }},
		{"System", "Service Control Manager", 7045, []interface{}{"ImagePath", `C:\svc.exe`}, "service_install", func(e normalizer.Event) bool { return e.FilePath == `C:\svc.exe` }},
		{"System", "Microsoft-Windows-Eventlog", 104, []interface{}{"SubjectDomainName", "CORP", "SubjectUserName", "alice"}, "log_cleared", func(e normalizer.Event) bool { return e.Subject.Domain == "CORP" }},
		{"Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104, []interface{}{"MessageNumber", int32(1), "ScriptBlockText", "Get-Process", "Path", `C:\a.ps1`}, "script_execution",
			func(e normalizer.Event) bool { return e.FilePath == `C:\a.ps1` && e.Metadata["MessageNumber"] == "1" }},
		{defChan, defender, 1116, []interface{}{"Detection User", `CORP\alice`, "Process Name", `C:\m.exe`, "Path", `file:_C:\m.exe`}, "malware_detected",
			func(e normalizer.Event) bool { return e.Subject.Name == "alice" && e.Process == `C:\m.exe` }},
		{defChan, defender, 1117, []interface{}{"Path", `C:\m.exe`}, "malware_detected", func(e normalizer.Event) bool { return e.FilePath == `C:\m.exe` }},
		{defChan, defender, 5001, nil, "av_config_change", nil},
		{defChan, defender, 5007, []interface{}{"New Value", "x"}, "av_config_change", func(e normalizer.Event) bool { return e.Metadata["New Value"] == "x" }},
		{"Microsoft-Windows-Sysmon/Operational", sysmon, 1, []interface{}{
			"UtcTime", "2019-02-06 14:17:00.123", "User", `CORP\alice`, "Image", `C:\x.exe`, "ProcessId", uint32(420),
			"ParentImage", `C:\p.exe`, "ParentProcessId", "0x1a4", "CommandLine", "x", "Hashes", "SHA1=AA" + strings.Repeat("0", 38) + ",MD5=" + strings.Repeat("B", 32) + ",IMPHASH=" + strings.Repeat("C", 32),
		}, "process_creation", func(e normalizer.Event) bool {
			ts := e.Timestamp.UTC().Format(time.RFC3339Nano) == "2019-02-06T14:17:00.123Z" && e.TimestampType == "executed"
			second := len(e.Timestamps) == 2 && e.Timestamps[0].Type == "logged" && e.Timestamps[1].Type == "written"
			return ts && second && e.Subject.Domain == "CORP" && e.Subject.Name == "alice" && e.ParentProcessID == 420 &&
				e.Hashes["md5"] == strings.Repeat("b", 32) && e.Hashes["sha1"] == "aa"+strings.Repeat("0", 38) && len(e.Hashes) == 3
		}},
	}
	for _, c := range cases {
		e := convert(t, record(c.channel, c.provider, c.id, c.data...))
		if e.EventType != c.want || (c.check != nil && !c.check(e)) {
			t.Errorf("%s/%d: %+v", c.channel, c.id, e)
		}
	}

	// Valeurs absentes, EventID inconnu, secondaires égaux au principal omis.
	e := convert(t, record(sec, auditing, 4624, "SubjectUserSid", "S-1-0-0", "SubjectUserName", "-", "TargetUserName", "", "ProcessName", "-"))
	if e.Subject != nil || e.Target != nil || e.Process != "" || len(e.Timestamps) != 0 || e.TimestampType != "logged" {
		t.Errorf("absent values: %+v", e)
	}
	if e := convert(t, record(sec, auditing, 4672)); e.EventType != "other" || e.Host != "HOST" || e.HostFQDN != "host.example.org" {
		t.Errorf("unknown EventID: %+v", e)
	}
}

func TestRenderValues(t *testing.T) {
	guid := binxml.GUID{D: 0x54849625, W1: 0x5478, W2: 0x4994, B: [8]byte{0xa5, 0xba, 0x3e, 0x3b, 0x03, 0x28, 0xc3, 0x0d}}
	cases := []struct {
		v    interface{}
		want string
	}{
		{binxml.HexInt32(0xC000006D), "0xc000006d"},
		{binxml.HexInt64(0x3E7), "0x3e7"},
		{binxml.HexInt64(0), "0x0"},
		{true, "true"},
		{int32(-5), "-5"},
		{uint64(18446744073709551615), "18446744073709551615"},
		{float64(0.1), "0.1"},
		{guid, "{54849625-5478-4994-A5BA-3E3B0328C30D}"},
		{binxml.SID("S-1-5-18"), "S-1-5-18"},
		{binxml.FileTime(131939362733172597), "2019-02-06T14:17:53.317259Z"},
		{binxml.Binary{0xAB, 0x01}, "ab01"},
		{"%%1833", "%%1833"},
	}
	for _, c := range cases {
		if got := render(c.v); got != c.want {
			t.Errorf("render(%#v) = %q, want %q", c.v, got, c.want)
		}
	}
}
