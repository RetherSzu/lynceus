package detection

import (
	"testing"

	"DFIRFlow/internal/normalizer"
)

func TestMatch(t *testing.T) {
	cmd := func(s string) map[string]string { return map[string]string{"CommandLine": s, "Empty": ""} }
	sec := func(md map[string]string) normalizer.Event {
		return evtx("Security", "Microsoft-Windows-Security-Auditing", 4688, md, 1)
	}
	for _, c := range []struct {
		det  string
		ev   normalizer.Event
		want bool
	}{
		{"CommandLine: 'powershell -enc'", sec(cmd("PowerShell -ENC")), true},
		{"CommandLine: 'powershell'", sec(cmd("powershell.exe")), false},
		{"CommandLine: ['a', 'b']", sec(cmd("b")), true},
		{"CommandLine: ['a', 'b']", sec(cmd("c")), false},
		{"CommandLine|contains|all: ['-nop', '-enc']", sec(cmd("x -NoP -enc y")), true},
		{"CommandLine|contains|all: ['-nop', '-enc']", sec(cmd("x -enc y")), false},
		{"CommandLine: 'po*ll -?nc'", sec(cmd("powershell -enc")), true},
		{"CommandLine: 'po*ll -?nc'", sec(cmd("powershell -nc")), false},
		{`CommandLine: 'a\*b'`, sec(cmd("a*b")), true},
		{`CommandLine: 'a\*b'`, sec(cmd("axxb")), false},
		{`CommandLine: 'a\?b'`, sec(cmd("axb")), false},
		{`CommandLine: 'c:\\temp\\x'`, sec(cmd(`C:\temp\x`)), true},
		{`CommandLine: 'c:\temp'`, sec(cmd(`C:\temp`)), true},
		{"CommandLine|contains: 'shell'", sec(cmd("powershell.exe")), true},
		{"CommandLine|startswith: 'power'", sec(cmd("powershell.exe")), true},
		{"CommandLine|startswith: 'shell'", sec(cmd("powershell.exe")), false},
		{"CommandLine|endswith: '.EXE'", sec(cmd("powershell.exe")), true},
		{"CommandLine|endswith: 'power'", sec(cmd("powershell.exe")), false},
		{"CommandLine|re: '^Power'", sec(cmd("Powershell")), true},
		{"CommandLine|re: '^power'", sec(cmd("Powershell")), false},
		{"CommandLine|re|i: '^power'", sec(cmd("Powershell")), true},
		{"CommandLine|re: 'shell'", sec(cmd("Powershell -x")), true},
		{"CommandLine: null", sec(nil), true},
		{"Empty: null", sec(cmd("x")), true},
		{"CommandLine: null", sec(cmd("x")), false},
		{"Missing: 'x'", sec(cmd("x")), false},
		{"Missing|contains: ''", sec(cmd("x")), false},
		{"EventID: 4688", sec(nil), true},
		{"EventID: [4624, 4688]", sec(nil), true},
		{"EventID: 4624", sec(nil), false},
		{"Channel: security", sec(nil), true},
		{"Provider_Name: 'Microsoft-Windows-Security-Auditing'", sec(nil), true},
		{"Computer: 'pc01'", sec(map[string]string{"System.Computer": "PC01"}), true},
		{"System.Level: 4", sec(map[string]string{"System.Level": "4"}), true},
	} {
		r := mustRule(t, rule("", "  sel:\n    "+c.det+"\n  condition: sel\n"))
		if got := r.match(&c.ev); got != c.want {
			t.Errorf("%s on %v: %v, want %v", c.det, c.ev.Metadata, got, c.want)
		}
	}

	// Sélection en liste de tables : l'une ou l'autre.
	r := mustRule(t, rule("", "  sel:\n    - CommandLine: a\n    - CommandLine: b\n      Empty: x\n  condition: sel\n"))
	if !r.match(ptr(sec(cmd("a")))) || r.match(ptr(sec(cmd("b")))) {
		t.Error("list of maps")
	}
	// Plusieurs champs d'une table : tous.
	r = mustRule(t, rule("", "  sel:\n    EventID: 4688\n    CommandLine: a\n  condition: sel\n"))
	if !r.match(ptr(sec(cmd("a")))) || r.match(ptr(sec(cmd("b")))) {
		t.Error("map AND")
	}
}

func ptr(ev normalizer.Event) *normalizer.Event { return &ev }
