package detection

import (
	"strings"
	"testing"
)

const sel = "  sel:\n    EventID: 4624\n  condition: sel\n"

func TestLoadRule(t *testing.T) {
	r := mustRule(t, rule("status: stable\ntags:\n  - attack.lateral-movement\n  - attack.t1021.002\n  - attack.t1078\n", sel))
	if r.ID != "r1" || r.Title != "T" || r.Severity != "high" || r.Confidence != 0.8 || r.MITRE != "T1021.002" || r.Channel != "Security" {
		t.Errorf("rule: %+v", r)
	}
	if len(r.Version) != 16 {
		t.Errorf("version %q", r.Version)
	}
	crlf := mustRule(t, strings.ReplaceAll(rule("status: stable\ntags:\n  - attack.lateral-movement\n  - attack.t1021.002\n  - attack.t1078\n", sel), "\n", "\r\n"))
	if crlf.Version != r.Version {
		t.Errorf("CRLF version %s != %s", crlf.Version, r.Version)
	}
	if other := mustRule(t, rule("# changed\n", sel)); other.Version == mustRule(t, rule("", sel)).Version {
		t.Error("version unchanged after edit")
	}

	for _, c := range []struct {
		extra      string
		severity   string
		confidence float64
		mitre      string
	}{
		{"status: test\n", "high", 0.6, ""},
		{"status: experimental\n", "high", 0.4, ""},
		{"", "high", 0.4, ""},
		{"confidence: 0.95\nstatus: test\n", "high", 0.95, ""},
		{"tags: [attack.execution, attack.t1059]\n", "high", 0.4, "T1059"},
	} {
		r := mustRule(t, rule(c.extra, sel))
		if r.Severity != c.severity || r.Confidence != c.confidence || r.MITRE != c.mitre {
			t.Errorf("%q: %+v", c.extra, r)
		}
	}
	r = mustRule(t, strings.Replace(rule("", sel), "level: high", "level: informational", 1))
	if r.Severity != "info" {
		t.Errorf("informational -> %q", r.Severity)
	}
	for svc, ch := range map[string]string{"system": "System", "powershell": "Microsoft-Windows-PowerShell/Operational", "sysmon": "Microsoft-Windows-Sysmon/Operational", "wmi": "Microsoft-Windows-WMI-Activity/Operational"} {
		if r := mustRule(t, strings.Replace(rule("", sel), "service: security", "service: "+svc, 1)); r.Channel != ch {
			t.Errorf("service %s -> %q", svc, r.Channel)
		}
	}
}

func TestSkippedRule(t *testing.T) {
	for _, src := range []string{
		strings.Replace(rule("", sel), "product: windows", "product: linux", 1),
		// Produit examiné en premier : écartée même invalide par ailleurs.
		"title: x\nlogsource:\n  product: macos\n  category: process_creation\n",
		rule("status: deprecated\n", sel),
		rule("status: unsupported\n", sel),
	} {
		if _, skipped, err := parseRule("r.yml", []byte(src)); !skipped || err != nil {
			t.Errorf("want skipped, got skipped=%v err=%v:\n%s", skipped, err, src)
		}
	}
	if _, skipped, err := parseRule("r.yml", []byte(strings.Replace(catRule("  category: webserver\n", sel), "product: windows", "product: linux", 1))); !skipped || err != nil {
		t.Errorf("linux with unknown category: skipped=%v err=%v", skipped, err)
	}
	if _, skipped, err := parseRule("r.yml", []byte(strings.Replace(rule("", sel), "product: windows", "product: Windows", 1))); skipped || err != nil {
		t.Errorf("product case: skipped=%v err=%v", skipped, err)
	}
}

// TestRefusedRule couvre le tableau « Raisons de refus » de contracts/detect.md.
func TestRefusedRule(t *testing.T) {
	nested := strings.Repeat("(", 65) + "sel" + strings.Repeat(")", 65)
	for _, c := range []struct{ src, reason string }{
		{strings.Repeat("#", 1<<20+1), "file too large"},
		{"title: [", "invalid YAML: "},
		{rule("", sel) + "---\n" + rule("", sel), "more than one rule in the file"},
		{strings.Replace(rule("", sel), "id: r1\n", "", 1), "missing id"},
		{strings.Replace(rule("", sel), "title: T\n", "", 1), "missing title"},
		{strings.Replace(rule("", sel), "level: high\n", "", 1), "missing level"},
		{strings.Replace(rule("", sel), "    EventID: 4624\n  condition: sel\n", "    EventID: 4624\n", 1), "missing condition"},
		{"title: T\nid: r1\nlevel: high\nlogsource:\n  product: windows\n  service: security\n", "missing detection"},
		{"title: T\nid: r1\nlevel: high\ndetection:\n" + sel, "missing logsource.product"},
		{strings.Replace(rule("", sel), "  service: security\n", "", 1), "missing logsource.service or logsource.category"},
		{catRule("  category: webserver\n", sel), "unknown logsource category: webserver"},
		{catRule("  category: process_creation\n  service: system\n", sel), "logsource category and service do not match"},
		{strings.Replace(rule("", sel), "level: high", "level: urgent", 1), "invalid level: urgent"},
		{rule("status: beta\n", sel), "invalid status: beta"},
		{rule("confidence: 1.5\n", sel), "invalid confidence: 1.5"},
		{rule("confidence: high\n", sel), "invalid confidence: high"},
		{strings.Replace(rule("", sel), "service: security", "service: nginx", 1), "unknown logsource service: nginx"},
		{rule("", "  sel:\n    EventID: 4625\n  condition: sel | count() > 5\n"), "aggregation is not supported"},
		{rule("", sel+"  timeframe: 5m\n"), "timeframe is not supported"},
		{rule("", "  kw:\n    - mimikatz\n  condition: kw\n"), "keyword search is not supported"},
		{rule("", "  sel:\n    '|contains': mimikatz\n  condition: sel\n"), "keyword search is not supported"},
		{rule("", "  sel:\n    CommandLine|re|m: x\n  condition: sel\n"), "unsupported modifier: m"},
		{rule("", "  sel:\n    CommandLine|re|windash: x\n  condition: sel\n"), "unsupported modifier: windash"},
		{rule("", "  sel:\n    CommandLine|re|base64: x\n  condition: sel\n"), "unsupported modifier: base64"},
		{rule("", "  sel:\n    CommandLine|re|cased: x\n  condition: sel\n"), "unsupported modifier: cased"},
		{rule("", "  sel:\n    CommandLine|base64|base64offset: x\n  condition: sel\n"), "unsupported modifier: base64offset"},
		{rule("", "  sel:\n    CommandLine|wide|utf16be|base64: x\n  condition: sel\n"), "unsupported modifier: utf16be"},
		{rule("", "  sel:\n    CommandLine|wide: x\n  condition: sel\n"), "unsupported modifier: wide"},
		{rule("", "  sel:\n    CommandLine|base64|wide: x\n  condition: sel\n"), "unsupported modifier: wide"},
		{rule("", "  sel:\n    CommandLine|base64|windash: x\n  condition: sel\n"), "unsupported modifier: windash"},
		{rule("", "  sel:\n    CommandLine|base64|cased: x\n  condition: sel\n"), "unsupported modifier: cased"},
		{rule("", "  sel:\n    CommandLine|contains|base64: x\n  condition: sel\n"), "unsupported modifier: base64"},
		{rule("", "  sel:\n    Ip|cidr|contains: x\n  condition: sel\n"), "unsupported modifier: contains"},
		{rule("", "  sel:\n    Ip|exists|contains: x\n  condition: sel\n"), "unsupported modifier: contains"},
		{rule("", "  sel:\n    Ip|fieldref|startswith: x\n  condition: sel\n"), "unsupported modifier: startswith"},
		{rule("", "  sel:\n    Ip|windash|fieldref: x\n  condition: sel\n"), "unsupported modifier: fieldref"},
		{rule("", "  sel:\n    CommandLine|contains|contains: x\n  condition: sel\n"), "unsupported modifier: contains"},
		{rule("", "  sel:\n    CommandLine|utf16|base64: x\n  condition: sel\n"), "unsupported modifier: utf16"},
		{rule("", "  sel:\n    CommandLine|expand: x\n  condition: sel\n"), "unsupported modifier: expand"},
		{rule("", "  sel:\n    Count|gt: 5\n  condition: sel\n"), "unsupported modifier: gt"},
		{rule("", "  sel:\n    Ip|cidr: 300.0.0.0/8\n  condition: sel\n"), "invalid selection sel: field Ip: "},
		{rule("", "  sel:\n    Ip|exists: maybe\n  condition: sel\n"), "invalid selection sel: field Ip: "},
		{rule("", "  sel:\n    Ip|exists: [true, false]\n  condition: sel\n"), "invalid selection sel: field Ip: "},
		{rule("", "  sel:\n    Ip|fieldref: ''\n  condition: sel\n"), "invalid selection sel: field Ip: "},
		{rule("", "  sel:\n    CommandLine|i: x\n  condition: sel\n"), "unsupported modifier: i"},
		{rule("", "  sel:\n    CommandLine|contains|re: x\n  condition: sel\n"), "unsupported modifier: re"},
		{rule("", "  sel:\n    CommandLine|re|contains: x\n  condition: sel\n"), "unsupported modifier: contains"},
		{rule("", "  sel:\n    CommandLine|re: '(x'\n  condition: sel\n"), "invalid regular expression: "},
		{rule("", "  sel:\n    CommandLine:\n      a: b\n  condition: sel\n"), "invalid selection sel: "},
		{rule("", "  sel:\n    EventID: 1\n  condition: other\n"), "invalid condition: unknown selection other"},
		{rule("", "  sel:\n    EventID: 1\n  condition: sel and\n"), "invalid condition: "},
		{rule("", "  sel:\n    EventID: 1\n  condition:\n    - sel\n"), "invalid condition: "},
		{rule("", "  sel:\n    EventID: 1\n  condition: "+nested+"\n"), "invalid condition: too deeply nested"},
	} {
		_, skipped, err := parseRule("r.yml", []byte(c.src))
		if skipped || err == nil || !strings.HasPrefix(err.Error(), c.reason) || (!strings.HasSuffix(c.reason, ": ") && err.Error() != c.reason) {
			t.Errorf("want %q, got skipped=%v err=%v", c.reason, skipped, err)
		}
	}
}
