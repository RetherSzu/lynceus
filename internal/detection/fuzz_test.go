package detection

import (
	"io/fs"
	"regexp"
	"testing"
)

var hex16 = regexp.MustCompile(`^[0-9a-f]{16}$`)

// FuzzParseRule : une règle malformée ne fait jamais paniquer le chargement,
// et tout refus porte une raison (constitution, entrées non fiables).
func FuzzParseRule(f *testing.F) {
	names, _ := fs.Glob(embedded, "rules/*.yml")
	for _, n := range names {
		b, _ := embedded.ReadFile(n)
		f.Add(b)
	}
	for _, s := range []string{
		rule("", sel),
		rule("", "  sel:\n    EventID: 4625\n  condition: sel | count() > 5\n"),
		rule("", "  kw:\n    - mimikatz\n  condition: kw\n"),
		rule("", "  sel:\n    CommandLine|re: '(x'\n  condition: sel\n"),
		rule("", "  sel:\n    EventID: 1\n  condition: ((not sel) or 1 of s*)\n"),
		catRule("  category: process_creation\n", "  sel:\n    CommandLine|windash|contains: ' -enc'\n  f:\n    Hashes|exists: true\n  condition: sel and not f\n"),
		catRule("  category: network_connection\n", "  sel:\n    DestinationIp|cidr: ['10.0.0.0/8', 'fe80::/10']\n  condition: sel\n"),
		catRule("  category: ps_script\n  service: powershell\n", "  sel:\n    ScriptBlockText|wide|base64offset|contains|all: [IEX, x]\n  condition: sel\n"),
		catRule("  category: process_access\n", "  sel:\n    SourceUser|fieldref|cased: TargetUser\n  condition: sel\n"),
		catRule("  category: webserver\n", sel),
		rule("", "  sel:\n    CommandLine|base64|windash: x\n  condition: sel\n"),
		"title: [",
		"a: &a [*a, *a]",
	} {
		f.Add([]byte(s))
	}
	channels := map[string]bool{}
	for _, ch := range services {
		channels[ch] = true
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r, skipped, err := parseRule("f.yml", data)
		switch {
		case err != nil:
			if err.Error() == "" || r != nil || skipped {
				t.Fatalf("refusal without reason or with a rule: %v", err)
			}
		case skipped:
			if r != nil {
				t.Fatal("skipped rule returned")
			}
		default:
			service := channels[r.Channel] && r.sources == nil
			category := r.Channel == "" && len(r.sources) > 0
			if r.ID == "" || !hex16.MatchString(r.Version) || !(service || category) || r.cond == nil {
				t.Fatalf("bad rule: %+v", r)
			}
			ev := evtx(r.Channel, "P", 1, map[string]string{"CommandLine": "x"}, 1)
			r.match(&ev, nil)
			for _, s := range r.sources {
				r.match(&ev, s)
			}
		}
	})
}
