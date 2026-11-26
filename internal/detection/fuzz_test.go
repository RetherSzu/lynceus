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
			if r.ID == "" || !hex16.MatchString(r.Version) || !channels[r.Channel] || r.cond == nil {
				t.Fatalf("bad rule: %+v", r)
			}
			ev := evtx(r.Channel, "P", 1, map[string]string{"CommandLine": "x"}, 1)
			r.match(&ev)
		}
	})
}
