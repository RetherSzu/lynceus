package detection

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func writeRules(t testing.TB, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func withID(id, src string) string { return strings.Replace(src, "id: r1", "id: "+id, 1) }

func TestLoadPath(t *testing.T) {
	good := rule("", sel)
	agg := rule("", "  sel:\n    EventID: 4625\n  condition: sel | count() > 5\n")
	linux := strings.Replace(rule("", sel), "product: windows", "product: linux", 1)
	reM := rule("", "  sel:\n    CommandLine|re|m: x\n  condition: sel\n")
	dir := writeRules(t, map[string]string{
		"a.yml":            good,
		"sub/b.yaml":       withID("r2", good),
		"sub/c.YML":        withID("r3", good),
		"notes.txt":        "not a rule",
		"agg.yml":          agg,
		"linux.yml":        withID("r1", linux), // même id qu'une règle appliquée : pas un doublon
		"sub/re.yml":       reM,
		".github/ci.yml":   "on: push",
		".hidden.yml":      "x: [",
		"sub/.cache/x.yml": "x: [",
	})
	rs, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Applied) != 3 || rs.Skipped != 1 || rs.Source != dir {
		t.Fatalf("applied %d skipped %d source %s", len(rs.Applied), rs.Skipped, rs.Source)
	}
	want := []Refusal{
		{filepath.Join(dir, "agg.yml"), "aggregation is not supported"},
		{filepath.Join(dir, "sub", "re.yml"), "unsupported modifier: m"},
	}
	if len(rs.Refused) != len(want) {
		t.Fatalf("refused %v", rs.Refused)
	}
	for i := range want {
		if rs.Refused[i] != want[i] {
			t.Errorf("refused[%d] = %v, want %v", i, rs.Refused[i], want[i])
		}
	}

	// Fichier unique désigné, extension quelconque.
	one := filepath.Join(dir, "notes.rule")
	os.WriteFile(one, []byte(good), 0o644)
	if rs, err := Load(one); err != nil || len(rs.Applied) != 1 {
		t.Errorf("single file: %v", err)
	}

	// Chemin inexistant.
	missing := filepath.Join(dir, "absent")
	if _, err := Load(missing); err == nil || err.Error() != "rules: "+missing+": no such file or directory" {
		t.Errorf("missing: %v", err)
	}

	// Aucune règle applicable : les refus restent visibles.
	none := writeRules(t, map[string]string{"agg.yml": agg, "linux.yml": linux})
	rs, err = Load(none)
	if err == nil || err.Error() != "no applicable rule in "+none || rs == nil || len(rs.Refused) != 1 || rs.Skipped != 1 {
		t.Errorf("none applicable: %v", err)
	}

	// Doublon parmi les règles appliquées.
	dup := writeRules(t, map[string]string{"a.yml": good, "b.yml": good})
	if _, err := Load(dup); err == nil || err.Error() != "duplicate rule id r1: "+filepath.Join(dup, "a.yml")+", "+filepath.Join(dup, "b.yml") {
		t.Errorf("duplicate: %v", err)
	}

	// Version du jeu : indépendante de l'ordre des fichiers, change avec une règle.
	x := writeRules(t, map[string]string{"1.yml": good, "2.yml": withID("r2", good)})
	y := writeRules(t, map[string]string{"2.yml": good, "1.yml": withID("r2", good)})
	z := writeRules(t, map[string]string{"1.yml": good, "2.yml": withID("r2", good) + "# edit\n"})
	vx, vy, vz := mustLoad(t, x), mustLoad(t, y), mustLoad(t, z)
	if vx.Version != vy.Version || vx.Version == vz.Version {
		t.Errorf("versions x=%s y=%s z=%s", vx.Version, vy.Version, vz.Version)
	}

	// Fichier trop gros : refusé sans être lu.
	big := writeRules(t, map[string]string{"a.yml": good, "big.yml": strings.Repeat("#", maxRuleSize+1)})
	if rs := mustLoad(t, big); len(rs.Refused) != 1 || rs.Refused[0].Reason != "file too large" {
		t.Errorf("big: %v", rs.Refused)
	}
}

func mustLoad(t testing.TB, p string) *Ruleset {
	t.Helper()
	rs, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestCategoryAndService(t *testing.T) {
	det := "  sel:\n    Image: x\n  condition: sel\n"
	for _, c := range []struct {
		logsource, channel string
		id                 uint32
		src                string
	}{
		{"  category: process_creation\n  service: sysmon\n", sysmonCh, 1, "sysmon-1"},
		{"  category: ps_script\n  service: powershell\n", psCh, 4104, "powershell-4104"},
	} {
		rs := mustLoad(t, writeRules(t, map[string]string{"r.yml": catRule(c.logsource, det)}))
		n := 0
		for ch, ci := range rs.byChannel {
			for id, es := range ci.byID {
				for _, e := range es {
					n++
					if ch != strings.ToLower(c.channel) || id != c.id || e.src.Name != c.src {
						t.Errorf("%q: entry %s/%d/%s", c.logsource, ch, id, e.src.Name)
					}
				}
			}
			if len(ci.any) != 0 {
				t.Errorf("%q: entries without event id", c.logsource)
			}
		}
		if n != 1 {
			t.Errorf("%q: %d entries, want 1", c.logsource, n)
		}
	}
}

// TestGuard4688 : la garde retire Security 4688 des règles qui citent un champ
// qu'elle ne fournit pas (FR-006, FR-008, research R3, R7).
func TestGuard4688(t *testing.T) {
	pc := "  category: process_creation\n"
	sources := func(rs *Ruleset) []string {
		set := map[string]bool{}
		for _, ci := range rs.byChannel {
			for _, es := range ci.byID {
				for _, e := range es {
					set[e.src.Name] = true
				}
			}
		}
		var out []string
		for s := range set {
			out = append(out, s)
		}
		sort.Strings(out)
		return out
	}
	full := "  sel:\n    Image|endswith: '\\x.exe'\n    CommandLine|contains: y\n    EventID: 1\n    Channel: c\n    Provider_Name: p\n    Computer: h\n  condition: sel\n"
	rs := mustLoad(t, writeRules(t, map[string]string{"a.yml": catRule(pc, full)}))
	if got := sources(rs); strings.Join(got, ",") != "security-4688,sysmon-1" || rs.Restricted != nil {
		t.Errorf("full rule: sources %v, restricted %v", got, rs.Restricted)
	}

	hashes := "  sel:\n    Image|endswith: '\\x.exe'\n  filter:\n    Hashes|contains: 'SHA256='\n    User: u\n  condition: sel and not filter\n"
	dir := writeRules(t, map[string]string{
		"b.yml": withID("b", catRule(pc, hashes)),
		"a.yml": withID("a", catRule(pc, hashes)),
	})
	rs = mustLoad(t, dir)
	if got := sources(rs); strings.Join(got, ",") != "sysmon-1" {
		t.Errorf("hashes rule: sources %v", got)
	}
	want := []Restriction{
		{filepath.Join(dir, "a.yml"), "security-4688", []string{"Hashes", "User"}, "Security 4688"},
		{filepath.Join(dir, "b.yml"), "security-4688", []string{"Hashes", "User"}, "Security 4688"},
	}
	if !reflect.DeepEqual(rs.Restricted, want) || len(rs.Refused) != 0 {
		t.Errorf("restricted %v, refused %v", rs.Restricted, rs.Refused)
	}

	r := mustRule(t, catRule(pc, "  sel:\n    Image|fieldref: OriginalFileName\n  condition: sel\n"))
	if len(r.restricted) != 1 || strings.Join(r.restricted[0].Missing, ",") != "OriginalFileName" {
		t.Errorf("fieldref target: %v", r.restricted)
	}
	_, _, err := parseRule("r.yml", []byte(catRule(pc+"  service: security\n", hashes)))
	if err == nil || err.Error() != "fields not available in any source: Hashes,User" {
		t.Errorf("security only: %v", err)
	}
}
