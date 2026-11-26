package detection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRules(t *testing.T, files map[string]string) string {
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

func mustLoad(t *testing.T, p string) *Ruleset {
	t.Helper()
	rs, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}
