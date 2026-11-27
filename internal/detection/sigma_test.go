package detection

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestSigmaCorpus mesure la part des règles Windows des catégories couvertes
// qu'une copie locale de SigmaHQ fait charger (SC-002, research R8). Lancé à
// la main ; non bloquant sous 90 %, l'écart est journalisé.
func TestSigmaCorpus(t *testing.T) {
	dir := os.Getenv("DFIRFLOW_SIGMA_DIR")
	if dir == "" {
		t.Skip("set DFIRFLOW_SIGMA_DIR to a local SigmaHQ rules directory")
	}
	total, loaded := 0, 0
	reasons := map[string]int{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yml") {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var head struct {
			Logsource struct{ Product, Category string }
		}
		if yaml.Unmarshal(data, &head) != nil || !strings.EqualFold(head.Logsource.Product, "windows") ||
			categories[strings.ToLower(head.Logsource.Category)] == nil {
			return nil
		}
		total++
		_, skipped, err := parseRule(p, data)
		switch {
		case err != nil:
			reason := err.Error()
			if i := strings.Index(reason, ": "); i >= 0 {
				reason = reason[:i]
			}
			reasons[reason]++
		case !skipped:
			loaded++
		default:
			total-- // deprecated ou unsupported : hors mesure
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if total == 0 {
		t.Fatalf("no rule of a covered category under %s", dir)
	}
	rate := 100 * float64(loaded) / float64(total)
	t.Logf("%d/%d rules loaded (%.1f %%)", loaded, total, rate)
	var keys []string
	for k := range reasons {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return reasons[keys[i]] > reasons[keys[j]] || reasons[keys[i]] == reasons[keys[j]] && keys[i] < keys[j]
	})
	for _, k := range keys {
		t.Logf("%6d  %s", reasons[k], k)
	}
	if rate < 90 {
		t.Logf("below the 90 %% objective (SC-002, not blocking): record the gap in docs/architecture-actuelle.md")
	}
}
