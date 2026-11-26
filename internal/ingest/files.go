package ingest

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	casefile "DFIRFlow/internal/case"
)

// EventFiles renvoie, dans l'ordre du manifeste, les fichiers d'événements
// des preuves (normalized/<preuve>.jsonl) qui existent, et les fichiers de
// normalized/ sans preuve au manifeste ; chemins relatifs au cas, séparateur
// "/" (spec 006 research R1, spec 012 research R5).
func EventFiles(c *casefile.Case) (files, unknown []string, err error) {
	entries, err := c.Evidence()
	if err != nil {
		return nil, nil, err
	}
	known := map[string]bool{}
	for _, e := range entries {
		rel := "normalized/" + e.File + ".jsonl"
		known[rel], known["normalized/"+e.File+".anomalies.jsonl"] = true, true
		if _, err := os.Stat(filepath.Join(c.BaseDir, filepath.FromSlash(rel))); err == nil {
			files = append(files, rel)
		}
	}
	err = filepath.WalkDir(filepath.Join(c.BaseDir, "normalized"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(p, ".partial") {
			return err
		}
		rel, err := filepath.Rel(c.BaseDir, p)
		if err != nil {
			return err
		}
		if rel = filepath.ToSlash(rel); !known[rel] {
			unknown = append(unknown, rel)
		}
		return nil
	})
	sort.Strings(unknown)
	return files, unknown, err
}
