// Package casefile gère le dossier de cas d'une investigation : métadonnées,
// manifeste SHA-256 des preuves, vérification d'intégrité et journal.
package casefile

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SchemaVersion est la version du format de dossier de cas.
const SchemaVersion = 1

var subdirs = []string{"evidence", "parsed", "normalized", "timeline", "detections", "reports", "hashes"}

type Case struct {
	SchemaVersion int       `json:"schema_version"`
	ID            string    `json:"case_id"`
	Hostname      string    `json:"hostname"`
	Analyst       string    `json:"analyst"`
	CreatedAt     time.Time `json:"created_at"`
	ToolVersion   string    `json:"tool_version"`
	BaseDir       string    `json:"-"`

	entries map[string]bool // files already in the manifest
}

// Create crée le dossier dir/id ; il échoue si ce dossier existe déjà et ne
// laisse aucun cas partiel en cas d'erreur.
func Create(dir, id, hostname, analyst, toolVersion string, now time.Time) (c *Case, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	base := filepath.Join(dir, id)
	if err := os.Mkdir(base, 0o755); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(base) // only what this call created
		}
	}()
	for _, d := range subdirs {
		if err := os.Mkdir(filepath.Join(base, d), 0o755); err != nil {
			return nil, err
		}
	}
	c = &Case{
		SchemaVersion: SchemaVersion, ID: id, Hostname: hostname, Analyst: analyst,
		CreatedAt: now.UTC().Truncate(time.Second), ToolVersion: toolVersion,
		BaseDir: base, entries: map[string]bool{},
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeNew(filepath.Join(base, "case.json"), append(data, '\n')); err != nil {
		return nil, err
	}
	for _, f := range []string{"case.log", filepath.Join("hashes", "manifest.jsonl")} {
		if err := writeNew(filepath.Join(base, f), nil); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Open charge un cas existant et valide son format et son manifeste.
func Open(path string) (*Case, error) {
	name := filepath.Join(path, "case.json")
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("not a case directory: %w", err)
	}
	c := &Case{}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if c.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%s: unsupported schema_version %d", name, c.SchemaVersion)
	}
	c.BaseDir = path
	entries, err := c.manifest()
	if err != nil {
		return nil, err
	}
	c.entries = make(map[string]bool, len(entries))
	for _, e := range entries {
		c.entries[e.File] = true
	}
	return c, nil
}

func (c *Case) Dir(kind string) string {
	return filepath.Join(c.BaseDir, kind)
}

func (c *Case) manifestPath() string {
	return filepath.Join(c.BaseDir, "hashes", "manifest.jsonl")
}

// manifest lit toutes les entrées du manifeste, en validant chaque ligne.
func (c *Case) manifest() ([]ManifestEntry, error) {
	f, err := os.Open(c.manifestPath())
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []ManifestEntry
	s := bufio.NewScanner(f)
	for line := 1; s.Scan(); line++ {
		var e ManifestEntry
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("%s: line %d: %w", c.manifestPath(), line, err)
		}
		if _, err := cleanRel(filepath.FromSlash(e.File)); err != nil {
			return nil, fmt.Errorf("%s: line %d: %w", c.manifestPath(), line, err)
		}
		entries = append(entries, e)
	}
	return entries, s.Err()
}

// appendLine ajoute une ligne JSON à un fichier en ajout seul.
func appendLine(path string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
