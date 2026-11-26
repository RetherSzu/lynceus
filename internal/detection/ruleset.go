package detection

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed rules/*.yml
var embedded embed.FS

// Embedded est l'origine des règles embarquées dans case.log.
const Embedded = "embedded"

// Refusal est une règle refusée et sa raison (contracts/detect.md).
type Refusal struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
}

// Ruleset est le jeu de règles d'une exécution.
type Ruleset struct {
	Source  string // Embedded ou chemin donné à --rules
	Version string // 16 hexa (research R4)
	Applied []*Rule
	Skipped int
	Refused []Refusal

	byChannel map[string][]*Rule // canal en minuscules
}

// Load charge le jeu embarqué (path vide) ou les règles de path. En cas
// d'erreur sur le jeu, le Ruleset renvoyé porte les refus déjà relevés.
func Load(path string) (*Ruleset, error) {
	rs := &Ruleset{Source: path}
	if path == "" {
		rs.Source = Embedded
		names, err := fs.Glob(embedded, "rules/*.yml")
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			data, err := embedded.ReadFile(n)
			if err != nil {
				return nil, err
			}
			rs.add("embedded:"+strings.TrimPrefix(n, "rules/"), data)
		}
		return rs, rs.finish()
	}

	fi, err := os.Stat(path)
	if err != nil {
		var pe *fs.PathError
		if errors.Is(err, fs.ErrNotExist) {
			err = errors.New("no such file or directory") // texte du contrat, identique sous Windows
		} else if errors.As(err, &pe) {
			err = pe.Err
		}
		return nil, fmt.Errorf("rules: %s: %w", path, err)
	}
	if !fi.IsDir() {
		if err := rs.addFile(path, fi.Size()); err != nil {
			return nil, err
		}
		return rs, rs.finish()
	}
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p != path && strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if d.IsDir() || (ext != ".yml" && ext != ".yaml") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return rs.addFile(p, info.Size())
	})
	if err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	return rs, rs.finish()
}

// addFile lit une règle ; un fichier trop gros est refusé sans être lu.
func (rs *Ruleset) addFile(p string, size int64) error {
	if size > maxRuleSize {
		rs.Refused = append(rs.Refused, Refusal{p, "file too large"})
		return nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return fmt.Errorf("rules: %w", err)
	}
	rs.add(p, data)
	return nil
}

func (rs *Ruleset) add(name string, data []byte) {
	r, skipped, err := parseRule(name, data)
	switch {
	case err != nil:
		rs.Refused = append(rs.Refused, Refusal{name, err.Error()})
	case skipped:
		rs.Skipped++
	default:
		rs.Applied = append(rs.Applied, r)
	}
}

// finish contrôle les doublons, calcule la version du jeu et indexe par canal.
func (rs *Ruleset) finish() error {
	sort.Slice(rs.Refused, func(i, j int) bool { return rs.Refused[i].File < rs.Refused[j].File })
	if len(rs.Applied) == 0 {
		return fmt.Errorf("no applicable rule in %s", rs.Source)
	}
	seen := map[string]string{}
	var lines []string
	rs.byChannel = map[string][]*Rule{}
	for _, r := range rs.Applied {
		if f, ok := seen[r.ID]; ok {
			return fmt.Errorf("duplicate rule id %s: %s, %s", r.ID, f, r.File)
		}
		seen[r.ID] = r.File
		lines = append(lines, r.ID+"\x00"+r.Version+"\n")
		ch := strings.ToLower(r.Channel)
		rs.byChannel[ch] = append(rs.byChannel[ch], r)
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "")))
	rs.Version = hex.EncodeToString(sum[:8])
	return nil
}
