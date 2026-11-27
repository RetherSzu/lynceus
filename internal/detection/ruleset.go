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

	"DFIRFlow/internal/normalizer"
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

// Restriction est une source partielle retirée d'une règle par la garde.
type Restriction struct {
	File    string   `json:"file"`
	Source  string   `json:"source"`
	Missing []string `json:"missing"`
	Label   string   `json:"-"` // libellé de la source, pour l'avertissement
}

// Ruleset est le jeu de règles d'une exécution.
type Ruleset struct {
	Source  string // Embedded ou chemin donné à --rules
	Version string // 16 hexa (research R4)
	Applied []*Rule
	Skipped int
	Refused []Refusal
	// Restricted liste les couples (règle, source partielle) écartés par la
	// garde, triés par fichier puis source ; ce ne sont pas des refus (FR-015a).
	Restricted []Restriction

	byChannel map[string]*channelIndex // canal en minuscules
}

// entry est une règle évaluée sur une source ; src nil pour une règle de service.
type entry struct {
	rule *Rule
	src  *Source
}

// channelIndex range les entrées d'un canal par EventID ; any reçoit celles
// qui ne contraignent pas l'EventID (research R4).
type channelIndex struct {
	any  []entry
	byID map[uint32][]entry
}

func (rs *Ruleset) index(channel string) *channelIndex {
	ch := strings.ToLower(channel)
	ci := rs.byChannel[ch]
	if ci == nil {
		ci = &channelIndex{byID: map[uint32][]entry{}}
		rs.byChannel[ch] = ci
	}
	return ci
}

// candidates renvoie les entrées qui peuvent concerner ev.
func (rs *Ruleset) candidates(ev *normalizer.Event) [2][]entry {
	ci := rs.byChannel[strings.ToLower(ev.Channel)]
	if ci == nil {
		return [2][]entry{}
	}
	var byID []entry
	if ev.EventID != nil {
		byID = ci.byID[*ev.EventID]
	}
	return [2][]entry{byID, ci.any}
}

// accepts vérifie la contrainte EventType de la source (data-model.md).
func (s *Source) accepts(ev *normalizer.Event) bool {
	if s == nil || s.EventType == nil {
		return true
	}
	return s.EventType[strings.ToLower(ev.Metadata["EventType"])]
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
		rs.Restricted = append(rs.Restricted, r.restricted...)
	}
}

// finish contrôle les doublons, calcule la version du jeu et indexe par canal.
func (rs *Ruleset) finish() error {
	sort.Slice(rs.Refused, func(i, j int) bool { return rs.Refused[i].File < rs.Refused[j].File })
	sort.Slice(rs.Restricted, func(i, j int) bool {
		a, b := rs.Restricted[i], rs.Restricted[j]
		return a.File < b.File || a.File == b.File && a.Source < b.Source
	})
	if len(rs.Applied) == 0 {
		return fmt.Errorf("no applicable rule in %s", rs.Source)
	}
	seen := map[string]string{}
	var lines []string
	rs.byChannel = map[string]*channelIndex{}
	for _, r := range rs.Applied {
		if f, ok := seen[r.ID]; ok {
			return fmt.Errorf("duplicate rule id %s: %s, %s", r.ID, f, r.File)
		}
		seen[r.ID] = r.File
		lines = append(lines, r.ID+"\x00"+r.Version+"\n")
		if r.sources == nil {
			ci := rs.index(r.Channel)
			ci.any = append(ci.any, entry{rule: r})
			continue
		}
		for _, s := range r.sources {
			ci := rs.index(s.Channel)
			for id := range s.EventIDs {
				ci.byID[id] = append(ci.byID[id], entry{rule: r, src: s})
			}
		}
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "")))
	rs.Version = hex.EncodeToString(sum[:8])
	return nil
}
