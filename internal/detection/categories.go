package detection

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed categories.json
var categoriesJSON []byte

// Source est une source d'une catégorie Sigma (data-model.md).
type Source struct {
	Name, Label, Channel string
	EventIDs             map[uint32]bool
	EventType            map[string]bool   // valeurs admises de EventType, en minuscules ; nil = sans contrainte
	Rename               map[string]string // champ de la règle → champ de l'événement
	Fields               map[string]bool   // champs fournis par une source partielle ; nil = source complète
}

// commonFields sont lus sur tout événement, quelle que soit la source.
var commonFields = map[string]bool{"EventID": true, "Channel": true, "Provider_Name": true, "Computer": true}

var (
	categories map[string][]*Source
	// CategoriesVersion est l'empreinte de la table embarquée (research R1).
	CategoriesVersion string
)

func init() {
	var err error
	if categories, err = loadCategories(categoriesJSON); err != nil {
		panic("detection: categories.json: " + err.Error()) // bogue de construction, couvert par TestCategoriesTable
	}
	sum := sha256.Sum256(categoriesJSON)
	CategoriesVersion = hex.EncodeToString(sum[:8])
}

func loadCategories(data []byte) (map[string][]*Source, error) {
	var table []struct {
		Category string `json:"category"`
		Sources  []struct {
			Name      string            `json:"name"`
			Label     string            `json:"label"`
			Channel   string            `json:"channel"`
			EventIDs  []uint32          `json:"event_ids"`
			EventType []string          `json:"event_type"`
			Rename    map[string]string `json:"rename"`
			Fields    []string          `json:"fields"`
		} `json:"sources"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&table); err != nil {
		return nil, err
	}
	cats := map[string][]*Source{}
	names := map[string]bool{}
	for _, c := range table {
		if c.Category == "" || cats[c.Category] != nil || len(c.Sources) == 0 {
			return nil, fmt.Errorf("category %q: empty, duplicate or without source", c.Category)
		}
		for _, s := range c.Sources {
			if s.Name == "" || names[s.Name] || s.Label == "" || s.Channel == "" || len(s.EventIDs) == 0 {
				return nil, fmt.Errorf("source %q: empty, duplicate or incomplete", s.Name)
			}
			names[s.Name] = true
			src := &Source{Name: s.Name, Label: s.Label, Channel: s.Channel, EventIDs: map[uint32]bool{}, Rename: s.Rename}
			for _, id := range s.EventIDs {
				src.EventIDs[id] = true
			}
			if len(s.EventType) > 0 {
				src.EventType = map[string]bool{}
				for _, v := range s.EventType {
					src.EventType[strings.ToLower(v)] = true
				}
			}
			if s.Fields != nil {
				src.Fields = map[string]bool{}
				for _, f := range s.Fields {
					src.Fields[f] = true
				}
				for f := range s.Rename {
					if !src.Fields[f] {
						return nil, fmt.Errorf("source %s: renamed field %s not in fields", s.Name, f)
					}
				}
			}
			cats[c.Category] = append(cats[c.Category], src)
		}
	}
	return cats, nil
}
