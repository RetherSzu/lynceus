package detection

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"DFIRFlow/internal/normalizer"
)

// fieldCond est une condition sur un champ de l'événement.
type fieldCond struct {
	field  string
	all    bool                // toutes les valeurs (modificateur all), sinon l'une d'elles
	values []func(string) bool // une par valeur ; nil = test d'absence (null)
}

// group est une table de conditions de champ, toutes vraies (ET).
type group []fieldCond

// selection est une liste de tables, l'une ou l'autre (OU).
type selection []group

func (s selection) match(ev *normalizer.Event) bool {
	for _, g := range s {
		if g.match(ev) {
			return true
		}
	}
	return false
}

func (g group) match(ev *normalizer.Event) bool {
	for _, c := range g {
		if !c.match(ev) {
			return false
		}
	}
	return true
}

func (c fieldCond) match(ev *normalizer.Event) bool {
	v, ok := field(ev, c.field)
	for _, m := range c.values {
		var r bool
		if m == nil {
			r = !ok || v == ""
		} else {
			r = ok && m(v)
		}
		if r != c.all { // première valeur vraie (OU) ou fausse (ET) décide
			return r
		}
	}
	return c.all
}

// field lit un champ de l'événement (research R3).
func field(ev *normalizer.Event, name string) (string, bool) {
	switch name {
	case "EventID":
		if ev.EventID == nil {
			return "", false
		}
		return strconv.FormatUint(uint64(*ev.EventID), 10), true
	case "Channel":
		return ev.Channel, ev.Channel != ""
	case "Provider_Name":
		return ev.Provider, ev.Provider != ""
	case "Computer":
		name = "System.Computer"
	}
	v, ok := ev.Metadata[name]
	return v, ok
}

// refusal est une raison de refus d'une règle, au texte du contrat.
type refusal string

func (r refusal) Error() string { return string(r) }

func refusef(format string, a ...interface{}) error { return refusal(fmt.Sprintf(format, a...)) }

// compileSelection compile une sélection nommée (research R2).
func compileSelection(name string, n *yaml.Node) (selection, error) {
	switch n.Kind {
	case yaml.MappingNode:
		g, err := compileGroup(name, n)
		return selection{g}, err
	case yaml.SequenceNode:
		var s selection
		for _, item := range n.Content {
			if item.Kind != yaml.MappingNode {
				return nil, refusal("keyword search is not supported")
			}
			g, err := compileGroup(name, item)
			if err != nil {
				return nil, err
			}
			s = append(s, g)
		}
		return s, nil
	}
	return nil, refusef("invalid selection %s: must be a map or a list of maps", name)
}

func compileGroup(name string, n *yaml.Node) (group, error) {
	var g group
	for i := 0; i+1 < len(n.Content); i += 2 {
		parts := strings.Split(n.Content[i].Value, "|")
		if parts[0] == "" {
			return nil, refusal("keyword search is not supported")
		}
		c := fieldCond{field: parts[0]}
		var str, re, ci bool
		var wrap func(string) string
		for j, m := range parts[1:] {
			switch m {
			case "all":
				c.all = true
			case "contains", "startswith", "endswith":
				if str || re {
					return nil, refusef("unsupported modifier: %s", m)
				}
				str = true
				switch m {
				case "contains":
					wrap = func(s string) string { return "*" + s + "*" }
				case "startswith":
					wrap = func(s string) string { return s + "*" }
				default:
					wrap = func(s string) string { return "*" + s }
				}
			case "re":
				if str || re {
					return nil, refusef("unsupported modifier: %s", m)
				}
				re = true
			case "i":
				if !re || ci || parts[j] != "re" {
					return nil, refusef("unsupported modifier: %s", m)
				}
				ci = true
			default:
				return nil, refusef("unsupported modifier: %s", m)
			}
		}
		vals := []*yaml.Node{n.Content[i+1]}
		if vals[0].Kind == yaml.SequenceNode {
			vals = vals[0].Content
		}
		for _, v := range vals {
			if v.Kind != yaml.ScalarNode {
				return nil, refusef("invalid selection %s: field %s: values must be scalars", name, parts[0])
			}
			if v.Tag == "!!null" {
				c.values = append(c.values, nil)
				continue
			}
			s := v.Value
			if re {
				if ci {
					s = "(?i)" + s
				}
				rx, err := regexp.Compile(s)
				if err != nil {
					return nil, refusef("invalid regular expression: %v", err)
				}
				c.values = append(c.values, rx.MatchString)
				continue
			}
			if wrap != nil {
				s = wrap(s)
			}
			p := compileGlob(s)
			c.values = append(c.values, p.match)
		}
		if len(c.values) == 0 {
			return nil, refusef("invalid selection %s: field %s: no value", name, parts[0])
		}
		g = append(g, c)
	}
	return g, nil
}

// glob est un motif Sigma en minuscules : '*' toute suite, '?' un caractère.
type glob []globTok

type globTok struct {
	r    rune
	kind byte // 0 littéral, '*', '?'
}

func compileGlob(s string) glob {
	var g glob
	rs := []rune(strings.ToLower(s))
	for i := 0; i < len(rs); i++ {
		switch r := rs[i]; {
		case r == '\\' && i+1 < len(rs) && (rs[i+1] == '*' || rs[i+1] == '?' || rs[i+1] == '\\'):
			i++
			g = append(g, globTok{r: rs[i]})
		case r == '*' || r == '?':
			g = append(g, globTok{kind: byte(r)})
		default:
			g = append(g, globTok{r: r})
		}
	}
	return g
}

// match teste v, insensible à la casse ; retour arrière sur la dernière étoile.
func (g glob) match(v string) bool {
	s := []rune(strings.ToLower(v))
	pi, si, star, mark := 0, 0, -1, 0
	for si < len(s) {
		switch {
		case pi < len(g) && (g[pi].kind == '?' || (g[pi].kind == 0 && g[pi].r == s[si])):
			pi, si = pi+1, si+1
		case pi < len(g) && g[pi].kind == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi, mark = star+1, mark+1
			si = mark
		default:
			return false
		}
	}
	for pi < len(g) && g[pi].kind == '*' {
		pi++
	}
	return pi == len(g)
}
