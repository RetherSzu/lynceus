package detection

import (
	"fmt"
	"net/netip"
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
	exists *bool               // modificateur exists : présence attendue du champ
	refs   []string            // modificateur fieldref : champs à comparer
	cased  bool                // fieldref sensible à la casse
}

// group est une table de conditions de champ, toutes vraies (ET).
type group []fieldCond

// selection est une liste de tables, l'une ou l'autre (OU).
type selection []group

func (s selection) match(ev *normalizer.Event, src *Source) bool {
	for _, g := range s {
		if g.match(ev, src) {
			return true
		}
	}
	return false
}

// addFields ajoute à set les champs cités par la sélection.
func (s selection) addFields(set map[string]bool) {
	for _, g := range s {
		for _, c := range g {
			set[c.field] = true
			for _, r := range c.refs {
				set[r] = true
			}
		}
	}
}

func (g group) match(ev *normalizer.Event, src *Source) bool {
	for _, c := range g {
		if !c.match(ev, src) {
			return false
		}
	}
	return true
}

func (c fieldCond) match(ev *normalizer.Event, src *Source) bool {
	v, ok := field(ev, c.field, src)
	if c.exists != nil {
		return ok == *c.exists
	}
	for _, ref := range c.refs {
		rv, rok := field(ev, ref, src)
		r := ok && rok && (v == rv || !c.cased && strings.EqualFold(v, rv))
		if r != c.all {
			return r
		}
	}
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

// field lit un champ de l'événement (research R3), sous le nom que lui donne
// la source quand elle le renomme (spec 013, research R3).
func field(ev *normalizer.Event, name string, src *Source) (string, bool) {
	if src != nil {
		if n, ok := src.Rename[name]; ok {
			name = n
		}
	}
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
		m, err := parseMods(parts[1:])
		if err != nil {
			return nil, err
		}
		c := fieldCond{field: parts[0], all: m.all, cased: m.cased}
		bad := func(format string, a ...interface{}) error {
			return refusef("invalid selection %s: field %s: %s", name, parts[0], fmt.Sprintf(format, a...))
		}
		node := n.Content[i+1]
		vals := []*yaml.Node{node}
		if node.Kind == yaml.SequenceNode {
			vals = node.Content
		}
		if m.exists {
			b, err := strconv.ParseBool(node.Value)
			if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" || err != nil {
				return nil, bad("exists takes a single boolean")
			}
			c.exists = &b
			g = append(g, c)
			continue
		}
		for _, v := range vals {
			if v.Kind != yaml.ScalarNode {
				return nil, refusef("invalid selection %s: field %s: values must be scalars", name, parts[0])
			}
			if v.Tag == "!!null" && !m.cidr && !m.fieldref {
				c.values = append(c.values, nil)
				continue
			}
			s := v.Value
			switch {
			case m.fieldref:
				if s == "" {
					return nil, bad("empty fieldref target")
				}
				c.refs = append(c.refs, s)
			case m.cidr:
				p, err := netip.ParsePrefix(s)
				if err != nil {
					return nil, bad("invalid cidr %s", s)
				}
				c.values = append(c.values, func(v string) bool {
					a, err := netip.ParseAddr(v)
					return err == nil && p.Contains(a.Unmap())
				})
			case m.re:
				if m.ci {
					s = "(?i)" + s
				}
				rx, err := regexp.Compile(s)
				if err != nil {
					return nil, refusef("invalid regular expression: %v", err)
				}
				c.values = append(c.values, rx.MatchString)
			default:
				ps := m.textPatterns(s)
				c.values = append(c.values, func(v string) bool {
					for _, p := range ps {
						if p.match(v) {
							return true
						}
					}
					return false
				})
			}
		}
		if len(c.values) == 0 && len(c.refs) == 0 {
			return nil, refusef("invalid selection %s: field %s: no value", name, parts[0])
		}
		g = append(g, c)
	}
	return g, nil
}

// glob est un motif Sigma : '*' toute suite, '?' un caractère, 'd' un tiret
// windash ; comparé en minuscules sauf cased.
type glob struct {
	toks  []globTok
	cased bool
	// Chemin rapide : motif = littéral ASCII entouré ou non d'étoiles.
	lit   string
	shape byte // 0 aucun, '=' égal, 'p' préfixe, 's' suffixe, 'c' sous-chaîne
}

// prepare reconnaît les motifs du chemin rapide ; appelé une fois le motif complet.
func (g *glob) prepare() {
	t := g.toks
	pre := len(t) > 0 && t[0].kind == '*'
	post := len(t) > 1 && t[len(t)-1].kind == '*' || len(t) == 1 && !pre && t[0].kind == '*'
	if pre {
		t = t[1:]
	}
	if post && len(t) > 0 {
		t = t[:len(t)-1]
	}
	b := make([]byte, 0, len(t))
	for _, k := range t {
		if k.kind != 0 || k.r >= 0x80 {
			return
		}
		b = append(b, byte(k.r))
	}
	g.lit = string(b)
	switch {
	case pre && post:
		g.shape = 'c'
	case pre:
		g.shape = 's'
	case post:
		g.shape = 'p'
	default:
		g.shape = '='
	}
}

// fast applique le chemin rapide ; ok faux si la valeur n'est pas ASCII.
func (g glob) fast(v string) (match, ok bool) {
	for i := 0; i < len(v); i++ {
		if v[i] >= 0x80 {
			return false, false
		}
	}
	eq := func(a string) bool { return a == g.lit || !g.cased && strings.EqualFold(a, g.lit) }
	n := len(g.lit)
	if len(v) < n {
		return false, true
	}
	switch g.shape {
	case '=':
		return eq(v), true
	case 'p':
		return eq(v[:n]), true
	case 's':
		return eq(v[len(v)-n:]), true
	}
	if g.cased {
		return strings.Contains(v, g.lit), true
	}
	for i := 0; i+n <= len(v); i++ {
		if eq(v[i : i+n]) {
			return true, true
		}
	}
	return false, true
}

type globTok struct {
	r    rune
	kind byte // 0 littéral, '*', '?', 'd'
}

func compileGlob(s string, cased, windash bool) glob {
	g := glob{cased: cased}
	if !cased {
		s = strings.ToLower(s)
	}
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		switch r := rs[i]; {
		case r == '\\' && i+1 < len(rs) && (rs[i+1] == '*' || rs[i+1] == '?' || rs[i+1] == '\\'):
			i++
			g.toks = append(g.toks, globTok{r: rs[i]})
		case r == '*' || r == '?':
			g.toks = append(g.toks, globTok{kind: byte(r)})
		case windash && windashAt(rs, i):
			g.toks = append(g.toks, globTok{kind: 'd'})
		default:
			g.toks = append(g.toks, globTok{r: r})
		}
	}
	return g
}

// match teste v ; retour arrière sur la dernière étoile.
func (g glob) match(v string) bool {
	if g.shape != 0 {
		if m, ok := g.fast(v); ok {
			return m
		}
	}
	if !g.cased {
		v = strings.ToLower(v)
	}
	s, t := []rune(v), g.toks
	pi, si, star, mark := 0, 0, -1, 0
	for si < len(s) {
		switch {
		case pi < len(t) && (t[pi].kind == '?' || (t[pi].kind == 0 && t[pi].r == s[si]) || (t[pi].kind == 'd' && isDash(s[si]))):
			pi, si = pi+1, si+1
		case pi < len(t) && t[pi].kind == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi, mark = star+1, mark+1
			si = mark
		default:
			return false
		}
	}
	for pi < len(t) && t[pi].kind == '*' {
		pi++
	}
	return pi == len(t)
}
