package detection

import (
	"path"
	"sort"
	"strings"

	"DFIRFlow/internal/normalizer"
)

// maxDepth borne l'imbrication des parenthèses et des not (research R2).
const maxDepth = 64

// node est un nœud de l'arbre d'une condition.
type node interface {
	eval(ev *normalizer.Event, src *Source) bool
}

type (
	selNode selection
	notNode struct{ n node }
	andNode []node
	orNode  []node
)

func (n selNode) eval(ev *normalizer.Event, src *Source) bool { return selection(n).match(ev, src) }
func (n notNode) eval(ev *normalizer.Event, src *Source) bool { return !n.n.eval(ev, src) }
func (n andNode) eval(ev *normalizer.Event, src *Source) bool {
	for _, c := range n {
		if !c.eval(ev, src) {
			return false
		}
	}
	return true
}
func (n orNode) eval(ev *normalizer.Event, src *Source) bool {
	for _, c := range n {
		if c.eval(ev, src) {
			return true
		}
	}
	return false
}

// condParser analyse une condition Sigma par descente récursive :
// expr := and ('or' and)* ; and := unary ('and' unary)* ;
// unary := 'not' unary | primary ;
// primary := '(' expr ')' | ('1'|'all') 'of' (motif|'them') | nom.
type condParser struct {
	toks []string
	pos  int
	sels map[string]selection
}

func parseCondition(s string, sels map[string]selection) (node, error) {
	if strings.Contains(s, "|") {
		return nil, refusal("aggregation is not supported")
	}
	p := &condParser{toks: tokenize(s), sels: sels}
	if len(p.toks) == 0 {
		return nil, refusal("invalid condition: empty")
	}
	n, err := p.expr(0)
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.toks) {
		return nil, refusef("invalid condition: unexpected %q", p.toks[p.pos])
	}
	return n, nil
}

func tokenize(s string) []string {
	s = strings.NewReplacer("(", " ( ", ")", " ) ").Replace(s)
	return strings.Fields(s)
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *condParser) expr(depth int) (node, error) {
	var or orNode
	for {
		n, err := p.and(depth)
		if err != nil {
			return nil, err
		}
		or = append(or, n)
		if p.peek() != "or" {
			break
		}
		p.pos++
	}
	if len(or) == 1 {
		return or[0], nil
	}
	return or, nil
}

func (p *condParser) and(depth int) (node, error) {
	var and andNode
	for {
		n, err := p.unary(depth)
		if err != nil {
			return nil, err
		}
		and = append(and, n)
		if p.peek() != "and" {
			break
		}
		p.pos++
	}
	if len(and) == 1 {
		return and[0], nil
	}
	return and, nil
}

func (p *condParser) unary(depth int) (node, error) {
	if p.peek() != "not" {
		return p.primary(depth)
	}
	if depth+1 > maxDepth {
		return nil, refusal("invalid condition: too deeply nested")
	}
	p.pos++
	n, err := p.unary(depth + 1)
	if err != nil {
		return nil, err
	}
	return notNode{n}, nil
}

func (p *condParser) primary(depth int) (node, error) {
	t := p.peek()
	switch t {
	case "":
		return nil, refusal("invalid condition: unexpected end")
	case "(":
		if depth+1 > maxDepth {
			return nil, refusal("invalid condition: too deeply nested")
		}
		p.pos++
		n, err := p.expr(depth + 1)
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, refusal("invalid condition: missing )")
		}
		p.pos++
		return n, nil
	case "1", "all":
		p.pos++
		if p.peek() != "of" {
			return nil, refusef("invalid condition: expected of after %s", t)
		}
		p.pos++
		pat := p.peek()
		if pat == "" || pat == "(" || pat == ")" {
			return nil, refusef("invalid condition: expected a selection pattern after %s of", t)
		}
		p.pos++
		names := p.matching(pat)
		if len(names) == 0 {
			return nil, refusef("invalid condition: no selection matches %s", pat)
		}
		var ns []node
		for _, name := range names {
			ns = append(ns, selNode(p.sels[name]))
		}
		if t == "all" {
			return andNode(ns), nil
		}
		return orNode(ns), nil
	case ")", "and", "or", "of", "them":
		return nil, refusef("invalid condition: unexpected %q", t)
	}
	p.pos++
	s, ok := p.sels[t]
	if !ok {
		return nil, refusef("invalid condition: unknown selection %s", t)
	}
	return selNode(s), nil
}

// matching renvoie, triés, les noms de sélection désignés par un motif.
func (p *condParser) matching(pat string) []string {
	var out []string
	for name := range p.sels {
		if pat == "them" {
			if !strings.HasPrefix(name, "_") {
				out = append(out, name)
			}
		} else if ok, _ := path.Match(pat, name); ok {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
