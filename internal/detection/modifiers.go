package detection

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"unicode"
	"unicode/utf16"
)

// mods est la chaîne de modificateurs d'une clé de sélection (data-model.md).
type mods struct {
	pos                    string // contains, startswith, endswith ou vide
	all, re, ci            bool
	windash, cased         bool
	b64, enc               string // base64 ou base64offset ; wide, utf16le ou utf16be
	cidr, exists, fieldref bool
}

// parseMods contrôle l'ordre et les combinaisons ; le refus cite le premier
// modificateur incompatible avec ceux qui le précèdent.
func parseMods(list []string) (mods, error) {
	var m mods
	seen := map[string]bool{}
	others := func(allowed ...string) bool { // un modificateur hors allowed déjà vu
		for s := range seen {
			ok := false
			for _, a := range allowed {
				ok = ok || s == a
			}
			if !ok {
				return true
			}
		}
		return false
	}
	special := func() bool { return m.cidr || m.exists || m.fieldref }
	for j, s := range list {
		bad := seen[s]
		switch s {
		case "all":
			bad = bad || m.exists
			m.all = true
		case "contains", "startswith", "endswith":
			bad = bad || m.pos != "" || m.re || special()
			m.pos = s
		case "re":
			bad = bad || m.pos != "" || m.windash || m.cased || m.b64 != "" || m.enc != "" || special()
			m.re = true
		case "i":
			bad = bad || !m.re || j == 0 || list[j-1] != "re"
			m.ci = true
		case "windash":
			bad = bad || m.re || m.b64 != "" || special()
			m.windash = true
		case "cased":
			bad = bad || m.re || m.b64 != "" || m.cidr || m.exists
			m.cased = true
		case "base64", "base64offset":
			bad = bad || m.b64 != "" || m.pos != "" || m.re || m.windash || m.cased || special()
			m.b64 = s
		case "wide", "utf16le", "utf16be":
			bad = bad || m.enc != "" || m.b64 != "" || m.pos != "" || m.re || m.windash || m.cased || special()
			m.enc = s
		case "cidr":
			bad = bad || others("all")
			m.cidr = true
		case "exists":
			bad = bad || others()
			m.exists = true
		case "fieldref":
			bad = bad || others("cased", "all")
			m.fieldref = true
		default:
			bad = true
		}
		if bad {
			return m, refusef("unsupported modifier: %s", s)
		}
		seen[s] = true
	}
	if m.enc != "" && m.b64 == "" {
		return m, refusef("unsupported modifier: %s", m.enc)
	}
	return m, nil
}

// textPatterns renvoie les motifs d'une valeur texte : un seul, ou trois
// reliés par OU pour base64offset (research R6).
func (m mods) textPatterns(s string) []glob {
	if m.b64 == "" {
		return []glob{m.wrap(compileGlob(s, m.cased, m.windash))}
	}
	var b []byte
	switch m.enc {
	case "wide", "utf16le", "utf16be":
		u := utf16.Encode([]rune(s))
		b = make([]byte, 2*len(u))
		for i, c := range u {
			if m.enc == "utf16be" {
				binary.BigEndian.PutUint16(b[2*i:], c)
			} else {
				binary.LittleEndian.PutUint16(b[2*i:], c)
			}
		}
	default:
		b = []byte(s)
	}
	if m.b64 == "base64" {
		return []glob{m.wrap(literal(base64.StdEncoding.EncodeToString(b)))}
	}
	var out []glob
	start, end := [3]int{0, 2, 3}, [3]int{0, 3, 2}
	for i := 0; i < 3; i++ {
		e := base64.StdEncoding.EncodeToString(append(make([]byte, i), b...))
		e = e[start[i] : len(e)-end[(len(b)+i)%3]]
		out = append(out, m.wrap(literal(e)))
	}
	return out
}

// wrap ajoute les étoiles de position au motif compilé.
func (m mods) wrap(g glob) glob {
	if m.pos == "contains" || m.pos == "endswith" {
		g.toks = append([]globTok{{kind: '*'}}, g.toks...)
	}
	if m.pos == "contains" || m.pos == "startswith" {
		g.toks = append(g.toks, globTok{kind: '*'})
	}
	g.prepare()
	return g
}

// literal est un motif sans joker, sensible à la casse (texte base64).
func literal(s string) glob {
	g := glob{cased: true}
	for _, r := range s {
		g.toks = append(g.toks, globTok{r: r})
	}
	return g
}

// windashAt dit si le tiret ou la barre rs[i] commence un mot (research R6).
func windashAt(rs []rune, i int) bool {
	word := func(r rune) bool { return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) }
	return (rs[i] == '-' || rs[i] == '/') && (i == 0 || !word(rs[i-1])) &&
		i+1 < len(rs) && (unicode.IsLetter(rs[i+1]) || unicode.IsDigit(rs[i+1]))
}

// dashes sont les caractères admis par windash.
const dashes = "-/–—―"

func isDash(r rune) bool { return strings.ContainsRune(dashes, r) }
