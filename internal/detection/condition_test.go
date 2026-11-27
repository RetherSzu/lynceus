package detection

import (
	"strings"
	"testing"
)

func TestCondition(t *testing.T) {
	// a, b, _c vrais ; d, x1, x2 faux selon la table de l'événement.
	det := "  a:\n    A: 1\n  b:\n    B: 1\n  _c:\n    C: 1\n  d:\n    D: 1\n  x1:\n    A: 1\n  x2:\n    D: 1\n  condition: "
	ev := evtx("Security", "P", 1, map[string]string{"A": "1", "B": "1", "C": "1", "D": "0"}, 1)
	for cond, want := range map[string]bool{
		"a":                      true,
		"d":                      false,
		"not d":                  true,
		"a and d":                false,
		"a or d":                 true,
		"d or a and b":           true, // and avant or
		"(d or a) and b":         true,
		"d or a and d":           false,
		"not a or b":             true, // not avant or
		"not (a or b)":           false,
		"not a and b":            false,
		"1 of x*":                true,
		"all of x*":              false,
		"1 of them":              true,
		"all of them":            false,
		"all of a":               true,
		"a and all of _*":        true,
		"not d and 1 of them":    true,
		"(((a)))":                true,
		"a and not (d or not b)": true,
	} {
		r := mustRule(t, rule("", det+cond+"\n"))
		if got := r.match(&ev, nil); got != want {
			t.Errorf("%q: %v, want %v", cond, got, want)
		}
	}
	// them exclut _c, faux ici : all of them ne dépend que de a.
	r := mustRule(t, rule("", "  a:\n    A: 1\n  _c:\n    C: 9\n  condition: all of them\n"))
	if !r.match(&ev, nil) {
		t.Error("them must skip _c")
	}

	ok := strings.Repeat("(", 64) + "a" + strings.Repeat(")", 64)
	mustRule(t, rule("", det+ok+"\n"))
	mustRule(t, rule("", det+strings.Repeat("not ", 63)+"(a)\n"))
	for _, bad := range []string{"", "a and", "a or or b", "(a", "a)", "1 of", "1 of y*", "2 of x*", "a b", "not", strings.Repeat("not ", 65) + "a"} {
		_, _, err := parseRule("r.yml", []byte(rule("", det+"'"+bad+"'\n")))
		if err == nil || !strings.HasPrefix(err.Error(), "invalid condition: ") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
