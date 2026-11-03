package main

import (
	"flag"
	"io"
	"reflect"
	"testing"
)

func newTestFlagSet() (*flag.FlagSet, *onceString) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var c onceString
	fs.Var(&c, "case", "")
	return fs, &c
}

func TestParseInterspersed(t *testing.T) {
	tests := []struct {
		args     []string
		wantPos  []string
		wantCase string
	}{
		{[]string{"--case", "X", "./logs"}, []string{"./logs"}, "X"},
		{[]string{"./logs", "--case", "X"}, []string{"./logs"}, "X"},
		{[]string{"a", "--case=X", "b"}, []string{"a", "b"}, "X"},
		{[]string{"-case", "X"}, nil, "X"},
		{[]string{"--case", "X", "--", "-f.evtx", "--case"}, []string{"-f.evtx", "--case"}, "X"},
	}
	for _, tt := range tests {
		fs, c := newTestFlagSet()
		pos, err := parseInterspersed(fs, tt.args)
		if err != nil {
			t.Fatalf("%v: unexpected error %v", tt.args, err)
		}
		if !reflect.DeepEqual(pos, tt.wantPos) || c.value != tt.wantCase {
			t.Errorf("%v: got pos=%q case=%q, want pos=%q case=%q", tt.args, pos, c.value, tt.wantPos, tt.wantCase)
		}
	}
}

func TestParseInterspersedErrors(t *testing.T) {
	for _, args := range [][]string{
		{"--case", "A", "--case", "B"},
		{"--case", ""},
		{"--case="},
		{"--unknown"},
		{"--case"},
	} {
		fs, _ := newTestFlagSet()
		if _, err := parseInterspersed(fs, args); err == nil {
			t.Errorf("%v: expected an error", args)
		}
	}
}

func TestParseList(t *testing.T) {
	allowed := []string{"html", "sqlite", "jsonl"}
	got, err := parseList("format", "jsonl,html", allowed)
	if err != nil || !reflect.DeepEqual(got, []string{"jsonl", "html"}) {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, v := range []string{"pdf", "html,html", "html,", ",html", ""} {
		if _, err := parseList("format", v, allowed); err == nil {
			t.Errorf("%q: expected an error", v)
		}
	}
}
