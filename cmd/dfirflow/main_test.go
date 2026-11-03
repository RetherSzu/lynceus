package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--version"}, &stdout, &stderr); err != nil {
		t.Fatalf("run returned an error: %v", err)
	}
	if got, want := stdout.String(), "DFIRFlow dev\n"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr output: %q", stderr.String())
	}
}

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--help"}, &stdout, &stderr); err != nil {
		t.Fatalf("run returned an error: %v", err)
	}
	if !strings.Contains(stdout.String(), "Usage: dfirflow [options]") {
		t.Fatalf("help output missing usage: %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr output: %q", stderr.String())
	}
}

// invoke runs the CLI like main does and returns exit code, stdout and stderr.
func invoke(ctx context.Context, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := cli(ctx, args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestExitCode(t *testing.T) {
	bg := context.Background()
	cancelled, cancel := context.WithCancel(bg)
	cancel()
	tests := []struct {
		ctx  context.Context
		err  error
		want int
	}{
		{bg, nil, 0},
		{bg, &usageError{msg: "bad"}, 2},
		{bg, &cmdError{cmd: "detect", err: &usageError{msg: "bad"}}, 2},
		{bg, errNotImplemented, 3},
		{bg, &cmdError{cmd: "detect", err: errNotImplemented}, 3},
		{cancelled, context.Canceled, 130},
		{bg, errors.New("boom"), 1},
	}
	for _, tt := range tests {
		if got := exitCode(tt.ctx, tt.err); got != tt.want {
			t.Errorf("exitCode(%v) = %d, want %d", tt.err, got, tt.want)
		}
	}
}

var pipelineOrder = []string{
	"case init", "case verify", "collect", "ingest", "import",
	"timeline", "detect", "correlate", "report", "investigate",
}

func TestHelp(t *testing.T) {
	for _, args := range [][]string{nil, {"-h"}, {"--help"}} {
		code, out, errOut := invoke(context.Background(), args...)
		if code != 0 || errOut != "" {
			t.Fatalf("%v: code=%d stderr=%q", args, code, errOut)
		}
		if !strings.Contains(out, "Usage: dfirflow [options]") {
			t.Fatalf("%v: missing usage line: %q", args, out)
		}
		last := -1
		for _, name := range pipelineOrder {
			i := strings.Index(out, "  "+name+" ")
			if i <= last {
				t.Fatalf("%v: command %q missing or out of order in %q", args, name, out)
			}
			last = i
		}
	}
}

func TestCommandHelp(t *testing.T) {
	expect := map[string][]string{
		"case init":   {"<ID>", "--host", "--analyst", "--dir", "./cases"},
		"case verify": {"--case"},
		"collect":     {"--case", "--target"},
		"ingest":      {"--case", "[path...]"},
		"import":      {"--case", "--tool", "kape, orc, eztools, hayabusa, plaso, volatility", "<path>"},
		"timeline":    {"--case", "--from", "--to", "--source", "evtx, mft, usnjrnl"},
		"detect":      {"--case", "--rules"},
		"correlate":   {"--case"},
		"report":      {"--case", "--format", "html,sqlite,jsonl"},
		"investigate": {"--case", "--target"},
	}
	for _, name := range pipelineOrder {
		for _, help := range []string{"--help", "-h"} {
			args := append(strings.Fields(name), help)
			code, out, errOut := invoke(context.Background(), args...)
			if code != 0 || errOut != "" {
				t.Fatalf("%v: code=%d stderr=%q", args, code, errOut)
			}
			want := append([]string{"Usage: dfirflow " + name, "(required)", "Example:"}, expect[name]...)
			for _, w := range want {
				if !strings.Contains(out, w) {
					t.Errorf("%v: help missing %q:\n%s", args, w, out)
				}
			}
		}
	}
	// --help wins over invalid arguments.
	if code, _, _ := invoke(context.Background(), "report", "--format", "pdf", "--help"); code != 0 {
		t.Errorf("--help with invalid args: code=%d, want 0", code)
	}
}

func TestUsageErrors(t *testing.T) {
	long := strings.Repeat("a", 65)
	tests := []struct {
		args    []string
		cmd     string // command named in the error prefix ("" for global errors)
		mention string // option or argument the message must name
	}{
		{[]string{"analyze"}, "", "analyze"},
		{[]string{"case"}, "", "case"},
		{[]string{"case", "delete"}, "", "delete"},
		{[]string{"--version", "detect"}, "", "--version"},
		{[]string{"detect"}, "detect", "--case"},
		{[]string{"detect", "--case", ""}, "detect", "case"},
		{[]string{"detect", "--case", "A", "--case", "B"}, "detect", "case"},
		{[]string{"detect", "--case", "A", "--bogus"}, "detect", "bogus"},
		{[]string{"import", "--case", "C", "--tool", "foo", "./x"}, "import", "kape, orc, eztools, hayabusa, plaso, volatility"},
		{[]string{"import", "--case", "C", "./x"}, "import", "--tool"},
		{[]string{"import", "--case", "C", "--tool", "kape"}, "import", "<path>"},
		{[]string{"import", "--case", "C", "--tool", "kape", "a", "b"}, "import", "b"},
		{[]string{"report", "--case", "C", "--format", "pdf"}, "report", "html, sqlite, jsonl"},
		{[]string{"report", "--case", "C", "--format", "html,html"}, "report", "html"},
		{[]string{"report", "--case", "C", "--format", "html,"}, "report", "--format"},
		{[]string{"case", "init"}, "case init", "<ID>"},
		{[]string{"case", "init", "../evil", "--host", "H", "--analyst", "A"}, "case init", "../evil"},
		{[]string{"case", "init", long, "--host", "H", "--analyst", "A"}, "case init", long},
		{[]string{"case", "init", "C1", "--analyst", "A"}, "case init", "--host"},
		{[]string{"case", "init", "C1", "--host", "H"}, "case init", "--analyst"},
		{[]string{"collect", "--case", "C"}, "collect", "--target"},
		{[]string{"timeline", "--case", "C", "--from", "yesterday"}, "timeline", "--from"},
		{[]string{"timeline", "--case", "C", "--from", "2026-11-02T10:00:00Z", "--to", "2026-11-01T00:00:00Z"}, "timeline", "--from"},
		{[]string{"timeline", "--case", "C", "--source", "foo"}, "timeline", "evtx"},
		{[]string{"correlate", "--case", "C", "extra"}, "correlate", "extra"},
		{[]string{"investigate", "--case", "C"}, "investigate", "--target"},
	}
	for _, tt := range tests {
		code, out, errOut := invoke(context.Background(), tt.args...)
		if code != 2 || out != "" {
			t.Errorf("%v: code=%d stdout=%q, want code 2 and empty stdout", tt.args, code, out)
			continue
		}
		prefix, hint := "dfirflow: ", "Run 'dfirflow --help' for usage."
		if tt.cmd != "" {
			prefix += tt.cmd + ": "
			hint = "Run 'dfirflow " + tt.cmd + " --help' for usage."
		}
		if !strings.HasPrefix(errOut, prefix) || !strings.Contains(errOut, tt.mention) || !strings.Contains(errOut, hint) {
			t.Errorf("%v: stderr=%q, want prefix %q, mention %q and hint %q", tt.args, errOut, prefix, tt.mention, hint)
		}
	}
}

func TestNotImplemented(t *testing.T) {
	dir := t.TempDir()
	c := filepath.Join(dir, "cases", "CASE-001")
	ev := filepath.Join(dir, "evidence")
	tests := [][]string{
		{"case", "init", "CASE-001", "--host", "WIN-CLIENT01", "--analyst", "dfir-team", "--dir", filepath.Join(dir, "cases")},
		{"case", "verify", "--case", c},
		{"collect", "--case", c, "--target", ev},
		{"ingest", "--case", c},
		{"import", "--case", c, "--tool", "hayabusa", filepath.Join(dir, "out.jsonl")},
		{"timeline", "--case", c, "--from", "2026-11-01T00:00:00", "--to", "2026-11-02T00:00:00+01:00", "--source", "evtx,mft"},
		{"detect", "--case", c, "--rules", filepath.Join(dir, "rules")},
		{"correlate", "--case", c},
		{"report", "--case", c, "--format", "html,jsonl"},
	}
	for _, args := range tests {
		name := args[0]
		if name == "case" {
			name += " " + args[1]
		}
		code, out, errOut := invoke(context.Background(), args...)
		if want := "dfirflow: " + name + ": not implemented yet\n"; code != 3 || out != "" || errOut != want {
			t.Errorf("%v: code=%d stdout=%q stderr=%q, want 3 and %q", args, code, out, errOut, want)
		}
	}
	code, _, errOut := invoke(context.Background(), "investigate", "--case", c, "--target", ev)
	if want := "dfirflow: investigate: collect: not implemented yet\n"; code != 3 || errOut != want {
		t.Errorf("investigate: code=%d stderr=%q, want 3 and %q", code, errOut, want)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("commands wrote to disk: %v", entries)
	}
}

func TestScriptUsage(t *testing.T) {
	bg := context.Background()
	if code, out, _ := invoke(bg, "ingest", "./logs", "--case", "./cases/CASE-001"); code != 3 || out != "" {
		t.Errorf("options after positionals: code=%d stdout=%q", code, out)
	}
	if code, _, _ := invoke(bg, "ingest", "--case", "./cases/CASE-001", "--", "-fichier.evtx"); code != 3 {
		t.Errorf("'--' separator: code=%d", code)
	}
	cancelled, cancel := context.WithCancel(bg)
	cancel()
	if code, out, errOut := invoke(cancelled, "investigate", "--case", "C", "--target", "E"); code != 130 || out != "" || errOut != "" {
		t.Errorf("interrupted: code=%d stdout=%q stderr=%q, want 130 and no output", code, out, errOut)
	}
}
