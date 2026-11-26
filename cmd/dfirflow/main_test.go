package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
		{bg, &cmdError{cmd: "case verify", err: errIntegrity}, 4},
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
		"timeline":    {"--case", "--from", "--to", "--source", "evtx, mft, usnjrnl, registry, prefetch, memory"},
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
		{[]string{"timeline", "--case", "C", "--source", "powershell"}, "timeline", "evtx, mft, usnjrnl, registry, prefetch, memory"},
		{[]string{"timeline", "--case", "C", "--source", "defender"}, "timeline", "evtx, mft, usnjrnl, registry, prefetch, memory"},
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
	tests := [][]string{
		{"import", "--case", c, "--tool", "hayabusa", filepath.Join(dir, "out.jsonl")},
		{"timeline", "--case", c, "--from", "2026-11-01T00:00:00", "--to", "2026-11-02T00:00:00+01:00", "--source", "evtx,mft,usnjrnl,registry,prefetch,memory"},
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
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("commands wrote to disk: %v", entries)
	}

	// investigate runs the real collect, then stops on the first missing step.
	inv := t.TempDir()
	cases := filepath.Join(inv, "cases")
	invoke(context.Background(), "case", "init", "CASE-001", "--host", "H", "--analyst", "A", "--dir", cases)
	target := filepath.Join(inv, "target")
	writeEvidence(t, target, "Security.evtx", string(fixture(t)))
	code, _, errOut := invoke(context.Background(), "investigate", "--case", filepath.Join(cases, "CASE-001"), "--target", target)
	if want := "dfirflow: investigate: timeline: not implemented yet\n"; code != 3 || errOut != want {
		t.Errorf("investigate: code=%d stderr=%q, want 3 and %q", code, errOut, want)
	}
}

const evtxDir = "Windows/System32/winevt/Logs"

// writeEvidence creates target/Windows/System32/winevt/Logs/name.
func writeEvidence(t *testing.T, target, name, content string) string {
	t.Helper()
	p := filepath.Join(target, filepath.FromSlash(evtxDir), name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// newCollectCase creates a case and a target; it returns their paths.
func newCollectCase(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	cases := filepath.Join(dir, "cases")
	if code, _, errOut := invoke(context.Background(), "case", "init", "CASE-004", "--host", "H", "--analyst", "A", "--dir", cases); code != 0 {
		t.Fatalf("case init: %s", errOut)
	}
	return filepath.Join(cases, "CASE-004"), filepath.Join(dir, "target")
}

func TestCollectCommand(t *testing.T) {
	ctx := context.Background()
	c, target := newCollectCase(t)
	writeEvidence(t, target, "System.evtx", "system")
	writeEvidence(t, target, "Security.evtx", "security")
	code, out, errOut := invoke(ctx, "collect", "--case", c, "--target", target)
	want := "COLLECTED  " + evtxDir + "/Security.evtx  sha256=" + sha("security") + "\n" +
		"COLLECTED  " + evtxDir + "/System.evtx  sha256=" + sha("system") + "\n" +
		"2 files: 2 COLLECTED, 0 ALREADY, 0 CONFLICT, 0 FAILED, 0 SKIPPED\n"
	if code != 0 || out != want || errOut != "" {
		t.Errorf("code=%d stdout=%q stderr=%q, want 0 and %q", code, out, errOut, want)
	}
	empty := t.TempDir()
	code, _, errOut = invoke(ctx, "collect", "--case", c, "--target", empty)
	if want := "dfirflow: collect: no artifact found under " + empty + "\n"; code != 1 || errOut != want {
		t.Errorf("empty target: code=%d stderr=%q, want 1 and %q", code, errOut, want)
	}
}

func TestScriptUsage(t *testing.T) {
	bg := context.Background()
	if code, out, _ := invoke(bg, "import", "./out.jsonl", "--case", "./cases/CASE-001", "--tool", "hayabusa"); code != 3 || out != "" {
		t.Errorf("options after positionals: code=%d stdout=%q", code, out)
	}
	if code, _, _ := invoke(bg, "import", "--case", "./cases/CASE-001", "--tool", "hayabusa", "--", "-fichier.jsonl"); code != 3 {
		t.Errorf("'--' separator: code=%d", code)
	}
	cancelled, cancel := context.WithCancel(bg)
	cancel()
	if code, out, errOut := invoke(cancelled, "investigate", "--case", "C", "--target", "E"); code != 130 || out != "" || errOut != "" {
		t.Errorf("interrupted: code=%d stdout=%q stderr=%q, want 130 and no output", code, out, errOut)
	}
}

func readLog(t *testing.T, caseDir string) []map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(caseDir, "case.log"))
	if err != nil {
		t.Fatal(err)
	}
	var entries []map[string]interface{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e map[string]interface{}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("invalid journal line %q: %v", line, err)
		}
		entries = append(entries, e)
	}
	return entries
}

func TestCaseInit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cases")
	want := filepath.Join(dir, "CASE-001")
	code, out, errOut := invoke(context.Background(), "case", "init", "CASE-001", "--host", "WIN-CLIENT01", "--analyst", "dfir-team", "--dir", dir)
	if code != 0 || out != want+"\n" || errOut != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if code, _, errOut := invoke(context.Background(), "case", "init", "CASE-001", "--host", "H", "--analyst", "A", "--dir", dir); code != 1 || !strings.HasPrefix(errOut, "dfirflow: case init: ") {
		t.Errorf("existing case: code=%d stderr=%q", code, errOut)
	}
	log := readLog(t, want)
	if len(log) != 1 || log[0]["command"] != "case init" || log[0]["exit_code"] != 0.0 {
		t.Errorf("journal = %v", log)
	}
}

func TestCaseVerify(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "cases")
	c := filepath.Join(dir, "CASE-001")
	invoke(ctx, "case", "init", "CASE-001", "--host", "H", "--analyst", "A", "--dir", dir)

	code, out, _ := invoke(ctx, "case", "verify", "--case", c)
	if code != 0 || out != "0 evidence files: 0 OK, 0 MODIFIED, 0 MISSING, 0 UNTRACKED\n" {
		t.Fatalf("intact case: code=%d stdout=%q", code, out)
	}
	if err := os.WriteFile(filepath.Join(c, "evidence", "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := invoke(ctx, "case", "verify", "--case", c)
	if code != 4 || !strings.Contains(out, "UNTRACKED  notes.txt") || errOut != "dfirflow: case verify: integrity check failed\n" {
		t.Errorf("altered case: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if code, _, _ := invoke(ctx, "case", "verify", "--case", filepath.Join(dir, "nope")); code != 1 {
		t.Errorf("invalid case: code=%d, want 1", code)
	}
	log := readLog(t, c)
	if len(log) != 3 || log[1]["exit_code"] != 0.0 || log[2]["exit_code"] != 4.0 || log[2]["summary"].(map[string]interface{})["UNTRACKED"] != 1.0 {
		t.Errorf("journal = %v", log)
	}
}

func TestCollectLog(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("chmod 0 does not deny reads here")
	}
	ctx := context.Background()
	c, target := newCollectCase(t)
	writeEvidence(t, target, "a.evtx", "a")
	writeEvidence(t, target, "c.evtx", "c")
	bad := writeEvidence(t, target, "b.evtx", "b")
	os.Chmod(bad, 0)
	defer os.Chmod(bad, 0o644)
	code, _, errOut := invoke(ctx, "collect", "--case", c, "--target", target)
	if code != 1 || errOut != "dfirflow: collect: collection incomplete\n" {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	log := readLog(t, c)
	last := log[len(log)-1]
	sum, _ := last["summary"].(map[string]interface{})
	abs, _ := filepath.Abs(target)
	problems, _ := sum["problems"].([]interface{})
	if last["command"] != "collect" || last["exit_code"] != 1.0 || sum["target"] != abs ||
		sum["COLLECTED"] != 2.0 || sum["ALREADY"] != 0.0 || sum["CONFLICT"] != 0.0 || sum["FAILED"] != 1.0 || sum["SKIPPED"] != 0.0 || len(problems) != 1 {
		t.Fatalf("journal entry = %v", last)
	}
	p := problems[0].(map[string]interface{})
	if p["file"] != evtxDir+"/b.evtx" || p["status"] != "FAILED" || p["reason"] == "" {
		t.Errorf("problem = %v", p)
	}

	c, target = newCollectCase(t)
	writeEvidence(t, target, "a.evtx", "a")
	if code, _, errOut := invoke(ctx, "collect", "--case", c, "--target", target); code != 0 {
		t.Fatalf("second run: code=%d stderr=%q", code, errOut)
	}
	log = readLog(t, c)
	last = log[len(log)-1]
	if sum := last["summary"].(map[string]interface{}); last["exit_code"] != 0.0 || sum["problems"] != nil {
		t.Errorf("clean run journal = %v", last)
	}
}

func TestCollectRerun(t *testing.T) {
	ctx := context.Background()
	c, target := newCollectCase(t)
	writeEvidence(t, target, "Security.evtx", "security")
	invoke(ctx, "collect", "--case", c, "--target", target)
	code, out, _ := invoke(ctx, "collect", "--case", c, "--target", target)
	if want := "ALREADY    " + evtxDir + "/Security.evtx  sha256=" + sha("security") + "\n"; code != 0 || !strings.HasPrefix(out, want) {
		t.Errorf("rerun: code=%d stdout=%q", code, out)
	}
	writeEvidence(t, target, "Security.evtx", "tampered")
	code, out, errOut := invoke(ctx, "collect", "--case", c, "--target", target)
	want := "CONFLICT   " + evtxDir + "/Security.evtx  expected=" + sha("security") + " actual=" + sha("tampered") + "\n"
	if code != 1 || !strings.HasPrefix(out, want) || errOut != "dfirflow: collect: collection incomplete\n" {
		t.Errorf("conflict: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
}

func TestCollectInterrupted(t *testing.T) {
	c, target := newCollectCase(t)
	writeEvidence(t, target, "Security.evtx", "security")
	// run checks the context once before starting: interrupt right after.
	if code, _, _ := invoke(&cancelAfter{Context: context.Background(), n: 1}, "collect", "--case", c, "--target", target); code != 130 {
		t.Errorf("code=%d, want 130", code)
	}
	filepath.Walk(filepath.Join(c, "evidence"), func(p string, fi os.FileInfo, err error) error {
		if strings.HasSuffix(p, ".partial") {
			t.Errorf("partial copy left: %s", p)
		}
		return nil
	})
	if log := readLog(t, c); log[len(log)-1]["command"] != "collect" || log[len(log)-1]["exit_code"] != 130.0 {
		t.Errorf("journal = %v", log[len(log)-1])
	}
	code, out, _ := invoke(context.Background(), "case", "verify", "--case", c)
	if code != 0 || !strings.HasSuffix(out, "0 MODIFIED, 0 MISSING, 0 UNTRACKED\n") {
		t.Errorf("verify after interrupt: code=%d stdout=%q", code, out)
	}
}

// cancelAfter reports cancellation once Err has been called n times.
type cancelAfter struct {
	context.Context
	n int
}

func (c *cancelAfter) Err() error {
	if c.n <= 0 {
		return context.Canceled
	}
	c.n--
	return nil
}

const securityEvidence = evtxDir + "/Security.evtx"

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../internal/parser/evtx/testdata/Security.evtx")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newIngestCase collects Security.evtx (fixture) and the given extra logs.
func newIngestCase(t *testing.T, extra map[string]string) string {
	t.Helper()
	c, target := newCollectCase(t)
	writeEvidence(t, target, "Security.evtx", string(fixture(t)))
	for name, content := range extra {
		writeEvidence(t, target, name, content)
	}
	if code, _, errOut := invoke(context.Background(), "collect", "--case", c, "--target", target); code != 0 {
		t.Fatalf("collect: %s", errOut)
	}
	return c
}

func TestIngestCommand(t *testing.T) {
	ctx := context.Background()
	c := newIngestCase(t, nil)
	code, out, errOut := invoke(ctx, "ingest", "--case", c)
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if code != 0 || errOut != "" || len(lines) != 3 ||
		lines[0] != "INGESTED  "+securityEvidence+"  events=739 anomalies=0" ||
		lines[1] != "1 files: 1 INGESTED, 0 SKIPPED, 0 ALTERED, 0 FAILED; 739 events, 0 anomalies" ||
		!strings.HasPrefix(lines[2], "other: 68.6% (507 events); top: Security/4627=194, ") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}

	// Preuve EVTX à l'en-tête tronqué : FAILED, code 1 (FR-019).
	c = newIngestCase(t, map[string]string{"Broken.evtx": string(fixture(t)[:100])})
	code, out, errOut = invoke(ctx, "ingest", "--case", c)
	if code != 1 || errOut != "dfirflow: ingest: ingestion incomplete\n" || !strings.HasPrefix(out, "FAILED    "+evtxDir+"/Broken.evtx  reason=") {
		t.Fatalf("failed evidence: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
}

func TestIngestLog(t *testing.T) {
	ctx := context.Background()
	c := newIngestCase(t, map[string]string{"Copy.evtx": string(fixture(t))})
	invoke(ctx, "ingest", "--case", c)
	last := readLog(t, c)
	entry := last[len(last)-1]
	if entry["command"] != "ingest" || entry["exit_code"] != 0.0 {
		t.Fatalf("clean run journal = %v", entry)
	}

	p := filepath.Join(c, "evidence", filepath.FromSlash(securityEvidence))
	os.Chmod(p, 0o644)
	data := fixture(t)
	data[7000] ^= 0xff
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := invoke(ctx, "ingest", "--case", c)
	if code != 4 || errOut != "dfirflow: ingest: integrity check failed\n" {
		t.Fatalf("altered: code=%d stderr=%q", code, errOut)
	}
	last = readLog(t, c)
	entry = last[len(last)-1]
	sum, _ := entry["summary"].(map[string]interface{})
	files, _ := sum["files"].([]interface{})
	if entry["exit_code"] != 4.0 || sum["ALTERED"] != 1.0 || sum["INGESTED"] != 1.0 || sum["events"] != 739.0 ||
		sum["anomalies"] != 0.0 || sum["other_ratio"] != "0.686" || len(files) != 2 {
		t.Fatalf("journal = %v", entry)
	}
	top, _ := sum["top_other"].([]interface{})
	if len(top) != 10 || top[0].(map[string]interface{})["event_id"] != 4627.0 {
		t.Fatalf("top_other = %v", top)
	}
	first := files[0].(map[string]interface{})
	second := files[1].(map[string]interface{})
	if first["file"] != evtxDir+"/Copy.evtx" || first["reason"] != nil ||
		second["file"] != securityEvidence || second["status"] != "ALTERED" || !strings.HasPrefix(second["reason"].(string), "expected=") {
		t.Fatalf("files = %v", files)
	}
}

func TestIngestInterrupted(t *testing.T) {
	c := newIngestCase(t, nil)
	invoke(context.Background(), "ingest", "--case", c)
	out := filepath.Join(c, "normalized", filepath.FromSlash(securityEvidence)+".jsonl")
	before, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	// Interruption pendant le décodage (après la vérification d'empreinte).
	if code, _, _ := invoke(&cancelAfter{Context: context.Background(), n: 120}, "ingest", "--case", c); code != 130 {
		t.Fatalf("code=%d, want 130", code)
	}
	filepath.Walk(filepath.Join(c, "normalized"), func(p string, fi os.FileInfo, err error) error {
		if strings.HasSuffix(p, ".partial") {
			t.Errorf("partial file left: %s", p)
		}
		return nil
	})
	if after, _ := os.ReadFile(out); !bytes.Equal(before, after) {
		t.Error("previous normalized file changed")
	}
	if log := readLog(t, c); log[len(log)-1]["command"] != "ingest" || log[len(log)-1]["exit_code"] != 130.0 {
		t.Errorf("journal = %v", log[len(log)-1])
	}
}
