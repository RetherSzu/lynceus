package casefile

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 3, 9, 0, 0, 0, time.FixedZone("CET", 3600))

func newCase(t *testing.T) *Case {
	t.Helper()
	c, err := Create(filepath.Join(t.TempDir(), "cases"), "CASE-001", "WIN-CLIENT01", "dfir-team", "v0.1.0", now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []string
	for s := bufio.NewScanner(f); s.Scan(); {
		lines = append(lines, s.Text())
	}
	return lines
}

func TestCreate(t *testing.T) {
	c := newCase(t)
	for _, p := range []string{"case.json", "case.log", "hashes/manifest.jsonl", "evidence", "parsed", "normalized", "timeline", "detections", "reports", "hashes"} {
		if _, err := os.Stat(filepath.Join(c.BaseDir, p)); err != nil {
			t.Errorf("missing %s: %v", p, err)
		}
	}
	if lines := readLines(t, filepath.Join(c.BaseDir, "hashes", "manifest.jsonl")); len(lines) != 0 {
		t.Errorf("manifest not empty: %q", lines)
	}
	var got map[string]interface{}
	data, _ := os.ReadFile(filepath.Join(c.BaseDir, "case.json"))
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]interface{}{
		"schema_version": 1.0, "case_id": "CASE-001", "hostname": "WIN-CLIENT01",
		"analyst": "dfir-team", "created_at": "2026-11-03T08:00:00Z", "tool_version": "v0.1.0",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("case.json = %v, want %v", got, want)
	}
}

func TestCreateExisting(t *testing.T) {
	c := newCase(t)
	marker := writeFile(t, filepath.Join(c.BaseDir, "marker"), "keep")
	if _, err := Create(filepath.Dir(c.BaseDir), "CASE-001", "H", "A", "v", now); err == nil {
		t.Fatal("expected an error for an existing case")
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "keep" {
		t.Fatal("existing case was modified")
	}

	empty := filepath.Join(t.TempDir(), "CASE-002")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(filepath.Dir(empty), "CASE-002", "H", "A", "v", now); err == nil {
		t.Fatal("expected an error for an existing empty directory")
	}

	file := writeFile(t, filepath.Join(t.TempDir(), "notadir"), "x")
	if _, err := Create(file, "CASE-003", "H", "A", "v", now); err == nil {
		t.Fatal("expected an error when --dir is a file")
	}
}

func TestOpen(t *testing.T) {
	c := newCase(t)
	got, err := Open(c.BaseDir)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != c.ID || got.Hostname != c.Hostname || !got.CreatedAt.Equal(c.CreatedAt) {
		t.Errorf("Open = %+v, want %+v", got, c)
	}

	if _, err := Open(t.TempDir()); err == nil || !strings.Contains(err.Error(), "case.json") {
		t.Errorf("missing case.json: err = %v", err)
	}
	bad := newCase(t)
	writeFile(t, filepath.Join(bad.BaseDir, "case.json"), `{"schema_version": 2}`)
	if _, err := Open(bad.BaseDir); err == nil || !strings.Contains(err.Error(), "case.json") {
		t.Errorf("unknown schema: err = %v", err)
	}
	writeFile(t, filepath.Join(bad.BaseDir, "case.json"), `not json`)
	if _, err := Open(bad.BaseDir); err == nil {
		t.Error("invalid case.json: expected an error")
	}

	m := newCase(t)
	writeFile(t, filepath.Join(m.BaseDir, "hashes", "manifest.jsonl"), "{\"file\":\"../x\",\"sha256\":\"\",\"size\":0}\n")
	if _, err := Open(m.BaseDir); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Errorf("escaping manifest entry: err = %v", err)
	}
	writeFile(t, filepath.Join(m.BaseDir, "hashes", "manifest.jsonl"), "garbage\n")
	if _, err := Open(m.BaseDir); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Errorf("garbage manifest: err = %v", err)
	}
}

func TestAddEvidence(t *testing.T) {
	c := newCase(t)
	src := writeFile(t, filepath.Join(t.TempDir(), "Security.evtx"), "evtx-content")
	e, err := c.AddEvidence(context.Background(), src, filepath.Join("Logs", "Security.evtx"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.File != "Logs/Security.evtx" || len(e.SHA256) != 64 || strings.ToLower(e.SHA256) != e.SHA256 || e.Size != 12 || e.CollectedAt.Location() != time.UTC {
		t.Errorf("entry = %+v", e)
	}
	dst := filepath.Join(c.BaseDir, "evidence", "Logs", "Security.evtx")
	if data, _ := os.ReadFile(dst); string(data) != "evtx-content" {
		t.Errorf("copy content = %q", data)
	}
	if fi, _ := os.Stat(dst); fi.Mode().Perm()&0o222 != 0 {
		t.Errorf("copy is writable: %v", fi.Mode())
	}
	reopened, err := Open(c.BaseDir)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := reopened.Verify(context.Background()); err != nil || len(res) != 1 || res[0].Status != StatusOK {
		t.Errorf("Verify after add = %+v, %v", res, err)
	}

	for _, rel := range []string{"Logs/Security.evtx", "Logs/../Logs/Security.evtx", "../x", ".", "", filepath.Join(string(filepath.Separator), "abs")} {
		if _, err := c.AddEvidence(context.Background(), src, rel, nil); err == nil {
			t.Errorf("AddEvidence(%q): expected an error", rel)
		}
	}
	if _, err := c.AddEvidence(context.Background(), filepath.Join(t.TempDir(), "missing"), "missing.evtx", nil); err == nil {
		t.Error("unreadable source: expected an error")
	}
	if _, err := os.Lstat(filepath.Join(c.BaseDir, "evidence", "missing.evtx.partial")); !os.IsNotExist(err) {
		t.Error("partial copy left behind")
	}
	if lines := readLines(t, filepath.Join(c.BaseDir, "hashes", "manifest.jsonl")); len(lines) != 1 {
		t.Errorf("manifest has %d entries, want 1", len(lines))
	}
}

func statuses(res []VerifyResult) map[string]string {
	m := map[string]string{}
	for _, r := range res {
		m[r.File] = r.Status
	}
	return m
}

func TestVerify(t *testing.T) {
	ctx := context.Background()
	c := newCase(t)
	if res, err := c.Verify(ctx); err != nil || len(res) != 0 {
		t.Fatalf("empty case: %v, %v", res, err)
	}
	dir := t.TempDir()
	for _, name := range []string{"a.evtx", "b.evtx", "c.evtx", "d.evtx"} {
		if _, err := c.AddEvidence(ctx, writeFile(t, filepath.Join(dir, name), "content of "+name), name, nil); err != nil {
			t.Fatal(err)
		}
	}
	first, err := c.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := c.Verify(ctx)
	if !reflect.DeepEqual(first, second) {
		t.Error("Verify is not deterministic")
	}

	ev := filepath.Join(c.BaseDir, "evidence")
	for _, name := range []string{"a.evtx", "b.evtx"} {
		os.Chmod(filepath.Join(ev, name), 0o644)
	}
	writeFile(t, filepath.Join(ev, "a.evtx"), "content of a.evtX") // one byte changed
	writeFile(t, filepath.Join(ev, "b.evtx"), "content")           // truncated
	os.Remove(filepath.Join(ev, "c.evtx"))
	writeFile(t, filepath.Join(ev, "extra", "notes.txt"), "x")
	symlink := os.Symlink(filepath.Join(ev, "d.evtx"), filepath.Join(ev, "link.evtx")) == nil

	res, err := c.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"a.evtx": StatusModified, "b.evtx": StatusModified, "c.evtx": StatusMissing, "d.evtx": StatusOK, "extra/notes.txt": StatusUntracked}
	if symlink {
		want["link.evtx"] = StatusUntracked
	}
	if got := statuses(res); !reflect.DeepEqual(got, want) {
		t.Errorf("statuses = %v, want %v", got, want)
	}
	for i := 1; i < len(res); i++ {
		if res[i-1].File > res[i].File {
			t.Errorf("results not sorted: %q before %q", res[i-1].File, res[i].File)
		}
	}
	if r := res[0]; r.File != "a.evtx" || r.Expected == "" || r.Actual == "" || r.Expected == r.Actual {
		t.Errorf("MODIFIED result = %+v", r)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c.Verify(cancelled); err != context.Canceled {
		t.Errorf("cancelled Verify err = %v", err)
	}
}

func TestLog(t *testing.T) {
	c := newCase(t)
	e := LogEntry{Command: "case init", Args: []string{"CASE-001"}, StartedAt: now, FinishedAt: now, ToolVersion: "v0.1.0"}
	if err := c.Log(e); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.BaseDir, "case.log")
	first := readLines(t, path)
	e.Command, e.ExitCode, e.Summary = "case verify", 4, map[string]int{"OK": 1}
	if err := c.Log(e); err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, path)
	if len(lines) != 2 || lines[0] != first[0] || !strings.Contains(lines[1], `"exit_code":4`) {
		t.Errorf("log lines = %q", lines)
	}
}

func TestAddEvidenceOrigin(t *testing.T) {
	c := newCase(t)
	dir := t.TempDir()
	mod := time.Date(2026, 10, 1, 9, 0, 0, 0, time.FixedZone("CET", 3600))
	o := &Origin{SourcePath: "/mnt/img/a.evtx", Modified: &mod}
	if _, err := c.AddEvidence(context.Background(), writeFile(t, filepath.Join(dir, "a.evtx"), "a"), "a.evtx", o); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddEvidence(context.Background(), writeFile(t, filepath.Join(dir, "b.evtx"), "b"), "b.evtx", nil); err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, filepath.Join(c.BaseDir, "hashes", "manifest.jsonl"))
	if !strings.Contains(lines[0], `"origin":{"source_path":"/mnt/img/a.evtx","modified":"2026-10-01T08:00:00Z"}`) {
		t.Errorf("origin line = %s", lines[0])
	}
	if strings.Contains(lines[1], "origin") {
		t.Errorf("nil origin written: %s", lines[1])
	}
	var e ManifestEntry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil || e.Origin == nil || !e.Origin.Modified.Equal(mod) || e.Origin.Accessed != nil {
		t.Errorf("read back = %+v, %v", e.Origin, err)
	}
}

func TestAddEvidenceCancelled(t *testing.T) {
	c := newCase(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	src := writeFile(t, filepath.Join(t.TempDir(), "a.evtx"), "a")
	if _, err := c.AddEvidence(ctx, src, "a.evtx", nil); err == nil {
		t.Fatal("expected an error")
	}
	for _, p := range []string{"a.evtx", "a.evtx.partial"} {
		if _, err := os.Lstat(filepath.Join(c.BaseDir, "evidence", p)); !os.IsNotExist(err) {
			t.Errorf("%s left behind", p)
		}
	}
	if lines := readLines(t, filepath.Join(c.BaseDir, "hashes", "manifest.jsonl")); len(lines) != 0 {
		t.Errorf("manifest = %q", lines)
	}
}

func TestRecorded(t *testing.T) {
	c := newCase(t)
	if _, ok := c.Recorded("Logs/a.evtx"); ok {
		t.Error("unknown file recorded")
	}
	e, err := c.AddEvidence(context.Background(), writeFile(t, filepath.Join(t.TempDir(), "a.evtx"), "a"), filepath.Join("Logs", "a.evtx"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if sum, ok := c.Recorded("Logs/a.evtx"); !ok || sum != e.SHA256 {
		t.Errorf("Recorded after add = %q, %v", sum, ok)
	}
	reopened, err := Open(c.BaseDir)
	if err != nil {
		t.Fatal(err)
	}
	if sum, ok := reopened.Recorded("Logs/a.evtx"); !ok || sum != e.SHA256 {
		t.Errorf("Recorded after Open = %q, %v", sum, ok)
	}
}

func TestOpenSpec002Manifest(t *testing.T) {
	c := newCase(t)
	writeFile(t, filepath.Join(c.BaseDir, "hashes", "manifest.jsonl"),
		`{"file":"a.evtx","sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","size":4,"collected_at":"2026-11-03T09:05:00Z"}`+"\n")
	reopened, err := Open(c.BaseDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Recorded("a.evtx"); !ok {
		t.Error("spec 002 entry not loaded")
	}
}
