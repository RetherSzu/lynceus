package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	casefile "DFIRFlow/internal/case"
)

const logs = "Windows/System32/winevt/Logs"

func write(t *testing.T, root, rel, content string) string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func newCase(t *testing.T) *casefile.Case {
	t.Helper()
	c, err := casefile.Create(filepath.Join(t.TempDir(), "cases"), "CASE-004", "WIN-01", "me", "test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func rels(cands []candidate) []string {
	var out []string
	for _, c := range cands {
		out = append(out, c.rel)
	}
	return out
}

func TestFind(t *testing.T) {
	root := t.TempDir()
	write(t, root, "windows/System32/WINEVT/Logs/Security.evtx", "s")
	write(t, root, "windows/System32/WINEVT/Logs/System.EVTX", "y")
	write(t, root, "windows/System32/WINEVT/Logs/notes.txt", "n")
	got, err := find(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"windows/System32/WINEVT/Logs/Security.evtx", "windows/System32/WINEVT/Logs/System.EVTX"}
	if !reflect.DeepEqual(rels(got), want) {
		t.Errorf("find = %v, want %v", rels(got), want)
	}

	empty := t.TempDir()
	if got, err := find(empty); err != nil || len(got) != 0 {
		t.Errorf("empty root: %v, %v", rels(got), err)
	}

	both := t.TempDir()
	write(t, both, "Windows/System32/winevt/Logs/a.evtx", "a")
	if _, err := os.Stat(filepath.Join(both, "windows")); err == nil {
		t.Skip("case-insensitive filesystem")
	}
	write(t, both, "windows/System32/winevt/Logs/b.evtx", "b")
	got, _ = find(both)
	want = []string{"Windows/System32/winevt/Logs/a.evtx", "windows/System32/winevt/Logs/b.evtx"}
	if !reflect.DeepEqual(rels(got), want) {
		t.Errorf("both cases = %v, want %v", rels(got), want)
	}
}

func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	m := map[string]string{}
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(p)
		m[p] = fi.ModTime().String() + fi.Mode().String() + string(data)
		return nil
	})
	return m
}

func TestCollect(t *testing.T) {
	root := t.TempDir()
	write(t, root, logs+"/Security.evtx", "security")
	write(t, root, logs+"/Empty.evtx", "")
	before := snapshot(t, root)
	c := newCase(t)
	res, err := Collect(context.Background(), c, root)
	if err != nil {
		t.Fatal(err)
	}
	want := []Result{
		{File: logs + "/Empty.evtx", Status: Collected, SHA256: sum("")},
		{File: logs + "/Security.evtx", Status: Collected, SHA256: sum("security")},
	}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("Collect = %+v, want %+v", res, want)
	}
	if data, _ := os.ReadFile(filepath.Join(c.BaseDir, "evidence", filepath.FromSlash(logs), "Security.evtx")); string(data) != "security" {
		t.Errorf("copy = %q", data)
	}
	v, err := c.Verify(context.Background())
	if err != nil || len(v) != 2 || v[0].Status != casefile.StatusOK || v[1].Status != casefile.StatusOK {
		t.Errorf("Verify = %+v, %v", v, err)
	}
	if after := snapshot(t, root); !reflect.DeepEqual(before, after) {
		t.Error("target was modified")
	}
}

func TestCollectTargetErrors(t *testing.T) {
	ctx := context.Background()
	c := newCase(t)
	file := write(t, t.TempDir(), "f", "x")
	for _, target := range []string{filepath.Join(t.TempDir(), "missing"), file} {
		if _, err := Collect(ctx, c, target); err == nil || !strings.Contains(err.Error(), "invalid target") {
			t.Errorf("%s: err = %v", target, err)
		}
	}
	// the case lives under <tmp>/cases/CASE-004
	write(t, c.BaseDir, logs+"/x.evtx", "x")
	for _, target := range []string{c.BaseDir, filepath.Dir(c.BaseDir), filepath.Dir(filepath.Dir(c.BaseDir))} {
		if _, err := Collect(ctx, c, target); err == nil || !strings.Contains(err.Error(), "case directory must not be inside the target") {
			t.Errorf("%s: err = %v", target, err)
		}
	}
	if _, ok := c.Recorded(logs + "/x.evtx"); ok {
		t.Error("evidence recorded despite refusal")
	}
	if _, err := Collect(ctx, c, t.TempDir()); !errors.Is(err, ErrNoArtifact) {
		t.Errorf("empty target: err = %v", err)
	}
	onlyLink := t.TempDir()
	os.MkdirAll(filepath.Join(onlyLink, filepath.FromSlash(logs)), 0o755)
	if err := os.Symlink(file, filepath.Join(onlyLink, filepath.FromSlash(logs), "link.evtx")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if _, err := Collect(ctx, c, onlyLink); !errors.Is(err, ErrNoArtifact) {
		t.Errorf("only a link: err = %v", err)
	}
}

func manifestOrigin(t *testing.T, c *casefile.Case, file string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(c.BaseDir, "hashes", "manifest.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e map[string]interface{}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if e["file"] == file {
			o, _ := e["origin"].(map[string]interface{})
			return o
		}
	}
	t.Fatalf("%s not in manifest", file)
	return nil
}

func TestOrigin(t *testing.T) {
	root := t.TempDir()
	src := write(t, root, logs+"/Security.evtx", "s")
	atime := time.Date(2026, 11, 20, 14, 12, 3, 0, time.UTC)
	mtime := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	if err := os.Chtimes(src, atime, mtime); err != nil {
		t.Fatal(err)
	}
	c := newCase(t)
	if _, err := Collect(context.Background(), c, root); err != nil {
		t.Fatal(err)
	}
	o := manifestOrigin(t, c, logs+"/Security.evtx")
	real, _ := filepath.EvalSymlinks(src)
	if o["source_path"] != real || o["modified"] != "2026-10-01T08:00:00Z" || o["accessed"] != "2026-11-20T14:12:03Z" {
		t.Errorf("origin = %v", o)
	}
	_, created := o["created"]
	_, changed := o["changed"]
	switch runtime.GOOS {
	case "linux":
		if created || !changed {
			t.Errorf("linux origin = %v: want changed, no created", o)
		}
	case "windows":
		if !created || changed {
			t.Errorf("windows origin = %v: want created, no changed", o)
		}
	}
}

func TestCollectContinuesOnError(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("chmod 0 does not deny reads here")
	}
	root := t.TempDir()
	write(t, root, logs+"/a.evtx", "a")
	locked := write(t, root, logs+"/b.evtx", "b")
	write(t, root, logs+"/c.evtx", "c")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(locked, 0o644)
	res, err := Collect(context.Background(), newCase(t), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 || res[0].Status != Collected || res[1].Status != Failed || res[1].Reason == "" || res[2].Status != Collected {
		t.Errorf("results = %+v", res)
	}
}

func manifestLines(t *testing.T, c *casefile.Case) int {
	t.Helper()
	data, _ := os.ReadFile(filepath.Join(c.BaseDir, "hashes", "manifest.jsonl"))
	return strings.Count(string(data), "\n")
}

func TestCollectTwice(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	write(t, root, logs+"/Security.evtx", "security")
	write(t, root, logs+"/System.evtx", "system")
	c := newCase(t)
	if _, err := Collect(ctx, c, root); err != nil {
		t.Fatal(err)
	}
	res, err := Collect(ctx, c, root)
	if err != nil {
		t.Fatal(err)
	}
	want := []Result{
		{File: logs + "/Security.evtx", Status: Already, SHA256: sum("security")},
		{File: logs + "/System.evtx", Status: Already, SHA256: sum("system")},
	}
	if !reflect.DeepEqual(res, want) || manifestLines(t, c) != 2 {
		t.Errorf("second run = %+v (%d manifest lines)", res, manifestLines(t, c))
	}
	write(t, root, logs+"/Security.evtx", "tampered")
	res, _ = Collect(ctx, c, root)
	if res[0] != (Result{File: logs + "/Security.evtx", Status: Conflict, SHA256: sum("security"), Actual: sum("tampered")}) {
		t.Errorf("conflict = %+v", res[0])
	}
	if data, _ := os.ReadFile(filepath.Join(c.BaseDir, "evidence", filepath.FromSlash(logs), "Security.evtx")); string(data) != "security" {
		t.Errorf("evidence overwritten: %q", data)
	}
}

func TestCollectSymlink(t *testing.T) {
	ctx := context.Background()
	outside := write(t, t.TempDir(), "x/Hidden.evtx", "hidden")
	root := t.TempDir()
	write(t, root, logs+"/Security.evtx", "s")
	if err := os.Symlink(outside, filepath.Join(root, filepath.FromSlash(logs), "link.evtx")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	res, err := Collect(ctx, newCase(t), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || res[0].Status != Collected || res[1] != (Result{File: logs + "/link.evtx", Status: Skipped, Reason: "not a regular file"}) {
		t.Errorf("results = %+v", res)
	}

	linked := t.TempDir()
	os.MkdirAll(filepath.Join(linked, "Windows/System32/winevt"), 0o755)
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(linked, "Windows/System32/winevt/Logs")); err != nil {
		t.Fatal(err)
	}
	c := newCase(t)
	if _, err := Collect(ctx, c, linked); !errors.Is(err, ErrNoArtifact) {
		t.Errorf("linked Logs: err = %v", err)
	}
	if manifestLines(t, c) != 0 {
		t.Error("followed a linked directory")
	}
}

func TestCollectDeterministic(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	write(t, root, logs+"/b.evtx", "b")
	write(t, root, logs+"/a.evtx", "a")
	norm := func(c *casefile.Case) []string {
		data, _ := os.ReadFile(filepath.Join(c.BaseDir, "hashes", "manifest.jsonl"))
		var out []string
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var e map[string]interface{}
			json.Unmarshal([]byte(line), &e)
			delete(e, "collected_at")
			delete(e["origin"].(map[string]interface{}), "accessed") // reading may update it
			b, _ := json.Marshal(e)
			out = append(out, string(b))
		}
		return out
	}
	c1, c2 := newCase(t), newCase(t)
	r1, err1 := Collect(ctx, c1, root)
	r2, err2 := Collect(ctx, c2, root)
	if err1 != nil || err2 != nil || !reflect.DeepEqual(r1, r2) || !reflect.DeepEqual(norm(c1), norm(c2)) {
		t.Errorf("not deterministic:\n%v\n%v\n%v\n%v", r1, r2, norm(c1), norm(c2))
	}
}

func TestCollectMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 1 GiB")
	}
	root := t.TempDir()
	big := write(t, root, logs+"/Big.evtx", "")
	if err := os.Truncate(big, 1<<30); err != nil {
		t.Fatal(err)
	}
	c := newCase(t)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := Collect(context.Background(), c, root); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 16<<20 {
		t.Errorf("allocated %d MiB for a 1 GiB file", alloc>>20)
	}
	if after.HeapInuse > 64<<20 {
		t.Errorf("heap in use %d MiB", after.HeapInuse>>20)
	}
}
