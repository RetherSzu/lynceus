package extsort

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// line encode une clé de test : "ts s n t\n" ; decode la relit.
func line(k Key) []byte { return []byte(fmt.Sprintf("%d %s %d %s\n", k.TS, k.S, k.N, k.T)) }

func decode(b []byte) (Key, error) {
	var k Key
	_, err := fmt.Sscanf(string(b), "%d %s %d %s\n", &k.TS, &k.S, &k.N, &k.T)
	return k, err
}

// keys renvoie n clés aux composantes souvent égales, dans le désordre.
func keys(n int) []Key {
	r := rand.New(rand.NewSource(1))
	ks := make([]Key, n)
	for i := range ks {
		ks[i] = Key{int64(r.Intn(50) - 25), fmt.Sprintf("f%d", r.Intn(3)), uint64(r.Intn(5)), fmt.Sprintf("u%05d", i)}
	}
	return ks
}

// sortAll trie ks avec le budget et le fan-in donnés.
func sortAll(t *testing.T, ks []Key, budget, fanIn int) ([]byte, string) {
	t.Helper()
	defer func(b, f int) { SegmentBudget, MaxFanIn = b, f }(SegmentBudget, MaxFanIn)
	SegmentBudget, MaxFanIn = budget, fanIn
	dir := t.TempDir()
	s := &Sorter{Ctx: context.Background(), Parent: dir, Decode: decode}
	defer s.Cleanup()
	for _, k := range ks {
		if err := s.Add(k, line(k)); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := s.Finish(&out); err != nil {
		t.Fatal(err)
	}
	if budget < 1<<20 && s.Segments() < 2 {
		t.Errorf("budget %d: %d segments, want several", budget, s.Segments())
	}
	return out.Bytes(), dir
}

func TestExternalSort(t *testing.T) {
	ks := keys(5000)
	want := append([]Key(nil), ks...)
	sort.Slice(want, func(i, j int) bool { return Less(want[i], want[j]) })
	var w bytes.Buffer
	for _, k := range want {
		w.Write(line(k))
	}
	single, _ := sortAll(t, ks, 64<<20, 128)
	if !bytes.Equal(single, w.Bytes()) {
		t.Fatal("single segment differs from sort.Slice")
	}
	multi, dir := sortAll(t, ks, 4<<10, 3)
	if !bytes.Equal(multi, single) {
		t.Fatal("external sort differs from single segment")
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Errorf("work files left: %v", left)
	}
}

func TestSortCanceled(t *testing.T) {
	defer func(b int) { SegmentBudget = b }(SegmentBudget)
	SegmentBudget = 4 << 10
	ctx, cancel := context.WithCancel(context.Background())
	s := &Sorter{Ctx: ctx, Parent: t.TempDir(), Decode: decode}
	defer s.Cleanup()
	for _, k := range keys(500) {
		if err := s.Add(k, line(k)); err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	if err := s.Finish(&bytes.Buffer{}); err != context.Canceled {
		t.Fatalf("finish after cancel: %v", err)
	}
}

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "f.jsonl")
	os.WriteFile(out, []byte("old"), 0o644)
	if _, err := WriteAtomic(out, func(w io.Writer) error { w.Write([]byte("x")); return os.ErrClosed }); err == nil {
		t.Fatal("want error")
	}
	if b, _ := os.ReadFile(out); string(b) != "old" {
		t.Fatalf("previous file changed: %q", b)
	}
	sum, err := WriteAtomic(out, func(w io.Writer) error { _, err := w.Write([]byte("new")); return err })
	if err != nil || sum != "11507a0e2f5e69d5dfa40a62a1bd7b6ee57e6bcd85c67c9b8431b36fff21c437" {
		t.Fatalf("sum %s, err %v", sum, err)
	}
	os.WriteFile(out+".partial", nil, 0o644)
	os.Mkdir(filepath.Join(dir, ".work-x"), 0o755)
	CleanStale(dir, "f.jsonl")
	if left, _ := os.ReadDir(dir); len(left) != 1 || !strings.HasSuffix(left[0].Name(), "f.jsonl") {
		t.Fatalf("left: %v", left)
	}
}
