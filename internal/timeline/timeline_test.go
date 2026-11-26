package timeline

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	casefile "DFIRFlow/internal/case"
	"DFIRFlow/internal/extsort"
	"DFIRFlow/internal/normalizer"
)

// newCase crée un cas dont le manifeste contient les preuves données.
func newCase(t *testing.T, evidence ...string) *casefile.Case {
	t.Helper()
	dir := t.TempDir()
	c, err := casefile.Create(filepath.Join(dir, "cases"), "CASE-006", "HOST", "me", "test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for i, rel := range evidence {
		src := filepath.Join(dir, "src", rel)
		os.MkdirAll(filepath.Dir(src), 0o755)
		if err := os.WriteFile(src, []byte{byte(i)}, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := c.AddEvidence(context.Background(), src, rel, nil); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// writeNormalized écrit le fichier d'événements (ou d'anomalies si suffix) d'une preuve.
func writeNormalized(t *testing.T, c *casefile.Case, name string, data []byte) {
	t.Helper()
	p := filepath.Join(c.Dir("normalized"), filepath.FromSlash(name))
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readTimeline(t *testing.T, c *casefile.Case) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(c.Dir("timeline"), "timeline.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// snapshot relève l'empreinte de chaque fichier sous les dossiers donnés.
func snapshot(t *testing.T, c *casefile.Case, dirs ...string) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, d := range dirs {
		filepath.Walk(filepath.Join(c.BaseDir, d), func(p string, fi os.FileInfo, err error) error {
			if err == nil && !fi.IsDir() {
				b, _ := os.ReadFile(p)
				s := sha256.Sum256(b)
				m[p] = hex.EncodeToString(s[:])
			}
			return nil
		})
	}
	return m
}

func timelineDir(t *testing.T, c *casefile.Case) []string {
	t.Helper()
	entries, _ := os.ReadDir(c.Dir("timeline"))
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

const (
	sec = "Windows/System32/winevt/Logs/Security.evtx"
	sys = "Windows/System32/winevt/Logs/System.evtx"
)

// twoFiles prépare deux preuves ingérées et renvoie leurs événements.
func twoFiles(t *testing.T) (*casefile.Case, []normalizer.Event) {
	c := newCase(t, sec, sys)
	var all []normalizer.Event
	for _, f := range []string{sec, sys} {
		evs := shuffled(300)
		for i := range evs {
			evs[i].SourceFile = f
			evs[i].UID = normalizer.UID(zeroHash, f, evs[i].RecordLocator)
		}
		writeNormalized(t, c, f+".jsonl", canonical(t, evs))
		writeNormalized(t, c, f+".anomalies.jsonl", []byte("{\"record_locator\":\"x\"}\n"))
		all = append(all, evs...)
	}
	writeNormalized(t, c, sys+".jsonl.partial", []byte("garbage"))
	normalizer.SortEvents(all)
	return c, all
}

func TestRunAll(t *testing.T) {
	c, all := twoFiles(t)
	before := snapshot(t, c, "normalized", "hashes", "evidence")
	sum, err := Run(context.Background(), c, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	got := readTimeline(t, c)
	if !bytes.Equal(got, canonical(t, all)) {
		t.Fatal("timeline differs from the sorted union")
	}
	h := sha256.Sum256(got)
	if sum.Files != 2 || sum.EventsRead != 600 || sum.EventsWritten != 600 || sum.SHA256 != hex.EncodeToString(h[:]) {
		t.Errorf("summary: %+v", sum)
	}
	if names := timelineDir(t, c); len(names) != 1 {
		t.Errorf("timeline/ contains %v", names)
	}
	after := snapshot(t, c, "normalized", "hashes", "evidence")
	if len(after) != len(before) {
		t.Fatalf("files changed: %d -> %d", len(before), len(after))
	}
	for p, h := range before {
		if after[p] != h {
			t.Errorf("modified: %s", p)
		}
	}
}

func TestRunDeterministic(t *testing.T) {
	c, _ := twoFiles(t)
	var runs [][]byte
	for _, budget := range []int{extsort.SegmentBudget, extsort.SegmentBudget, 4 << 10} {
		old := extsort.SegmentBudget
		extsort.SegmentBudget = budget
		_, err := Run(context.Background(), c, Filter{})
		extsort.SegmentBudget = old
		if err != nil {
			t.Fatal(err)
		}
		runs = append(runs, readTimeline(t, c))
	}
	if !bytes.Equal(runs[0], runs[1]) || !bytes.Equal(runs[0], runs[2]) {
		t.Fatal("runs differ")
	}
}

func TestRunInputs(t *testing.T) {
	// (a) aucune preuve ingérée.
	c := newCase(t, sec)
	if _, err := Run(context.Background(), c, Filter{}); !errors.Is(err, ErrNoEvents) || err.Error() != "no normalized events in the case; run ingest first" {
		t.Errorf("no events: %v", err)
	}
	if names := timelineDir(t, c); len(names) != 0 {
		t.Errorf("timeline/ contains %v", names)
	}

	// (b) preuve sans fichier, (c) fichier vide, (d) orphelin, (e) preuve nommée *.anomalies.
	c = newCase(t, sec, sys, "y.anomalies")
	writeNormalized(t, c, sec+".jsonl", nil)
	writeNormalized(t, c, "old/x.evtx.jsonl", []byte("not read\n"))
	writeNormalized(t, c, "old/x.evtx.anomalies.jsonl", []byte("not read\n"))
	writeNormalized(t, c, "y.anomalies.jsonl", canonical(t, []normalizer.Event{event("mft", "y.anomalies", 1, base, 1)}))
	sum, err := Run(context.Background(), c, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"normalized/old/x.evtx.anomalies.jsonl", "normalized/old/x.evtx.jsonl"}
	if sum.Files != 2 || sum.EventsWritten != 1 || strings.Join(sum.UnknownFiles, ",") != strings.Join(want, ",") {
		t.Errorf("summary: %+v", sum)
	}

	// (c) seul fichier vide : chronologie de zéro octet.
	c = newCase(t, sec)
	writeNormalized(t, c, sec+".jsonl", nil)
	if _, err := Run(context.Background(), c, Filter{}); err != nil || len(readTimeline(t, c)) != 0 {
		t.Errorf("empty file: err=%v", err)
	}
}

func TestRunBadLine(t *testing.T) {
	c, _ := twoFiles(t)
	if _, err := Run(context.Background(), c, Filter{}); err != nil {
		t.Fatal(err)
	}
	prev := readTimeline(t, c)
	data := canonical(t, shuffled(5))
	lines := bytes.SplitAfter(data, []byte("\n"))
	lines[2] = []byte("{\"schema_version\":1,\"bogus\":1}\n")
	writeNormalized(t, c, sys+".jsonl", bytes.Join(lines, nil))
	_, err := Run(context.Background(), c, Filter{})
	if err == nil || !strings.Contains(err.Error(), "normalized/"+sys+".jsonl: line 3") {
		t.Fatalf("bad line: %v", err)
	}
	if !bytes.Equal(readTimeline(t, c), prev) {
		t.Error("previous timeline changed")
	}
	if names := timelineDir(t, c); len(names) != 1 {
		t.Errorf("timeline/ contains %v", names)
	}
}

// cancelAfter annule le contexte après n appels à Err.
type cancelAfter struct {
	context.Context
	n int
}

func (c *cancelAfter) Err() error {
	if c.n--; c.n < 0 {
		return context.Canceled
	}
	return nil
}

func TestRunCanceled(t *testing.T) {
	c, _ := twoFiles(t)
	if _, err := Run(context.Background(), c, Filter{}); err != nil {
		t.Fatal(err)
	}
	prev := readTimeline(t, c)
	defer func(b int) { extsort.SegmentBudget = b }(extsort.SegmentBudget)
	extsort.SegmentBudget = 4 << 10
	for _, n := range []int{10, 700} { // pendant la lecture, puis pendant la fusion
		_, err := Run(&cancelAfter{context.Background(), n}, c, Filter{})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("n=%d: %v", n, err)
		}
		if !bytes.Equal(readTimeline(t, c), prev) {
			t.Errorf("n=%d: previous timeline changed", n)
		}
		if names := timelineDir(t, c); len(names) != 1 {
			t.Errorf("n=%d: timeline/ contains %v", n, names)
		}
	}

	// Restes d'un arrêt brutal supprimés par l'exécution suivante.
	os.WriteFile(filepath.Join(c.Dir("timeline"), "timeline.jsonl.partial"), []byte("x"), 0o644)
	os.MkdirAll(filepath.Join(c.Dir("timeline"), ".work-x", "seg-1"), 0o755)
	if _, err := Run(context.Background(), c, Filter{}); err != nil {
		t.Fatal(err)
	}
	if names := timelineDir(t, c); len(names) != 1 {
		t.Errorf("leftovers: %v", names)
	}
}

func TestRunFilter(t *testing.T) {
	c := newCase(t, sec, "$MFT")
	var evs, mft []normalizer.Event
	for i := 0; i < 40; i++ {
		// Pas de 250 ns : plusieurs événements par µs, de part et d'autre des bornes.
		ts := base.Add(time.Duration(i) * 250 * time.Nanosecond)
		evs = append(evs, event("evtx", sec, uint64(i), ts, i))
		mft = append(mft, event("mft", "$MFT", uint64(i), ts, 100+i))
	}
	writeNormalized(t, c, sec+".jsonl", canonical(t, evs))
	writeNormalized(t, c, "$MFT.jsonl", canonical(t, mft))
	full := append(append([]normalizer.Event(nil), evs...), mft...)
	normalizer.SortEvents(full)
	if _, err := Run(context.Background(), c, Filter{}); err != nil {
		t.Fatal(err)
	}
	all := readTimeline(t, c)

	us := func(n int) time.Time { return base.Add(time.Duration(n) * time.Microsecond) }
	filters := []Filter{
		{From: us(3)}, {To: us(5)}, {From: us(2), To: us(6)}, {From: us(4), To: us(4)},
		{Sources: []string{"evtx"}}, {Sources: []string{"mft"}}, {Sources: []string{"evtx", "mft"}},
		{From: us(-1), To: us(100)}, {},
	}
	for _, f := range filters {
		var want []normalizer.Event
		for _, ev := range full {
			t0 := ev.Timestamp.Truncate(time.Microsecond)
			okSrc := len(f.Sources) == 0 || strings.Contains(","+strings.Join(f.Sources, ",")+",", ","+ev.Source+",")
			if okSrc && (f.From.IsZero() || !t0.Before(f.From)) && (f.To.IsZero() || !t0.After(f.To)) {
				want = append(want, ev)
			}
		}
		sum, err := Run(context.Background(), c, f)
		if err != nil {
			t.Fatal(err)
		}
		got := readTimeline(t, c)
		if !bytes.Equal(got, canonical(t, want)) || sum.EventsRead != 80 || sum.EventsWritten != len(want) {
			t.Errorf("filter %+v: %d written, want %d", f, sum.EventsWritten, len(want))
		}
		if len(want) == len(full) && !bytes.Equal(got, all) {
			t.Errorf("filter %+v: differs from the full timeline", f)
		}
	}
}

func TestRunMissingSource(t *testing.T) {
	c := newCase(t, sec)
	writeNormalized(t, c, sec+".jsonl", canonical(t, []normalizer.Event{event("evtx", sec, 1, base, 1)}))
	sum, err := Run(context.Background(), c, Filter{Sources: []string{"prefetch", "evtx", "mft"}})
	if err != nil || strings.Join(sum.MissingSources, ",") != "mft,prefetch" {
		t.Errorf("missing: %v %v", sum.MissingSources, err)
	}
	// Source présente mais hors fenêtre : pas signalée.
	sum, _ = Run(context.Background(), c, Filter{From: base.Add(time.Hour), Sources: []string{"evtx"}})
	if len(sum.MissingSources) != 0 || sum.EventsWritten != 0 {
		t.Errorf("out of window: %+v", sum)
	}
}

// TestRunLarge vérifie SC-003 : 10 millions d'événements, mémoire bornée.
func TestRunLarge(t *testing.T) {
	if os.Getenv("DFIRFLOW_LARGE") != "1" {
		t.Skip("set DFIRFLOW_LARGE=1 (about 12 GB of temporary disk)")
	}
	const total, nfiles = 10_000_000, 4
	names := []string{"a.evtx", "b.evtx", "c.evtx", "d.evtx"}
	c := newCase(t, names...)
	r := rand.New(rand.NewSource(42))
	for _, name := range names {
		p := filepath.Join(c.Dir("normalized"), name+".jsonl")
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		w := bufio.NewWriterSize(f, 1<<20)
		enc := normalizer.NewEncoder(w)
		for i := 0; i < total/nfiles; i++ {
			ev := event("evtx", name, uint64(i), base.Add(time.Duration(r.Int63n(int64(365*24*time.Hour)))), i)
			ev.Metadata = nil
			if err := enc.Event(ev); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	runtime.GC()
	var peak uint64
	done := make(chan struct{})
	go func() {
		var m runtime.MemStats
		for {
			select {
			case <-done:
				return
			case <-time.After(100 * time.Millisecond):
				runtime.ReadMemStats(&m)
				if m.HeapInuse > peak {
					peak = m.HeapInuse
				}
			}
		}
	}()
	start := time.Now()
	sum, err := Run(context.Background(), c, Filter{})
	elapsed := time.Since(start)
	close(done)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d events in %v, peak heap %d MiB", sum.EventsWritten, elapsed, peak>>20)
	if sum.EventsWritten != total || peak > 256<<20 {
		t.Fatalf("written=%d peak=%d MiB", sum.EventsWritten, peak>>20)
	}

	f, err := os.Open(filepath.Join(c.Dir("timeline"), "timeline.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r2 := bufio.NewReaderSize(f, 1<<20)
	n, prev := 0, extsort.Key{}
	for {
		line, err := r2.ReadBytes('\n')
		if len(line) == 0 && err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		k, err := decodeKey(line)
		if err != nil {
			t.Fatal(err)
		}
		if n > 0 && !extsort.Less(prev, k) {
			t.Fatalf("line %d out of order", n+1)
		}
		prev, n = k, n+1
	}
	if n != total {
		t.Fatalf("%d lines, want %d", n, total)
	}
}
