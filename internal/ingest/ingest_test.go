package ingest

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	casefile "DFIRFlow/internal/case"
	"DFIRFlow/internal/normalizer"
	"DFIRFlow/internal/parser"
	"DFIRFlow/internal/parser/evtx"
)

const (
	logs     = "Windows/System32/winevt/Logs/"
	security = logs + "Security.evtx"
	fixture  = "../parser/evtx/testdata/Security.evtx"
)

var parsers = []parser.Parser{evtx.Parser{}}

func newCase(t *testing.T) *casefile.Case {
	t.Helper()
	c, err := casefile.Create(filepath.Join(t.TempDir(), "cases"), "CASE-005", "WIN-01", "me", "test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// add place data dans le cas sous evidence/rel.
func add(t *testing.T, c *casefile.Case, rel string, data []byte) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(src, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddEvidence(context.Background(), src, filepath.FromSlash(rel), nil); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func normalized(c *casefile.Case, rel string) string {
	return filepath.Join(c.Dir("normalized"), filepath.FromSlash(rel))
}

func status(s Summary) map[string]Result {
	m := map[string]Result{}
	for _, r := range s.Results {
		m[r.File] = r
	}
	return m
}

func noPartial(t *testing.T, c *casefile.Case) {
	t.Helper()
	filepath.Walk(c.Dir("normalized"), func(p string, _ os.FileInfo, _ error) error {
		if strings.HasSuffix(p, ".partial") {
			t.Errorf("partial file left: %s", p)
		}
		return nil
	})
}

func TestIngest(t *testing.T) {
	ctx := context.Background()
	c := newCase(t)
	sec := read(t, fixture)
	add(t, c, security, sec)
	add(t, c, logs+"notes.evtx", []byte("x"))
	add(t, c, logs+"Security.dat", sec)         // FR-002 : signature, pas extension
	add(t, c, logs+"Truncated.evtx", sec[:100]) // en-tête tronqué → FAILED

	sum, err := Run(ctx, c, nil, parsers)
	if err != nil {
		t.Fatal(err)
	}
	files := make([]string, len(sum.Results))
	for i, r := range sum.Results {
		files[i] = r.File
	}
	if !sort.StringsAreSorted(files) || len(files) != 4 {
		t.Fatalf("results not sorted or incomplete: %v", files)
	}
	st := status(sum)
	if r := st[security]; r.Status != Ingested || r.Events != 739 || r.Anomalies != 0 {
		t.Fatalf("Security.evtx: %+v", r)
	}
	if r := st[logs+"Security.dat"]; r.Status != Ingested || r.Events != 739 {
		t.Fatalf("Security.dat: %+v", r)
	}
	if r := st[logs+"notes.evtx"]; r.Status != Skipped || r.Reason != "not an EVTX file" {
		t.Fatalf("notes.evtx: %+v", r)
	}
	if r := st[logs+"Truncated.evtx"]; r.Status != Failed || r.Reason == "" {
		t.Fatalf("Truncated.evtx: %+v", r)
	}
	if _, err := os.Stat(normalized(c, logs+"Truncated.evtx.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("normalized file written for a FAILED evidence: %v", err)
	}

	evPath := normalized(c, security+".jsonl")
	n := 0
	f, err := os.Open(evPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := normalizer.ReadEvents(f, func(normalizer.Event) error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if n != 739 {
		t.Fatalf("%d events in %s", n, evPath)
	}
	if b := read(t, normalized(c, security+".anomalies.jsonl")); len(b) != 0 {
		t.Fatalf("anomalies file not empty: %s", b)
	}
	noPartial(t, c)

	// Relance : fichiers identiques octet par octet (SC-005).
	first := read(t, evPath)
	if _, err := Run(ctx, c, nil, parsers); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, read(t, evPath)) {
		t.Fatal("second ingestion differs")
	}

	// Sélection d'un chemin, avec le séparateur du système.
	sum, err = Run(ctx, c, []string{filepath.FromSlash(security)}, parsers)
	if err != nil || len(sum.Results) != 1 || sum.Results[0].File != security {
		t.Fatalf("selection: %+v, %v", sum.Results, err)
	}

	// Chemin hors manifeste : refusé avant tout traitement.
	os.RemoveAll(c.Dir("normalized"))
	os.MkdirAll(c.Dir("normalized"), 0o755)
	if _, err := Run(ctx, c, []string{security, "absent.evtx"}, parsers); err == nil || err.Error() != "not in the case manifest: absent.evtx" {
		t.Fatalf("err = %v", err)
	}
	if es, _ := os.ReadDir(c.Dir("normalized")); len(es) != 0 {
		t.Fatalf("files written despite a refused path: %v", es)
	}
}

func TestIngestNoEVTX(t *testing.T) {
	c := newCase(t)
	add(t, c, logs+"notes.evtx", []byte("x"))
	if _, err := Run(context.Background(), c, nil, parsers); err != ErrNoEVTX {
		t.Fatalf("err = %v, want %v", err, ErrNoEVTX)
	}
	if _, err := Run(context.Background(), newCase(t), nil, parsers); err != ErrNoEVTX {
		t.Fatalf("empty case: err = %v", err)
	}
}

func TestIngestAltered(t *testing.T) {
	c := newCase(t)
	sec := read(t, fixture)
	add(t, c, security, sec)
	add(t, c, logs+"Copy.evtx", sec)
	p := filepath.Join(c.Dir("evidence"), filepath.FromSlash(security))
	os.Chmod(p, 0o644)
	altered := append([]byte(nil), sec...)
	altered[5000] ^= 0xff
	if err := os.WriteFile(p, altered, 0o644); err != nil {
		t.Fatal(err)
	}
	sum, err := Run(context.Background(), c, nil, parsers)
	if err != nil {
		t.Fatal(err)
	}
	st := status(sum)
	r := st[security]
	if r.Status != Altered || !strings.HasPrefix(r.Reason, "expected=") || !strings.Contains(r.Reason, " actual=") {
		t.Fatalf("altered: %+v", r)
	}
	if _, err := os.Stat(normalized(c, security+".jsonl")); !os.IsNotExist(err) {
		t.Fatal("altered evidence was ingested")
	}
	if st[logs+"Copy.evtx"].Status != Ingested {
		t.Fatalf("other evidence not processed: %+v", st)
	}
}

func TestOtherSummary(t *testing.T) {
	c := newCase(t)
	add(t, c, security, read(t, fixture))
	sum, err := Run(context.Background(), c, nil, parsers)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[OtherCount]int{}
	total := 0
	f, _ := os.Open(normalized(c, security+".jsonl"))
	defer f.Close()
	normalizer.ReadEvents(f, func(e normalizer.Event) error {
		total++
		if e.EventType == normalizer.TypeOther {
			counts[OtherCount{Channel: e.Channel, EventID: *e.EventID}]++
		}
		return nil
	})
	other := 0
	var want []OtherCount
	for k, n := range counts {
		other += n
		k.Count = n
		want = append(want, k)
	}
	sort.Slice(want, func(i, j int) bool {
		if want[i].Count != want[j].Count {
			return want[i].Count > want[j].Count
		}
		if want[i].Channel != want[j].Channel {
			return want[i].Channel < want[j].Channel
		}
		return want[i].EventID < want[j].EventID
	})
	if len(want) > 10 {
		want = want[:10]
	}
	if sum.Other != other || sum.Events != total || len(sum.TopOther) != len(want) {
		t.Fatalf("other=%d/%d events=%d/%d top=%v", sum.Other, other, sum.Events, total, sum.TopOther)
	}
	for i := range want {
		if sum.TopOther[i] != want[i] {
			t.Fatalf("top[%d] = %+v, want %+v", i, sum.TopOther[i], want[i])
		}
	}
	if sum.OtherRatio() == "0.000" {
		t.Fatalf("ratio %s", sum.OtherRatio())
	}
}
