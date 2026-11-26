package detection

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
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

const (
	secLog = "Windows/System32/winevt/Logs/Security.evtx"
	sysLog = "Windows/System32/winevt/Logs/System.evtx"
)

// newCase crée un cas dont le manifeste contient les preuves données.
func newCase(t *testing.T, evidence ...string) *casefile.Case {
	t.Helper()
	dir := t.TempDir()
	c, err := casefile.Create(filepath.Join(dir, "cases"), "CASE-012", "HOST", "me", "test", time.Now())
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

func writeEvents(t *testing.T, c *casefile.Case, name string, evs []normalizer.Event) {
	t.Helper()
	var b bytes.Buffer
	enc := normalizer.NewEncoder(&b)
	for _, ev := range evs {
		if err := enc.Event(ev); err != nil {
			t.Fatal(err)
		}
	}
	writeRaw(t, c, name, b.Bytes())
}

func writeRaw(t *testing.T, c *casefile.Case, name string, data []byte) {
	t.Helper()
	p := filepath.Join(c.Dir("normalized"), filepath.FromSlash(name))
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readDetections(t *testing.T, c *casefile.Case) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(c.Dir("detections"), "detections.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// snapshot relève l'empreinte de chaque fichier sous les dossiers donnés.
func snapshot(c *casefile.Case, dirs ...string) map[string]string {
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

func detectionsDir(t *testing.T, c *casefile.Case) []string {
	t.Helper()
	es, err := os.ReadDir(c.Dir("detections"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// mixedCase : deux preuves, événements dans le désordre, dont un 4732 qui
// satisfait aussi une règle fournie, et des événements sans règle.
func mixedCase(t *testing.T) (*casefile.Case, []normalizer.Event) {
	c := newCase(t, secLog, sysLog)
	sec := []normalizer.Event{
		evtx("Security", "Microsoft-Windows-Security-Auditing", 4719, nil, 30),
		evtx("Security", "Microsoft-Windows-Security-Auditing", 4624, nil, 10),
		evtx("Security", "Microsoft-Windows-Eventlog", 1102, nil, 20),
		evtx("Security", "Microsoft-Windows-Security-Auditing", 4732, map[string]string{"TargetSid": "S-1-5-32-544"}, 5),
	}
	sys := []normalizer.Event{
		evtx("System", "Service Control Manager", 7045, nil, 25),
		evtx("System", "Service Control Manager", 7036, nil, 26),
	}
	for i := range sys {
		sys[i].SourceFile, sys[i].UID = sysLog, normalizer.UID(zeroHash, sysLog, sys[i].RecordLocator)
	}
	mft := evtx("", "", 0, nil, 40)
	mft.Source, mft.Channel, mft.Provider, mft.EventID = normalizer.SourceMFT, "", "", nil
	writeEvents(t, c, secLog+".jsonl", append(sec, mft))
	writeEvents(t, c, sysLog+".jsonl", sys)
	writeRaw(t, c, secLog+".anomalies.jsonl", []byte("not read\n"))
	return c, append(append(sec, sys...), mft)
}

func TestRunEmbedded(t *testing.T) {
	c, evs := mixedCase(t)
	rs, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	before := snapshot(c, "normalized", "timeline", "hashes", "evidence")
	sum, err := Run(context.Background(), c, rs)
	if err != nil {
		t.Fatal(err)
	}
	// Attendu : une détection par couple (règle, événement) satisfait.
	var want []normalizer.Detection
	for _, ev := range evs {
		for _, r := range rs.Applied {
			if ev.Source == normalizer.SourceEVTX && strings.EqualFold(ev.Channel, r.Channel) && r.match(&ev) {
				want = append(want, normalizer.Detection{
					ID: normalizer.DetectionID(r.ID, r.Version, []string{ev.UID}), Timestamp: ev.Timestamp,
					RuleID: r.ID, RuleVersion: r.Version, Severity: r.Severity, Confidence: r.Confidence,
					MITRE: r.MITRE, Events: []string{ev.UID},
				})
			}
		}
	}
	if len(want) != 4 {
		t.Fatalf("test setup: %d expected detections, want 4", len(want))
	}
	normalizer.SortDetections(want)
	var wb bytes.Buffer
	enc := normalizer.NewEncoder(&wb)
	for _, d := range want {
		if err := enc.Detection(d); err != nil {
			t.Fatal(err)
		}
	}
	got := readDetections(t, c)
	if !bytes.Equal(got, wb.Bytes()) {
		t.Fatalf("detections:\n%s\nwant:\n%s", got, wb.Bytes())
	}
	n := 0
	if err := normalizer.ReadDetections(bytes.NewReader(got), func(normalizer.Detection) error { n++; return nil }); err != nil || n != 4 {
		t.Fatalf("ReadDetections: %d, %v", n, err)
	}
	s := sha256.Sum256(got)
	if sum.Files != 2 || sum.EventsRead != 7 || sum.Detections != 4 || sum.SHA256 != hex.EncodeToString(s[:]) || len(sum.UnknownFiles) != 0 {
		t.Errorf("summary: %+v", sum)
	}
	if after := snapshot(c, "normalized", "timeline", "hashes", "evidence"); len(after) != len(before) {
		t.Errorf("case files changed")
	} else {
		for p, h := range before {
			if after[p] != h {
				t.Errorf("%s changed", p)
			}
		}
	}
	if names := detectionsDir(t, c); len(names) != 1 {
		t.Errorf("detections/ contains %v", names)
	}

	// Un même événement satisfait deux règles : deux détections.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.yml"), []byte(rule("", "  sel:\n    EventID: 4732\n  condition: sel\n")), 0o644)
	os.WriteFile(filepath.Join(dir, "b.yml"), []byte(strings.Replace(rule("", "  sel:\n    TargetSid|endswith: '-544'\n  condition: sel\n"), "id: r1", "id: r2", 1)), 0o644)
	rs2, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if sum, err := Run(context.Background(), c, rs2); err != nil || sum.Detections != 2 {
		t.Errorf("two rules on one event: %+v %v", sum, err)
	}
}

func TestRunDeterministic(t *testing.T) {
	c, _ := mixedCase(t)
	rs, _ := Load("")
	var outs [][]byte
	for _, budget := range []int{extsort.SegmentBudget, extsort.SegmentBudget, 300} {
		old, oldFan := extsort.SegmentBudget, extsort.MaxFanIn
		extsort.SegmentBudget, extsort.MaxFanIn = budget, 3
		_, err := Run(context.Background(), c, rs)
		extsort.SegmentBudget, extsort.MaxFanIn = old, oldFan
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, readDetections(t, c))
	}
	if !bytes.Equal(outs[0], outs[1]) || !bytes.Equal(outs[0], outs[2]) {
		t.Fatal("outputs differ")
	}
}

func TestRunErrors(t *testing.T) {
	rs, _ := Load("")

	// Aucun fichier d'événements.
	c := newCase(t, secLog)
	if _, err := Run(context.Background(), c, rs); !errors.Is(err, ErrNoEvents) || err.Error() != "no normalized events in the case; run ingest first" {
		t.Errorf("no events: %v", err)
	}
	if names := detectionsDir(t, c); len(names) != 0 {
		t.Errorf("detections/ contains %v", names)
	}

	// Aucun événement satisfaisant : fichier de zéro octet.
	writeEvents(t, c, secLog+".jsonl", []normalizer.Event{evtx("Security", "P", 4624, nil, 1)})
	if sum, err := Run(context.Background(), c, rs); err != nil || sum.Detections != 0 || len(readDetections(t, c)) != 0 {
		t.Errorf("no match: %+v %v", sum, err)
	}

	// Ligne refusée : chemin et numéro de ligne, fichier précédent intact.
	c, _ = mixedCase(t)
	if _, err := Run(context.Background(), c, rs); err != nil {
		t.Fatal(err)
	}
	prev := readDetections(t, c)
	good, _ := os.ReadFile(filepath.Join(c.Dir("normalized"), filepath.FromSlash(sysLog+".jsonl")))
	writeRaw(t, c, sysLog+".jsonl", append(good, []byte(`{"schema_version":1,"bogus":1}`+"\n")...))
	_, err := Run(context.Background(), c, rs)
	if err == nil || !strings.Contains(err.Error(), "normalized/"+sysLog+".jsonl") || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("bad line: %v", err)
	}
	if !bytes.Equal(readDetections(t, c), prev) {
		t.Error("previous detections changed")
	}
	if names := detectionsDir(t, c); len(names) != 1 {
		t.Errorf("detections/ contains %v", names)
	}
	writeRaw(t, c, sysLog+".jsonl", good)

	// Interruption pendant la lecture, puis pendant la fusion.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, c, rs); err != context.Canceled {
		t.Errorf("canceled read: %v", err)
	}
	old := extsort.SegmentBudget
	extsort.SegmentBudget = 300
	s := &cancelAfter{n: 7}
	_, err = Run(s.ctx(), c, rs)
	extsort.SegmentBudget = old
	if err != context.Canceled {
		t.Errorf("canceled merge: %v", err)
	}
	if !bytes.Equal(readDetections(t, c), prev) {
		t.Error("previous detections changed after cancel")
	}
	if names := detectionsDir(t, c); len(names) != 1 {
		t.Errorf("detections/ contains %v after cancel", names)
	}

	// Restes d'un arrêt brutal supprimés par une exécution réussie.
	os.WriteFile(filepath.Join(c.Dir("detections"), "detections.jsonl.partial"), nil, 0o644)
	os.Mkdir(filepath.Join(c.Dir("detections"), ".work-x"), 0o755)
	if _, err := Run(context.Background(), c, rs); err != nil {
		t.Fatal(err)
	}
	if names := detectionsDir(t, c); len(names) != 1 {
		t.Errorf("stale files left: %v", names)
	}
}

// cancelAfter renvoie un contexte annulé après n appels à Err, pour
// interrompre la fusion une fois tous les événements lus.
type cancelAfter struct {
	context.Context
	n int
}

func (c *cancelAfter) ctx() context.Context { c.Context = context.Background(); return c }

func (c *cancelAfter) Err() error {
	if c.n--; c.n < 0 {
		return context.Canceled
	}
	return nil
}

// TestRunLarge mesure SC-004 ; lancé seulement avec DFIRFLOW_LARGE=1.
func TestRunLarge(t *testing.T) {
	if os.Getenv("DFIRFLOW_LARGE") != "1" {
		t.Skip("set DFIRFLOW_LARGE=1")
	}
	const total, nfiles = 10_000_000, 4
	names := []string{"a.evtx", "b.evtx", "c.evtx", "d.evtx"}
	c := newCase(t, names...)
	wantDet := 0
	for f, name := range names {
		p := filepath.Join(c.Dir("normalized"), name+".jsonl")
		fh, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		w := bufio.NewWriterSize(fh, 1<<20)
		enc := normalizer.NewEncoder(w)
		for i := 0; i < total/nfiles; i++ {
			n := f*total/nfiles + i
			ev := evtx("Security", "Microsoft-Windows-Security-Auditing", 4624, map[string]string{"LogonType": "3", "TargetUserName": "user"}, n)
			switch {
			case n%100 == 0: // 1 % satisfait une règle embarquée
				ev.EventID = ptrU32(4719)
				wantDet++
			case n%2 == 0:
				ev.Channel, ev.Provider, ev.EventID = "System", "Service Control Manager", ptrU32(7036)
			}
			ev.SourceFile = name
			ev.UID = normalizer.UID(zeroHash, name, ev.RecordLocator)
			if err := enc.Event(ev); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		fh.Close()
	}
	rs, _ := Load("")

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
	sum, err := Run(context.Background(), c, rs)
	elapsed := time.Since(start)
	close(done)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d events, %d detections in %v, peak heap %d MiB", sum.EventsRead, sum.Detections, elapsed, peak>>20)
	if sum.EventsRead != total || sum.Detections != wantDet || peak > 256<<20 || elapsed > 5*time.Minute {
		t.Fatalf("read=%d detections=%d (want %d) peak=%d MiB elapsed=%v", sum.EventsRead, sum.Detections, wantDet, peak>>20, elapsed)
	}

	f, err := os.Open(filepath.Join(c.Dir("detections"), "detections.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	n, prev := 0, extsort.Key{}
	for {
		line, err := r.ReadBytes('\n')
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
	if n != wantDet {
		t.Fatalf("%d lines, want %d", n, wantDet)
	}
}

func ptrU32(v uint32) *uint32 { return &v }
