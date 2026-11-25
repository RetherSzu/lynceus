package evtx

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"DFIRFlow/internal/normalizer"
	"DFIRFlow/internal/parser"
	"DFIRFlow/internal/parser/evtx/binxml"
)

const (
	securityEVTX = "testdata/Security.evtx"
	testFile     = "Windows/System32/winevt/Logs/Security.evtx"
	testSHA      = "0000000000000000000000000000000000000000000000000000000000000000"
)

var testSrc = parser.Source{File: testFile, SHA256: testSHA, Host: "CASEHOST"}

// collect garde, dans l'ordre, ce que le parser émet.
type collect struct {
	events    []normalizer.Event
	anomalies []parser.Anomaly
	order     []string // "event" ou kind de l'anomalie
}

func (c *collect) Event(e normalizer.Event) error {
	c.events = append(c.events, e)
	c.order = append(c.order, "event")
	return nil
}

func (c *collect) Anomaly(a parser.Anomaly) error {
	c.anomalies = append(c.anomalies, a)
	c.order = append(c.order, a.Kind)
	return nil
}

func load(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// parse décode data à travers parser.Validating, comme ingest.
func parse(t testing.TB, data []byte) (*collect, error) {
	t.Helper()
	c := &collect{}
	err := Parser{}.Parse(context.Background(), bytes.NewReader(data), int64(len(data)), testSrc, parser.Validating(c))
	return c, err
}

func TestMatch(t *testing.T) {
	p := Parser{}
	if p.Name() != "evtx" {
		t.Fatalf("Name = %q", p.Name())
	}
	head := load(t, securityEVTX)[:8]
	for _, c := range []struct {
		head []byte
		want bool
	}{{head, true}, {[]byte("MZ\x90\x00"), false}, {nil, false}, {[]byte("ElfFile is text"), false}} {
		if got := p.Match(c.head); got != c.want {
			t.Errorf("Match(%q) = %v, want %v", c.head, got, c.want)
		}
	}
}

var locatorRE = regexp.MustCompile(`^chunk:\d+/record:\d+$`)

func TestParseBaseline(t *testing.T) {
	c, err := parse(t, load(t, securityEVTX))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.events) != 739 || len(c.anomalies) != 0 {
		t.Fatalf("events=%d anomalies=%v, want 739 and none", len(c.events), c.anomalies)
	}
	for _, e := range c.events {
		if e.Source != "evtx" || e.Channel == "" || e.Provider == "" || e.EventID == nil || e.Host == "" {
			t.Fatalf("incomplete event: %+v", e)
		}
		if !locatorRE.MatchString(e.RecordLocator) || !strings.HasSuffix(e.RecordLocator, "/record:"+strconv.FormatUint(e.RecordID, 10)) {
			t.Fatalf("locator %q for record %d", e.RecordLocator, e.RecordID)
		}
		if e.Ingest != "native" || e.UID != normalizer.UID(testSHA, testFile, e.RecordLocator) {
			t.Fatalf("provenance: %+v", e)
		}
		if vs := e.Validate(); len(vs) > 0 {
			t.Fatalf("invalid event %s: %v", e.RecordLocator, vs)
		}
		if e.Metadata["System.EventRecordID"] == "" {
			t.Fatalf("metadata without System fields: %v", e.Metadata)
		}
	}
}

// TestInvalidEvent : un enregistrement décodable mais invalide pour le modèle
// 003 (canal vide) devient une anomalie invalid, jamais un événement.
func TestInvalidEvent(t *testing.T) {
	sys := binxml.NewDict()
	sys.Set("Provider", dict("Name", "P"))
	sys.Set("EventID", uint16(1))
	sys.Set("TimeCreated", dict("SystemTime", binxml.FileTime(131939362733172597)))
	sys.Set("Channel", "")
	sys.Set("Computer", "")
	rec := &binxml.EventRecord{Event: dict("Event", dict("System", sys))}
	rec.Header.RecordID = 7
	ev, err := toEvent(rec, 0, testSrc, Table{})
	if err != nil {
		t.Fatal(err)
	}
	c := &collect{}
	if err := parser.Validating(c).Event(ev); err != nil {
		t.Fatal(err)
	}
	if len(c.events) != 0 || len(c.anomalies) != 1 || c.anomalies[0].Kind != parser.KindInvalid || c.anomalies[0].Locator != "chunk:0/record:7" {
		t.Fatalf("events=%v anomalies=%v", c.events, c.anomalies)
	}
	if ev.Host != "CASEHOST" {
		t.Fatalf("host fallback = %q, want CASEHOST", ev.Host)
	}
}

func dict(kv ...interface{}) *binxml.Dict {
	d := binxml.NewDict()
	for i := 0; i < len(kv); i += 2 {
		d.Set(kv[i].(string), kv[i+1])
	}
	return d
}

const (
	headerBlock = 4096
	chunkSize   = 65536
)

func sumCheck(t *testing.T, c *collect, announced int) {
	t.Helper()
	if got := len(c.events) + len(c.anomalies); got != announced {
		t.Fatalf("events+anomalies = %d+%d, want %d", len(c.events), len(c.anomalies), announced)
	}
}

// TestCorruptChunk : E2 / C11, un chunk abîmé ne fait rien perdre en silence.
func TestCorruptChunk(t *testing.T) {
	data := load(t, securityEVTX)
	start := headerBlock + 512 // premier enregistrement du chunk 0
	for i := start; i < start+200; i++ {
		data[i] = ^data[i]
	}
	c, err := parse(t, data)
	if err != nil {
		t.Fatal(err)
	}
	sumCheck(t, c, 739)
	if len(c.anomalies) != 78 || c.anomalies[0].Kind != parser.KindUnreadable || c.anomalies[0].Locator != "chunk:0/record:31878" ||
		c.anomalies[1].Kind != parser.KindMissing || c.anomalies[77].Locator != "chunk:0/record:31955" {
		t.Fatalf("anomalies = %v ... %v", c.anomalies[:2], c.anomalies[len(c.anomalies)-1])
	}
	if c.order[0] != parser.KindUnreadable || c.events[0].RecordLocator != "chunk:1/record:31956" {
		t.Fatalf("other chunks not emitted in order: %v", c.events[0].RecordLocator)
	}
}

func TestTruncated(t *testing.T) {
	data := load(t, securityEVTX)
	cut := headerBlock + 2*chunkSize + 30000 // milieu du chunk 2 (78 enregistrements)
	c, err := parse(t, data[:cut])
	if err != nil {
		t.Fatal(err)
	}
	sumCheck(t, c, 78+76+78)
	last := c.order[len(c.order)-1]
	if last != parser.KindTruncated || len(c.events) <= 154 {
		t.Fatalf("events=%d last=%s", len(c.events), last)
	}
	for i, k := range c.order {
		if k == parser.KindTruncated && i < len(c.events) {
			t.Fatalf("truncated anomaly before a complete record")
		}
	}

	if _, err := parse(t, data[:100]); err == nil {
		t.Fatal("truncated file header: no error")
	}

	// Journal vide : en-tête valide, aucun chunk.
	c, err = parse(t, data[:headerBlock])
	if err != nil || len(c.events)+len(c.anomalies) != 0 {
		t.Fatalf("empty log: %v, %v, %v", err, c.events, c.anomalies)
	}
}

// TestParseDeterministic : même entrée, même suite (spec 003, FR-016c).
func TestParseDeterministic(t *testing.T) {
	data := load(t, securityEVTX)
	a, _ := parse(t, data)
	b, _ := parse(t, data)
	if len(a.events) != len(b.events) {
		t.Fatal("different lengths")
	}
	for i := range a.events {
		x, _ := json.Marshal(a.events[i])
		y, _ := json.Marshal(b.events[i])
		if !bytes.Equal(x, y) {
			t.Fatalf("event %d differs", i)
		}
	}
}

// repeated simule un journal de size octets en répétant les chunks utilisés
// de Security.evtx, sans jamais le matérialiser.
type repeated struct {
	data   []byte
	chunks int
}

func (r repeated) ReadAt(p []byte, off int64) (int, error) {
	for i := range p {
		o := off + int64(i)
		if o < headerBlock {
			p[i] = r.data[o]
			continue
		}
		k := (o - headerBlock) / chunkSize % int64(r.chunks)
		p[i] = r.data[headerBlock+k*chunkSize+(o-headerBlock)%chunkSize]
	}
	return len(p), nil
}

type counter struct {
	n       int
	maxHeap uint64
}

func (c *counter) Event(normalizer.Event) error {
	c.n++
	if c.n%5000 == 0 {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		if m.HeapInuse > c.maxHeap {
			c.maxHeap = m.HeapInuse
		}
	}
	return nil
}
func (c *counter) Anomaly(parser.Anomaly) error { return nil }

// TestParseMemory : mémoire constante (SC-004). 64 Mio par défaut ;
// DFIRFLOW_LARGE=1 lance la mesure sur 1 Gio (environ une minute).
func TestParseMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	size := int64(64 << 20)
	if os.Getenv("DFIRFLOW_LARGE") == "1" {
		size = 1 << 30
	}
	r := repeated{data: load(t, securityEVTX), chunks: 10}
	c := &counter{}
	if err := (Parser{}).Parse(context.Background(), r, headerBlock+size, testSrc, c); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d events, max heap in use %d MiB", c.n, c.maxHeap>>20)
	if c.n < 700 || c.maxHeap > 64<<20 {
		t.Fatalf("events=%d max heap=%d MiB", c.n, c.maxHeap>>20)
	}
}
