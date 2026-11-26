package binxml

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const securityEVTX = "../testdata/Security.evtx"

func load(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// readAll décode tout le fichier ; il échoue sur une erreur d'E/S.
func readAll(t testing.TB, data []byte) (recs []*EventRecord, lost []Lost) {
	t.Helper()
	f, err := OpenFile(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < f.NumChunks; i++ {
		es, err := f.ReadChunk(i)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			if e.Record != nil {
				recs = append(recs, e.Record)
			} else {
				lost = append(lost, *e.Lost)
			}
		}
	}
	return recs, lost
}

func system(t testing.TB, rec *EventRecord) *Dict {
	t.Helper()
	ev, ok := rec.Event.(*Dict)
	if !ok {
		t.Fatalf("record %d: event is %T", rec.Header.RecordID, rec.Event)
	}
	e, _ := ev.Get("Event")
	sys, _ := e.(*Dict).Get("System")
	d, ok := sys.(*Dict)
	if !ok {
		t.Fatalf("record %d: no System", rec.Header.RecordID)
	}
	return d
}

func TestDecodeBaseline(t *testing.T) {
	recs, lost := readAll(t, load(t, securityEVTX))
	if len(recs) != 739 || len(lost) != 0 {
		t.Fatalf("records=%d lost=%v, want 739 and none", len(recs), lost)
	}
	prev := uint64(0)
	for _, r := range recs {
		if r.Header.RecordID <= prev {
			t.Fatalf("record numbers not increasing: %d after %d", r.Header.RecordID, prev)
		}
		prev = r.Header.RecordID
		sys := system(t, r)
		for _, k := range []string{"EventID", "Channel"} {
			if _, ok := sys.Get(k); !ok {
				t.Fatalf("record %d: no System/%s", r.Header.RecordID, k)
			}
		}
	}
}

// TestNoExternalDependency : non-régression C12 / E1 (dépendance MPL-2.0).
func TestNoExternalDependency(t *testing.T) {
	mod := string(load(t, "../../../../go.mod"))
	if strings.Contains(mod, "require") {
		t.Fatalf("go.mod declares dependencies:\n%s", mod)
	}
	lru := "golang" + "-lru"
	err := filepath.Walk("../../../..", func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && (info.Name() == ".git" || info.Name() == "spikes") {
			return filepath.SkipDir
		}
		if strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			if strings.Contains(string(load(t, p)), lru) {
				t.Errorf("%s imports %s", p, lru)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// decodeAll décode data sans jamais échouer sur le contenu ; il renvoie le
// nombre d'entrées et l'erreur d'ouverture.
func decodeAll(data []byte) (int, error) {
	f, err := OpenFile(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return 0, err
	}
	n := 0
	for i := 0; i < f.NumChunks; i++ {
		es, err := f.ReadChunk(i)
		if err != nil {
			return n, err
		}
		n += len(es)
	}
	return n, nil
}

func allocated(fn func()) uint64 {
	var a, b runtime.MemStats
	runtime.ReadMemStats(&a)
	fn()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// TestMalformed : E5, aucune panique ni allocation de la taille lue.
func TestMalformed(t *testing.T) {
	sec := load(t, securityEVTX)
	twoChunks := func() []byte { return append([]byte(nil), sec[:4096+2*EVTX_CHUNK_SIZE]...) }

	// Taille d'enregistrement démesurée sur le premier enregistrement.
	data := twoChunks()
	binary.LittleEndian.PutUint32(data[4096+512+4:], 0xFFFFFFFF)
	f, _ := OpenFile(bytes.NewReader(data), int64(len(data)))
	var es []Entry
	if n := allocated(func() { es, _ = f.ReadChunk(0) }); n > 1<<20 {
		t.Errorf("record size: %d bytes allocated", n)
	}
	if len(es) != 78 || es[0].Lost == nil || es[0].Lost.Kind != LostUnreadable || es[1].Lost.Kind != LostMissing {
		t.Fatalf("record size: %d entries, first %+v", len(es), es[0])
	}

	// Nombre de chunks de l'en-tête démesuré : ignoré, déduit de la taille.
	data = twoChunks()
	binary.LittleEndian.PutUint16(data[42:], 0xFFFF)
	if f, err := OpenFile(bytes.NewReader(data), int64(len(data))); err != nil || f.NumChunks != 2 {
		t.Fatalf("chunk count: %v, %+v", err, f)
	}

	// Longueur de chaîne démesurée : lecture hors limites, sans allocation.
	ctx := NewParseContext(&Chunk{})
	ctx.buff = []byte{0xFF, 0xFF, 'a', 0}
	var s string
	if n := allocated(func() { s = ReadPrefixedUnicodeString(ctx, false) }); n > 1<<10 || s != "" || !*ctx.bad {
		t.Fatalf("string length: alloc=%d s=%q bad=%v", n, s, *ctx.bad)
	}

	// Signature de fichier invalide, plage d'enregistrements démesurée.
	data = twoChunks()
	data[0] = 'X'
	if _, err := decodeAll(data); err == nil {
		t.Fatal("wrong file magic accepted")
	}
	data = twoChunks()
	binary.LittleEndian.PutUint64(data[4096+32:], 0xFFFFFFFFFFFFFFF0)
	if es, _ := (&File{r: bytes.NewReader(data), Header: EVTXHeader{HeaderBlockSize: 4096}}).ReadChunk(0); len(es) != 1 || es[0].Lost.Number != 0 {
		t.Fatalf("record range: %+v", es)
	}
}

// TestRenderTypes : E3 (HexInt) et E4 (MessageNumber, Int32) gardent leur type.
func TestDecodeValue(t *testing.T) {
	le := func(n int, v uint64) []byte {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, v)
		return b[:n]
	}
	sid := []byte{1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0}
	cases := []struct {
		typ  uint16
		raw  []byte
		want interface{}
	}{
		{0x14, le(4, 0xC000006D), HexInt32(0xC000006D)},
		{0x15, le(8, 0x3E7), HexInt64(0x3E7)},
		{0x07, le(4, 1), int32(1)},
		{0x07, le(4, 0xFFFFFFFF), int32(-1)},
		{0x0D, le(4, 1), true},
		{0x13, sid, SID("S-1-5-32-544")},
		{0x11, le(8, 131939362733172597), FileTime(131939362733172597)},
		{0x08, le(2, 1), Binary(le(2, 1))}, // taille incohérente : brut
	}
	for _, c := range cases {
		if got := DecodeValue(c.typ, c.raw); !equal(got, c.want) {
			t.Errorf("DecodeValue(0x%x, %x) = %#v, want %#v", c.typ, c.raw, got, c.want)
		}
	}
	if got := FileTime(131939362733172597).Time().Format("2006-01-02T15:04:05.0000000Z"); got != "2019-02-06T14:17:53.3172597Z" {
		t.Errorf("FileTime = %s", got)
	}
}

func equal(a, b interface{}) bool {
	if x, ok := a.(Binary); ok {
		y, ok := b.(Binary)
		return ok && bytes.Equal(x, y)
	}
	return a == b
}

// FuzzChunk : aucune panique, et chaque enregistrement annoncé par un chunk
// lisible est rendu, lu ou perdu (R12).
func FuzzChunk(f *testing.F) {
	sec := load(f, securityEVTX)
	for i := 0; i < 3; i++ {
		f.Add(append(append([]byte(nil), sec[:4096]...), sec[4096+i*EVTX_CHUNK_SIZE:4096+(i+1)*EVTX_CHUNK_SIZE]...))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := OpenFile(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		for i := 0; i < file.NumChunks; i++ {
			es, err := file.ReadChunk(i)
			if err != nil {
				t.Fatal(err)
			}
			if len(es) == 0 || (es[0].Lost != nil && es[0].Lost.Number == 0) {
				continue
			}
			h := ChunkHeader{}
			off := int(file.Header.HeaderBlockSize) + i*EVTX_CHUNK_SIZE
			binary.Read(bytes.NewReader(data[off:]), binary.LittleEndian, &h)
			if want := h.LastEventRecID - h.FirstEventRecID + 1; uint64(len(es)) != want {
				t.Fatalf("chunk %d: %d entries, %d announced", i, len(es), want)
			}
		}
	})
}
