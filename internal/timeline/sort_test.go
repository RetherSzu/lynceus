package timeline

import (
	"bytes"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"
	"time"

	"DFIRFlow/internal/extsort"
	"DFIRFlow/internal/normalizer"
)

var zeroHash = strings.Repeat("0", 64)

var base = time.Date(2019, 2, 6, 14, 17, 53, 0, time.UTC)

// event construit un événement valide ; i fixe uid et record_id.
func event(src, file string, rid uint64, t time.Time, i int) normalizer.Event {
	id := uint32(4624)
	ev := normalizer.Event{
		UID:           normalizer.UID(zeroHash, file, fmt.Sprint(i)),
		Timestamp:     normalizer.Time{Time: t},
		TimestampType: normalizer.TSLogged,
		Source:        src,
		EventType:     normalizer.TypeOther,
		Host:          "HOST",
		SourceFile:    file,
		SourceHash:    zeroHash,
		RecordID:      rid,
		RecordLocator: fmt.Sprint(i),
		Ingest:        "native",
		Metadata:      map[string]string{"n": fmt.Sprint(i)},
	}
	if src == normalizer.SourceEVTX {
		ev.Channel, ev.Provider, ev.EventID = "Security", "P", &id
	}
	return ev
}

// shuffled renvoie n événements aux clés souvent égales, dans le désordre.
func shuffled(n int) []normalizer.Event {
	r := rand.New(rand.NewSource(1))
	evs := make([]normalizer.Event, n)
	for i := range evs {
		// Écarts sous la µs : même clé d'horodatage après troncature.
		t := base.Add(time.Duration(r.Intn(50))*time.Microsecond + time.Duration(r.Intn(1000)))
		evs[i] = event(normalizer.SourceEVTX, fmt.Sprintf("f%d.evtx", r.Intn(3)), uint64(r.Intn(5)), t, i)
	}
	return evs
}

func canonical(t *testing.T, evs []normalizer.Event) []byte {
	t.Helper()
	var b bytes.Buffer
	enc := normalizer.NewEncoder(&b)
	for _, ev := range evs {
		if err := enc.Event(ev); err != nil {
			t.Fatal(err)
		}
	}
	return b.Bytes()
}

func TestKeyOrder(t *testing.T) {
	evs := shuffled(2000)
	want := append([]normalizer.Event(nil), evs...)
	normalizer.SortEvents(want)
	got := append([]normalizer.Event(nil), evs...)
	sort.Slice(got, func(i, j int) bool { return extsort.Less(keyOf(got[i]), keyOf(got[j])) })
	for i := range want {
		if got[i].UID != want[i].UID {
			t.Fatalf("position %d: uid %s, want %s", i, got[i].UID, want[i].UID)
		}
	}
	// Avant 1970 la troncature reste un plancher.
	a, b := keyOf(event("mft", "x", 0, time.Date(1601, 1, 1, 0, 0, 0, 1500, time.UTC), 1)), keyOf(event("mft", "x", 0, time.Date(1601, 1, 1, 0, 0, 0, 1000, time.UTC), 2))
	if a.TS != b.TS {
		t.Errorf("pre-1970 truncation: %d != %d", a.TS, b.TS)
	}
}
