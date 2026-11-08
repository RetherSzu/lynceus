package parser

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"DFIRFlow/internal/normalizer"
)

var testSrc = Source{
	File:   "Logs/fake.txt",
	SHA256: strings.Repeat("ab", 32),
	Host:   "win-01.example.corp",
}

const (
	healthy = fakeMagic +
		"1|2020-01-01T00:00:01Z|process_creation|a\n" +
		"2|2020-01-01T00:00:02Z|other|b\n" +
		"3|2020-01-01T00:00:03Z|other|c\n"
	// 8 enregistrements : 1, ! (2), 3, 4 et 5 manquants, 6 sans horodatage, 7, 8 tronqué.
	degraded = fakeMagic +
		"1|2020-01-01T00:00:01Z|process_creation|a\n" +
		"!\n" +
		"3|2020-01-01T00:00:03Z|other|b\n" +
		"6||other|c\n" +
		"7|2020-01-01T00:00:07Z|other|d\n" +
		"8|2020-01-01T00:00:08Z|other|e"
	degradedRecords = 8
)

// recorder garde, dans l'ordre de réception, tout ce que le parseur émet.
type recorder struct {
	events    []normalizer.Event
	anomalies []Anomaly
	order     []string // "event" ou le kind de l'anomalie
	onEvent   func() error
}

func (r *recorder) Event(e normalizer.Event) error {
	r.events = append(r.events, e)
	r.order = append(r.order, "event")
	if r.onEvent != nil {
		return r.onEvent()
	}
	return nil
}

func (r *recorder) Anomaly(a Anomaly) error {
	r.anomalies = append(r.anomalies, a)
	r.order = append(r.order, a.Kind)
	return nil
}

func run(ctx context.Context, input string, out Sink) error {
	return fakeParser{}.Parse(ctx, bytes.NewReader([]byte(input)), int64(len(input)), testSrc, out)
}

func TestHealthyInput(t *testing.T) {
	rec := &recorder{}
	if err := run(context.Background(), healthy, Validating(rec)); err != nil {
		t.Fatal(err)
	}
	if len(rec.anomalies) != 0 {
		t.Errorf("anomalies: %v", rec.anomalies)
	}
	for i, e := range rec.events {
		if e.RecordID != uint64(i+1) {
			t.Errorf("event %d has record_id %d: not in file order", i, e.RecordID)
		}
		if vs := e.Validate(); len(vs) != 0 {
			t.Errorf("event %d invalid: %v", i, vs)
		}
		if e.Host != "WIN-01" || e.HostFQDN != testSrc.Host {
			t.Errorf("event %d host = %q, %q", i, e.Host, e.HostFQDN)
		}
	}
	if len(rec.events) != 3 {
		t.Errorf("%d events, want 3", len(rec.events))
	}
}

func TestDegradedInput(t *testing.T) {
	rec := &recorder{}
	if err := run(context.Background(), degraded, Validating(rec)); err != nil {
		t.Fatal(err)
	}
	want := []string{"event", KindUnreadable, "event", KindMissing, KindMissing, KindInvalid, "event", KindTruncated}
	if !reflect.DeepEqual(rec.order, want) {
		t.Fatalf("order = %v, want %v", rec.order, want)
	}
	// SC-005 : aucun enregistrement perdu en silence.
	if n := len(rec.events) + len(rec.anomalies); n != degradedRecords {
		t.Errorf("events + anomalies = %d, want %d", n, degradedRecords)
	}
	var invalid Anomaly
	for _, a := range rec.anomalies {
		if a.Kind == KindInvalid {
			invalid = a
		}
	}
	uid := normalizer.UID(testSrc.SHA256, testSrc.File, "line=5")
	if invalid.Locator != "line=5" || !strings.HasPrefix(invalid.Message, "uid="+uid+": ") || !strings.Contains(invalid.Message, "timestamp:") {
		t.Errorf("invalid anomaly = %+v", invalid)
	}
	if m := rec.anomalies[1]; m.Locator != "record=4" || rec.anomalies[2].Locator != "record=5" {
		t.Errorf("missing anomalies = %+v, %+v", m, rec.anomalies[2])
	}
}

func TestUnknownFormat(t *testing.T) {
	in := "MZ\x90\x00 not a fake file\n"
	if (fakeParser{}).Match([]byte(in)) {
		t.Error("Match accepted an unknown format")
	}
	rec := &recorder{}
	if err := run(context.Background(), in, rec); err == nil {
		t.Error("forced Parse on unknown format returned nil")
	}
	if len(rec.order) != 0 {
		t.Errorf("emitted %v before the fatal error", rec.order)
	}
	if !(fakeParser{}).Match([]byte(healthy)) {
		t.Error("Match rejected its own format")
	}
}

func TestCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &recorder{onEvent: func() error { cancel(); return nil }}
	if err := run(ctx, healthy, Validating(rec)); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(rec.events) != 1 || len(rec.events[0].Validate()) != 0 {
		t.Errorf("events before cancel = %v", rec.events)
	}
}

func TestSinkError(t *testing.T) {
	stop := errors.New("disk full")
	rec := &recorder{onEvent: func() error { return stop }}
	if err := run(context.Background(), healthy, Validating(rec)); err != stop {
		t.Fatalf("err = %v, want the sink error", err)
	}
	if len(rec.order) != 1 {
		t.Errorf("parser continued after sink error: %v", rec.order)
	}
}

func TestDeterministic(t *testing.T) {
	a, b := &recorder{}, &recorder{}
	if err := run(context.Background(), degraded, Validating(a)); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), degraded, Validating(b)); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Error("two runs on the same input differ")
	}
}
