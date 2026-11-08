package normalizer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func validDetection() Detection {
	uids := []string{strings.Repeat("1", 32), strings.Repeat("2", 32)}
	return Detection{
		ID:          DetectionID("brute-force", "1.0", uids),
		Timestamp:   at("2020-09-09T13:18:23.627952Z"),
		RuleID:      "brute-force",
		RuleVersion: "1.0",
		Severity:    SeverityHigh,
		Confidence:  0.85,
		MITRE:       "T1110.001",
		Events:      uids,
	}
}

func TestDetectionValidate(t *testing.T) {
	if vs := validDetection().Validate(); len(vs) != 0 {
		t.Fatalf("valid detection: %v", vs)
	}
	uid := func(c string) string { return strings.Repeat(c, 32) }
	// withEvents change la liste et recalcule l'id, pour ne tester que events.
	withEvents := func(evs ...string) func(*Detection) {
		return func(d *Detection) {
			d.Events = evs
			d.ID = DetectionID(d.RuleID, d.RuleVersion, evs)
		}
	}
	cases := []struct {
		name string
		mut  func(*Detection)
		want []string
	}{
		{"id wrong", func(d *Detection) { d.ID = uid("f") }, []string{"id"}},
		{"id short", func(d *Detection) { d.ID = d.ID[:31] }, []string{"id"}},
		{"timestamp zero", func(d *Detection) { d.Timestamp = Time{} }, []string{"timestamp"}},
		{"rule_id empty", func(d *Detection) { d.RuleID, d.ID = "", DetectionID("", d.RuleVersion, d.Events) }, []string{"rule_id"}},
		{"rule_version empty", func(d *Detection) { d.RuleVersion, d.ID = "", DetectionID(d.RuleID, "", d.Events) }, []string{"rule_version"}},
		{"severity unknown", func(d *Detection) { d.Severity = "urgent" }, []string{"severity"}},
		{"confidence negative", func(d *Detection) { d.Confidence = -0.1 }, []string{"confidence"}},
		{"confidence above 1", func(d *Detection) { d.Confidence = 1.5 }, []string{"confidence"}},
		{"mitre malformed", func(d *Detection) { d.MITRE = "T59" }, []string{"mitre"}},
		{"events empty", withEvents(), []string{"events"}},
		{"events unsorted", withEvents(uid("2"), uid("1")), []string{"events"}},
		{"events duplicate", withEvents(uid("1"), uid("1")), []string{"events"}},
		{"events bad uid", withEvents(uid("1"), "XYZ"), []string{"events[1]"}},
		{"confidence 0 valid", func(d *Detection) { d.Confidence = 0 }, []string{}},
		{"confidence 1 valid", func(d *Detection) { d.Confidence = 1 }, []string{}},
		{"mitre absent valid", func(d *Detection) { d.MITRE = "" }, []string{}},
		{"mitre technique valid", func(d *Detection) { d.MITRE = "T1110" }, []string{}},
	}
	for _, c := range cases {
		d := validDetection()
		c.mut(&d)
		if got := fields(d.Validate()); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: fields = %v, want %v (%v)", c.name, got, c.want, d.Validate())
		}
	}
}

func TestDetectionID(t *testing.T) {
	a, b := strings.Repeat("1", 32), strings.Repeat("2", 32)
	in := []string{b, a}
	got := DetectionID("r", "1", in)
	sum := sha256.Sum256([]byte("r\x001\x00" + a + "\x00" + b))
	if want := hex.EncodeToString(sum[:])[:32]; got != want {
		t.Errorf("DetectionID = %s, want %s", got, want)
	}
	if DetectionID("r", "1", []string{a, b}) != got {
		t.Error("DetectionID depends on uid order")
	}
	if in[0] != b {
		t.Error("DetectionID sorted the caller's slice")
	}
	if DetectionID("r", "2", in) == got {
		t.Error("DetectionID ignores rule_version")
	}
}

func TestDetectionJSONL(t *testing.T) {
	early := validDetection()
	early.Timestamp, early.Confidence, early.MITRE = at("2020-01-01T00:00:00.000000Z"), 0, ""
	ds := []Detection{validDetection(), early}
	SortDetections(ds)
	if ds[0].ID != early.ID {
		t.Fatal("SortDetections: earliest timestamp not first")
	}

	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	for _, d := range ds {
		if err := enc.Detection(d); err != nil {
			t.Fatal(err)
		}
	}
	out := buf.String()
	first := strings.SplitN(out, "\n", 2)[0]
	if !strings.Contains(first, `"confidence":0,`) || strings.Contains(first, `"mitre"`) {
		t.Errorf("confidence 0 must be written, empty mitre omitted: %s", first)
	}
	var keys []string
	dec := json.NewDecoder(strings.NewReader(strings.SplitN(out, "\n", 3)[1]))
	dec.Token()
	for dec.More() {
		k, _ := dec.Token()
		keys = append(keys, k.(string))
		var skip json.RawMessage
		dec.Decode(&skip)
	}
	want := []string{"schema_version", "id", "timestamp", "rule_id", "rule_version", "severity", "confidence", "mitre", "events"}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("field order = %v, want %v", keys, want)
	}

	var back []Detection
	if err := ReadDetections(strings.NewReader(out), func(d Detection) error { back = append(back, d); return nil }); err != nil {
		t.Fatal(err)
	}
	var again bytes.Buffer
	for _, d := range back {
		if err := NewEncoder(&again).Detection(d); err != nil {
			t.Fatal(err)
		}
	}
	if again.String() != out {
		t.Errorf("round trip differs:\n got: %s\nwant: %s", again.String(), out)
	}

	bad := validDetection()
	bad.Severity = "urgent"
	var none bytes.Buffer
	if err := NewEncoder(&none).Detection(bad); err == nil || none.Len() != 0 {
		t.Errorf("invalid detection: err %v, written %q", err, none.String())
	}

	line1 := strings.SplitN(out, "\n", 2)[0] + "\n"
	for name, line2 := range map[string]string{
		"unknown field": strings.Replace(line1, `{"schema_version":1,`, `{"schema_version":1,"note":"x",`, 1),
		"invalid":       strings.Replace(line1, `"severity":"high"`, `"severity":"urgent"`, 1),
		"version 2":     strings.Replace(line1, `"schema_version":1`, `"schema_version":2`, 1),
	} {
		err := ReadDetections(strings.NewReader(line1+line2), func(Detection) error { return nil })
		if err == nil || !strings.Contains(err.Error(), "line 2") {
			t.Errorf("%s: err = %v, want error with line 2", name, err)
		}
	}
}
