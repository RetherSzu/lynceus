package normalizer

import (
	"encoding/json"
	"math/rand"
	"sort"
	"testing"
	"time"
)

func TestTime(t *testing.T) {
	ref := time.Date(2020, 9, 9, 13, 18, 23, 627952000, time.UTC)

	cet, err := time.LoadLocation("CET")
	if err != nil {
		t.Fatal(err)
	}
	encode := []struct {
		name string
		in   time.Time
		want string
	}{
		{"utc", ref, `"2020-09-09T13:18:23.627952Z"`},
		{"cet converted to utc", time.Date(2020, 9, 9, 15, 18, 23, 627952000, cet), `"2020-09-09T13:18:23.627952Z"`},
		{"truncated not rounded", time.Date(2020, 1, 1, 0, 0, 0, 1999, time.UTC), `"2020-01-01T00:00:00.000001Z"`},
	}
	for _, c := range encode {
		got, err := json.Marshal(Time{c.in})
		if err != nil || string(got) != c.want {
			t.Errorf("%s: Marshal = %s, %v; want %s", c.name, got, err, c.want)
		}
	}

	for _, bad := range []string{
		`"2020-09-09T13:18:23.62795Z"`,
		`"2020-09-09T13:18:23.6279521Z"`,
		`"2020-09-09T13:18:23Z"`,
		`"2020-09-09T13:18:23.627952+01:00"`,
		`null`,
		`123`,
	} {
		var v Time
		if err := json.Unmarshal([]byte(bad), &v); err == nil {
			t.Errorf("Unmarshal(%s) accepted, want error", bad)
		}
	}

	in := `"2020-09-09T13:18:23.627952Z"`
	var v Time
	if err := json.Unmarshal([]byte(in), &v); err != nil {
		t.Fatal(err)
	}
	if !v.Equal(ref) {
		t.Errorf("Unmarshal = %v, want %v", v.Time, ref)
	}
	if out, _ := json.Marshal(v); string(out) != in {
		t.Errorf("round trip = %s, want %s", out, in)
	}

	// SC-006 : l'ordre des chaînes encodées est l'ordre chronologique.
	rng := rand.New(rand.NewSource(1))
	// Bornes en secondes : UnixNano déborde au-delà de 2262.
	loS := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	hiS := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC).Unix()
	times := make([]time.Time, 1000)
	strs := make([]string, len(times))
	for i := range times {
		times[i] = time.Unix(loS+rng.Int63n(hiS-loS+1), rng.Int63n(1e6)*1000).UTC()
		b, err := json.Marshal(Time{times[i]})
		if err != nil {
			t.Fatal(err)
		}
		strs[i] = string(b)
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	sort.Strings(strs)
	for i := range times {
		b, _ := json.Marshal(Time{times[i]})
		if string(b) != strs[i] {
			t.Fatalf("sort mismatch at %d: %s vs %s", i, b, strs[i])
		}
	}
}
