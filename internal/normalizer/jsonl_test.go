package normalizer

import (
	"bytes"
	"errors"
	"flag"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata reference files")

const goldenEvents = "testdata/events.v1.jsonl"

func at(s string) Time {
	t, err := time.Parse(timeLayout, s)
	if err != nil {
		panic(err)
	}
	return Time{t}
}

// referenceEvents couvre chaque forme de champ du contrat (T009).
func referenceEvents() []Event {
	const shaA = "1111111111111111111111111111111111111111111111111111111111111111"
	const shaB = "2222222222222222222222222222222222222222222222222222222222222222"
	evtx := func(id uint32, rec uint64, ts string, typ string) Event {
		loc := "record=" + strconv.FormatUint(rec, 10)
		return Event{
			UID: UID(shaA, "Logs/Security.evtx", loc), Timestamp: at(ts), TimestampType: TSLogged,
			Source: SourceEVTX, EventType: typ, Host: "WIN-77LTAPHIQ1R",
			Channel: "Security", Provider: "Microsoft-Windows-Security-Auditing", EventID: u32(id),
			SourceFile: "Logs/Security.evtx", SourceHash: shaA, RecordID: rec, RecordLocator: loc,
			Ingest: IngestNative,
		}
	}

	logon := evtx(4624, 1234, "2020-09-09T13:18:23.627952Z", TypeLogon)
	logon.HostFQDN = "WIN-77LTAPHIQ1R.example.corp"
	logon.Subject = &Account{Domain: "EXAMPLE", Name: "WIN-77LTAPHIQ1R$", SID: "S-1-5-18"}
	logon.Target = &Account{Domain: "EXAMPLE", Name: "alice", SID: "S-1-5-21-1-2-3-1104"}
	logon.Metadata = map[string]string{"LogonType": "3", "Status": "0x0", "System.EventRecordID": "1234"}

	sysmon := evtx(1, 88, "2020-09-09T13:20:00.000001Z", TypeProcessCreation)
	sysmon.Channel, sysmon.Provider = "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon"
	sysmon.Timestamps = []TimestampEntry{
		{Type: TSWritten, Time: at("2020-09-09T13:20:00.120000Z"), Origin: "Header"},
		{Type: TSLogged, Time: at("2020-09-09T13:20:00.100000Z"), Origin: "TimeCreated"},
	}
	sysmon.Process, sysmon.ProcessID = `C:\Windows\System32\cmd.exe`, 4242
	sysmon.ParentProcess, sysmon.ParentProcessID = `C:\Windows\explorer.exe`, 1000
	sysmon.CommandLine = `cmd.exe /c whoami`
	sysmon.Hashes = map[string]string{"sha256": strings.Repeat("c", 64), "md5": strings.Repeat("d", 32), "imphash": strings.Repeat("e", 32)}

	script := evtx(4104, 90, "2020-09-09T13:21:00.500000Z", TypeScriptExecution)
	script.Channel, script.Provider = "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell"
	script.CommandLine = `if ($a -lt 1 -and $b -gt 2) { "<b>" & 'x' }`

	mft := Event{
		UID: UID(shaB, "C/$MFT", "entry=0"), Timestamp: at("2019-01-01T00:00:00.000000Z"), TimestampType: TSCreated,
		Source: SourceMFT, EventType: TypeOther, Host: "WIN-77LTAPHIQ1R", FilePath: `C:\$MFT`,
		SourceFile: "C/$MFT", SourceHash: shaB, RecordID: 0, RecordLocator: "entry=0", Ingest: IngestNative,
		Timestamps: []TimestampEntry{{Type: TSChanged, Time: at("2019-01-01T00:00:00.000000Z"), Origin: "$FN"}},
	}

	other := evtx(9999, 91, "2020-09-09T13:21:00.500000Z", TypeOther)

	recovered := evtx(4688, 92, "2020-09-09T12:00:00.000000Z", TypeProcessCreation)
	recovered.Recovered = true

	zero := evtx(0, 0, "2020-09-09T11:00:00.000000Z", TypeOther)
	zero.Ingest = "import:hayabusa@2.16.0"

	return []Event{logon, sysmon, script, mft, other, recovered, zero}
}

func encodeAll(t *testing.T, evs []Event) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	for _, e := range evs {
		if err := enc.Event(e); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func TestGolden(t *testing.T) {
	evs := referenceEvents()
	SortEvents(evs)
	got := encodeAll(t, evs)
	if *update {
		if err := os.MkdirAll(filepath.Dir(goldenEvents), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenEvents, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenEvents)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("encoding differs from %s:\n got: %s\nwant: %s", goldenEvents, got, want)
	}
}

func TestRoundTrip(t *testing.T) {
	want, err := os.ReadFile(goldenEvents)
	if err != nil {
		t.Fatal(err)
	}
	var evs []Event
	if err := ReadEvents(bytes.NewReader(want), func(e Event) error { evs = append(evs, e); return nil }); err != nil {
		t.Fatal(err)
	}
	if got := encodeAll(t, evs); !bytes.Equal(got, want) {
		t.Errorf("round trip differs:\n got: %s\nwant: %s", got, want)
	}
}

func TestEncodeNoHTMLEscape(t *testing.T) {
	out := encodeAll(t, referenceEvents()[2:3])
	if !bytes.Contains(out, []byte(`\"<b>\" & 'x'`)) {
		t.Errorf("HTML characters escaped: %s", out)
	}
}

func TestEncodeRejectsInvalid(t *testing.T) {
	e := referenceEvents()[0]
	e.Host = ""
	var buf bytes.Buffer
	if err := NewEncoder(&buf).Event(e); err == nil || !strings.Contains(err.Error(), "host") {
		t.Errorf("Event(invalid) = %v, want error naming host", err)
	}
	if buf.Len() != 0 {
		t.Errorf("invalid event written: %s", buf.Bytes())
	}
}

func TestSortEvents(t *testing.T) {
	base := referenceEvents()[0]
	mk := func(ts, file string, rec uint64, uid string) Event {
		e := base
		e.Timestamp, e.SourceFile, e.RecordID, e.UID = at(ts), file, rec, uid
		return e
	}
	uidA, uidB := strings.Repeat("a", 32), strings.Repeat("b", 32)
	want := []Event{
		mk("2020-01-01T00:00:00.000000Z", "b", 9, uidB),
		mk("2020-01-01T00:00:00.000001Z", "a", 1, uidA),
		mk("2020-01-01T00:00:00.000001Z", "b", 1, uidA),
		mk("2020-01-01T00:00:00.000001Z", "b", 2, uidA),
		mk("2020-01-01T00:00:00.000001Z", "b", 2, uidB),
	}
	// Une nanoseconde de plus ne change pas l'ordre : elle disparaît à l'écriture.
	want[1].Timestamp = Time{want[1].Timestamp.Add(999)}
	for seed := int64(1); seed <= 2; seed++ {
		got := append([]Event(nil), want...)
		rand.New(rand.NewSource(seed)).Shuffle(len(got), func(i, j int) { got[i], got[j] = got[j], got[i] })
		SortEvents(got)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("seed %d: unexpected order", seed)
		}
	}
}

func TestReadEventsErrors(t *testing.T) {
	golden, err := os.ReadFile(goldenEvents)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(golden, []byte("\n"))
	head := append(append([]byte{}, lines[0]...), lines[1]...)
	valid := strings.TrimSuffix(string(lines[2]), "\n")
	invalid := strings.Replace(valid, `"host":"WIN-77LTAPHIQ1R"`, `"host":"win"`, 1)

	for name, line3 := range map[string]string{
		"bad json":      "{\"schema_version\":1,\n",
		"unknown field": strings.Replace(valid, `{"schema_version":1,`, `{"schema_version":1,"severity":"high",`, 1) + "\n",
		"version 2":     strings.Replace(valid, `"schema_version":1`, `"schema_version":2`, 1) + "\n",
		"crlf":          valid + "\r\n",
		"not utf8":      strings.Replace(valid, `"ingest":"native"`, "\"ingest\":\"nat\xffive\"", 1) + "\n",
		"trailing data": valid + " {}\n",
		"invalid event": invalid + "\n",
		"empty line":    "\n",
		"no newline":    valid,
		"null":          "null\n",
		"no version":    strings.Replace(valid, `"schema_version":1,`, ``, 1) + "\n",
	} {
		calls := 0
		err := ReadEvents(bytes.NewReader(append(append([]byte{}, head...), line3...)), func(Event) error { calls++; return nil })
		if err == nil || !strings.Contains(err.Error(), "line 3") {
			t.Errorf("%s: err = %v, want error with line 3", name, err)
		}
		if calls != 2 {
			t.Errorf("%s: %d events delivered, want 2", name, calls)
		}
	}

	calls := 0
	if err := ReadEvents(bytes.NewReader(nil), func(Event) error { calls++; return nil }); err != nil || calls != 0 {
		t.Errorf("empty file: %d events, err %v", calls, err)
	}

	stop := errors.New("stop")
	if err := ReadEvents(bytes.NewReader(golden), func(Event) error { return stop }); err != stop {
		t.Errorf("callback error = %v, want it returned as is", err)
	}
}

func TestReadEventsGarbage(t *testing.T) {
	golden, err := os.ReadFile(goldenEvents)
	if err != nil {
		t.Fatal(err)
	}
	var inputs [][]byte
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		b := make([]byte, rng.Intn(400))
		rng.Read(b)
		inputs = append(inputs, b)
	}
	first := golden[:bytes.IndexByte(golden, '\n')]
	for n := 0; n < len(first); n++ {
		inputs = append(inputs, append(append([]byte{}, first[:n]...), '\n'))
	}
	for _, in := range inputs {
		err := ReadEvents(bytes.NewReader(in), func(Event) error { return nil })
		if err != nil && !strings.Contains(err.Error(), "line ") {
			t.Fatalf("error without line number: %v", err)
		}
	}
}

// TestUnsupportedVersion (US5) : la consigne dépend du sens de l'écart de version.
func TestUnsupportedVersion(t *testing.T) {
	readers := map[string]func(string) error{
		"events": func(s string) error { return ReadEvents(strings.NewReader(s), func(Event) error { return nil }) },
		"detections": func(s string) error {
			return ReadDetections(strings.NewReader(s), func(Detection) error { return nil })
		},
	}
	for name, read := range readers {
		for v, hint := range map[int]string{2: "upgrade dfirflow", 0: "re-ingest the case", -1: "re-ingest the case"} {
			err := read(`{"schema_version":` + strconv.Itoa(v) + "}\n")
			want := []string{"line 1", "schema_version " + strconv.Itoa(v), hint}
			for _, w := range want {
				if err == nil || !strings.Contains(err.Error(), w) {
					t.Errorf("%s v%d: err = %v, want it to contain %q", name, v, err, w)
				}
			}
		}
	}
}
