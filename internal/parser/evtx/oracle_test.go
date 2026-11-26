package evtx

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// bareGUID : evtx_dump écrit les GUID sans accolades ; la spec 003 (FR-013)
// les veut comme la vue XML Windows, entre accolades (écart documenté dans
// testdata/oracle/README.md).
var bareGUID = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

func oracleValue(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		if bareGUID.MatchString(x) {
			return "{" + strings.ToUpper(x) + "}"
		}
		return x
	case json.Number:
		return x.String()
	case bool:
		return fmt.Sprint(x)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// TestOracleEvtxDump compare chaque enregistrement avec evtx_dump v0.12.3
// (FR-020, SC-002).
func TestOracleEvtxDump(t *testing.T) {
	c, err := parse(t, load(t, securityEVTX))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[uint64]int{}
	for i, e := range c.events {
		byID[e.RecordID] = i
	}
	s := bufio.NewScanner(bytes.NewReader(load(t, "testdata/oracle/Security.evtx_dump.jsonl")))
	s.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for s.Scan() {
		dec := json.NewDecoder(bytes.NewReader(s.Bytes()))
		dec.UseNumber()
		var line struct {
			Event struct {
				System struct {
					Provider struct {
						Attributes map[string]string `json:"#attributes"`
					}
					EventID       json.Number
					EventRecordID uint64
					Channel       string
					TimeCreated   struct {
						Attributes map[string]string `json:"#attributes"`
					}
				}
				EventData map[string]interface{}
				UserData  map[string]map[string]interface{}
			}
		}
		if err := dec.Decode(&line); err != nil {
			t.Fatal(err)
		}
		n++
		o := line.Event
		i, ok := byID[o.System.EventRecordID]
		if !ok {
			t.Errorf("record %d: missing", o.System.EventRecordID)
			continue
		}
		e := c.events[i]
		diff := func(field, got, want string) {
			if got != want {
				t.Errorf("record %d %s = %q, evtx_dump %q", e.RecordID, field, got, want)
			}
		}
		diff("timestamp", formatTime(e.Timestamp.Time), o.System.TimeCreated.Attributes["SystemTime"])
		diff("event_id", fmt.Sprint(*e.EventID), o.System.EventID.String())
		diff("channel", e.Channel, o.System.Channel)
		diff("provider", e.Provider, o.System.Provider.Attributes["Name"])
		fields := o.EventData
		for _, root := range o.UserData {
			fields = root
		}
		for k, v := range fields {
			if k == "#attributes" {
				continue
			}
			got, ok := e.Metadata[k]
			if !ok {
				t.Errorf("record %d: field %s missing", e.RecordID, k)
				continue
			}
			diff(k, got, oracleValue(v))
		}
	}
	if n != 739 || len(c.events) != 739 {
		t.Fatalf("oracle lines=%d events=%d", n, len(c.events))
	}
}
