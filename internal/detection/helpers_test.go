package detection

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"DFIRFlow/internal/normalizer"
)

var (
	zeroHash = strings.Repeat("0", 64)
	base     = time.Date(2019, 2, 6, 14, 17, 53, 0, time.UTC)
)

// evtx construit un événement EVTX valide ; i fixe uid et record_id.
func evtx(channel, provider string, id uint32, md map[string]string, i int) normalizer.Event {
	return normalizer.Event{
		UID:           normalizer.UID(zeroHash, "Logs/x.evtx", fmt.Sprint(i)),
		Timestamp:     normalizer.Time{Time: base.Add(time.Duration(i) * time.Second)},
		TimestampType: normalizer.TSLogged,
		Source:        normalizer.SourceEVTX,
		EventType:     normalizer.TypeOther,
		Host:          "HOST",
		Channel:       channel,
		Provider:      provider,
		EventID:       &id,
		SourceFile:    "Logs/x.evtx",
		SourceHash:    zeroHash,
		RecordID:      uint64(i),
		RecordLocator: fmt.Sprint(i),
		Ingest:        normalizer.IngestNative,
		Metadata:      md,
	}
}

// rule renvoie une règle Windows Security valide dont detection vaut det
// (lignes indentées de deux espaces) ; extra est ajouté en tête.
func rule(extra, det string) string {
	return extra + "title: T\nid: r1\nlevel: high\nlogsource:\n  product: windows\n  service: security\ndetection:\n" + det
}

// mustRule charge src et échoue si la règle n'est pas appliquée.
func mustRule(t *testing.T, src string) *Rule {
	t.Helper()
	r, skipped, err := parseRule("r.yml", []byte(src))
	if err != nil || skipped {
		t.Fatalf("rule refused (%v) or skipped (%v):\n%s", err, skipped, src)
	}
	return r
}

// catRule renvoie rule(det) dont la source est logsource (lignes indentées de
// deux espaces, par exemple "  category: process_creation\n").
func catRule(logsource, det string) string {
	return strings.Replace(rule("", det), "  service: security\n", logsource, 1)
}

const (
	sysmonCh = "Microsoft-Windows-Sysmon/Operational"
	psCh     = "Microsoft-Windows-PowerShell/Operational"
)
