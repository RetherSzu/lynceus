package timeline

import (
	"encoding/json"
	"fmt"
	"time"

	"DFIRFlow/internal/extsort"
	"DFIRFlow/internal/normalizer"
)

// keyOf renvoie la clé de l'ordre canonique (spec 003, FR-018a) : horodatage
// tronqué à la µs comme il est écrit, source_file, record_id, uid.
func keyOf(ev normalizer.Event) extsort.Key {
	return extsort.Key{TS: ev.Timestamp.Truncate(time.Microsecond).UnixMicro(), S: ev.SourceFile, N: ev.RecordID, T: ev.UID}
}

// decodeKey relit la clé d'une ligne canonique sans décoder le reste.
func decodeKey(line []byte) (extsort.Key, error) {
	var k struct {
		Timestamp  normalizer.Time `json:"timestamp"`
		SourceFile string          `json:"source_file"`
		RecordID   uint64          `json:"record_id"`
		UID        string          `json:"uid"`
	}
	if err := json.Unmarshal(line, &k); err != nil {
		return extsort.Key{}, fmt.Errorf("work segment: %w", err)
	}
	return extsort.Key{TS: k.Timestamp.Truncate(time.Microsecond).UnixMicro(), S: k.SourceFile, N: k.RecordID, T: k.UID}, nil
}
