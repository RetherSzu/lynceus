package evtx

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"DFIRFlow/internal/normalizer"
	"DFIRFlow/internal/parser/evtx/binxml"
)

// render rend une valeur décodée comme la vue XML Windows (spec 003, FR-013).
func render(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case int8, int16, int32, int64, uint8, uint16, uint32, uint64:
		return fmt.Sprint(x)
	case float32:
		return strconv.FormatFloat(float64(x), 'g', -1, 32)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case binxml.HexInt32:
		return normalizer.FormatHex(uint64(x))
	case binxml.HexInt64:
		return normalizer.FormatHex(uint64(x))
	case binxml.GUID:
		g := binxml.EvtxGUID(x)
		return "{" + g.ToString() + "}"
	case binxml.SID:
		return string(x)
	case binxml.FileTime:
		return formatTime(x.Time())
	case binxml.SystemTime:
		return formatTime(time.Time(x))
	case binxml.Binary:
		return hex.EncodeToString(x)
	case []string:
		return strings.Join(x, ",")
	}
	return fmt.Sprint(v)
}

// formatTime reprend le format d'horodatage du JSONL canonique (FR-017).
func formatTime(t time.Time) string {
	b, _ := normalizer.Time{Time: t}.MarshalJSON()
	return strings.Trim(string(b), `"`)
}

// timeOf extrait un instant d'une valeur décodée ou d'une chaîne Sysmon
// (« 2019-03-20 16:05:13.245 », UTC).
func timeOf(v interface{}) (time.Time, bool) {
	switch x := v.(type) {
	case binxml.FileTime:
		t := x.Time()
		return t, !t.IsZero()
	case binxml.SystemTime:
		return time.Time(x), true
	case string:
		for _, layout := range []string{"2006-01-02 15:04:05.999999999", time.RFC3339Nano} {
			if t, err := time.Parse(layout, x); err == nil {
				return t.UTC(), true
			}
		}
	}
	return time.Time{}, false
}
