package normalizer

import (
	"encoding/json"
	"time"
)

// timeLayout fixe 6 décimales et un « Z » littéral : l'ordre lexical des
// chaînes est l'ordre chronologique, et le décodage refuse tout autre format.
const timeLayout = "2006-01-02T15:04:05.000000Z"

// Time est un horodatage UTC sérialisé à la microseconde (troncature).
type Time struct{ time.Time }

func (t Time) MarshalJSON() ([]byte, error) {
	return []byte(`"` + t.UTC().Truncate(time.Microsecond).Format(timeLayout) + `"`), nil
}

func (t *Time) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	v, err := time.Parse(timeLayout, s)
	if err != nil {
		return err
	}
	t.Time = v
	return nil
}
