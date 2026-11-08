package normalizer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Detection est le résultat d'une règle appliquée à des événements (FR-019).
// L'ordre des champs est l'ordre de sérialisation.
type Detection struct {
	ID          string   `json:"id"`
	Timestamp   Time     `json:"timestamp"` // Plus ancien horodatage des événements, fixé par le moteur
	RuleID      string   `json:"rule_id"`
	RuleVersion string   `json:"rule_version"`
	Severity    string   `json:"severity"`   // Voir constantes Severity*
	Confidence  float64  `json:"confidence"` // 0 à 1, toujours écrit
	MITRE       string   `json:"mitre,omitempty"`
	Events      []string `json:"events"` // uid triés, sans doublon
}

// Valeurs de Severity.
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

var (
	severities = set(SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical)
	mitreRegex = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)
)

// DetectionID calcule l'identifiant d'une détection (FR-020) ; l'ordre des
// uid fournis est indifférent et la liste de l'appelant n'est pas modifiée.
func DetectionID(ruleID, ruleVersion string, uids []string) string {
	u := append([]string(nil), uids...)
	sort.Strings(u)
	sum := sha256.Sum256([]byte(ruleID + "\x00" + ruleVersion + "\x00" + strings.Join(u, "\x00")))
	return hex.EncodeToString(sum[:16])
}

// Validate renvoie les violations de la détection, dans l'ordre des champs.
// L'id est recalculé : une liste d'événements modifiée après coup est refusée.
func (d Detection) Validate() []Violation {
	var vs []Violation
	add := func(field, rule string) { vs = append(vs, Violation{field, rule}) }
	required := func(field, s string) {
		if s == "" {
			add(field, "must not be empty")
		} else if !utf8.ValidString(s) {
			add(field, notUTF8)
		}
	}

	if !isLowerHex(d.ID, 32) {
		add("id", "must be 32 lowercase hex characters")
	} else if d.ID != DetectionID(d.RuleID, d.RuleVersion, d.Events) {
		add("id", "does not match rule_id, rule_version and events")
	}
	if d.Timestamp.IsZero() {
		add("timestamp", "must not be zero")
	}
	required("rule_id", d.RuleID)
	required("rule_version", d.RuleVersion)
	if !severities[d.Severity] {
		add("severity", fmt.Sprintf("unknown value %q", d.Severity))
	}
	if !(d.Confidence >= 0 && d.Confidence <= 1) { // écrit ainsi pour refuser aussi NaN
		add("confidence", "must be between 0 and 1")
	}
	if d.MITRE != "" && !mitreRegex.MatchString(d.MITRE) {
		add("mitre", "must be T#### or T####.###")
	}
	if len(d.Events) == 0 {
		add("events", "must list at least one uid")
	}
	for i, u := range d.Events {
		if !isLowerHex(u, 32) {
			add(fmt.Sprintf("events[%d]", i), "must be 32 lowercase hex characters")
		}
	}
	for i := 1; i < len(d.Events); i++ {
		if d.Events[i-1] >= d.Events[i] {
			add("events", "must be sorted without duplicates")
			break
		}
	}
	return vs
}
