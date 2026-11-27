// Package detection applique des règles Sigma mono-événement aux événements
// normalisés d'un cas (specs/012-detection).
package detection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"DFIRFlow/internal/normalizer"
)

const maxRuleSize = 1 << 20

// Rule est une règle chargée et compilée (data-model.md).
type Rule struct {
	File       string // chemin tel que reçu, ou embedded:<nom>
	ID         string
	Title      string
	Version    string // 16 hexa du SHA-256 du fichier, fins de ligne en \n
	Severity   string
	Confidence float64
	MITRE      string
	Channel    string
	cond       node
	sources    []*Source       // sources d'une règle de catégorie, dans l'ordre de la table
	restricted []Restriction   // sources partielles écartées par la garde
	fields     map[string]bool // champs cités par les sélections (garde, research R3)
}

func (r *Rule) match(ev *normalizer.Event, src *Source) bool { return r.cond.eval(ev, src) }

// services associe un service Sigma à son canal EVTX (data-model.md).
var services = map[string]string{
	"security":           "Security",
	"system":             "System",
	"application":        "Application",
	"powershell":         "Microsoft-Windows-PowerShell/Operational",
	"powershell-classic": "Windows PowerShell",
	"sysmon":             "Microsoft-Windows-Sysmon/Operational",
	"taskscheduler":      "Microsoft-Windows-TaskScheduler/Operational",
	"windefend":          "Microsoft-Windows-Windows Defender/Operational",
	"wmi":                "Microsoft-Windows-WMI-Activity/Operational",
}

var (
	levels = map[string]string{
		"informational": normalizer.SeverityInfo, "low": normalizer.SeverityLow,
		"medium": normalizer.SeverityMedium, "high": normalizer.SeverityHigh,
		"critical": normalizer.SeverityCritical,
	}
	confidences = map[string]float64{"stable": 0.8, "test": 0.6, "experimental": 0.4, "": 0.4}
	technique   = regexp.MustCompile(`^attack\.t[0-9]{4}(\.[0-9]{3})?$`)
)

// parseRule charge une règle ; skipped vaut vrai si elle n'est pas
// applicable ; une erreur porte la raison du refus (contracts/detect.md).
func parseRule(name string, data []byte) (r *Rule, skipped bool, err error) {
	if len(data) > maxRuleSize {
		return nil, false, refusal("file too large")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if err == io.EOF {
			return nil, false, refusal("invalid YAML: empty file")
		}
		return nil, false, refusef("invalid YAML: %v", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, false, refusef("invalid YAML: %v", err)
		}
		return nil, false, refusal("more than one rule in the file")
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, false, refusal("invalid YAML: rule is not a map")
	}
	top := doc.Content[0]

	logsource := get(top, "logsource")
	product := scalar(get(logsource, "product"))
	if product == "" {
		return nil, false, refusal("missing logsource.product")
	}
	status := scalar(get(top, "status"))
	if !strings.EqualFold(product, "windows") || status == "deprecated" || status == "unsupported" {
		return nil, true, nil
	}
	if _, ok := confidences[status]; !ok {
		return nil, false, refusef("invalid status: %s", status)
	}

	r = &Rule{File: name, ID: scalar(get(top, "id")), Title: scalar(get(top, "title"))}
	if r.ID == "" {
		return nil, false, refusal("missing id")
	}
	if r.Title == "" {
		return nil, false, refusal("missing title")
	}
	level := scalar(get(top, "level"))
	if level == "" {
		return nil, false, refusal("missing level")
	}
	if r.Severity = levels[level]; r.Severity == "" {
		return nil, false, refusef("invalid level: %s", level)
	}
	r.Confidence = confidences[status]
	if c := get(top, "confidence"); c != nil {
		f, err := strconv.ParseFloat(c.Value, 64)
		if c.Kind != yaml.ScalarNode || err != nil || !(f >= 0 && f <= 1) {
			return nil, false, refusef("invalid confidence: %s", c.Value)
		}
		r.Confidence = f
	}
	// Ordre des contrôles de logsource : data-model.md (spec 013).
	service, category := scalar(get(logsource, "service")), scalar(get(logsource, "category"))
	if service == "" && category == "" {
		return nil, false, refusal("missing logsource.service or logsource.category")
	}
	var srcs []*Source
	if category != "" {
		if srcs = categories[strings.ToLower(category)]; srcs == nil {
			return nil, false, refusef("unknown logsource category: %s", category)
		}
	}
	if service != "" {
		if r.Channel = services[strings.ToLower(service)]; r.Channel == "" {
			return nil, false, refusef("unknown logsource service: %s", service)
		}
	}
	if category != "" {
		for _, s := range srcs {
			if service == "" || strings.EqualFold(s.Channel, r.Channel) {
				r.sources = append(r.sources, s)
			}
		}
		if r.sources == nil {
			return nil, false, refusal("logsource category and service do not match")
		}
		r.Channel = ""
	}

	det := get(top, "detection")
	if det == nil || det.Kind != yaml.MappingNode {
		return nil, false, refusal("missing detection")
	}
	if get(det, "timeframe") != nil {
		return nil, false, refusal("timeframe is not supported")
	}
	cond := get(det, "condition")
	if cond == nil {
		return nil, false, refusal("missing condition")
	}
	if cond.Kind != yaml.ScalarNode {
		return nil, false, refusal("invalid condition: must be a single expression")
	}
	sels := map[string]selection{}
	r.fields = map[string]bool{}
	for i := 0; i+1 < len(det.Content); i += 2 {
		k := det.Content[i].Value
		if k == "condition" {
			continue
		}
		s, err := compileSelection(k, det.Content[i+1])
		if err != nil {
			return nil, false, err
		}
		sels[k] = s
		s.addFields(r.fields)
	}
	if r.cond, err = parseCondition(cond.Value, sels); err != nil {
		return nil, false, err
	}
	if err := r.guard(); err != nil {
		return nil, false, err
	}

	if tags := get(top, "tags"); tags != nil {
		for _, t := range tags.Content {
			if technique.MatchString(strings.ToLower(t.Value)) {
				r.MITRE = strings.ToUpper(strings.TrimPrefix(strings.ToLower(t.Value), "attack."))
				break
			}
		}
	}
	sum := sha256.Sum256(bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")))
	r.Version = hex.EncodeToString(sum[:8])
	return r, false, nil
}

// guard retire d'une règle de catégorie les sources partielles qui ne
// fournissent pas un champ cité (research R3) ; aucune source restante → refus.
func (r *Rule) guard() error {
	if r.sources == nil {
		return nil
	}
	var kept []*Source
	all := map[string]bool{}
	for _, s := range r.sources {
		var missing []string
		for f := range r.fields {
			if s.Fields != nil && !s.Fields[f] && !commonFields[f] {
				missing = append(missing, f)
				all[f] = true
			}
		}
		if missing == nil {
			kept = append(kept, s)
			continue
		}
		sort.Strings(missing)
		r.restricted = append(r.restricted, Restriction{File: r.File, Source: s.Name, Missing: missing, Label: s.Label})
	}
	if kept == nil {
		var fs []string
		for f := range all {
			fs = append(fs, f)
		}
		sort.Strings(fs)
		return refusef("fields not available in any source: %s", strings.Join(fs, ","))
	}
	r.sources = kept
	return nil
}

// get renvoie la valeur de la clé k d'une table YAML, ou nil.
func get(n *yaml.Node, k string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == k {
			return n.Content[i+1]
		}
	}
	return nil
}

// scalar renvoie le texte d'un scalaire, vide s'il est absent ou nul.
func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
		return ""
	}
	return strings.TrimSpace(n.Value)
}
