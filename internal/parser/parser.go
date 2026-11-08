// Package parser définit le contrat commun aux parseurs natifs et aux
// importers (spec 003, D9, FR-014 à FR-016d).
package parser

import (
	"context"
	"io"
	"strings"

	"DFIRFlow/internal/normalizer"
)

// Source est la provenance d'une preuve : chemin relatif à evidence/,
// SHA-256 du manifeste et hostname du cas.
type Source struct {
	File   string
	SHA256 string
	Host   string
}

// Anomaly signale un enregistrement non converti en événement ; le parseur continue.
type Anomaly struct {
	Locator string
	Kind    string // Voir constantes Kind*
	Message string
}

// Valeurs de Anomaly.Kind.
const (
	KindUnreadable = "unreadable"
	KindMissing    = "missing"
	KindTruncated  = "truncated"
	KindInvalid    = "invalid"
)

// Sink reçoit, de façon synchrone et dans l'ordre du fichier, ce que le
// parseur émet ; une erreur renvoyée arrête le parseur, qui la renvoie.
type Sink interface {
	Event(normalizer.Event) error
	Anomaly(Anomaly) error
}

// Parser convertit une preuve en événements. Il n'ouvre aucun fichier, ne
// garde aucun état entre deux appels et ne panique sur aucune entrée.
type Parser interface {
	// Name est la valeur de source, ou le nom de l'outil pour un importer.
	Name() string
	// Match reconnaît le format sur les premiers octets, jamais sur l'extension.
	Match(head []byte) bool
	// Parse renvoie une erreur fatale pour un format non reconnu, une erreur
	// d'E/S ou une annulation ; ce qui a déjà été émis reste valide.
	Parse(ctx context.Context, r io.ReaderAt, size int64, src Source, out Sink) error
}

// Validating transmet les événements valides et remplace chaque événement
// invalide par une anomalie invalid (FR-010, FR-016b).
func Validating(next Sink) Sink { return validating{next} }

type validating struct{ next Sink }

func (v validating) Event(e normalizer.Event) error {
	vs := e.Validate()
	if len(vs) == 0 {
		return v.next.Event(e)
	}
	rules := make([]string, len(vs))
	for i, x := range vs {
		rules[i] = x.String()
	}
	return v.next.Anomaly(Anomaly{
		Locator: e.RecordLocator,
		Kind:    KindInvalid,
		Message: "uid=" + e.UID + ": " + strings.Join(rules, "; "),
	})
}

func (v validating) Anomaly(a Anomaly) error { return v.next.Anomaly(a) }
