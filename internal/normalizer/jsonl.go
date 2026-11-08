package normalizer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Encoder écrit des lignes JSONL canoniques (contracts/event-model.md).
type Encoder struct{ enc *json.Encoder }

func NewEncoder(w io.Writer) *Encoder {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &Encoder{enc}
}

// eventLine place schema_version avant les champs promus de Event (R1).
type eventLine struct {
	SchemaVersion int `json:"schema_version"`
	Event
}

// Event écrit un événement valide ; un événement invalide n'est pas écrit (FR-010).
func (e *Encoder) Event(ev Event) error {
	if vs := ev.Validate(); len(vs) > 0 {
		return fmt.Errorf("invalid event uid=%s: %s", ev.UID, joinViolations(vs))
	}
	return e.enc.Encode(eventLine{SchemaVersion, ev})
}

// ReadEvents lit un fichier JSONL d'événements et appelle fn pour chacun ;
// toute ligne non conforme arrête la lecture avec son numéro (R3).
func ReadEvents(r io.Reader, fn func(Event) error) error {
	return readLines(r, func(b []byte) error {
		var l eventLine
		if err := decodeStrict(b, &l); err != nil {
			return err
		}
		if vs := l.Event.Validate(); len(vs) > 0 {
			return fmt.Errorf("uid=%s: %s", l.UID, joinViolations(vs))
		}
		return callback{fn(l.Event)}
	})
}

// SortEvents trie dans l'ordre canonique : timestamp, source_file, record_id, uid.
// L'horodatage est comparé tronqué à la µs, comme il est écrit.
func SortEvents(evs []Event) {
	sort.Slice(evs, func(i, j int) bool {
		a, b := &evs[i], &evs[j]
		ta, tb := a.Timestamp.Truncate(time.Microsecond), b.Timestamp.Truncate(time.Microsecond)
		switch {
		case !ta.Equal(tb):
			return ta.Before(tb)
		case a.SourceFile != b.SourceFile:
			return a.SourceFile < b.SourceFile
		case a.RecordID != b.RecordID:
			return a.RecordID < b.RecordID
		}
		return a.UID < b.UID
	})
}

type detectionLine struct {
	SchemaVersion int `json:"schema_version"`
	Detection
}

// Detection écrit une détection valide ; une détection invalide n'est pas écrite.
func (e *Encoder) Detection(d Detection) error {
	if vs := d.Validate(); len(vs) > 0 {
		return fmt.Errorf("invalid detection id=%s: %s", d.ID, joinViolations(vs))
	}
	return e.enc.Encode(detectionLine{SchemaVersion, d})
}

// ReadDetections lit un fichier JSONL de détections avec les mêmes règles que ReadEvents.
func ReadDetections(r io.Reader, fn func(Detection) error) error {
	return readLines(r, func(b []byte) error {
		var l detectionLine
		if err := decodeStrict(b, &l); err != nil {
			return err
		}
		if vs := l.Detection.Validate(); len(vs) > 0 {
			return fmt.Errorf("id=%s: %s", l.ID, joinViolations(vs))
		}
		return callback{fn(l.Detection)}
	})
}

// SortDetections trie dans l'ordre canonique : timestamp (tronqué à la µs), puis id.
func SortDetections(ds []Detection) {
	sort.Slice(ds, func(i, j int) bool {
		ta, tb := ds[i].Timestamp.Truncate(time.Microsecond), ds[j].Timestamp.Truncate(time.Microsecond)
		if !ta.Equal(tb) {
			return ta.Before(tb)
		}
		return ds[i].ID < ds[j].ID
	})
}

// callback distingue l'erreur de l'appelant, renvoyée telle quelle, des
// erreurs de format, préfixées du numéro de ligne.
type callback struct{ err error }

func (c callback) Error() string { return c.err.Error() }

// readLines découpe r en lignes strictes et passe chacune, sans son "\n", à decode.
func readLines(r io.Reader, decode func([]byte) error) error {
	br := bufio.NewReader(r)
	for line := 1; ; line++ {
		b, err := br.ReadBytes('\n')
		if len(b) == 0 && err == io.EOF {
			return nil
		}
		if err == nil {
			b = b[:len(b)-1]
			err = checkLine(b)
		} else if err == io.EOF {
			err = errors.New("missing final newline")
		}
		if err == nil {
			err = decode(b)
		}
		var cb callback
		if errors.As(err, &cb) {
			if cb.err != nil {
				return cb.err
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
	}
}

func checkLine(b []byte) error {
	switch {
	case len(b) == 0:
		return errors.New("empty line")
	case b[len(b)-1] == '\r':
		return errors.New("CRLF line ending")
	case !utf8.Valid(b): // avant le JSON, qui remplacerait l'octet par U+FFFD
		return errors.New("invalid UTF-8")
	}
	return nil
}

// decodeStrict vérifie schema_version avant le décodage strict, pour qu'un
// fichier plus récent soit signalé comme tel et non comme corrompu.
//
// shortcut: une clé JSON en double n'est pas détectée (encoding/json garde la
// dernière) ; à durcir si l'on doit relire des fichiers venus d'un tiers.
func decodeStrict(b []byte, v interface{}) error {
	var head struct {
		SchemaVersion *int `json:"schema_version"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return err
	}
	if head.SchemaVersion == nil {
		return errors.New("missing schema_version")
	}
	if *head.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %d", *head.SchemaVersion)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the JSON object")
	}
	return nil
}

func joinViolations(vs []Violation) string {
	s := make([]string, len(vs))
	for i, v := range vs {
		s[i] = v.String()
	}
	return strings.Join(s, "; ")
}
