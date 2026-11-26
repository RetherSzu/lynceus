package detection

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	casefile "DFIRFlow/internal/case"
	"DFIRFlow/internal/extsort"
	"DFIRFlow/internal/ingest"
	"DFIRFlow/internal/normalizer"
)

// ErrNoEvents signale un cas sans aucun fichier d'événements (FR-002).
var ErrNoEvents = errors.New("no normalized events in the case; run ingest first")

// Summary résume une exécution (data-model.md).
type Summary struct {
	Files, EventsRead, Detections int
	SHA256                        string
	UnknownFiles                  []string
}

// Run applique rs aux événements du cas et écrit detections/detections.jsonl ;
// le fichier précédent n'est remplacé qu'une fois le nouveau complet (FR-014).
func Run(ctx context.Context, c *casefile.Case, rs *Ruleset) (sum Summary, err error) {
	dir := c.Dir("detections")
	out := filepath.Join(dir, "detections.jsonl")
	extsort.CleanStale(dir, "detections.jsonl")

	files, unknown, err := ingest.EventFiles(c)
	sum.UnknownFiles = unknown
	if err != nil {
		return sum, err
	}
	if len(files) == 0 {
		return sum, ErrNoEvents
	}

	s := &extsort.Sorter{Ctx: ctx, Parent: dir, Decode: decodeKey}
	defer s.Cleanup()
	var line bytes.Buffer
	enc := normalizer.NewEncoder(&line)
	for _, rel := range files {
		in, err := os.Open(filepath.Join(c.BaseDir, filepath.FromSlash(rel)))
		if err != nil {
			return sum, err
		}
		err = normalizer.ReadEvents(bufio.NewReaderSize(in, 1<<16), func(ev normalizer.Event) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			sum.EventsRead++
			if ev.Source != normalizer.SourceEVTX {
				return nil
			}
			for _, r := range rs.byChannel[strings.ToLower(ev.Channel)] {
				if !r.match(&ev) {
					continue
				}
				d := normalizer.Detection{
					ID:          normalizer.DetectionID(r.ID, r.Version, []string{ev.UID}),
					Timestamp:   ev.Timestamp,
					RuleID:      r.ID,
					RuleVersion: r.Version,
					Severity:    r.Severity,
					Confidence:  r.Confidence,
					MITRE:       r.MITRE,
					Events:      []string{ev.UID},
				}
				line.Reset()
				if err := enc.Detection(d); err != nil {
					return err
				}
				sum.Detections++
				if err := s.Add(keyOf(d), append([]byte(nil), line.Bytes()...)); err != nil {
					return err
				}
			}
			return nil
		})
		in.Close()
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return sum, cerr
			}
			return sum, fmt.Errorf("%s: %w", rel, err)
		}
		sum.Files++
	}
	sum.SHA256, err = extsort.WriteAtomic(out, s.Finish)
	return sum, err
}

// keyOf renvoie la clé de l'ordre des détections (spec 003, FR-021).
func keyOf(d normalizer.Detection) extsort.Key {
	return extsort.Key{TS: d.Timestamp.Truncate(time.Microsecond).UnixMicro(), S: d.ID}
}

func decodeKey(line []byte) (extsort.Key, error) {
	var k struct {
		Timestamp normalizer.Time `json:"timestamp"`
		ID        string          `json:"id"`
	}
	if err := json.Unmarshal(line, &k); err != nil {
		return extsort.Key{}, fmt.Errorf("work segment: %w", err)
	}
	return extsort.Key{TS: k.Timestamp.Truncate(time.Microsecond).UnixMicro(), S: k.ID}, nil
}
