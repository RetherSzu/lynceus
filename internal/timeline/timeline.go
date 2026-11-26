// Package timeline construit la chronologie consolidée d'un cas
// (specs/006-timeline) à partir des fichiers d'événements de normalized/.
package timeline

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	casefile "DFIRFlow/internal/case"
	"DFIRFlow/internal/extsort"
	"DFIRFlow/internal/ingest"
	"DFIRFlow/internal/normalizer"
)

// ErrNoEvents signale un cas sans aucun fichier d'événements (FR-003).
var ErrNoEvents = errors.New("no normalized events in the case; run ingest first")

// Filter restreint la chronologie ; une borne nulle est absente.
// shortcut: une borne explicite à l'instant zéro vaut absence, sans effet sur des données réelles.
type Filter struct {
	From, To time.Time
	Sources  []string
}

// Summary résume une exécution (data-model.md).
type Summary struct {
	Files, EventsRead, EventsWritten int
	SHA256                           string
	MissingSources, UnknownFiles     []string
}

// Run écrit timeline/timeline.jsonl ; la chronologie précédente n'est
// remplacée qu'une fois la nouvelle complète (FR-013).
func Run(ctx context.Context, c *casefile.Case, f Filter) (sum Summary, err error) {
	dir := c.Dir("timeline")
	out := filepath.Join(dir, "timeline.jsonl")
	extsort.CleanStale(dir, "timeline.jsonl")

	files, unknown, err := ingest.EventFiles(c)
	sum.UnknownFiles = unknown
	if err != nil {
		return sum, err
	}
	if len(files) == 0 {
		return sum, ErrNoEvents
	}

	want := map[string]bool{}
	for _, s := range f.Sources {
		want[s] = true
	}
	from, to := f.From.Truncate(time.Microsecond), f.To.Truncate(time.Microsecond)
	seen := map[string]bool{}
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
			seen[ev.Source] = true
			t := ev.Timestamp.Truncate(time.Microsecond)
			if (len(want) > 0 && !want[ev.Source]) || (!f.From.IsZero() && t.Before(from)) || (!f.To.IsZero() && t.After(to)) {
				return nil
			}
			line.Reset()
			if err := enc.Event(ev); err != nil {
				return err
			}
			sum.EventsWritten++
			return s.Add(keyOf(ev), append([]byte(nil), line.Bytes()...))
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
	for _, src := range f.Sources {
		if !seen[src] {
			sum.MissingSources = append(sum.MissingSources, src)
		}
	}
	sort.Strings(sum.MissingSources)

	sum.SHA256, err = extsort.WriteAtomic(out, s.Finish)
	return sum, err
}
