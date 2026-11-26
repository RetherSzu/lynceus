// Package timeline construit la chronologie consolidée d'un cas
// (specs/006-timeline) à partir des fichiers d'événements de normalized/.
package timeline

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	casefile "DFIRFlow/internal/case"
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
	// shortcut: suppose une seule exécution de timeline à la fois sur le cas, à revoir avec un verrou de cas.
	os.Remove(out + ".partial")
	if olds, _ := filepath.Glob(filepath.Join(dir, ".work-*")); olds != nil {
		for _, o := range olds {
			os.RemoveAll(o)
		}
	}

	entries, err := c.Evidence()
	if err != nil {
		return sum, err
	}
	known := map[string]bool{}
	var files []string
	for _, e := range entries {
		rel := "normalized/" + e.File + ".jsonl"
		known[rel], known["normalized/"+e.File+".anomalies.jsonl"] = true, true
		if _, err := os.Stat(filepath.Join(c.BaseDir, filepath.FromSlash(rel))); err == nil {
			files = append(files, rel)
		}
	}
	if sum.UnknownFiles, err = unknownFiles(c.BaseDir, known); err != nil {
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
	s := &sorter{ctx: ctx, parent: dir}
	defer s.cleanup()
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
			return s.add(keyOf(ev), append([]byte(nil), line.Bytes()...))
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

	sum.SHA256, err = writeAtomic(out, s.finish)
	return sum, err
}

// writeAtomic écrit out.partial via write, puis le renomme en out ;
// le .partial est supprimé sur toute erreur.
func writeAtomic(out string, write func(io.Writer) error) (string, error) {
	tmp := out + ".partial"
	fh, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	bw := bufio.NewWriterSize(io.MultiWriter(fh, h), 1<<16)
	err = write(bw)
	if err == nil {
		err = bw.Flush()
	}
	if err == nil {
		err = fh.Sync()
	}
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, out)
	}
	if err != nil {
		os.Remove(tmp)
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// unknownFiles liste les fichiers de normalized/ sans preuve au manifeste (FR-002).
func unknownFiles(base string, known map[string]bool) ([]string, error) {
	var out []string
	err := filepath.WalkDir(filepath.Join(base, "normalized"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(p, ".partial") {
			return err
		}
		rel, err := filepath.Rel(base, p)
		if err != nil {
			return err
		}
		if rel = filepath.ToSlash(rel); !known[rel] {
			out = append(out, rel)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}
