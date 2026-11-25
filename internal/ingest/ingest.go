// Package ingest décode les preuves d'un cas vers normalized/ (spec 005,
// contracts/ingest.md).
package ingest

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	casefile "DFIRFlow/internal/case"
	"DFIRFlow/internal/normalizer"
	"DFIRFlow/internal/parser"
)

// Statuts d'une preuve.
const (
	Ingested = "INGESTED"
	Skipped  = "SKIPPED"
	Altered  = "ALTERED"
	Failed   = "FAILED"
)

// ErrNoEVTX signale qu'aucune preuve sélectionnée n'est un journal reconnu.
var ErrNoEVTX = errors.New("no EVTX evidence to ingest")

// Result est l'issue de l'ingestion d'une preuve.
type Result struct {
	File      string `json:"file"` // relatif à evidence/, séparateur "/"
	Status    string `json:"status"`
	Events    int    `json:"events"`
	Anomalies int    `json:"anomalies"`
	Reason    string `json:"reason,omitempty"`
}

// OtherCount compte les événements classés other d'un couple (canal, EventID).
type OtherCount struct {
	Channel string `json:"channel"`
	EventID uint32 `json:"event_id"`
	Count   int    `json:"count"`
}

// Summary regroupe les résultats, triés par chemin, et les totaux.
type Summary struct {
	Results   []Result
	Events    int
	Anomalies int
	Other     int
	TopOther  []OtherCount // au plus 10 (FR-018a)
}

// OtherRatio est la part des événements other, sur trois décimales.
func (s Summary) OtherRatio() string {
	if s.Events == 0 {
		return "0.000"
	}
	return fmt.Sprintf("%.3f", float64(s.Other)/float64(s.Events))
}

// Run ingère les preuves désignées par paths (relatives à evidence/), ou
// toutes. Un chemin hors manifeste est refusé avant tout traitement. Une
// erreur sur une preuve est rapportée dans son Result ; seule une annulation
// interrompt la suite, avec le résumé des preuves déjà traitées.
func Run(ctx context.Context, c *casefile.Case, paths []string, parsers []parser.Parser) (Summary, error) {
	var sum Summary
	entries, err := c.Evidence()
	if err != nil {
		return sum, err
	}
	selected, err := selectEntries(entries, paths)
	if err != nil {
		return sum, err
	}
	other := map[OtherCount]int{} // clé sans Count
	for _, e := range selected {
		if err := ctx.Err(); err != nil {
			return sum, err
		}
		r, err := ingestOne(ctx, c, e, parsers, other)
		if err != nil {
			return sum, err
		}
		sum.Results = append(sum.Results, r)
		sum.Events += r.Events
		sum.Anomalies += r.Anomalies
	}
	for k, n := range other {
		k.Count = n
		sum.Other += n
		sum.TopOther = append(sum.TopOther, k)
	}
	sort.Slice(sum.TopOther, func(i, j int) bool {
		a, b := sum.TopOther[i], sum.TopOther[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		if a.Channel != b.Channel {
			return a.Channel < b.Channel
		}
		return a.EventID < b.EventID
	})
	if len(sum.TopOther) > 10 {
		sum.TopOther = sum.TopOther[:10]
	}
	for _, r := range sum.Results {
		if r.Status != Skipped {
			return sum, nil
		}
	}
	return sum, ErrNoEVTX
}

func selectEntries(entries []casefile.ManifestEntry, paths []string) ([]casefile.ManifestEntry, error) {
	if len(paths) == 0 {
		return entries, nil
	}
	byFile := map[string]casefile.ManifestEntry{}
	for _, e := range entries {
		byFile[e.File] = e
	}
	want := map[string]bool{}
	for _, p := range paths {
		rel := path.Clean(filepath.ToSlash(p))
		if _, ok := byFile[rel]; !ok {
			return nil, fmt.Errorf("not in the case manifest: %s", p)
		}
		want[rel] = true
	}
	var out []casefile.ManifestEntry
	for _, e := range entries {
		if want[e.File] {
			out = append(out, e)
		}
	}
	return out, nil
}

// ingestOne traite une preuve ; l'erreur renvoyée n'est qu'une annulation.
func ingestOne(ctx context.Context, c *casefile.Case, e casefile.ManifestEntry, parsers []parser.Parser, other map[OtherCount]int) (Result, error) {
	r := Result{File: e.File}
	fail := func(err error) (Result, error) {
		if ctx.Err() != nil {
			return r, ctx.Err()
		}
		r.Status, r.Reason, r.Events, r.Anomalies = Failed, err.Error(), 0, 0
		return r, nil
	}
	f, err := os.Open(filepath.Join(c.Dir("evidence"), filepath.FromSlash(e.File)))
	if err != nil {
		return fail(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fail(err)
	}

	head := make([]byte, 8)
	n, _ := io.ReadFull(f, head)
	var p parser.Parser
	for _, candidate := range parsers {
		if candidate.Match(head[:n]) {
			p = candidate
			break
		}
	}
	if p == nil {
		r.Status, r.Reason = Skipped, "not an EVTX file"
		return r, nil
	}

	// L'empreinte est vérifiée avant tout décodage (FR-015).
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, ctxReader{ctx, f}); err != nil {
		return fail(err)
	}
	if actual := hex.EncodeToString(h.Sum(nil)); actual != e.SHA256 {
		r.Status, r.Reason = Altered, "expected="+e.SHA256+" actual="+actual
		return r, nil
	}

	base := filepath.Join(c.Dir("normalized"), filepath.FromSlash(e.File))
	if err := os.MkdirAll(filepath.Dir(base), 0o755); err != nil {
		return fail(err)
	}
	evPath, anPath := base+".jsonl", base+".anomalies.jsonl"
	w, err := newWriter(evPath+".partial", anPath+".partial")
	if err != nil {
		return fail(err)
	}
	src := parser.Source{File: e.File, SHA256: e.SHA256, Host: c.Hostname}
	perr := p.Parse(ctx, f, fi.Size(), src, parser.Validating(w))
	if cerr := w.close(); perr == nil {
		perr = cerr
	}
	if perr == nil {
		perr = rename(anPath, evPath)
	}
	if perr != nil {
		os.Remove(evPath + ".partial")
		os.Remove(anPath + ".partial")
		return fail(perr)
	}
	for k, n := range w.other {
		other[k] += n
	}
	r.Status, r.Events, r.Anomalies = Ingested, w.events, w.anomalies
	return r, nil
}

// rename publie les deux fichiers ; les anciens restent en place jusque-là.
func rename(anPath, evPath string) error {
	if err := os.Rename(anPath+".partial", anPath); err != nil {
		return err
	}
	return os.Rename(evPath+".partial", evPath)
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// writer est le Sink final : événements en JSONL canonique, anomalies une par ligne.
type writer struct {
	evFile, anFile *os.File
	evBuf, anBuf   *bufio.Writer
	enc            *normalizer.Encoder
	anEnc          *json.Encoder
	events         int
	anomalies      int
	other          map[OtherCount]int
}

type anomalyLine struct {
	RecordLocator string `json:"record_locator"`
	Kind          string `json:"kind"`
	Message       string `json:"message"`
}

func newWriter(evPath, anPath string) (*writer, error) {
	ev, err := os.Create(evPath)
	if err != nil {
		return nil, err
	}
	an, err := os.Create(anPath)
	if err != nil {
		ev.Close()
		os.Remove(evPath)
		return nil, err
	}
	w := &writer{evFile: ev, anFile: an, evBuf: bufio.NewWriter(ev), anBuf: bufio.NewWriter(an), other: map[OtherCount]int{}}
	w.enc = normalizer.NewEncoder(w.evBuf)
	w.anEnc = json.NewEncoder(w.anBuf)
	w.anEnc.SetEscapeHTML(false)
	return w, nil
}

func (w *writer) Event(e normalizer.Event) error {
	if err := w.enc.Event(e); err != nil {
		return err
	}
	w.events++
	if e.EventType == normalizer.TypeOther && e.EventID != nil {
		w.other[OtherCount{Channel: e.Channel, EventID: *e.EventID}]++
	}
	return nil
}

func (w *writer) Anomaly(a parser.Anomaly) error {
	w.anomalies++
	return w.anEnc.Encode(anomalyLine{a.Locator, a.Kind, a.Message})
}

func (w *writer) close() error {
	var errs []string
	for _, err := range []error{w.evBuf.Flush(), w.anBuf.Flush(), w.evFile.Sync(), w.anFile.Sync(), w.evFile.Close(), w.anFile.Close()} {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
