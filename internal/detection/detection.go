package detection

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
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
	Merged                        int // détections Sysmon 1 et 4688 rapprochées (FR-005a)
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
	// research R9 : candidates au rapprochement, budget réduit pour borner la mémoire totale.
	cands := &extsort.Sorter{Ctx: ctx, Parent: dir, Decode: decodeKey, Budget: 16 << 20}
	defer cands.Cleanup()
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
			for _, list := range rs.candidates(&ev) {
				for _, e := range list {
					if !e.src.accepts(&ev) || !e.rule.match(&ev, e.src) {
						continue
					}
					r := e.rule
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
					if e.src != nil && mergeSources[e.src.Name] && ev.ProcessID != 0 {
						if err := addCandidate(cands, d, e.src.Name, &ev, line.Bytes()); err != nil {
							return err
						}
						continue
					}
					if err := s.Add(keyOf(d), append([]byte(nil), line.Bytes()...)); err != nil {
						return err
					}
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
	if sum.Merged, err = mergeCandidates(cands, s); err != nil {
		return sum, err
	}
	sum.Detections -= sum.Merged
	sum.SHA256, err = extsort.WriteAtomic(out, s.Finish)
	return sum, err
}

// mergeSources sont les sources d'un même lancement de processus (FR-005a).
var mergeSources = map[string]bool{"sysmon-1": true, "security-4688": true}

// mergeWindow est l'écart maximal entre les deux enregistrements d'un lancement.
const mergeWindow = 2 * time.Second

// candidate est une détection en attente de rapprochement ; Timestamp et ID
// en tête pour decodeKey.
type candidate struct {
	Timestamp normalizer.Time `json:"timestamp"`
	ID        string          `json:"id"`
	Source    string          `json:"source"`
	Key       string          `json:"key"`
	Detection json.RawMessage `json:"detection"`
	done      bool
}

func addCandidate(cands *extsort.Sorter, d normalizer.Detection, src string, ev *normalizer.Event, line []byte) error {
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%d\x00%s", d.RuleID, d.RuleVersion, ev.Host,
		ev.ProcessID, ev.ParentProcessID, strings.ToLower(ev.Process))
	b, err := json.Marshal(candidate{Timestamp: d.Timestamp, ID: d.ID, Source: src, Key: key,
		Detection: bytes.TrimSuffix(line, []byte("\n"))})
	if err != nil {
		return err
	}
	return cands.Add(keyOf(d), append(b, '\n'))
}

// mergeCandidates parcourt les candidates dans l'ordre (horodatage, id) et
// apparie chacune à la plus ancienne candidate libre de même clé et de l'autre
// source, à mergeWindow au plus (data-model.md « Rapprochement ») ; le résultat
// rejoint le tri principal.
func mergeCandidates(cands, s *extsort.Sorter) (merged int, err error) {
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(cands.Finish(pw)) }()
	defer pr.Close()

	var queue []*candidate               // en attente, par ordre d'arrivée
	open := map[string][]*candidate{}    // les mêmes, par clé
	single := func(c *candidate) error { // candidate sans partenaire : écrite telle quelle
		return s.Add(extsort.Key{TS: c.Timestamp.Truncate(time.Microsecond).UnixMicro(), S: c.ID}, append(append([]byte(nil), c.Detection...), '\n'))
	}
	expire := func(now time.Time, all bool) error {
		for len(queue) > 0 && (all || now.Sub(queue[0].Timestamp.Time) > mergeWindow) {
			c := queue[0]
			queue = queue[1:]
			open[c.Key] = open[c.Key][1:]
			if len(open[c.Key]) == 0 {
				delete(open, c.Key)
			}
			if !c.done {
				if err := single(c); err != nil {
					return err
				}
			}
		}
		return nil
	}
	var line bytes.Buffer
	enc := normalizer.NewEncoder(&line)
	r := bufio.NewReaderSize(pr, 1<<16)
	for {
		b, rerr := r.ReadBytes('\n')
		if len(b) > 0 {
			c := &candidate{}
			if err := json.Unmarshal(b, c); err != nil {
				return merged, fmt.Errorf("work segment: %w", err)
			}
			if err := expire(c.Timestamp.Time, false); err != nil {
				return merged, err
			}
			var p *candidate
			for _, o := range open[c.Key] {
				if !o.done && o.Source != c.Source {
					p = o
					break
				}
			}
			if p == nil {
				queue = append(queue, c)
				open[c.Key] = append(open[c.Key], c)
			} else {
				p.done = true
				var d normalizer.Detection
				if err := json.Unmarshal(p.Detection, &d); err != nil {
					return merged, err
				}
				d.Events = []string{d.Events[0], c.eventUID()}
				sort.Strings(d.Events)
				d.ID = normalizer.DetectionID(d.RuleID, d.RuleVersion, d.Events)
				line.Reset()
				if err := enc.Detection(d); err != nil {
					return merged, err
				}
				if err := s.Add(keyOf(d), append([]byte(nil), line.Bytes()...)); err != nil {
					return merged, err
				}
				merged++
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return merged, rerr
		}
	}
	return merged, expire(time.Time{}, true)
}

// eventUID renvoie l'uid de l'événement unique de la détection candidate.
func (c *candidate) eventUID() string {
	var d struct {
		Events []string `json:"events"`
	}
	json.Unmarshal(c.Detection, &d)
	return d.Events[0]
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
