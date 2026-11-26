package timeline

import (
	"bufio"
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"DFIRFlow/internal/normalizer"
)

// Bornes du tri externe (research.md R2) ; modifiables par les tests.
var (
	segmentBudget = 64 << 20 // octets de lignes et de clés gardés en mémoire
	maxFanIn      = 128      // segments fusionnés à la fois
)

// key est la clé de l'ordre canonique (spec 003, FR-018a).
type key struct {
	ts  int64 // µs depuis l'époque Unix, horodatage tronqué comme il est écrit
	src string
	rid uint64
	uid string
}

func keyOf(ev normalizer.Event) key {
	return key{ev.Timestamp.Truncate(time.Microsecond).UnixMicro(), ev.SourceFile, ev.RecordID, ev.UID}
}

func less(a, b key) bool {
	switch {
	case a.ts != b.ts:
		return a.ts < b.ts
	case a.src != b.src:
		return a.src < b.src
	case a.rid != b.rid:
		return a.rid < b.rid
	}
	return a.uid < b.uid
}

type entry struct {
	k    key
	line []byte // ligne canonique, "\n" compris
}

// sorter trie des lignes canoniques sous un budget mémoire borné.
type sorter struct {
	ctx    context.Context
	parent string // dossier où créer le dossier de travail
	dir    string // dossier de travail, créé au premier segment
	buf    []entry
	size   int
	segs   []string
}

func (s *sorter) add(k key, line []byte) error {
	s.buf = append(s.buf, entry{k, line})
	s.size += len(line) + len(k.src) + len(k.uid) + 64
	if s.size >= segmentBudget {
		return s.spill()
	}
	return nil
}

func (s *sorter) sortBuf() {
	sort.Slice(s.buf, func(i, j int) bool { return less(s.buf[i].k, s.buf[j].k) })
}

// spill écrit la mémoire triée dans un nouveau segment.
func (s *sorter) spill() error {
	if s.dir == "" {
		d, err := os.MkdirTemp(s.parent, ".work-")
		if err != nil {
			return err
		}
		s.dir = d
	}
	s.sortBuf()
	f, err := os.CreateTemp(s.dir, "seg-")
	if err != nil {
		return err
	}
	s.segs = append(s.segs, f.Name())
	w := bufio.NewWriterSize(f, 1<<16)
	for _, e := range s.buf {
		if _, err := w.Write(e.line); err != nil {
			f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	s.buf, s.size = nil, 0
	return f.Close()
}

// finish écrit toutes les lignes dans l'ordre canonique.
func (s *sorter) finish(w io.Writer) error {
	if len(s.segs) == 0 {
		s.sortBuf()
		for _, e := range s.buf {
			if _, err := w.Write(e.line); err != nil {
				return err
			}
		}
		return s.ctx.Err()
	}
	if len(s.buf) > 0 {
		if err := s.spill(); err != nil {
			return err
		}
	}
	for len(s.segs) > maxFanIn {
		var next []string
		for i := 0; i < len(s.segs); i += maxFanIn {
			j := i + maxFanIn
			if j > len(s.segs) {
				j = len(s.segs)
			}
			f, err := os.CreateTemp(s.dir, "seg-")
			if err != nil {
				return err
			}
			next = append(next, f.Name())
			bw := bufio.NewWriterSize(f, 1<<16)
			err = s.merge(s.segs[i:j], bw)
			if err == nil {
				err = bw.Flush()
			}
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
			for _, seg := range s.segs[i:j] {
				os.Remove(seg)
			}
		}
		s.segs = next
	}
	return s.merge(s.segs, w)
}

// cleanup supprime le dossier de travail.
func (s *sorter) cleanup() {
	if s.dir != "" {
		os.RemoveAll(s.dir)
	}
}

type cursor struct {
	e entry
	r *bufio.Reader
}

type cursors []*cursor

func (c cursors) Len() int            { return len(c) }
func (c cursors) Less(i, j int) bool  { return less(c[i].e.k, c[j].e.k) }
func (c cursors) Swap(i, j int)       { c[i], c[j] = c[j], c[i] }
func (c *cursors) Push(x interface{}) { *c = append(*c, x.(*cursor)) }
func (c *cursors) Pop() interface{} {
	old := *c
	x := old[len(old)-1]
	*c = old[:len(old)-1]
	return x
}

// next lit la ligne suivante du segment et n'en décode que la clé.
func (c *cursor) next() (bool, error) {
	line, err := c.r.ReadBytes('\n')
	if len(line) == 0 && err == io.EOF {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var k struct {
		Timestamp  normalizer.Time `json:"timestamp"`
		SourceFile string          `json:"source_file"`
		RecordID   uint64          `json:"record_id"`
		UID        string          `json:"uid"`
	}
	if err := json.Unmarshal(line, &k); err != nil {
		return false, fmt.Errorf("work segment: %w", err)
	}
	c.e = entry{key{k.Timestamp.Truncate(time.Microsecond).UnixMicro(), k.SourceFile, k.RecordID, k.UID}, line}
	return true, nil
}

// merge fusionne des segments triés vers w en recopiant les lignes.
func (s *sorter) merge(segs []string, w io.Writer) error {
	h := make(cursors, 0, len(segs))
	for _, name := range segs {
		f, err := os.Open(name)
		if err != nil {
			return err
		}
		defer f.Close()
		c := &cursor{r: bufio.NewReaderSize(f, 1<<16)}
		ok, err := c.next()
		if err != nil {
			return err
		}
		if ok {
			h = append(h, c)
		}
	}
	heap.Init(&h)
	for h.Len() > 0 {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		c := h[0]
		if _, err := w.Write(c.e.line); err != nil {
			return err
		}
		ok, err := c.next()
		if err != nil {
			return err
		}
		if ok {
			heap.Fix(&h, 0)
		} else {
			heap.Pop(&h)
		}
	}
	return nil
}
