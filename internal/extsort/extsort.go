// Package extsort trie des lignes sous un budget mémoire borné (tri externe)
// et les écrit de façon atomique ; extrait de la spec 006, research R2, et
// partagé par la chronologie et la détection (spec 012, research R6).
package extsort

import (
	"bufio"
	"container/heap"
	"context"
	"io"
	"os"
	"sort"
)

// Bornes du tri externe ; modifiables par les tests.
var (
	SegmentBudget = 64 << 20 // octets de lignes et de clés gardés en mémoire
	MaxFanIn      = 128      // segments fusionnés à la fois
)

// Key est une clé de tri à quatre composantes comparées dans l'ordre.
type Key struct {
	TS int64
	S  string
	N  uint64
	T  string
}

// Less compare deux clés dans l'ordre (TS, S, N, T), chaînes octet par octet.
func Less(a, b Key) bool {
	switch {
	case a.TS != b.TS:
		return a.TS < b.TS
	case a.S != b.S:
		return a.S < b.S
	case a.N != b.N:
		return a.N < b.N
	}
	return a.T < b.T
}

type entry struct {
	k    Key
	line []byte // ligne complète, "\n" compris
}

// Sorter trie des lignes ; Decode relit la clé d'une ligne d'un segment.
type Sorter struct {
	Ctx    context.Context
	Parent string // dossier où créer le dossier de travail
	Decode func(line []byte) (Key, error)
	Budget int // octets gardés en mémoire avant un segment ; 0 = SegmentBudget

	dir  string // dossier de travail, créé au premier segment
	buf  []entry
	size int
	segs []string
}

// Add ajoute une ligne et sa clé ; le Sorter garde line.
func (s *Sorter) Add(k Key, line []byte) error {
	s.buf = append(s.buf, entry{k, line})
	s.size += len(line) + len(k.S) + len(k.T) + 64
	budget := s.Budget
	if budget == 0 {
		budget = SegmentBudget
	}
	if s.size >= budget {
		return s.spill()
	}
	return nil
}

// Segments renvoie le nombre de segments écrits sur disque.
func (s *Sorter) Segments() int { return len(s.segs) }

func (s *Sorter) sortBuf() {
	sort.Slice(s.buf, func(i, j int) bool { return Less(s.buf[i].k, s.buf[j].k) })
}

// spill écrit la mémoire triée dans un nouveau segment.
func (s *Sorter) spill() error {
	if s.dir == "" {
		d, err := os.MkdirTemp(s.Parent, ".work-")
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

// Finish écrit toutes les lignes dans l'ordre des clés.
func (s *Sorter) Finish(w io.Writer) error {
	if len(s.segs) == 0 {
		s.sortBuf()
		for _, e := range s.buf {
			if _, err := w.Write(e.line); err != nil {
				return err
			}
		}
		return s.Ctx.Err()
	}
	if len(s.buf) > 0 {
		if err := s.spill(); err != nil {
			return err
		}
	}
	for len(s.segs) > MaxFanIn {
		var next []string
		for i := 0; i < len(s.segs); i += MaxFanIn {
			j := i + MaxFanIn
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

// Cleanup supprime le dossier de travail.
func (s *Sorter) Cleanup() {
	if s.dir != "" {
		os.RemoveAll(s.dir)
	}
}

type cursor struct {
	e      entry
	r      *bufio.Reader
	decode func([]byte) (Key, error)
}

type cursors []*cursor

func (c cursors) Len() int            { return len(c) }
func (c cursors) Less(i, j int) bool  { return Less(c[i].e.k, c[j].e.k) }
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
	k, err := c.decode(line)
	if err != nil {
		return false, err
	}
	c.e = entry{k, line}
	return true, nil
}

// merge fusionne des segments triés vers w en recopiant les lignes.
func (s *Sorter) merge(segs []string, w io.Writer) error {
	h := make(cursors, 0, len(segs))
	for _, name := range segs {
		f, err := os.Open(name)
		if err != nil {
			return err
		}
		defer f.Close()
		c := &cursor{r: bufio.NewReaderSize(f, 1<<16), decode: s.Decode}
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
		if err := s.Ctx.Err(); err != nil {
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
