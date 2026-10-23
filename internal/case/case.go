package casefile

import (
	"errors"
	"path/filepath"
	"time"
)

var ErrNotImplemented = errors.New("case management is not implemented yet")

type Case struct {
	ID          string
	Hostname    string
	Analyst     string
	CreatedAt   time.Time
	ToolVersion string
	BaseDir     string
}

func New(hostname, analyst string) (*Case, error) {
	return nil, ErrNotImplemented
}

func (c *Case) Load(path string) (*Case, error) {
	return nil, ErrNotImplemented
}

func (c *Case) Dir(kind string) string {
	return filepath.Join(c.BaseDir, kind)
}
