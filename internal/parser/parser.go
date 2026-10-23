package parser

import (
	"io"

	"DFIRFlow/internal/normalizer"
)

type Parser interface {
	Name() string
	Parse(r io.Reader) (<-chan normalizer.Event, error)
}
