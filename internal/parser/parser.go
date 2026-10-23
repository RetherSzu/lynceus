type Parser interface {
    Name() string
    Parse(r io.Reader) (<-chan Event, error)   // channel = streaming (MFT géants)
}