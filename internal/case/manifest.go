package casefile

import "time"

type ManifestEntry struct {
	File        string
	SHA256      string
	Size        int64
	CollectedAt time.Time
}

func (c *Case) AddEvidence(path string) (ManifestEntry, error) {
	return ManifestEntry{}, ErrNotImplemented
}

func (c *Case) Verify() (bool, error) {
	return false, ErrNotImplemented
}

func (c *Case) SaveManifest() error {
	return ErrNotImplemented
}
