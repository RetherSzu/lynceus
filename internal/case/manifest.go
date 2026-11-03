package casefile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ManifestEntry struct {
	File        string    `json:"file"` // relatif à evidence/, séparateur "/"
	SHA256      string    `json:"sha256"`
	Size        int64     `json:"size"`
	CollectedAt time.Time `json:"collected_at"`
}

// AddEvidence copie src sous evidence/rel en la hachant, vérifie la copie,
// l'ajoute au manifeste puis la passe en lecture seule. En cas d'échec,
// aucune copie ni entrée ne subsiste.
func (c *Case) AddEvidence(src, rel string) (ManifestEntry, error) {
	rel, err := cleanRel(rel)
	if err != nil {
		return ManifestEntry{}, err
	}
	file := filepath.ToSlash(rel)
	if c.entries[file] {
		return ManifestEntry{}, fmt.Errorf("evidence %q already recorded", file)
	}
	dst := filepath.Join(c.Dir("evidence"), rel)
	if _, err := os.Lstat(dst); err == nil {
		return ManifestEntry{}, fmt.Errorf("evidence %q already exists", file)
	}

	in, err := os.Open(src)
	if err != nil {
		return ManifestEntry{}, err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return ManifestEntry{}, err
	}
	partial := dst + ".partial"
	sum, size, err := copyHashed(partial, in)
	if err != nil {
		os.Remove(partial)
		return ManifestEntry{}, err
	}
	if check, checkSize, err := hashFile(nil, partial); err != nil || check != sum || checkSize != size {
		os.Remove(partial)
		if err == nil {
			err = fmt.Errorf("copy of %q does not match its source", file)
		}
		return ManifestEntry{}, err
	}
	if err := os.Rename(partial, dst); err != nil {
		os.Remove(partial)
		return ManifestEntry{}, err
	}
	e := ManifestEntry{File: file, SHA256: sum, Size: size, CollectedAt: time.Now().UTC().Truncate(time.Second)}
	if err := appendLine(c.manifestPath(), e); err != nil {
		os.Remove(dst)
		return ManifestEntry{}, err
	}
	c.entries[file] = true
	return e, os.Chmod(dst, 0o444)
}

func copyHashed(dst string, src io.Reader) (string, int64, error) {
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(out, h), src)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return hex.EncodeToString(h.Sum(nil)), size, err
}

// hashFile calcule en flux le SHA-256 d'un fichier ; wrap, si non nil,
// enveloppe le lecteur (vérification d'annulation).
func hashFile(wrap func(io.Reader) io.Reader, path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	var r io.Reader = f
	if wrap != nil {
		r = wrap(f)
	}
	h := sha256.New()
	size, err := io.Copy(h, r)
	return hex.EncodeToString(h.Sum(nil)), size, err
}

// cleanRel normalise un chemin relatif à evidence/ et refuse ceux qui en sortent.
func cleanRel(rel string) (string, error) {
	clean := filepath.Clean(rel)
	if rel == "" || clean == "." || filepath.IsAbs(clean) || filepath.VolumeName(clean) != "" ||
		clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid evidence path %q: must stay inside evidence/", rel)
	}
	if clean != rel && filepath.ToSlash(clean) != filepath.ToSlash(rel) {
		return "", fmt.Errorf("invalid evidence path %q: must be in canonical form", rel)
	}
	return clean, nil
}
