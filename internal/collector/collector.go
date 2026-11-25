// Package collector collecte les artefacts d'un volume Windows dans un cas DFIRFlow.
package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	casefile "DFIRFlow/internal/case"
)

// Statuts d'un fichier candidat (contracts/collect.md).
const (
	Collected = "COLLECTED"
	Already   = "ALREADY"
	Conflict  = "CONFLICT"
	Failed    = "FAILED"
	Skipped   = "SKIPPED"
)

// Result est l'issue de la collecte d'un fichier.
type Result struct {
	File   string // relatif à la cible et à evidence/, séparateur "/"
	Status string
	SHA256 string // empreinte enregistrée (COLLECTED, ALREADY) ou attendue (CONFLICT)
	Actual string // empreinte de la source (CONFLICT)
	Reason string // FAILED, SKIPPED
}

// ErrNoArtifact signale une cible sans aucun fichier régulier reconnu.
var ErrNoArtifact = errors.New("no artifact found")

// Collect copie dans le cas les artefacts reconnus sous target, qui n'est
// jamais modifiée. Une erreur sur un fichier est rapportée dans son Result ;
// les résultats sont triés par chemin.
func Collect(ctx context.Context, c *casefile.Case, target string) ([]Result, error) {
	root, err := resolve(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target %s: %w", target, err)
	}
	if fi, err := os.Stat(root); err != nil {
		return nil, fmt.Errorf("invalid target %s: %w", target, err)
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("invalid target %s: not a directory", target)
	}
	caseDir, err := resolve(c.BaseDir)
	if err != nil {
		return nil, err
	}
	if rel, err := filepath.Rel(root, caseDir); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, errors.New("case directory must not be inside the target")
	}
	cands, err := find(root)
	if err != nil {
		return nil, fmt.Errorf("invalid target %s: %w", target, err)
	}
	regular := 0
	for _, cd := range cands {
		if cd.skip == "" {
			regular++
		}
	}
	if regular == 0 {
		return nil, fmt.Errorf("%w under %s", ErrNoArtifact, target)
	}

	results := make([]Result, 0, len(cands))
	for _, cd := range cands {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := Result{File: cd.rel}
		if cd.skip != "" {
			r.Status, r.Reason = Skipped, cd.skip
			results = append(results, r)
			continue
		}
		if recorded, ok := c.Recorded(cd.rel); ok {
			actual, err := hashFile(ctx, cd.abs)
			switch {
			case ctx.Err() != nil:
				return nil, ctx.Err()
			case err != nil:
				r.Status, r.Reason = Failed, reason(err)
			case actual == recorded:
				r.Status, r.SHA256 = Already, recorded
			default:
				r.Status, r.SHA256, r.Actual = Conflict, recorded, actual
			}
			results = append(results, r)
			continue
		}
		e, err := c.AddEvidence(ctx, cd.abs, filepath.FromSlash(cd.rel), readOrigin(cd.abs, cd.fi))
		switch {
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case err != nil:
			r.Status, r.Reason = Failed, reason(err)
		default:
			r.Status, r.SHA256 = Collected, e.SHA256
		}
		results = append(results, r)
	}
	return results, nil
}

func reason(err error) string {
	if isLocked(err) {
		return "locked by the system: live collection is not supported"
	}
	return err.Error()
}

// hashFile calcule en flux le SHA-256 d'une source, sans rien écrire.
func hashFile(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, ctxReader{ctx, f}); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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

func resolve(p string) (string, error) {
	a, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(a)
}
