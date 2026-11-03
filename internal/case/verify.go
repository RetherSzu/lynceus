package casefile

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

const (
	StatusOK        = "OK"
	StatusModified  = "MODIFIED"
	StatusMissing   = "MISSING"
	StatusUntracked = "UNTRACKED"
)

type VerifyResult struct {
	File     string
	Status   string
	Expected string // empreinte du manifeste, vide pour UNTRACKED
	Actual   string // empreinte recalculée, vide pour MISSING et UNTRACKED
}

// Verify recalcule l'empreinte de chaque preuve du manifeste et signale les
// fichiers de evidence/ absents du manifeste. Les résultats sont triés par chemin.
func (c *Case) Verify(ctx context.Context) ([]VerifyResult, error) {
	entries, err := c.manifest()
	if err != nil {
		return nil, err
	}
	evidence := c.Dir("evidence")
	known := make(map[string]bool, len(entries))
	var results []VerifyResult
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		known[e.File] = true
		r := VerifyResult{File: e.File, Expected: e.SHA256}
		path := filepath.Join(evidence, filepath.FromSlash(e.File))
		fi, err := os.Lstat(path)
		switch {
		case os.IsNotExist(err):
			r.Status = StatusMissing
		case err != nil:
			return nil, err
		case !fi.Mode().IsRegular():
			r.Status = StatusModified
		default:
			sum, size, err := hashFile(func(r io.Reader) io.Reader { return ctxReader{ctx, r} }, path)
			if err != nil {
				return nil, err
			}
			r.Actual, r.Status = sum, StatusOK
			if sum != e.SHA256 || size != e.Size {
				r.Status = StatusModified
			}
		}
		results = append(results, r)
	}

	err = filepath.WalkDir(evidence, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(evidence, path)
		if err != nil {
			return err
		}
		if file := filepath.ToSlash(rel); !known[file] {
			results = append(results, VerifyResult{File: file, Status: StatusUntracked})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(results, func(i, j int) bool { return results[i].File < results[j].File })
	return results, nil
}

// ctxReader interrompt une lecture longue quand le contexte est annulé.
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
