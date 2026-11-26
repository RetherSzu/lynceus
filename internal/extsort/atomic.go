package extsort

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
)

// WriteAtomic écrit out.partial via write, puis le renomme en out et renvoie
// le SHA-256 du contenu ; le .partial est supprimé sur toute erreur.
func WriteAtomic(out string, write func(io.Writer) error) (string, error) {
	tmp := out + ".partial"
	fh, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	bw := bufio.NewWriterSize(io.MultiWriter(fh, h), 1<<16)
	err = write(bw)
	if err == nil {
		err = bw.Flush()
	}
	if err == nil {
		err = fh.Sync()
	}
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, out)
	}
	if err != nil {
		os.Remove(tmp)
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CleanStale supprime dir/name.partial et les dossiers de travail dir/.work-*
// laissés par un arrêt brutal.
func CleanStale(dir, name string) {
	// shortcut: suppose une seule exécution à la fois sur le cas, à revoir avec un verrou de cas.
	os.Remove(filepath.Join(dir, name+".partial"))
	olds, _ := filepath.Glob(filepath.Join(dir, ".work-*"))
	for _, o := range olds {
		os.RemoveAll(o)
	}
}
