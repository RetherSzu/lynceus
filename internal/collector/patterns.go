package collector

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// pattern désigne un type d'artefact : une suite de répertoires sous la racine
// du volume et une extension, comparées sans tenir compte de la casse.
type pattern struct {
	name string
	dirs []string
	ext  string
}

// patterns est la liste des artefacts collectés, versionnée avec le binaire.
var patterns = []pattern{
	{"evtx", []string{"Windows", "System32", "winevt", "Logs"}, ".evtx"},
}

// candidate est une entrée repérée sous la cible ; skip est non vide si elle
// ne doit pas être collectée.
type candidate struct {
	rel  string // relatif à la cible, séparateur "/", casse réelle
	abs  string
	fi   fs.FileInfo // Lstat, lu avant toute copie
	skip string
}

const notRegular = "not a regular file"

// find résout les motifs sous root sans parcourir le reste du volume. Les liens
// et points de jonction ne sont jamais suivis : ils deviennent des candidats à ignorer.
func find(root string) ([]candidate, error) {
	var out []candidate
	for _, p := range patterns {
		dirs := []string{""}
		for _, want := range p.dirs {
			var next []string
			for _, d := range dirs {
				entries, err := readDir(root, d)
				if err != nil {
					return nil, err
				}
				for _, e := range entries {
					if !strings.EqualFold(e.Name(), want) {
						continue
					}
					rel := path.Join(d, e.Name())
					switch {
					case e.Type().IsDir():
						next = append(next, rel)
					case e.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0:
						out = append(out, candidate{rel: rel, abs: abs(root, rel), skip: notRegular})
					}
				}
			}
			dirs = next
		}
		for _, d := range dirs {
			entries, err := readDir(root, d)
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				if !strings.EqualFold(path.Ext(e.Name()), p.ext) || e.IsDir() {
					continue
				}
				c := candidate{rel: path.Join(d, e.Name()), abs: abs(root, path.Join(d, e.Name()))}
				if c.fi, err = e.Info(); err != nil {
					return nil, err
				}
				if !c.fi.Mode().IsRegular() {
					c.skip = notRegular
				}
				out = append(out, c)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out, nil
}

func abs(root, rel string) string { return filepath.Join(root, filepath.FromSlash(rel)) }

func readDir(root, rel string) ([]fs.DirEntry, error) {
	entries, err := os.ReadDir(abs(root, rel))
	if os.IsNotExist(err) {
		return nil, nil
	}
	return entries, err
}
