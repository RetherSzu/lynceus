package collector

import (
	"io/fs"
	"time"

	casefile "DFIRFlow/internal/case"
)

// readOrigin relève les métadonnées d'origine d'un fichier à partir de son
// Lstat, lu avant la copie ; un horodatage indisponible reste nil.
func readOrigin(abs string, fi fs.FileInfo) *casefile.Origin {
	mod := fi.ModTime().UTC()
	o := &casefile.Origin{SourcePath: abs, Modified: &mod}
	platformTimes(fi, o)
	return o
}

func utcPtr(t time.Time) *time.Time {
	t = t.UTC()
	return &t
}
