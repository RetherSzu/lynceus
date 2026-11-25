//go:build !windows && !linux

package collector

import (
	"io/fs"

	casefile "DFIRFlow/internal/case"
)

// platformTimes : seule la date de modification est portable.
func platformTimes(fs.FileInfo, *casefile.Origin) {}
