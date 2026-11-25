//go:build linux

package collector

import (
	"io/fs"
	"syscall"
	"time"

	casefile "DFIRFlow/internal/case"
)

// platformTimes ajoute accès et changement ; la création demanderait statx,
// absent de la bibliothèque standard en Go 1.18 (research.md R2).
func platformTimes(fi fs.FileInfo, o *casefile.Origin) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	o.Accessed = utcPtr(time.Unix(int64(st.Atim.Sec), int64(st.Atim.Nsec)))
	o.Changed = utcPtr(time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)))
}
