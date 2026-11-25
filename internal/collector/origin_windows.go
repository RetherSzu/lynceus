//go:build windows

package collector

import (
	"io/fs"
	"syscall"
	"time"

	casefile "DFIRFlow/internal/case"
)

// platformTimes ajoute création et accès ; Windows n'a pas d'horodatage de changement.
func platformTimes(fi fs.FileInfo, o *casefile.Origin) {
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return
	}
	o.Created = utcPtr(time.Unix(0, d.CreationTime.Nanoseconds()))
	o.Accessed = utcPtr(time.Unix(0, d.LastAccessTime.Nanoseconds()))
}
