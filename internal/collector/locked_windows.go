//go:build windows

package collector

import (
	"errors"
	"syscall"
)

// isLocked reconnaît ERROR_SHARING_VIOLATION (32) et ERROR_LOCK_VIOLATION (33).
func isLocked(err error) bool {
	return errors.Is(err, syscall.Errno(32)) || errors.Is(err, syscall.Errno(33))
}
