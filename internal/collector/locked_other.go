//go:build !windows

package collector

func isLocked(error) bool { return false }
