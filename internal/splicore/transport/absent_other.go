//go:build !windows

package transport

func platformAbsent(error) bool { return false }
