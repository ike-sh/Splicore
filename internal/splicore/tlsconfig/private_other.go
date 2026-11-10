//go:build !windows

package tlsconfig

func platformTLS(string, bool) error { return nil }
