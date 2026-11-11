package streamtransport

import "strings"

const GenericQUICALPN = "splicore-stream/1"

// NativeStream identifies only the Phase31 Splicore peer wire contracts.
func (c Config) NativeStream() bool {
	return c.Type() == "http" || c.Type() == "h2" || c.Type() == "quic-stream"
}

func validNativeHTTPPath(path string) bool {
	if strings.ContainsAny(path, "%\\") || strings.HasPrefix(path, "//") {
		return false
	}
	for part := range strings.SplitSeq(path, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}
