package native

import "github.com/ike-sh/Splicore/internal/splicore/tlsconfig"

func tlsSnapshot(settings tlsconfig.Settings) ([]byte, []byte, error) {
	return tlsconfig.Snapshot(settings)
}
