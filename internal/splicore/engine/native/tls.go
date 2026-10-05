package native

import "github.com/sagernet/sing-box/internal/splicore/tlsconfig"

func tlsSnapshot(settings tlsconfig.Settings) ([]byte, []byte, error) {
	return tlsconfig.Snapshot(settings)
}
