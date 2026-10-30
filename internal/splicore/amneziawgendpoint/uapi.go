package amneziawgendpoint

import (
	"encoding/hex"
	"fmt"
	"strings"

	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
)

// obfuscationUAPI is used only after validation, at the sensitive device
// boundary. It must never be logged, returned through status, or persisted.
func obfuscationUAPI(c E.AmneziaWG) string {
	var b strings.Builder
	fmt.Fprintf(&b, "jc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d\ns3=%d\ns4=%d\n", c.Jc, c.Jmin, c.Jmax, c.S1, c.S2, c.S3, c.S4)
	for i, h := range c.Headers() {
		fmt.Fprintf(&b, "h%d=%s\n", i+1, h)
	}
	for i, s := range c.Signatures() {
		if s != "" {
			fmt.Fprintf(&b, "i%d=%s\n", i+1, s)
		}
	}
	key := c.HeaderProtectionKey.Reveal()
	fmt.Fprintf(&b, "header_protection_key=%s\n", hex.EncodeToString(key[:]))
	fmt.Fprintf(&b, "content_padding_addition=%s\nrekey_after_time=%s\nrekey_timeout=%s\nreject_after_time=%s\nkeepalive_timeout=%s\nmax_handshake_attempts=%s\nrandom_trailers=false\ndisable_cookies=%t\n", c.ContentPaddingAddition, c.RekeyAfterTime, c.RekeyTimeout, c.RejectAfterTime, c.KeepaliveTimeout, c.MaxHandshakeAttempts, c.DisableCookies)
	return b.String()
}
