package secret

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestRedaction(t *testing.T) {
	for _, dummy := range []string{"dummy-psk", "dummy-password", "dummy-token", "dummy-api-token", "dummy-subscription-token", "dummy-private-key", "dummy-credential-payload", "vless://dummy@example.com"} {
		v := New(dummy)
		if v.Reveal() != dummy || v.Empty() {
			t.Fatal("explicit secret access failed")
		}
		for _, format := range []string{"%s", "%v", "%+v", "%#v", "%q"} {
			if s := fmt.Sprintf(format, struct{ Secret Value }{v}); strings.Contains(s, dummy) {
				t.Fatal("format leaked secret")
			}
		}
		b, _ := json.Marshal(v)
		if string(b) != `"[REDACTED]"` {
			t.Fatal("JSON leaked secret")
		}
	}
}
