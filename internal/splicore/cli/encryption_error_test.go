package cli

import (
	"bytes"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"strings"
	"testing"
)

func TestEncryptionFailureNeverPrintsCallerMaterial(t *testing.T) {
	for _, message := range []string{"invalid VLESS encryption configuration", "synthetic-private-key", "invalid VLESS encryption configuration" + " synthetic-private-key"} {
		var output bytes.Buffer
		if failure(&output, identity.Err(identity.Invalid, message)) != 1 {
			t.Fatal("missing failure")
		}
		if strings.Contains(output.String(), "synthetic-private-key") {
			t.Fatal("untrusted error disclosed")
		}
	}
}
