package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/ike-sh/Splicore/protocol/vless/encryption"
)

func TestVLESSEncryptionGenerator(t *testing.T) {
	for _, auth := range []string{"x25519", "mlkem768"} {
		for _, mode := range []string{"native", "xorpub", "random"} {
			var out, errOut bytes.Buffer
			if Run(context.Background(), []string{"vlessenc", "--auth", auth, "--mode", mode, "--handshake", "1rtt", "--ticket", "100-200s", "--padding", "100-35-35"}, &out, &errOut, Dependencies{}) != 0 {
				t.Fatal(errOut.String())
			}
			var pair map[string]string
			if e := json.Unmarshal(out.Bytes(), &pair); e != nil {
				t.Fatal(e)
			}
			server, e := encryption.ParseServer(pair["decryption"])
			if e != nil {
				t.Fatal(e)
			}
			if server.ClientString(false) != pair["encryption"] {
				t.Fatal("generated pair mismatch")
			}
		}
	}
	var out, errOut bytes.Buffer
	if Run(context.Background(), []string{"vlessenc", "--mode", "synthetic-secret"}, &out, &errOut, Dependencies{}) == 0 || bytes.Contains(errOut.Bytes(), []byte("synthetic-secret")) {
		t.Fatal("generator input/error redaction")
	}
}
