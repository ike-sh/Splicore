package cli

import (
	"flag"
	"io"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/protocol/vless/encryption"
)

// This is an explicit stateless secret-generation tool, with no persistence or
// alternate application service. Ordinary CLI error output never prints inputs.
func vlessEncryptionCLI(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("vlessenc", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	auth := fs.String("auth", "x25519", "static authentication: x25519 or mlkem768")
	mode := fs.String("mode", "native", "native, xorpub, random")
	policy := fs.String("handshake", "0rtt", "0rtt or 1rtt")
	duration := fs.String("ticket", "600s", "server ticket duration")
	padding := fs.String("padding", "", "optional padding tuples")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return failure(errOut, identity.Err(identity.Invalid, "invalid VLESS encryption generator options"))
	}
	server, client, e := encryption.Generate(*auth, *mode, *policy, *duration, *padding)
	if e != nil {
		return failure(errOut, identity.Err(identity.Invalid, "invalid VLESS encryption generator options"))
	}
	return outputJSON(out, map[string]string{"decryption": server, "encryption": client})
}
