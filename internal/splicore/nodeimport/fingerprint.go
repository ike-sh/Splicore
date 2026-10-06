package nodeimport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/provider"
	"strings"
)

// Fingerprint is a matching hint, never the Node ID. It excludes credentials,
// labels, ownership, display order and operator metadata.
func Fingerprint(n client.RemoteNode) string {
	n.ID = ""
	n.CredentialID = ""
	n.Name = ""
	n.Provenance = provider.Provenance{}
	n.Metadata = identity.Metadata{}
	n.Tags = nil
	n.Disabled = false
	n.State = ""
	n.Endpoint.Host = strings.ToLower(strings.TrimSuffix(n.Endpoint.Host, "."))
	var options any
	if json.Unmarshal(n.Options.Data, &options) == nil {
		n.Options.Data, _ = json.Marshal(options)
	}
	b, _ := json.Marshal(n)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func LogicalKey(c Candidate) string {
	if c.Key != "" {
		h := sha256.Sum256([]byte("Splicore/native-key/1/" + c.Key))
		return "native:" + hex.EncodeToString(h[:])
	}
	return "fingerprint:" + Fingerprint(c.Node)
}
