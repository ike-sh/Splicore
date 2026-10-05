package ports

import (
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
)

// CreationCodec validates a bounded command and generates typed credentials.
// Protocol code never owns transactions, storage, HTTP, or runtime lifecycle.
type CreationCodec interface {
	DecodeCreation(json.RawMessage) (CreationDraft, error)
	GenerateCreationCredential(access.Payload) (access.Payload, error)
}

// ServerMaterializer creates server secrets after plan validation, before pending.
// Settings contain only public, durable configuration; payloads use the vault.
type ServerMaterializer interface {
	MaterializeCreation(CreationDraft) (CreationDraft, error)
}
type PolicyDraft struct {
	QuotaBytes  *int64 `json:"quota_bytes,omitempty"`
	UploadBps   *int64 `json:"upload_bps,omitempty"`
	DownloadBps *int64 `json:"download_bps,omitempty"`
}
type CreationUser struct {
	Name                    string
	Enabled, AccountEnabled bool
	Payload                 access.Payload
	Policy                  *PolicyDraft
}
type CreationDraft struct {
	Name              string
	Engine            string
	Protocol          access.ProtocolKey
	Transport         string
	Listener, Display access.Endpoint
	Settings          json.RawMessage
	Users             []CreationUser
	TLSVerification   bool
	ServerPayloads    []access.Payload
}

func (CreationDraft) Format(s fmt.State, v rune) { _, _ = s.Write([]byte("CreationDraft{[REDACTED]}")) }
