package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
)

// No public serializers use this storage-only plaintext representation.
func encodePayload(payload access.Payload) ([]byte, error) {
	var fields []string
	switch p := payload.(type) {
	case access.PSKPayload:
		fields = []string{p.Key.Reveal()}
	case access.PasswordPayload:
		fields = []string{p.Password.Reveal()}
	case access.UUIDPayload:
		fields = []string{p.UUID.Reveal()}
	case access.UUIDPasswordPayload:
		fields = []string{p.UUID.Reveal(), p.Password.Reveal()}
	case access.UsernamePasswordPayload:
		fields = []string{p.Username.Reveal(), p.Password.Reveal()}
	default:
		return nil, identity.Err(identity.Invalid, "unsupported credential payload type")
	}
	return json.Marshal(fields)
}

func decodePayload(kind access.CredentialKind, b []byte) (access.Payload, error) {
	var f []string
	if json.Unmarshal(b, &f) != nil {
		return nil, identity.Err(identity.Corrupt, "invalid encrypted credential payload")
	}
	var p access.Payload
	switch {
	case kind == access.PSK && len(f) == 1:
		p = access.PSKPayload{Key: secret.New(f[0])}
	case kind == access.Password && len(f) == 1:
		p = access.PasswordPayload{Password: secret.New(f[0])}
	case kind == access.UUID && len(f) == 1:
		p = access.UUIDPayload{UUID: secret.New(f[0])}
	case kind == access.UUIDPassword && len(f) == 2:
		p = access.UUIDPasswordPayload{UUID: secret.New(f[0]), Password: secret.New(f[1])}
	case kind == access.UsernamePassword && len(f) == 2:
		p = access.UsernamePasswordPayload{Username: secret.New(f[0]), Password: secret.New(f[1])}
	default:
		return nil, identity.Err(identity.Corrupt, "invalid encrypted credential payload")
	}
	if p.Validate() != nil {
		return nil, identity.Err(identity.Corrupt, "invalid encrypted credential payload")
	}
	return p, nil
}

func credentialAAD(c access.Credential) []byte {
	account, inbound := "", ""
	if c.OwnerAccountID != nil {
		account = string(*c.OwnerAccountID)
	}
	if c.OwnerInboundID != nil {
		inbound = string(*c.OwnerInboundID)
	}
	return []byte(fmt.Sprintf("Splicore/credential/%s/%s/%s/%s/%d", c.ID, account, inbound, c.Kind, c.Schema))
}

// RevealCredential is an explicit secret read, never called by API/CLI/doctor.
// A future runtime/export application must authorize the projection before invoking it.
func (s *Store) RevealCredential(ctx context.Context, id identity.ID) (access.Credential, error) {
	if s.options.Cipher == nil {
		return access.Credential{}, identity.Err(identity.Unavailable, "credential key provisioning is required")
	}
	var c access.Credential
	var account, inbound sql.NullString
	var data []byte
	var keyID, created, updated string
	err := s.db.QueryRowContext(ctx, "SELECT id,account_id,inbound_id,kind,schema_version,ciphertext,key_id,state,revision,created_at,updated_at FROM credentials WHERE id=?", id).Scan(&c.ID, &account, &inbound, &c.Kind, &c.Schema, &data, &keyID, &c.State, &c.Revision, &created, &updated)
	if err != nil {
		return c, storageError(err)
	}
	if account.Valid {
		v := identity.ID(account.String)
		c.OwnerAccountID = &v
	}
	if inbound.Valid {
		v := identity.ID(inbound.String)
		c.OwnerInboundID = &v
	}
	if keyID != s.options.Cipher.KeyID() {
		return access.Credential{}, identity.Err(identity.Unavailable, "credential encryption key unavailable")
	}
	plain, err := s.options.Cipher.Open(data, credentialAAD(c))
	if err != nil {
		return access.Credential{}, err
	}
	defer clear(plain)
	c.Payload, err = decodePayload(c.Kind, plain)
	if err != nil {
		return access.Credential{}, err
	}
	c.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return access.Credential{}, identity.Err(identity.Corrupt, "invalid credential timestamp")
	}
	c.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	if err != nil || c.Validate() != nil {
		return access.Credential{}, identity.Err(identity.Corrupt, "invalid stored credential")
	}
	return c, nil
}
