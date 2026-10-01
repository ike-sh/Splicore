package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/policy"
)

type writer struct {
	ctx     context.Context
	tx      *sql.Tx
	options Options
}

func (w *writer) exec(query string, args ...any) error {
	_, err := w.tx.ExecContext(w.ctx, query, args...)
	return storageError(err)
}

func initial(s identity.Stamp) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if s.Revision != 1 {
		return identity.Err(identity.Invalid, "new resource revision must be one")
	}
	return nil
}

func (w *writer) CreateAccount(a access.Account) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if err := initial(a.Stamp); err != nil {
		return err
	}
	m, err := json.Marshal(a.Metadata)
	if err != nil {
		return identity.Err(identity.Invalid, "invalid metadata")
	}
	return w.exec("INSERT INTO accounts VALUES(?,?,?,?,?,?,?,?,?)", a.ID, a.Name, a.Status, a.Enabled, expiry(a.ExpiresAt), string(m), a.Revision, utc(a.CreatedAt), utc(a.UpdatedAt))
}

func (w *writer) UpdateAccount(a access.Account, expected identity.Revision) error {
	if err := a.Validate(); err != nil {
		return err
	}
	old, err := readAccount(w.tx.QueryRowContext(w.ctx, "SELECT id,name,status,enabled,expires_at,metadata,revision,created_at,updated_at FROM accounts WHERE id=?", a.ID))
	if err != nil {
		return err
	}
	if old.Revision != expected {
		return identity.RevisionConflict(old.Revision)
	}
	next, err := expected.Next()
	if err != nil {
		return err
	}
	m, err := json.Marshal(a.Metadata)
	if err != nil {
		return identity.Err(identity.Invalid, "invalid metadata")
	}
	return w.exec("UPDATE accounts SET name=?,status=?,enabled=?,expires_at=?,metadata=?,revision=?,updated_at=? WHERE id=? AND revision=?", a.Name, a.Status, a.Enabled, expiry(a.ExpiresAt), string(m), next, utc(time.Now()), a.ID, expected)
}

func expiry(t *time.Time) any {
	if t == nil {
		return nil
	}
	return utc(*t)
}

func (w *writer) CreateInbound(i access.Inbound) error {
	if err := i.Validate(); err != nil {
		return err
	}
	if err := initial(i.Stamp); err != nil {
		return err
	}
	if w.options.ValidateInbound != nil {
		if err := w.options.ValidateInbound(i); err != nil {
			return err
		}
	} else {
		var fields map[string]json.RawMessage
		if json.Unmarshal(i.Settings.Data, &fields) != nil || fields == nil || len(fields) != 0 {
			return identity.Err(identity.NotImplemented, "protocol settings persistence is deferred")
		}
	}
	if w.options.CredentialKinds == nil {
		return identity.Err(identity.Unavailable, "protocol metadata resolver unavailable")
	}
	if _, err := w.options.CredentialKinds(i.Protocol); err != nil {
		return err
	}
	tags, _ := json.Marshal(i.Tags)
	if err := w.exec("INSERT INTO inbounds VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", i.ID, i.NodeID, i.Name, i.Protocol.Protocol, i.Protocol.WireVersion, i.Protocol.FeatureProfile, i.Engine, i.Enabled, i.Settings.Schema, string(i.Settings.Data), string(tags), i.Revision, utc(i.CreatedAt), utc(i.UpdatedAt)); err != nil {
		return err
	}
	for _, l := range i.Listeners {
		if err := w.exec("INSERT INTO listeners VALUES(?,?,?,?,?)", l.ID, i.ID, l.Transport, l.Endpoint.Host, l.Endpoint.Port); err != nil {
			return err
		}
	}
	for _, e := range i.DisplayEndpoints {
		if err := w.exec("INSERT INTO display_endpoints VALUES(?,?,?,?,?)", e.ID, i.ID, e.Endpoint.Host, e.Endpoint.Port, e.Priority); err != nil {
			return err
		}
	}
	return nil
}

func (w *writer) CreateCredential(c access.Credential) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := initial(c.Stamp); err != nil {
		return err
	}
	if w.options.Cipher == nil {
		return identity.Err(identity.Unavailable, "credential key provisioning is required")
	}
	plain, err := encodePayload(c.Payload)
	if err != nil {
		return err
	}
	defer clear(plain)
	data, err := w.options.Cipher.Seal(plain, credentialAAD(c))
	if err != nil {
		return err
	}
	return w.exec("INSERT INTO credentials VALUES(?,?,?,?,?,?,?,?,?,?,?)", c.ID, c.OwnerAccountID, c.OwnerInboundID, c.Kind, c.Schema, data, w.options.Cipher.KeyID(), c.State, c.Revision, utc(c.CreatedAt), utc(c.UpdatedAt))
}

func (w *writer) CreateBinding(b access.Binding) error {
	if err := b.Validate(); err != nil {
		return err
	}
	if err := initial(b.Stamp); err != nil {
		return err
	}
	var owner, kind, state string
	var key access.ProtocolKey
	if err := w.tx.QueryRowContext(w.ctx, "SELECT account_id,kind,state FROM credentials WHERE id=?", b.CredentialID).Scan(&owner, &kind, &state); err != nil {
		return storageError(err)
	}
	if owner != string(b.AccountID) || state != "active" {
		return identity.Err(identity.Invalid, "credential owner or state mismatch")
	}
	if err := w.tx.QueryRowContext(w.ctx, "SELECT protocol,wire_version,feature_profile FROM inbounds WHERE id=?", b.InboundID).Scan(&key.Protocol, &key.WireVersion, &key.FeatureProfile); err != nil {
		return storageError(err)
	}
	if w.options.CredentialKinds == nil {
		return identity.Err(identity.Unavailable, "protocol metadata resolver unavailable")
	}
	kinds, err := w.options.CredentialKinds(key)
	if err != nil {
		return err
	}
	if !slices.Contains(kinds, access.CredentialKind(kind)) {
		return identity.Err(identity.Invalid, "credential protocol mismatch")
	}
	return w.exec("INSERT INTO bindings VALUES(?,?,?,?,?,?,?,?,?)", b.ID, b.AccountID, b.InboundID, b.CredentialID, b.Enabled, b.PolicyOverrideID, b.Revision, utc(b.CreatedAt), utc(b.UpdatedAt))
}

func (w *writer) CreatePolicy(p policy.TrafficPolicy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := initial(p.Stamp); err != nil {
		return err
	}
	var reset any
	if p.ResetPolicy != nil {
		b, err := json.Marshal(p.ResetPolicy)
		if err != nil {
			return identity.Err(identity.Invalid, "invalid reset policy")
		}
		reset = string(b)
	}
	return w.exec("INSERT INTO traffic_policies VALUES(?,?,?,?,?,?,?,?,?)", p.ID, p.QuotaBytes, p.UploadBps, p.DownloadBps, reset, p.MaxSessions, p.Revision, utc(p.CreatedAt), utc(p.UpdatedAt))
}
