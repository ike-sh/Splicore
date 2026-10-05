package sqlite

import (
	"context"
	"database/sql"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"time"
)

func (s *Store) Bindings(ctx context.Context, id identity.ID) ([]access.Binding, error) {
	if id.Validate() != nil {
		return nil, identity.Err(identity.Invalid, "invalid inbound ID")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,account_id,inbound_id,credential_id,enabled,policy_override_id,revision,created_at,updated_at FROM bindings WHERE inbound_id=? ORDER BY id", id)
	if err != nil {
		return nil, storageError(err)
	}
	defer rows.Close()
	out := []access.Binding{}
	for rows.Next() {
		var b access.Binding
		var policy sql.NullString
		var created, updated string
		if err = rows.Scan(&b.ID, &b.AccountID, &b.InboundID, &b.CredentialID, &b.Enabled, &policy, &b.Revision, &created, &updated); err != nil {
			return nil, storageError(err)
		}
		if policy.Valid {
			v := identity.ID(policy.String)
			b.PolicyOverrideID = &v
		}
		b.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, identity.Err(identity.Corrupt, "invalid binding timestamp")
		}
		b.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
		if err != nil || b.Validate() != nil {
			return nil, identity.Err(identity.Corrupt, "invalid binding")
		}
		out = append(out, b)
	}
	return out, storageError(rows.Err())
}
func (w *writer) SetBindingEnabled(id identity.ID, enabled bool, expected identity.Revision) error {
	if id.Validate() != nil {
		return identity.Err(identity.Invalid, "invalid binding ID")
	}
	var current identity.Revision
	if err := w.tx.QueryRowContext(w.ctx, "SELECT revision FROM bindings WHERE id=?", id).Scan(&current); err != nil {
		return storageError(err)
	}
	if current != expected {
		return identity.RevisionConflict(current)
	}
	next, err := current.Next()
	if err != nil {
		return err
	}
	return w.exec("UPDATE bindings SET enabled=?,revision=?,updated_at=? WHERE id=?", enabled, next, utc(time.Now()), id)
}
