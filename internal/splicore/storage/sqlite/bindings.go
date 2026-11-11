package sqlite

import (
	"context"
	"database/sql"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
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
	stamp, err := w.bindingUpdateStamp(id, expected)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	return w.setBindingEnabled(id, enabled, stamp, updateTime(now, stamp))
}

func (w *writer) bindingUpdateStamp(id identity.ID, expected identity.Revision) (identity.Stamp, error) {
	if id.Validate() != nil {
		return identity.Stamp{}, identity.Err(identity.Invalid, "invalid binding ID")
	}
	var current identity.Revision
	var created, updated string
	if err := w.tx.QueryRowContext(w.ctx, "SELECT revision,created_at,updated_at FROM bindings WHERE id=?", id).Scan(&current, &created, &updated); err != nil {
		return identity.Stamp{}, storageError(err)
	}
	if current != expected {
		return identity.Stamp{}, identity.RevisionConflict(current)
	}
	return storedStamp(current, created, updated, "binding")
}

func (w *writer) setBindingEnabled(id identity.ID, enabled bool, stamp identity.Stamp, updated time.Time) error {
	next, err := stamp.Revision.Next()
	if err != nil {
		return err
	}
	return w.exec("UPDATE bindings SET enabled=?,revision=?,updated_at=? WHERE id=?", enabled, next, utc(updated), id)
}
