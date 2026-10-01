package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"time"
)

func (s *Store) BeginOperation(ctx context.Context, expected identity.Revision, actor identity.Actor) (identity.Transaction, error) {
	return s.BeginRuntimeOperation(ctx, expected, actor, "snell_create")
}
func (s *Store) BeginRuntimeOperation(ctx context.Context, expected identity.Revision, actor identity.Actor, operation string) (identity.Transaction, error) {
	if operation != "snell_create" && operation != "runtime_create" && operation != "runtime_replace" {
		return identity.Transaction{}, identity.Err(identity.Invalid, "unsupported runtime operation")
	}
	if err := actor.Validate(); err != nil {
		return identity.Transaction{}, err
	}
	next, err := expected.Next()
	if err != nil {
		return identity.Transaction{}, err
	}
	id, err := identity.NewID()
	if err != nil {
		return identity.Transaction{}, err
	}
	now := time.Now().UTC()
	op := identity.Transaction{ID: id, State: identity.Pending, BaseRevision: expected, TargetRevision: next, Actor: actor, CreatedAt: now, UpdatedAt: now}
	s.write.Lock()
	defer s.write.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return op, storageError(err)
	}
	defer tx.Rollback()
	var current identity.Revision
	var pending int
	if err = tx.QueryRowContext(ctx, "SELECT committed_revision FROM settings WHERE singleton=1").Scan(&current); err != nil {
		return op, storageError(err)
	}
	if current != expected {
		return op, identity.RevisionConflict(current)
	}
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM transactions WHERE state='pending'").Scan(&pending); err != nil {
		return op, storageError(err)
	}
	if pending != 0 {
		return op, identity.Err(identity.Unavailable, "pending operation requires recovery")
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO transactions(id,state,base_revision,target_revision,principal,request_id,created_at,updated_at,operation) VALUES(?,?,?,?,?,?,?,?,?)", id, "pending", expected, next, actor.Principal, actor.RequestID, utc(now), utc(now), operation)
	if err != nil {
		return op, storageError(err)
	}
	return op, storageError(tx.Commit())
}
func (s *Store) CommitOperation(ctx context.Context, op identity.Transaction, fn func(ports.Writer) error) error {
	s.write.Lock()
	defer s.write.Unlock()
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM transactions WHERE id=? AND state='pending' AND base_revision=? AND target_revision=? AND operation IN ('snell_create','runtime_create','runtime_replace')", op.ID, op.BaseRevision, op.TargetRevision).Scan(&count); err != nil {
		return storageError(err)
	}
	if count != 1 || fn == nil {
		return identity.Err(identity.Invalid, "invalid pending operation")
	}
	return s.apply(ctx, op, fn)
}
func (s *Store) FailOperation(ctx context.Context, op identity.Transaction) error {
	s.write.Lock()
	defer s.write.Unlock()
	_, e := s.db.ExecContext(ctx, "UPDATE transactions SET state='failed',failure_code='unavailable',updated_at=? WHERE id=? AND state='pending' AND operation IN ('snell_create','runtime_create','runtime_replace')", utc(time.Now()), op.ID)
	return storageError(e)
}
func (s *Store) RecoverPending(ctx context.Context) error {
	s.write.Lock()
	defer s.write.Unlock()
	// Owned processes are gone at restart; committed rows reconstruct both creates and replacements.
	_, err := s.db.ExecContext(ctx, "UPDATE transactions SET state='failed',failure_code='unavailable',updated_at=? WHERE state='pending' AND operation IN ('snell_create','runtime_create','runtime_replace')", utc(time.Now()))
	return storageError(err)
}
func (s *Store) Inbounds(ctx context.Context) ([]access.Inbound, error) {
	s.write.Lock()
	defer s.write.Unlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, storageError(err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT id,node_id,name,protocol,wire_version,feature_profile,engine,enabled,settings_schema,settings,tags,revision,created_at,updated_at FROM inbounds ORDER BY id")
	if err != nil {
		return nil, storageError(err)
	}
	out := []access.Inbound{}
	for rows.Next() {
		var i access.Inbound
		var data, tags, created, updated string
		if err = rows.Scan(&i.ID, &i.NodeID, &i.Name, &i.Protocol.Protocol, &i.Protocol.WireVersion, &i.Protocol.FeatureProfile, &i.Engine, &i.Enabled, &i.Settings.Schema, &data, &tags, &i.Revision, &created, &updated); err != nil {
			break
		}
		i.Settings.Data = json.RawMessage(data)
		i.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			break
		}
		i.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
		if err != nil {
			break
		}
		if err = json.Unmarshal([]byte(tags), &i.Tags); err != nil {
			break
		}
		out = append(out, i)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, identity.Err(identity.Corrupt, "invalid committed inbound")
	}
	for n := range out {
		i := &out[n]
		rows, err = tx.QueryContext(ctx, "SELECT id,transport,host,port FROM listeners WHERE inbound_id=? ORDER BY id", i.ID)
		if err != nil {
			return nil, storageError(err)
		}
		for rows.Next() {
			var l access.Listener
			if err = rows.Scan(&l.ID, &l.Transport, &l.Endpoint.Host, &l.Endpoint.Port); err != nil {
				break
			}
			i.Listeners = append(i.Listeners, l)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return nil, storageError(err)
		}
		rows, err = tx.QueryContext(ctx, "SELECT id,host,port,priority FROM display_endpoints WHERE inbound_id=? ORDER BY priority,id", i.ID)
		if err != nil {
			return nil, storageError(err)
		}
		for rows.Next() {
			var e access.DisplayEndpoint
			if err = rows.Scan(&e.ID, &e.Endpoint.Host, &e.Endpoint.Port, &e.Priority); err != nil {
				break
			}
			i.DisplayEndpoints = append(i.DisplayEndpoints, e)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return nil, storageError(err)
		}
		if i.Validate() != nil {
			return nil, identity.Err(identity.Corrupt, "invalid committed inbound")
		}
	}
	return out, nil
}

// Binding resolves the sole binding of an inbound, never an arbitrary user.
func (s *Store) Binding(ctx context.Context, id identity.ID) (access.Binding, error) {
	var b access.Binding
	var policy sql.NullString
	var created, updated string
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM bindings WHERE inbound_id=?", id).Scan(&count); err != nil {
		return b, storageError(err)
	}
	if count != 1 {
		return b, identity.Err(identity.Corrupt, "inbound requires exactly one binding")
	}
	err := s.db.QueryRowContext(ctx, "SELECT id,account_id,inbound_id,credential_id,enabled,policy_override_id,revision,created_at,updated_at FROM bindings WHERE inbound_id=?", id).Scan(&b.ID, &b.AccountID, &b.InboundID, &b.CredentialID, &b.Enabled, &policy, &b.Revision, &created, &updated)
	if err != nil {
		return b, storageError(err)
	}
	if policy.Valid {
		v := identity.ID(policy.String)
		b.PolicyOverrideID = &v
	}
	b.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return b, identity.Err(identity.Corrupt, "invalid binding timestamp")
	}
	b.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	if err != nil || b.Validate() != nil {
		return b, identity.Err(identity.Corrupt, "invalid committed binding")
	}
	return b, nil
}
func (s *Store) UpdateDisplay(ctx context.Context, id identity.ID, e access.Endpoint, resource, global identity.Revision, actor identity.Actor) (identity.Transaction, error) {
	if err := e.Validate(); err != nil {
		return identity.Transaction{}, err
	}
	if err := id.Validate(); err != nil {
		return identity.Transaction{}, err
	}
	return s.Transact(ctx, global, actor, func(w ports.Writer) error {
		writer := w.(*writer)
		var current identity.Revision
		var protocol string
		if err := writer.tx.QueryRowContext(ctx, "SELECT revision,protocol FROM inbounds WHERE id=?", id).Scan(&current, &protocol); err != nil {
			return storageError(err)
		}
		if current != resource {
			return identity.RevisionConflict(current)
		}
		if protocol != "snell" && protocol != "hysteria2" {
			return identity.Err(identity.NotImplemented, "display mutation unsupported")
		}
		next, err := current.Next()
		if err != nil {
			return err
		}
		if err = writer.exec("UPDATE display_endpoints SET host=?,port=? WHERE inbound_id=?", e.Host, e.Port, id); err != nil {
			return err
		}
		return writer.exec("UPDATE inbounds SET revision=?,updated_at=? WHERE id=?", next, utc(time.Now()), id)
	})
}
