// Package sqlite implements durable domain storage behind repository ports.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"

	driver "modernc.org/sqlite"
)

type Options struct {
	Cipher ports.Cipher
	// CredentialKinds is resolved from compiled protocol metadata at composition.
	CredentialKinds func(access.ProtocolKey) ([]access.CredentialKind, error)
	ValidateInbound func(access.Inbound) error
}
type Store struct {
	db        *sql.DB
	lock      *os.File
	options   Options
	write     sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

var _ ports.Repository = (*Store)(nil)

func Open(ctx context.Context, path string, opts Options) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, identity.Err(identity.Invalid, "database path must be absolute")
	}
	path = filepath.Clean(path)
	if err := privateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	for _, suffix := range []string{"", "-wal", "-shm", ".lock"} {
		if err := safeFile(path + suffix); err != nil {
			return nil, err
		}
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, identity.Err(identity.Unavailable, "cannot open installation lock")
	}
	if err = lockFile(lock); err != nil {
		lock.Close()
		return nil, identity.Err(identity.Unavailable, "installation is already owned by another process")
	}
	s := &Store{lock: lock, options: opts}
	failed := true
	defer func() {
		if failed {
			s.Close()
		}
	}()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, identity.Err(identity.Unavailable, "cannot open database file")
	}
	f.Close()
	uriPath := filepath.ToSlash(path)
	if len(filepath.VolumeName(path)) > 0 {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	q := url.Values{}
	for _, p := range []string{"foreign_keys(1)", "busy_timeout(5000)", "journal_mode(WAL)", "synchronous(FULL)"} {
		q.Add("_pragma", p)
	}
	q.Set("_txlock", "immediate")
	u.RawQuery = q.Encode()
	s.db, err = sql.Open("sqlite", u.String())
	if err != nil {
		return nil, storageError(err)
	}
	s.db.SetMaxOpenConns(4)
	s.db.SetMaxIdleConns(4)
	if err = migrate(ctx, s.db, migrations()); err != nil {
		return nil, err
	}
	var count int
	if err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM nodes").Scan(&count); err != nil {
		return nil, storageError(err)
	}
	if count != 1 {
		return nil, identity.Err(identity.Corrupt, "invalid installation identity count")
	}
	if _, err = s.State(ctx); err != nil {
		return nil, err
	}
	for _, suffix := range []string{"", "-wal", "-shm", ".lock"} {
		if err = safeFile(path + suffix); err != nil {
			return nil, err
		}
	}
	failed = false
	return s, nil
}

func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		var err error
		if s.db != nil {
			err = s.db.Close()
		}
		if s.lock != nil {
			unlockFile(s.lock)
			err = errors.Join(err, s.lock.Close())
		}
		s.closeErr = storageError(err)
	})
	return s.closeErr
}

func (s *Store) State(ctx context.Context) (ports.State, error) {
	var out ports.State
	var schema string
	err := s.db.QueryRowContext(ctx, `SELECT n.id,s.committed_revision,m.value,
 (SELECT count(*) FROM transactions WHERE state='pending')
 FROM nodes n CROSS JOIN settings s JOIN metadata m ON m.key='db_schema' WHERE s.singleton=1`).Scan(&out.NodeID, &out.Revision, &schema, &out.PendingTransactions)
	if err != nil {
		return out, identity.Err(identity.Corrupt, "invalid committed state metadata")
	}
	n, err := strconv.Atoi(schema)
	if err != nil || n != len(migrations()) || out.Revision < 0 || out.NodeID.Validate() != nil {
		return ports.State{}, identity.Err(identity.Corrupt, "invalid committed state metadata")
	}
	out.Schema = n
	return out, nil
}

func (s *Store) Account(ctx context.Context, id identity.ID) (access.Account, error) {
	if err := id.Validate(); err != nil {
		return access.Account{}, err
	}
	return readAccount(s.db.QueryRowContext(ctx, "SELECT id,name,status,enabled,expires_at,metadata,revision,created_at,updated_at FROM accounts WHERE id=?", id))
}

func readAccount(row *sql.Row) (access.Account, error) {
	var a access.Account
	var expiry sql.NullString
	var meta, created, updated string
	if err := row.Scan(&a.ID, &a.Name, &a.Status, &a.Enabled, &expiry, &meta, &a.Revision, &created, &updated); err != nil {
		return a, storageError(err)
	}
	var err error
	a.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return a, identity.Err(identity.Corrupt, "invalid stored timestamp")
	}
	a.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		return a, identity.Err(identity.Corrupt, "invalid stored timestamp")
	}
	if expiry.Valid {
		t, err := time.Parse(time.RFC3339Nano, expiry.String)
		if err != nil {
			return a, identity.Err(identity.Corrupt, "invalid stored expiry")
		}
		a.ExpiresAt = &t
	}
	if json.Unmarshal([]byte(meta), &a.Metadata) != nil || a.Validate() != nil {
		return access.Account{}, identity.Err(identity.Corrupt, "invalid stored account")
	}
	return a, nil
}

func (s *Store) Transact(ctx context.Context, expected identity.Revision, actor identity.Actor, fn func(ports.Writer) error) (identity.Transaction, error) {
	if err := actor.Validate(); err != nil {
		return identity.Transaction{}, err
	}
	if fn == nil {
		return identity.Transaction{}, identity.Err(identity.Invalid, "missing transaction command")
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
	_, err = s.db.ExecContext(ctx, "INSERT INTO transactions(id,state,base_revision,target_revision,principal,request_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", op.ID, op.State, expected, next, actor.Principal, actor.RequestID, utc(now), utc(now))
	if err != nil {
		return op, storageError(err)
	}
	err = s.apply(ctx, op, fn)
	if err != nil {
		code := identity.Unavailable
		var de *identity.Error
		if errors.As(err, &de) {
			code = de.Code
		}
		_ = op.Finish(identity.Failed, time.Now(), code)
		// Persist failure with a bounded independent context even after caller cancellation.
		failCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, e := s.db.ExecContext(failCtx, "UPDATE transactions SET state='failed',failure_code=?,updated_at=? WHERE id=? AND state='pending'", code, utc(op.UpdatedAt), op.ID); e != nil {
			return op, identity.Err(identity.Unavailable, "mutation failed; journal requires recovery")
		}
		return op, err
	}
	_ = op.Finish(identity.Committed, time.Now(), "")
	return op, nil
}

func (s *Store) apply(ctx context.Context, op identity.Transaction, fn func(ports.Writer) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError(err)
	}
	defer tx.Rollback()
	var current identity.Revision
	if err = tx.QueryRowContext(ctx, "SELECT committed_revision FROM settings WHERE singleton=1").Scan(&current); err != nil {
		return storageError(err)
	}
	if current != op.BaseRevision {
		return identity.RevisionConflict(current)
	}
	var pending int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM transactions WHERE state='pending' AND id!=?", op.ID).Scan(&pending); err != nil {
		return storageError(err)
	}
	if pending > 0 {
		return identity.Err(identity.Unavailable, "pending journal requires operator review before mutation")
	}
	w := &writer{ctx: ctx, tx: tx, options: s.options}
	if err = fn(w); err != nil {
		return safeCommandError(err)
	}
	if _, err = tx.ExecContext(ctx, "UPDATE settings SET committed_revision=? WHERE singleton=1", op.TargetRevision); err != nil {
		return storageError(err)
	}
	if _, err = tx.ExecContext(ctx, "UPDATE transactions SET state='committed',updated_at=? WHERE id=? AND state='pending'", utc(time.Now()), op.ID); err != nil {
		return storageError(err)
	}
	return storageError(tx.Commit())
}

func safeCommandError(err error) error {
	var de *identity.Error
	if errors.As(err, &de) { // Drop potentially sensitive custom messages.
		if de.Code == identity.Conflict {
			return identity.RevisionConflict(de.Current)
		}
		return identity.Err(de.Code, "domain command rejected")
	}
	return identity.Err(identity.Unavailable, "domain command failed")
}

func storageError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return identity.Err(identity.NotFound, "resource not found")
	}
	var e *driver.Error
	if errors.As(err, &e) {
		switch e.Code() & 255 {
		case 19:
			return identity.Err(identity.Invalid, "database constraint rejected")
		case 11, 26:
			return identity.Err(identity.Corrupt, "database corrupt or not a database")
		}
	}
	return identity.Err(identity.Unavailable, "database operation failed")
}
func utc(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
