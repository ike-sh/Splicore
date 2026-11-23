package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

const (
	witnessFormat  = "splicore-commit-witness"
	witnessVersion = 1
	witnessSuffix  = ".witness"
	pendingSuffix  = ".witness.pending"

	witnessLineageNative = "native"
	witnessLineageLegacy = "legacy_baseline"

	witnessKindInitial  = "initial"
	witnessKindCommit   = "commit"
	witnessKindBaseline = "legacy_baseline"
)

// commitWitness is deliberately independent of the SQLite database and WAL.
// Its checksum detects accidental media corruption; it is not a MAC and does
// not claim protection from a principal that can rewrite both database and
// witness files.
type commitWitness struct {
	Format              string            `json:"format"`
	Version             int               `json:"version"`
	Kind                string            `json:"kind"`
	Lineage             string            `json:"lineage"`
	InstallationID      identity.ID       `json:"installation_id"`
	Schema              int               `json:"schema"`
	Revision            identity.Revision `json:"revision"`
	TransactionID       identity.ID       `json:"transaction_id,omitempty"`
	StateDigest         string            `json:"state_digest"`
	PreviousRevision    identity.Revision `json:"previous_revision"`
	PreviousStateDigest string            `json:"previous_state_digest,omitempty"`
	CommittedAt         time.Time         `json:"committed_at"`
	Checksum            string            `json:"checksum"`
}

type witnessDatabaseState struct {
	InstallationID identity.ID
	Schema         int
	Revision       identity.Revision
	Pending        int
	Digest         string
}

// WitnessInspection is a non-secret, read-only diagnosis of the relationship
// between the current SQLite view and the independent commit witness.
type WitnessInspection struct {
	Status              string            `json:"status"`
	Lineage             string            `json:"lineage,omitempty"`
	FormatVersion       int               `json:"format_version,omitempty"`
	InstallationID      identity.ID       `json:"installation_id,omitempty"`
	Schema              int               `json:"db_schema,omitempty"`
	DatabaseRevision    identity.Revision `json:"database_revision"`
	WitnessRevision     identity.Revision `json:"witness_revision"`
	DatabaseDigest      string            `json:"database_digest,omitempty"`
	WitnessDigest       string            `json:"witness_digest,omitempty"`
	PendingTransactions int               `json:"pending_transactions"`
	PendingWitness      bool              `json:"pending_witness"`
	HistoricalProof     bool              `json:"historical_proof"`
}

func integrityUnverified() error {
	return identity.Err(identity.StorageIntegrityUnverified, "committed storage integrity is unverified")
}

func digestText(sum []byte) string { return "sha256:" + hex.EncodeToString(sum) }

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func witnessChecksum(w commitWitness) (string, error) {
	w.Checksum = ""
	b, err := json.Marshal(w)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return digestText(sum[:]), nil
}

func encodeWitness(w commitWitness) ([]byte, error) {
	checksum, err := witnessChecksum(w)
	if err != nil {
		return nil, err
	}
	w.Checksum = checksum
	if err = validateWitness(w); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func decodeWitness(data []byte) (commitWitness, error) {
	var w commitWitness
	if len(data) == 0 || len(data) > 32*1024 {
		return w, errors.New("invalid witness size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&w); err != nil {
		return commitWitness{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return commitWitness{}, errors.New("trailing witness data")
	}
	if err := validateWitness(w); err != nil {
		return commitWitness{}, err
	}
	want, err := witnessChecksum(w)
	if err != nil || w.Checksum != want {
		return commitWitness{}, errors.New("witness checksum mismatch")
	}
	return w, nil
}

func validateWitness(w commitWitness) error {
	if w.Format != witnessFormat || w.Version != witnessVersion {
		return errors.New("unsupported witness format")
	}
	if w.Lineage != witnessLineageNative && w.Lineage != witnessLineageLegacy {
		return errors.New("invalid witness lineage")
	}
	if w.InstallationID.Validate() != nil || w.Schema != len(migrations()) || w.Revision < 0 || !validDigest(w.StateDigest) {
		return errors.New("invalid witness identity")
	}
	if w.CommittedAt.IsZero() || w.CommittedAt.Location() != time.UTC || !validDigest(w.Checksum) {
		return errors.New("invalid witness timestamp or checksum")
	}
	switch w.Kind {
	case witnessKindInitial:
		if w.Lineage != witnessLineageNative || w.Revision != 0 || w.TransactionID != "" || w.PreviousRevision != 0 || w.PreviousStateDigest != "" {
			return errors.New("invalid initial witness")
		}
	case witnessKindCommit:
		if w.Revision < 1 || w.TransactionID.Validate() != nil || w.PreviousRevision+1 != w.Revision || !validDigest(w.PreviousStateDigest) {
			return errors.New("invalid commit witness")
		}
	case witnessKindBaseline:
		if w.Lineage != witnessLineageLegacy || w.TransactionID != "" || w.PreviousRevision != w.Revision || w.PreviousStateDigest != "" {
			return errors.New("invalid legacy baseline witness")
		}
	default:
		return errors.New("invalid witness kind")
	}
	return nil
}

func readWitness(path string) (commitWitness, error) {
	if err := safeFile(path); err != nil {
		return commitWitness{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return commitWitness{}, err
	}
	return decodeWitness(data)
}

func pendingWitnessExists(path string) (bool, error) {
	pending := path + pendingSuffix
	if err := safeFile(pending); err != nil {
		return false, err
	}
	_, err := os.Lstat(pending)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func persistCommitWitness(databasePath string, expected *commitWitness, next commitWitness) error {
	path := databasePath + witnessSuffix
	pending, err := pendingWitnessExists(databasePath)
	if err != nil || pending {
		return errors.New("pending witness requires review")
	}
	if expected == nil {
		if _, err = os.Lstat(path); err == nil || !os.IsNotExist(err) {
			return errors.New("unexpected existing witness")
		}
	} else {
		current, readErr := readWitness(path)
		if readErr != nil || !reflect.DeepEqual(current, *expected) {
			return errors.New("witness changed before replacement")
		}
	}
	data, err := encodeWitness(next)
	if err != nil {
		return err
	}
	return durableReplaceFile(path+".pending", path, data)
}

func initialWitness(state witnessDatabaseState, lineage, kind string) commitWitness {
	w := commitWitness{
		Format: witnessFormat, Version: witnessVersion, Kind: kind, Lineage: lineage,
		InstallationID: state.InstallationID, Schema: state.Schema, Revision: state.Revision,
		StateDigest: state.Digest, PreviousRevision: state.Revision, CommittedAt: time.Now().UTC(),
	}
	w.Checksum, _ = witnessChecksum(w)
	return w
}

func nextWitness(previous commitWitness, op identity.Transaction, stateDigest string) commitWitness {
	w := commitWitness{
		Format: witnessFormat, Version: witnessVersion, Kind: witnessKindCommit, Lineage: previous.Lineage,
		InstallationID: previous.InstallationID, Schema: previous.Schema, Revision: op.TargetRevision,
		TransactionID: op.ID, StateDigest: stateDigest, PreviousRevision: previous.Revision,
		PreviousStateDigest: previous.StateDigest, CommittedAt: time.Now().UTC(),
	}
	w.Checksum, _ = witnessChecksum(w)
	return w
}

func databaseWitnessState(ctx context.Context, q queryer, includeDigest bool) (witnessDatabaseState, error) {
	var out witnessDatabaseState
	var schema string
	err := q.QueryRowContext(ctx, `SELECT n.id,s.committed_revision,m.value,
 (SELECT count(*) FROM transactions WHERE state='pending')
 FROM nodes n CROSS JOIN settings s JOIN metadata m ON m.key='db_schema' WHERE s.singleton=1`).Scan(&out.InstallationID, &out.Revision, &schema, &out.Pending)
	if err != nil {
		return out, err
	}
	out.Schema, err = strconv.Atoi(schema)
	if err != nil || out.InstallationID.Validate() != nil || out.Schema != len(migrations()) || out.Revision < 0 || out.Pending < 0 {
		return witnessDatabaseState{}, errors.New("invalid database witness state")
	}
	if includeDigest {
		out.Digest, err = logicalStateDigest(ctx, q)
	}
	return out, err
}

func verifyWitnessAgainst(ctx context.Context, q queryer, w commitWitness, runIntegrity bool) (witnessDatabaseState, error) {
	if runIntegrity {
		if err := integrity(ctx, q); err != nil {
			return witnessDatabaseState{}, err
		}
	}
	state, err := databaseWitnessState(ctx, q, true)
	if err != nil {
		return state, err
	}
	if state.InstallationID != w.InstallationID || state.Schema != w.Schema || state.Revision != w.Revision || state.Digest != w.StateDigest {
		return state, errors.New("database and witness differ")
	}
	if err = verifyWitnessTransaction(ctx, q, w); err != nil {
		return state, err
	}
	return state, nil
}

func verifyWitnessTransaction(ctx context.Context, q queryer, w commitWitness) error {
	if w.Kind != witnessKindCommit {
		return nil
	}
	var committed int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM transactions
 WHERE id=? AND state='committed' AND base_revision=? AND target_revision=?`, w.TransactionID, w.PreviousRevision, w.Revision).Scan(&committed); err != nil || committed != 1 {
		return errors.New("witness transaction is not committed")
	}
	return nil
}

func verifyExistingWitnessReadOnly(ctx context.Context, path string, w commitWitness) error {
	snapshot, cleanup, err := readOnlyEvidenceSnapshot(path)
	if err != nil {
		return err
	}
	defer cleanup()
	snapshotWitness, err := readWitness(snapshot + witnessSuffix)
	if err != nil || !reflect.DeepEqual(snapshotWitness, w) {
		return errors.New("witness changed during read-only verification")
	}
	u, err := readOnlyDatabaseURL(snapshot)
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite", u)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	_, err = verifyWitnessAgainst(ctx, db, w, true)
	return err
}

func writeFrame(h hash.Hash, kind byte, value []byte) {
	_, _ = h.Write([]byte{kind})
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = h.Write(length[:])
	_, _ = h.Write(value)
}

func writeSQLValue(h hash.Hash, value any) error {
	switch v := value.(type) {
	case nil:
		writeFrame(h, '0', nil)
	case int64:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(v))
		writeFrame(h, 'i', b[:])
	case float64:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], math.Float64bits(v))
		writeFrame(h, 'f', b[:])
	case bool:
		if v {
			writeFrame(h, 'b', []byte{1})
		} else {
			writeFrame(h, 'b', []byte{0})
		}
	case string:
		if !utf8.ValidString(v) {
			return errors.New("invalid database text")
		}
		writeFrame(h, 's', []byte(v))
	case []byte:
		writeFrame(h, 'x', v)
	case time.Time:
		writeFrame(h, 't', []byte(v.UTC().Format(time.RFC3339Nano)))
	default:
		return fmt.Errorf("unsupported database value type %T", value)
	}
	return nil
}

func quoteIdentifier(value string) (string, error) {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
		return "", errors.New("invalid SQLite identifier")
	}
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`, nil
}

// logicalStateDigest hashes the complete Schema 8 logical state, including
// SQLite schema objects and ciphertext bytes, in a canonical table/column/row
// order. Runtime transaction-journal rows are the sole exclusion: pending and
// failure lifecycle updates do not publish business state or a new revision.
func logicalStateDigest(ctx context.Context, q queryer) (string, error) {
	h := sha256.New()
	writeFrame(h, 'v', []byte("splicore-schema8-logical-state-v1"))
	rows, err := q.QueryContext(ctx, `SELECT type,name,tbl_name,sql FROM sqlite_schema
 WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name`)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var typ, name, table string
		var statement sql.NullString
		if err = rows.Scan(&typ, &name, &table, &statement); err != nil {
			rows.Close()
			return "", err
		}
		writeFrame(h, 'S', []byte(typ))
		writeFrame(h, 'n', []byte(name))
		writeFrame(h, 'T', []byte(table))
		if statement.Valid {
			writeFrame(h, 'q', []byte(statement.String))
		} else {
			writeFrame(h, 'q', nil)
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return "", err
	}
	rows.Close()

	rows, err = q.QueryContext(ctx, `SELECT name FROM sqlite_schema
 WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name<>'transactions' ORDER BY name`)
	if err != nil {
		return "", err
	}
	var tables []string
	for rows.Next() {
		var table string
		if err = rows.Scan(&table); err != nil {
			rows.Close()
			return "", err
		}
		tables = append(tables, table)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return "", err
	}
	rows.Close()
	for _, table := range tables {
		quotedTable, quoteErr := quoteIdentifier(table)
		if quoteErr != nil {
			return "", quoteErr
		}
		columns, queryErr := q.QueryContext(ctx, "PRAGMA table_xinfo("+quotedTable+")")
		if queryErr != nil {
			return "", queryErr
		}
		var names []string
		for columns.Next() {
			var cid, notNull, primaryKey, hidden int
			var name, declaredType string
			var defaultValue sql.NullString
			if queryErr = columns.Scan(&cid, &name, &declaredType, &notNull, &defaultValue, &primaryKey, &hidden); queryErr != nil {
				columns.Close()
				return "", queryErr
			}
			if hidden == 0 {
				names = append(names, name)
			}
		}
		if queryErr = columns.Err(); queryErr != nil || len(names) == 0 {
			columns.Close()
			if queryErr == nil {
				queryErr = errors.New("table has no visible columns")
			}
			return "", queryErr
		}
		columns.Close()
		quotedColumns := make([]string, len(names))
		for i, name := range names {
			quotedColumns[i], err = quoteIdentifier(name)
			if err != nil {
				return "", err
			}
		}
		writeFrame(h, 'D', []byte(table))
		for _, name := range names {
			writeFrame(h, 'C', []byte(name))
		}
		query := "SELECT " + strings.Join(quotedColumns, ",") + " FROM " + quotedTable + " ORDER BY " + strings.Join(quotedColumns, ",")
		dataRows, queryErr := q.QueryContext(ctx, query)
		if queryErr != nil {
			return "", queryErr
		}
		values := make([]any, len(names))
		destinations := make([]any, len(names))
		for i := range values {
			destinations[i] = &values[i]
		}
		for dataRows.Next() {
			if queryErr = dataRows.Scan(destinations...); queryErr != nil {
				dataRows.Close()
				return "", queryErr
			}
			writeFrame(h, 'R', nil)
			for _, value := range values {
				if queryErr = writeSQLValue(h, value); queryErr != nil {
					dataRows.Close()
					return "", queryErr
				}
			}
		}
		if queryErr = dataRows.Err(); queryErr != nil {
			dataRows.Close()
			return "", queryErr
		}
		dataRows.Close()
		writeFrame(h, 'E', nil)
	}
	return digestText(h.Sum(nil)), nil
}

func (s *Store) integrityFailure() error {
	s.integrityMu.RLock()
	defer s.integrityMu.RUnlock()
	return s.integrityErr
}

func (s *Store) markIntegrityFailure() error {
	err := integrityUnverified()
	s.integrityMu.Lock()
	first := s.integrityErr == nil
	if first {
		s.integrityErr = err
	} else {
		err = s.integrityErr
	}
	s.integrityMu.Unlock()
	if first && s.options.OnIntegrityFailure != nil {
		s.options.OnIntegrityFailure()
	}
	return err
}

// admitMutation proves the current logical state against the on-disk witness
// before any mutation journal side effect. Store.write must be held.
func (s *Store) admitMutation(ctx context.Context) error {
	// A nil persistence function exists only in same-package tests that build
	// pre-current migration fixtures without using the production Open path.
	if s.persistWitness == nil {
		return nil
	}
	if err := s.integrityFailure(); err != nil {
		return err
	}
	pending, err := pendingWitnessExists(s.path)
	if err != nil || pending {
		return s.markIntegrityFailure()
	}
	disk, err := readWitness(s.path + witnessSuffix)
	if err != nil || !reflect.DeepEqual(disk, s.witness) {
		return s.markIntegrityFailure()
	}
	if _, err = verifyWitnessAgainst(ctx, s.db, s.witness, false); err != nil {
		if ctx.Err() != nil {
			return identity.Err(identity.Unavailable, "mutation context unavailable")
		}
		return s.markIntegrityFailure()
	}
	return nil
}

func (s *Store) publishWitness(op identity.Transaction, digest string) error {
	if s.afterDatabaseCommit != nil {
		s.afterDatabaseCommit()
	}
	next := nextWitness(s.witness, op, digest)
	if err := s.persistWitness(s.path, &s.witness, next); err != nil {
		return s.markIntegrityFailure()
	}
	s.witness = next
	return nil
}

func inspectWitnessDatabase(ctx context.Context, path string) (WitnessInspection, error) {
	var out WitnessInspection
	snapshot, cleanup, err := readOnlyEvidenceSnapshot(path)
	if err != nil {
		return out, err
	}
	defer cleanup()
	path = snapshot
	pending, err := pendingWitnessExists(path)
	if err != nil {
		return out, err
	}
	out.PendingWitness = pending
	u, err := readOnlyDatabaseURL(path)
	if err != nil {
		return out, err
	}
	db, err := sql.Open("sqlite", u)
	if err != nil {
		return out, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	state, stateErr := databaseWitnessState(ctx, db, true)
	if stateErr != nil {
		return out, stateErr
	}
	out.InstallationID, out.Schema, out.DatabaseRevision, out.PendingTransactions, out.DatabaseDigest = state.InstallationID, state.Schema, state.Revision, state.Pending, state.Digest
	w, witnessErr := readWitness(path + witnessSuffix)
	if os.IsNotExist(witnessErr) {
		out.Status = "witness_missing"
		return out, nil
	}
	if witnessErr != nil {
		out.Status = "witness_corrupt"
		return out, nil
	}
	out.Lineage, out.FormatVersion, out.WitnessRevision, out.WitnessDigest = w.Lineage, w.Version, w.Revision, w.StateDigest
	if pending {
		out.Status = "pending_witness_update"
		return out, nil
	}
	if state.InstallationID != w.InstallationID || state.Schema != w.Schema || state.Revision != w.Revision || state.Digest != w.StateDigest {
		out.Status = "witness_mismatch"
		return out, nil
	}
	if err = verifyWitnessTransaction(ctx, db, w); err != nil {
		out.Status = "witness_transaction_missing"
		return out, nil
	}
	if err = integrity(ctx, db); err != nil {
		out.Status = "database_corrupt"
		return out, nil
	}
	out.Status = "verified"
	out.HistoricalProof = w.Lineage == witnessLineageNative
	return out, nil
}

func readOnlyDatabaseURL(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("invalid database path")
	}
	uriPath := filepath.ToSlash(path)
	if len(filepath.VolumeName(path)) > 0 {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	q := url.Values{"mode": {"ro"}, "_pragma": {"query_only(1)", "busy_timeout(5000)"}}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func writableExistingDatabaseURL(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("invalid database path")
	}
	uriPath := filepath.ToSlash(path)
	if len(filepath.VolumeName(path)) > 0 {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	q := url.Values{"mode": {"rw"}, "_txlock": {"immediate"}}
	for _, pragma := range []string{"foreign_keys(1)", "busy_timeout(5000)", "journal_mode(WAL)", "synchronous(FULL)"} {
		q.Add("_pragma", pragma)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// InspectCommitWitness performs a read-only diagnosis and never initializes,
// migrates, recovers, or establishes a witness.
func InspectCommitWitness(ctx context.Context, path string) (WitnessInspection, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return WitnessInspection{}, identity.Err(identity.Invalid, "database path must be absolute and clean")
	}
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || privateDirectory(dir) != nil {
		return WitnessInspection{}, identity.Err(identity.Invalid, "private directory owner or permissions invalid")
	}
	for _, suffix := range []string{"", "-wal", "-shm", ".lock", witnessSuffix, pendingSuffix} {
		if err = safeFile(path + suffix); err != nil {
			return WitnessInspection{}, err
		}
	}
	out, err := inspectWitnessDatabase(ctx, path)
	if err != nil {
		return WitnessInspection{}, identity.Err(identity.Corrupt, "committed storage cannot be inspected")
	}
	return out, nil
}

// EstablishCommitWitness creates an explicit legacy baseline for an existing,
// stopped Schema 8 database. It never overwrites a witness or pending update.
// The persisted legacy lineage records that earlier acknowledgements were not
// independently witnessed.
func EstablishCommitWitness(ctx context.Context, path string, acknowledgeCurrentState bool) (WitnessInspection, error) {
	if !acknowledgeCurrentState {
		return WitnessInspection{}, identity.Err(identity.Invalid, "explicit current-state acknowledgement required")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return WitnessInspection{}, identity.Err(identity.Invalid, "database path must be absolute and clean")
	}
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || privateDirectory(dir) != nil {
		return WitnessInspection{}, identity.Err(identity.Invalid, "private directory owner or permissions invalid")
	}
	for _, suffix := range []string{"", "-wal", "-shm", ".lock", witnessSuffix, pendingSuffix} {
		if err = safeFile(path + suffix); err != nil {
			return WitnessInspection{}, err
		}
	}
	if _, err = os.Stat(path); err != nil {
		return WitnessInspection{}, identity.Err(identity.NotFound, "database not found")
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return WitnessInspection{}, identity.Err(identity.Unavailable, "cannot open installation lock")
	}
	defer lock.Close()
	if err = lockFile(lock); err != nil {
		return WitnessInspection{}, identity.Err(identity.Unavailable, "stop the service before establishing witness")
	}
	defer unlockFile(lock)
	if pending, pendingErr := pendingWitnessExists(path); pendingErr != nil || pending {
		return WitnessInspection{}, integrityUnverified()
	}
	if _, err = os.Lstat(path + witnessSuffix); err == nil || !os.IsNotExist(err) {
		return WitnessInspection{}, identity.Err(identity.Invalid, "commit witness already exists")
	}
	if err = VerifyRuntimeBoundary(ctx, path); err != nil {
		return WitnessInspection{}, err
	}
	u, err := writableExistingDatabaseURL(path)
	if err != nil {
		return WitnessInspection{}, identity.Err(identity.Invalid, "invalid database path")
	}
	db, err := sql.Open("sqlite", u)
	if err != nil {
		return WitnessInspection{}, identity.Err(identity.Corrupt, "database unavailable for witness establishment")
	}
	db.SetMaxOpenConns(1)
	if err = integrity(ctx, db); err != nil {
		db.Close()
		return WitnessInspection{}, err
	}
	var pending int
	if err = db.QueryRowContext(ctx, "SELECT count(*) FROM transactions WHERE state='pending'").Scan(&pending); err != nil || pending != 0 {
		db.Close()
		return WitnessInspection{}, integrityUnverified()
	}
	if err = migrate(ctx, db, migrations()); err != nil {
		db.Close()
		return WitnessInspection{}, err
	}
	state, err := databaseWitnessState(ctx, db, true)
	if err != nil || state.Pending != 0 {
		db.Close()
		return WitnessInspection{}, integrityUnverified()
	}
	if err = migrateHistoryOnly(ctx, db); err != nil {
		db.Close()
		return WitnessInspection{}, err
	}
	w := initialWitness(state, witnessLineageLegacy, witnessKindBaseline)
	if err = persistCommitWitness(path, nil, w); err != nil {
		db.Close()
		return WitnessInspection{}, identity.Err(identity.Unavailable, "commit witness persistence failed")
	}
	if err = db.Close(); err != nil {
		return WitnessInspection{}, identity.Err(identity.Unavailable, "database close after witness establishment failed")
	}
	return InspectCommitWitness(ctx, path)
}

// migrateHistoryOnly validates current Schema 8 history without opening a
// write transaction or applying a migration.
func migrateHistoryOnly(ctx context.Context, q queryer) error {
	rows, err := q.QueryContext(ctx, "SELECT version,name,checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return identity.Err(identity.Corrupt, "missing migration history")
	}
	defer rows.Close()
	steps := migrations()
	current := 0
	for rows.Next() {
		var version int
		var name, sum string
		if err = rows.Scan(&version, &name, &sum); err != nil || version != current+1 || version > len(steps) || steps[version-1].Name != name || !migrationChecksumMatches(steps[version-1], sum) {
			return identity.Err(identity.Corrupt, "migration history checksum or sequence mismatch")
		}
		current = version
	}
	if err = rows.Err(); err != nil || current != len(steps) {
		return identity.Err(identity.Corrupt, "incomplete migration history")
	}
	return nil
}
