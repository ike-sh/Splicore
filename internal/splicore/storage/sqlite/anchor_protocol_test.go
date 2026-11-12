package sqlite

// Continuation of anchor_design_test.go, not a production ledger or migration.
// A live parent is the independent, fresh witness for a crashed SQL child. Its
// append-only log is outside the fault image, on the SAME host/physical medium.
// This proves ordering under process failure, not witness restart, namespace
// durability, power loss or resistance to coordinated media rollback.
import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/secretvault"
)

type protocolRecord struct {
	Version                  int
	Sequence                 int
	Previous, Epoch, KeyID   string
	Node                     identity.ID
	Phase, Outcome, Command  string
	Operation                identity.Transaction
	Base, Pending, Candidate string
}

type protocolEnvelope struct {
	Record protocolRecord
	MAC    string
}

func protocolHash(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

func protocolKey(master []byte, epoch string) []byte {
	m := hmac.New(sha256.New, master)
	m.Write([]byte("splicore-p33-test-witness-key\x00" + epoch))
	return m.Sum(nil)
}

func protocolSeal(r protocolRecord, key []byte) protocolEnvelope {
	b, _ := json.Marshal(r)
	m := hmac.New(sha256.New, key)
	m.Write([]byte("splicore-p33-test-record\x00"))
	m.Write(b)
	return protocolEnvelope{r, hex.EncodeToString(m.Sum(nil))}
}

func protocolVerify(e protocolEnvelope, key []byte) bool {
	a, err := hex.DecodeString(e.MAC)
	b, _ := hex.DecodeString(protocolSeal(e.Record, key).MAC)
	return err == nil && len(key) == 32 && hmac.Equal(a, b)
}

func protocolBytes(e protocolEnvelope) []byte { b, _ := json.Marshal(e); return b }

// Hash the complete logical database, including every journal column, inside
// the actual SQLite transaction when staging a candidate. Physical DB bytes
// alone would omit WAL state and would change with checkpoint timing.
func protocolSnapshot(t *testing.T, q queryer) string {
	t.Helper()
	ctx := context.Background()
	rows, err := q.QueryContext(ctx, "SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err = rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	tables := map[string][]string{}
	for _, n := range names {
		rows, err = q.QueryContext(ctx, `SELECT * FROM "`+strings.ReplaceAll(n, `"`, `""`)+`"`)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		tables[n] = []string{}
		for rows.Next() {
			values, targets := make([]any, len(columns)), make([]any, len(columns))
			for i := range targets {
				targets[i] = &values[i]
			}
			if err = rows.Scan(targets...); err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			tables[n] = append(tables[n], string(b))
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		sort.Strings(tables[n])
	}
	b, _ := json.Marshal(tables)
	return protocolHash(b)
}

type protocolWitness struct {
	key     []byte
	path    string
	history []protocolEnvelope
}

func (w *protocolWitness) latest() protocolEnvelope { return w.history[len(w.history)-1] }

func (w *protocolWitness) readFresh() (protocolEnvelope, error) {
	b, err := os.ReadFile(w.path)
	if err != nil || len(b) == 0 || len(b) > 1024*1024 || b[len(b)-1] != '\n' {
		return protocolEnvelope{}, errors.New("independent record missing or truncated")
	}
	var latest protocolEnvelope
	for i, line := range bytes.Split(bytes.TrimSuffix(b, []byte{'\n'}), []byte{'\n'}) {
		var e protocolEnvelope
		if json.Unmarshal(line, &e) != nil || !protocolVerify(e, w.key) || e.Record.Sequence != i+1 || (i > 0 && e.Record.Previous != protocolHash(protocolBytes(latest))) {
			return protocolEnvelope{}, errors.New("independent record authentication or chain failed")
		}
		latest = e
	}
	// The process-local high-water mark belongs to the surviving witness, not
	// to the failed SQL process or to this file. Restarting the witness without
	// an independently retained tip would invalidate this freshness assumption.
	if !reflect.DeepEqual(latest, w.latest()) {
		return protocolEnvelope{}, errors.New("independent record rolled back")
	}
	return latest, nil
}

func (w *protocolWitness) append(e protocolEnvelope) error {
	if !protocolVerify(e, w.key) {
		return errors.New("witness authentication failed")
	}
	if e.Record.Sequence != len(w.history)+1 {
		return errors.New("witness sequence conflict")
	}
	if len(w.history) != 0 {
		if _, err := w.readFresh(); err != nil {
			return err
		}
		previous := w.latest().Record
		if e.Record.Node != previous.Node || e.Record.Epoch != previous.Epoch || e.Record.KeyID != previous.KeyID || e.Record.Version != previous.Version {
			return errors.New("witness installation/key/epoch mismatch")
		}
	}
	if len(w.history) != 0 && e.Record.Previous != protocolHash(protocolBytes(w.latest())) {
		return errors.New("witness compare-and-swap conflict")
	}
	f, err := os.OpenFile(w.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	b := append(protocolBytes(e), '\n')
	n, err := f.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return err
	}
	w.history = append(w.history, e)
	return nil
}

type protocolSession struct {
	key     []byte
	latest  protocolEnvelope
	publish func(protocolEnvelope) error
}

func (p *protocolSession) append(r protocolRecord) error {
	r.Sequence = p.latest.Record.Sequence + 1
	r.Previous = protocolHash(protocolBytes(p.latest))
	e := protocolSeal(r, p.key)
	if err := p.publish(e); err != nil {
		return err
	}
	p.latest = e
	return nil
}

func protocolOpen(t *testing.T, root string) (*Store, []byte) {
	t.Helper()
	path := filepath.Join(root, "private", "vault.key")
	v, err := secretvault.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	master, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	opts := options(t)
	opts.Cipher = v
	s, err := Open(context.Background(), filepath.Join(root, "private", "state.db"), opts)
	if err != nil {
		t.Fatal(err)
	}
	return s, master
}

func protocolEnroll(t *testing.T, s *Store, w *protocolWitness, epoch, verifiedBackupHash string, approved bool) error {
	state, err := s.State(context.Background())
	if err != nil {
		return err
	}
	if !approved || verifiedBackupHash == "" || state.PendingTransactions != 0 || protocolSnapshot(t, s.db) != verifiedBackupHash || len(w.history) != 0 {
		return errors.New("explicit verified enrollment required")
	}
	// Explicit fixture provisioning establishes FUTURE evidence only. It does
	// not establish that this pre-anchor Schema8 history was never rolled back.
	return w.append(protocolSeal(protocolRecord{Version: 1, Sequence: 1, Epoch: epoch, Node: state.NodeID, KeyID: s.options.Cipher.KeyID(), Phase: "confirmed", Outcome: "enrolled", Candidate: verifiedBackupHash}, w.key))
}

// Authenticate against a FRESH independent witness, never a tip derived from
// the current database or the local ledger copy. An old authenticated prefix
// is insufficient. The live test parent supplies that freshness assumption.
func protocolCheck(p *protocolSession, witness protocolEnvelope, node identity.ID, keyID string) error {
	if !protocolVerify(p.latest, p.key) || !protocolVerify(witness, p.key) || !reflect.DeepEqual(p.latest, witness) || p.latest.Record.Node != node || p.latest.Record.KeyID != keyID {
		return errors.New("fresh independent authority unavailable or mismatched")
	}
	return nil
}

func protocolRecover(t *testing.T, s *Store, p *protocolSession, witness protocolEnvelope) (string, error) {
	t.Helper()
	s.write.Lock()
	defer s.write.Unlock()
	ctx := context.Background()
	state, err := s.State(ctx)
	if err != nil {
		return "", err
	}
	if err = protocolCheck(p, witness, state.NodeID, s.options.Cipher.KeyID()); err != nil {
		return "", err
	}
	r := p.latest.Record
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	actual := protocolSnapshot(t, tx)
	if r.Phase == "confirmed" {
		if actual != r.Candidate {
			return "", errors.New("confirmed database content lost or changed")
		}
		return r.Outcome, nil
	}
	if r.Phase != "prepared" {
		return "", errors.New("unknown acknowledgement phase")
	}
	if actual == r.Candidate && r.Candidate != "" {
		// SQL committed; confirmation/response did not. Confirm the exact
		// staged generation without rerunning a callback or retiring its row.
		r.Phase = "confirmed"
		return r.Outcome, p.append(r)
	}
	if r.Outcome == "abort" && actual != r.Pending {
		return "", errors.New("abort preimage mismatch")
	}
	if actual != r.Pending && actual != r.Base {
		return "", errors.New("prepared database content mismatch")
	}
	if actual == r.Pending {
		result, err := tx.ExecContext(ctx, "UPDATE transactions SET state='failed',failure_code='unavailable',updated_at=? WHERE id=? AND state='pending'", utc(r.Operation.CreatedAt), r.Operation.ID)
		if err != nil {
			return "", err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return "", errors.New("pending identity mismatch")
		}
	}
	// Abort also has prepared -> SQL -> confirmed ordering. A process crash
	// during retirement can be resumed from either exact preimage or result.
	r.Outcome, r.Candidate = "abort", protocolSnapshot(t, tx)
	if err = p.append(r); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	r.Phase = "confirmed"
	return "abort", p.append(r)
}

func protocolReplay(p *protocolSession, request identity.ID, command string) (string, error) {
	r := p.latest.Record
	if r.Operation.Actor.RequestID != request || r.Command != command {
		return "", errors.New("request identity or content conflict")
	}
	if r.Phase != "confirmed" {
		return "", errors.New("request outcome indeterminate; reconcile first")
	}
	return r.Outcome, nil // No callback; identical durable receipt, including abort.
}

func protocolWorker(t *testing.T) {
	root, cut := os.Getenv("P33_ACK_ROOT"), os.Getenv("P33_ACK_CUT")
	s, master := protocolOpen(t, root)
	defer s.Close()
	defer clear(master)
	var initial protocolEnvelope
	b, err := os.ReadFile(filepath.Join(root, "initial.json"))
	if err != nil || json.Unmarshal(b, &initial) != nil {
		t.Fatal("invalid fixture authority", err)
	}
	reader := bufio.NewReader(os.Stdin)
	p := &protocolSession{key: protocolKey(master, initial.Record.Epoch), latest: initial}
	p.publish = func(e protocolEnvelope) error {
		fmt.Printf("P33_RECORD %s\n", protocolBytes(e))
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.TrimSpace(line) != "P33_ACCEPT "+protocolHash(protocolBytes(e)) {
			return errors.New("fresh witness did not confirm persistence")
		}
		return nil
	}
	stop := func(stage string) {
		if cut == stage {
			os.Exit(77)
		}
	}
	ctx := context.Background()
	state, err := s.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = protocolCheck(p, initial, state.NodeID, s.options.Cipher.KeyID()); err != nil || state.PendingTransactions != 0 || initial.Record.Phase != "confirmed" || protocolSnapshot(t, s.db) != initial.Record.Candidate {
		t.Fatal("fresh confirmed baseline required before preparing a mutation", err)
	}
	op := identity.Transaction{ID: newID(t), State: identity.Pending, BaseRevision: state.Revision, TargetRevision: state.Revision + 1, Actor: actor(t), CreatedAt: time.Now().UTC()}
	op.UpdatedAt = op.CreatedAt
	a := account(t)
	a.Name = "confirmed-to-caller"
	commandBytes, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	r := initial.Record
	r.Phase, r.Outcome, r.Operation, r.Command = "prepared", "commit", op, protocolHash(commandBytes)
	r.Base, r.Candidate = protocolSnapshot(t, s.db), ""
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO transactions(id,state,base_revision,target_revision,principal,request_id,created_at,updated_at,operation) VALUES(?,?,?,?,?,?,?,?,?)", op.ID, "pending", op.BaseRevision, op.TargetRevision, op.Actor.Principal, op.Actor.RequestID, utc(op.CreatedAt), utc(op.CreatedAt), "runtime_replace"); err != nil {
		t.Fatal(err)
	}
	r.Pending = protocolSnapshot(t, tx)
	if err = p.append(r); err != nil {
		t.Fatal(err)
	}
	stop("prepared-before-pending")
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	admissionEvidence(t, cut+"-pending-image", admissionFiles(t, filepath.Join(root, "private", "state.db")), nil)
	pendingImage := filepath.Join(root, "pending-image")
	if err = privateDirectory(pendingImage); err != nil {
		t.Fatal(err)
	}
	for name, data := range admissionFiles(t, filepath.Join(root, "private", "state.db")) {
		if err = os.WriteFile(filepath.Join(pendingImage, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	stop("pending-before-sql")
	tx, err = s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = (&writer{ctx: ctx, tx: tx, options: s.options}).CreateAccount(a); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, "UPDATE settings SET committed_revision=? WHERE singleton=1", op.TargetRevision); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, "UPDATE transactions SET state='committed',updated_at=? WHERE id=?", utc(op.CreatedAt), op.ID); err != nil {
		t.Fatal(err)
	}
	r.Candidate = protocolSnapshot(t, tx)
	if err = p.append(r); err != nil {
		t.Fatal(err)
	}
	stop("sql-before-commit")
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Controlled external persistence failure: no confirmation is accepted by
	// the witness, and the application must not emit a success receipt.
	r.Phase = "confirmed"
	if cut == "sql-committed-confirmation-failed" {
		p.publish = func(protocolEnvelope) error { return errors.New("injected independent persistence failure") }
		if err = p.append(r); err == nil {
			t.Fatal("external persistence failure was hidden")
		}
		os.Exit(77) // No success receipt and no compensation of the SQL commit.
	}
	if err = p.append(r); err != nil {
		t.Fatal(err)
	}
	stop("confirmed-before-response")
	fmt.Printf("P33_ACK %s\n", op.ID)
	stop("response-acknowledged")
	t.Fatal("unknown controlled process cut")
}

func TestIndependentAcknowledgementCrashProtocol(t *testing.T) {
	if os.Getenv("P33_ACK_ROOT") != "" {
		protocolWorker(t)
		return
	}
	// The six logical cuts fill holes in the existing Prepared/Confirmed
	// experiment. No new WAL/media-corruption campaign is introduced.
	for _, cut := range []string{"prepared-before-pending", "pending-before-sql", "sql-before-commit", "sql-committed-confirmation-failed", "confirmed-before-response", "response-acknowledged"} {
		t.Run(cut, func(t *testing.T) { protocolCrashCase(t, cut) })
	}
}

func protocolCrashCase(t *testing.T, cut string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root := t.TempDir()
	if err := privateDirectory(filepath.Join(root, "private")); err != nil {
		t.Fatal(err)
	}
	if err := secretvault.InitFile(filepath.Join(root, "private", "vault.key")); err != nil {
		t.Fatal(err)
	}
	s, master := protocolOpen(t, root)
	defer clear(master)
	a := account(t)
	c := access.Credential{ID: newID(t), OwnerAccountID: &a.ID, Kind: access.PSK, Schema: 1, State: "active", Payload: access.PSKPayload{Key: secret.New("synthetic-p33-vault-pair")}, Stamp: identity.NewStamp(time.Now())}
	if _, err := s.Transact(ctx, 0, actor(t), func(w ports.Writer) error {
		if err := w.CreateAccount(a); err != nil {
			return err
		}
		return w.CreateCredential(c)
	}); err != nil {
		t.Fatal(err)
	}
	epoch := string(newID(t))
	f, err := os.OpenFile(filepath.Join(root, "witness.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Sync(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	witness := &protocolWitness{key: protocolKey(master, epoch), path: filepath.Join(root, "witness.jsonl")}
	base := protocolSnapshot(t, s.db)
	if err = protocolEnroll(t, s, witness, epoch, base, false); err == nil {
		t.Fatal("legacy enrollment was automatic")
	}
	if err = protocolEnroll(t, s, witness, epoch, "", true); err == nil {
		t.Fatal("legacy current revision used as historic proof")
	}
	if err = protocolEnroll(t, s, witness, epoch, base, true); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "initial.json"), protocolBytes(witness.latest()), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestIndependentAcknowledgementCrashProtocol$")
	command.Env = append(os.Environ(), "P33_ACK_ROOT="+root, "P33_ACK_CUT="+cut)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = stdin.Close() }()
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	acknowledged := false
	var processLog strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		processLog.WriteString(line + "\n")
		if strings.HasPrefix(line, "P33_RECORD ") {
			var e protocolEnvelope
			if err = json.Unmarshal([]byte(strings.TrimPrefix(line, "P33_RECORD ")), &e); err != nil {
				t.Fatal(err)
			}
			if err = witness.append(e); err != nil {
				t.Fatal(err)
			}
			if _, err = fmt.Fprintln(stdin, "P33_ACCEPT "+protocolHash(protocolBytes(e))); err != nil {
				t.Fatal(err)
			}
		}
		if strings.HasPrefix(line, "P33_ACK ") {
			if witness.latest().Record.Phase != "confirmed" || witness.latest().Record.Outcome != "commit" || strings.TrimPrefix(line, "P33_ACK ") != string(witness.latest().Record.Operation.ID) {
				t.Fatal("success preceded durable independent confirmation")
			}
			acknowledged = true
		}
	}
	if err = scanner.Err(); err != nil {
		t.Fatal(err)
	}
	err = command.Wait()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 77 {
		t.Fatalf("controlled crash not reached: %v\n%s\n%s", err, processLog.String(), stderr.String())
	}
	if acknowledged != (cut == "response-acknowledged") {
		t.Fatal("incorrect success contract")
	}
	path := filepath.Join(root, "private", "state.db")
	admissionEvidence(t, "original-before-recovery-open", admissionFiles(t, path), map[string]any{"acknowledged": acknowledged, "witness": witness.history, "child_trace": processLog.String()})
	s, reopenedMaster := protocolOpen(t, root)
	clear(reopenedMaster)
	defer s.Close()
	p := &protocolSession{key: witness.key, latest: witness.latest(), publish: witness.append}
	before := admissionLogicalSnapshot(t, s)
	want := "abort"
	if cut == "sql-committed-confirmation-failed" || cut == "confirmed-before-response" || acknowledged {
		want = "commit"
	}
	if cut == "pending-before-sql" {
		// Also exercise interruption after the abort SQL commit but before its
		// confirmation, reusing this logical cut rather than expanding a matrix.
		writes := 0
		p.publish = func(e protocolEnvelope) error {
			writes++
			if writes == 2 {
				return errors.New("injected abort confirmation persistence failure")
			}
			return witness.append(e)
		}
		if _, err = protocolRecover(t, s, p, witness.latest()); err == nil {
			t.Fatal("abort confirmation failure concealed")
		}
		p.publish = witness.append
	}
	outcome, err := protocolRecover(t, s, p, witness.latest())
	if err != nil || outcome != want {
		t.Fatal("normal process recovery failed", outcome, err)
	}
	state, err := s.State(ctx)
	if err != nil || state.PendingTransactions != 0 {
		t.Fatal("pending not reconciled", state, err)
	}
	var candidates int
	if err = s.db.QueryRow("SELECT count(*) FROM accounts WHERE name='confirmed-to-caller'").Scan(&candidates); err != nil {
		t.Fatal(err)
	}
	if candidates != map[string]int{"abort": 0, "commit": 1}[want] {
		t.Fatal("business outcome lost", candidates, want)
	}
	if want == "commit" && !reflect.DeepEqual(before.Tables, admissionLogicalSnapshot(t, s).Tables) {
		t.Fatal("committed business state was cleaned as pending")
	}
	got, err := protocolReplay(p, p.latest.Record.Operation.Actor.RequestID, p.latest.Record.Command)
	if err != nil || got != want {
		t.Fatal("same request did not return the recorded outcome without executing a callback", got, err)
	}
	if _, err = protocolReplay(p, p.latest.Record.Operation.Actor.RequestID, "different-command"); err == nil {
		t.Fatal("request ID reused for different content")
	}
	got, err = protocolRecover(t, s, p, witness.latest())
	if err != nil || got != want {
		t.Fatal("repeated recovery was not idempotent", got, err)
	}
	if got, err := s.RevealCredential(ctx, c.ID); err != nil || got.Payload.(access.PSKPayload).Key.Reveal() != "synthetic-p33-vault-pair" {
		t.Fatal("paired Vault key restore failed", err)
	}
	options := s.options
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	admissionEvidence(t, "after-recovery-close", admissionFiles(t, path), map[string]any{"outcome": outcome, "acknowledged": acknowledged, "replay_without_callback": true, "witness": witness.history, "process_failure_contract": "QUALIFIED_WITH_LIMITATIONS", "production_integration": "NOT_QUALIFIED", "witness_restart_and_physical_durability": "NOT_EXECUTED"})
	negative := protocolCopy(t, path, "")
	probe, err := Open(ctx, negative, options)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	protocolNegativeEvidence(t, probe, p, witness, negative)
	if acknowledged {
		// The actual successful operation is now projected back to its saved
		// pending generation. The intact fresh witness MUST forbid retirement.
		rolledBack := protocolCopy(t, filepath.Join(root, "pending-image", "state.db"), filepath.Join(root, "pending-image", "state.db-wal"))
		lost, err := Open(ctx, rolledBack, options)
		if err != nil {
			t.Fatal(err)
		}
		defer lost.Close()
		protocolRefusal(t, lost, p, witness.latest(), rolledBack, "acknowledged-commit-rolled-back")
		// Existing design counterexample, now against a real old DB image:
		// replay BOTH authorities to one old authentic generation. This cannot
		// be detected unless witness freshness exists outside that rollback.
		old := witness.history[1]
		stalePath := filepath.Join(t.TempDir(), "stale-witness.jsonl")
		if err = os.WriteFile(stalePath, nil, 0600); err != nil {
			t.Fatal(err)
		}
		stale := &protocolWitness{key: witness.key, path: stalePath}
		for _, e := range witness.history[:2] {
			if err = stale.append(e); err != nil {
				t.Fatal(err)
			}
		}
		staleSession := &protocolSession{key: witness.key, latest: old, publish: stale.append}
		if outcome, err = protocolRecover(t, lost, staleSession, old); err != nil || outcome != "abort" {
			t.Fatal("coordinated-rollback counterexample not exercised", outcome, err)
		}
		admissionEvidence(t, "COUNTEREXAMPLE-coordinated-authority-rollback", admissionFiles(t, rolledBack), map[string]any{"previously_acknowledged": true, "stale_authority_accepted": true, "qualification": "NOT_QUALIFIED", "reason": "the fresh-witness assumption was deliberately violated; a same-medium log cannot supply it"})
	}
}

func protocolCopy(t *testing.T, database, wal string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "private")
	if err := privateDirectory(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "state.db")
	for src, dst := range map[string]string{database: path, wal: path + "-wal"} {
		if src == "" {
			continue
		}
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(dst, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func protocolRefusal(t *testing.T, s *Store, p *protocolSession, fresh protocolEnvelope, path, name string) {
	t.Helper()
	before, files := admissionLogicalSnapshot(t, s), admissionFiles(t, path)
	_, err := protocolRecover(t, s, p, fresh)
	afterFiles := admissionFiles(t, path)
	after := admissionLogicalSnapshot(t, s)
	if err == nil || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(files, afterFiles) {
		t.Fatal("unsafe recovery was accepted or changed state", name, err)
	}
	admissionEvidence(t, name+"-before", files, before)
	admissionEvidence(t, name+"-after", afterFiles, map[string]any{"state": after, "error": err.Error(), "automatic_retirement": false})
}

func protocolNegativeEvidence(t *testing.T, s *Store, p *protocolSession, w *protocolWitness, path string) {
	t.Helper()
	state, err := s.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"missing", "corrupt", "old-authentic-prefix", "wrong-vault-key"} {
		before, files := admissionLogicalSnapshot(t, s), admissionFiles(t, path)
		probe := *p
		switch kind {
		case "missing":
			probe.latest = protocolEnvelope{}
		case "corrupt":
			probe.latest.Record.Candidate = "changed"
		case "old-authentic-prefix":
			probe.latest = w.history[0]
		case "wrong-vault-key":
			probe.key = bytes.Repeat([]byte{13}, 32)
		}
		if err := protocolCheck(&probe, w.latest(), state.NodeID, s.options.Cipher.KeyID()); err == nil {
			t.Fatal("unsafe authority accepted", kind)
		}
		if !reflect.DeepEqual(before, admissionLogicalSnapshot(t, s)) || !reflect.DeepEqual(files, admissionFiles(t, path)) {
			t.Fatal("rejected authority modified database", kind)
		}
		// Exercise the same existing observations against physical log copies;
		// never corrupt or truncate the actual fresh witness evidence.
		bad := *w
		bad.path = filepath.Join(t.TempDir(), "witness-copy.jsonl")
		data, err := os.ReadFile(w.path)
		if err != nil {
			t.Fatal(err)
		}
		switch kind {
		case "corrupt":
			data[len(data)/2] ^= 1
		case "old-authentic-prefix":
			data = append(protocolBytes(w.history[0]), '\n')
		case "wrong-vault-key":
			bad.key = probe.key
		}
		if kind != "missing" {
			if err = os.WriteFile(bad.path, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = bad.readFresh(); err == nil {
			t.Fatal("damaged independent file accepted", kind)
		}
	}
	// Reuse the existing same-revision/different-content observation. The
	// mutation is deliberate fault injection; the subsequent recovery is read-only.
	if _, err = s.db.Exec("UPDATE accounts SET name='same-revision-damaged' WHERE id=(SELECT id FROM accounts ORDER BY id LIMIT 1)"); err != nil {
		t.Fatal(err)
	}
	protocolRefusal(t, s, p, w.latest(), path, "same-revision-different-content")
}
