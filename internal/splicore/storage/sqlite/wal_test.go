package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

// Independent fixture encoder: integration below also checks real SQLite WALs.
func fixtureWAL(page int, big bool, pages ...uint32) []byte {
	h := make([]byte, 32)
	magic := uint32(0x377f0682)
	var order binary.ByteOrder = binary.LittleEndian
	if big {
		magic++
		order = binary.BigEndian
	}
	binary.BigEndian.PutUint32(h, magic)
	binary.BigEndian.PutUint32(h[4:], 3007000)
	binary.BigEndian.PutUint32(h[8:], uint32(page))
	copy(h[16:24], []byte("salt1234"))
	sum := func(b []byte, s [2]uint32) [2]uint32 {
		for i := 0; i < len(b); i += 8 {
			a := order.Uint32(b[i : i+4])
			v := order.Uint32(b[i+4 : i+8])
			s[0] = s[0] + a + s[1]
			s[1] = s[1] + v + s[0]
		}
		return s
	}
	state := sum(h[:24], [2]uint32{})
	binary.BigEndian.PutUint32(h[24:], state[0])
	binary.BigEndian.PutUint32(h[28:], state[1])
	out := h
	for i, p := range pages {
		f := make([]byte, 24+page)
		binary.BigEndian.PutUint32(f, p)
		if i == len(pages)-1 {
			binary.BigEndian.PutUint32(f[4:], p)
		}
		copy(f[8:16], h[16:24])
		for j := 24; j < len(f); j++ {
			f[j] = byte(i + j)
		}
		state = sum(f[:8], state)
		state = sum(f[24:], state)
		binary.BigEndian.PutUint32(f[16:], state[0])
		binary.BigEndian.PutUint32(f[20:], state[1])
		out = append(out, f...)
	}
	return out
}
func TestWALValidation(t *testing.T) {
	base := fixtureWAL(512, false, 1, 9, 2)
	clone := func() []byte { return bytes.Clone(base) }
	cases := []struct {
		name string
		data []byte
		bad  bool
	}{
		{"empty", nil, false}, {"header-only", base[:32], false},
		{"little-endian", base, false}, {"big-endian", fixtureWAL(512, true, 1, 9, 2), false},
		{"max-page", fixtureWAL(65536, false, 1), false},
		{"incomplete-tail", append(clone(), base[32:69]...), false},
		{"short-header", base[:17], true},
	}
	b := clone()
	b[0] ^= 1
	cases = append(cases, struct {
		name string
		data []byte
		bad  bool
	}{"bad-magic", b, true})
	for _, n := range []uint32{0, 1, 511, 513, 65537, 0xffffffff} {
		b = clone()
		binary.BigEndian.PutUint32(b[8:], n)
		cases = append(cases, struct {
			name string
			data []byte
			bad  bool
		}{fmt.Sprintf("bad-page-length-%d", n), b, true})
	}
	b = clone()
	b[24] ^= 1
	cases = append(cases, struct {
		name string
		data []byte
		bad  bool
	}{"header-checksum", b, true})
	b = clone()
	b[32+536+24+17] ^= 1
	cases = append(cases, struct {
		name string
		data []byte
		bad  bool
	}{"middle-checksum", b, true})
	b = clone()
	binary.BigEndian.PutUint32(b[32+536:], 0)
	cases = append(cases, struct {
		name string
		data []byte
		bad  bool
	}{"zero-page", b, true})
	b = clone()
	b[32+536+8] ^= 1
	cases = append(cases, struct {
		name string
		data []byte
		bad  bool
	}{"middle-salt", b, true})
	b = append(clone()[:32+536], base[32+2*536:]...)
	cases = append(cases, struct {
		name string
		data []byte
		bad  bool
	}{"deleted-frame-sequence", b, true})
	b = append(clone(), base[32:]...)
	for off := len(base); off < len(b); off += 536 {
		b[off+8] ^= 1
	}
	cases = append(cases, struct {
		name string
		data []byte
		bad  bool
	}{"old-generation-tail", b, false})
	// Uncommitted spills can be overwritten before SQLite recomputes checksums.
	b = append(clone(), base[32:32+536]...)
	b[len(base)+24] ^= 1
	cases = append(cases, struct {
		name string
		data []byte
		bad  bool
	}{"uncommitted-rechecksum-tail", b, false})
	for _, c := range cases {
		if !t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture-wal")
			if e := os.WriteFile(path, c.data, 0600); e != nil {
				t.Fatal(e)
			}
			err := validateWAL(context.Background(), path)
			if c.bad {
				if !codeIs(err, identity.Corrupt) || !strings.Contains(err.Error(), "original WAL retained") {
					t.Fatal("expected corruption", err)
				}
			} else if err != nil {
				t.Fatal("valid WAL rejected", err)
			}
			after, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(after, c.data) {
				t.Fatal("validator modified input", e)
			}
		}) {
			return
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(validateWAL(ctx, filepath.Join(t.TempDir(), "missing")), context.Canceled) {
		t.Fatal("cancellation lost")
	}
	if e := validateWAL(context.Background(), filepath.Join(t.TempDir(), "missing")); e != nil {
		t.Fatal(e)
	}
}
func recoveryAccount(n int) access.Account {
	payload := strings.Repeat(fmt.Sprintf("record-%d|", n), 16)
	return access.Account{ID: identity.ID(fmt.Sprintf("10000000-0000-4000-8000-%012d", n)), Name: fmt.Sprintf("WAL record%d", n), Enabled: true, Status: access.Active, Metadata: identity.Metadata{"payload": payload, "checksum": fmt.Sprintf("%x", sha256.Sum256([]byte(payload)))}, Stamp: identity.NewStamp(time.Date(2026, 11, 7, 0, 0, n, 0, time.UTC))}
}
func recoveryCommit(t *testing.T, s *Store, n int) {
	t.Helper()
	op, e := s.Transact(context.Background(), identity.Revision(n-1), actor(t), func(w ports.Writer) error { return w.CreateAccount(recoveryAccount(n)) })
	if e != nil || op.State != identity.Committed {
		t.Fatal(n, op, e)
	}
	fmt.Printf("acknowledged record=%d id=%s checksum=%s\n", n, recoveryAccount(n).ID, recoveryAccount(n).Metadata["checksum"])
}
func TestWALRecoveryWorker(t *testing.T) {
	path := os.Getenv("SPLICORE_WAL_FIX_CHILD")
	if path == "" {
		return
	}
	s, e := Open(context.Background(), path, options(t))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("PRAGMA wal_autocheckpoint=0"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); e != nil {
		t.Fatal(e)
	}
	for n := 1; n <= 3; n++ {
		recoveryCommit(t, s, n)
	}
	switch os.Getenv("SPLICORE_WAL_FIX_MODE") {
	case "normal":
		if e = s.Close(); e != nil {
			t.Fatal(e)
		}
		return
	case "uncommitted":
		s.db.SetMaxOpenConns(1)
		if _, e = s.db.Exec("PRAGMA cache_size=4"); e != nil {
			t.Fatal(e)
		}
		_, e = s.Transact(context.Background(), 3, actor(t), func(w ports.Writer) error {
			for n := 4; n <= 80; n++ {
				if e := w.CreateAccount(recoveryAccount(n)); e != nil {
					t.Fatal(e)
				}
			}
			os.Exit(77)
			return nil
		})
		t.Fatal("crash not reached", e)
	case "reuse":
		var busy, log, done int
		if e = s.db.QueryRow("PRAGMA wal_checkpoint(RESTART)").Scan(&busy, &log, &done); e != nil || busy != 0 {
			t.Fatal(e, busy)
		}
		a := recoveryAccount(1)
		a.Name = "reused WAL"
		if _, e = s.Transact(context.Background(), 3, actor(t), func(w ports.Writer) error { return w.UpdateAccount(a, 1) }); e != nil {
			t.Fatal(e)
		}
	}
	os.Exit(77)
}
func recoveryChild(t *testing.T, mode string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "private", "state.db")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWALRecoveryWorker$", "-test.v")
	cmd.Env = append(os.Environ(), "SPLICORE_WAL_FIX_CHILD="+p, "SPLICORE_WAL_FIX_MODE="+mode)
	out, e := cmd.CombinedOutput()
	t.Logf("child mode=%s exit=%v output=%s", mode, e, out)
	if mode == "normal" {
		if e != nil {
			t.Fatal(e)
		}
	} else {
		var x *exec.ExitError
		if !errors.As(e, &x) || x.ExitCode() != 77 {
			t.Fatal("crash not reached", e)
		}
	}
	return p
}
func recoveryCopy(t *testing.T, p string) string {
	t.Helper()
	copyPath := filepath.Join(t.TempDir(), "private", "state.db")
	if e := os.MkdirAll(filepath.Dir(copyPath), 0700); e != nil {
		t.Fatal(e)
	}
	for _, suffix := range []string{"", "-wal"} {
		b, e := os.ReadFile(p + suffix)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(copyPath+suffix, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	return copyPath
}
func recoveryEvidence(t *testing.T, label string, p string) {
	t.Helper()
	root := os.Getenv("SPLICORE_WAL_FIX_EVIDENCE")
	if root == "" {
		return
	}
	target := filepath.Join(root, runtime.GOOS, strings.ReplaceAll(t.Name(), "/", "_"), label)
	if e := os.MkdirAll(target, 0700); e != nil {
		t.Fatal(e)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		b, e := os.ReadFile(p + suffix)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(target, "state.db"+suffix), b, 0600); e != nil {
			t.Fatal(e)
		}
		t.Logf("evidence=%s bytes=%d sha256=%x", label+suffix, len(b), sha256.Sum256(b))
	}
}
func recoveryCheck(t *testing.T, p string, revision, pending int) {
	t.Helper()
	s, e := Open(context.Background(), p, options(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	st, e := s.State(context.Background())
	if e != nil || int(st.Revision) != revision || st.PendingTransactions != pending {
		t.Fatal(st, e)
	}
	var count int
	if e = s.db.QueryRow("SELECT count(*) FROM accounts").Scan(&count); e != nil || count != 3 {
		t.Fatal(count, e)
	}
	for i := 1; i <= 3; i++ {
		a, e := s.Account(context.Background(), recoveryAccount(i).ID)
		if e != nil {
			t.Fatal(e)
		}
		if a.Metadata["payload"] != recoveryAccount(i).Metadata["payload"] || a.Metadata["checksum"] != fmt.Sprintf("%x", sha256.Sum256([]byte(a.Metadata["payload"]))) {
			t.Fatal("record mismatch", i)
		}
	}
	if revision == 4 {
		a, e := s.Account(context.Background(), recoveryAccount(1).ID)
		if e != nil || a.Name != "reused WAL" || a.Revision != 2 {
			t.Fatal(a, e)
		}
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
}
func TestWALRecoveryValidRegression(t *testing.T) {
	for _, mode := range []string{"normal", "committed", "uncommitted", "incomplete-spill", "reuse"} {
		if !t.Run(mode, func(t *testing.T) {
			childMode := mode
			if mode == "incomplete-spill" {
				childMode = "uncommitted"
			}
			p := recoveryChild(t, childMode)
			recoveryEvidence(t, "original", p)
			revision, pending := 3, 0
			if mode == "uncommitted" || mode == "incomplete-spill" {
				pending = 1
			}
			if mode == "reuse" {
				revision = 4
				b, e := os.ReadFile(p + "-wal")
				if e != nil {
					t.Fatal(e)
				}
				frame := 24 + int(binary.BigEndian.Uint32(b[8:12]))
				stale := false
				for off := 32; off+frame <= len(b); off += frame {
					stale = stale || !bytes.Equal(b[off+8:off+16], b[16:24])
				}
				if !stale {
					t.Fatal("fixture did not retain old-generation frames")
				}
			}
			if mode == "committed" {
				b, e := os.ReadFile(p + "-wal")
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(p+"-wal", append(b, b[32:69]...), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "incomplete-spill" {
				p = recoveryCopy(t, p)
				b, e := os.ReadFile(p + "-wal")
				if e != nil {
					t.Fatal(e)
				}
				frame := 24 + int(binary.BigEndian.Uint32(b[8:12]))
				last := 32
				for off := 32; off+frame <= len(b); off += frame {
					if binary.BigEndian.Uint32(b[off+4:off+8]) != 0 {
						last = off + frame
					}
				}
				if len(b) < last+frame {
					t.Fatal("missing uncommitted spill")
				}
				if e = os.WriteFile(p+"-wal", b[:last+frame/2], 0600); e != nil {
					t.Fatal(e)
				}
			}
			for range 3 {
				recoveryCheck(t, p, revision, pending)
			}
		}) {
			return
		}
	}
}
func TestWALRecoveryCorruption(t *testing.T) {
	source := recoveryChild(t, "committed")
	recoveryEvidence(t, "original-pristine", source)
	raw, e := os.ReadFile(source + "-wal")
	if e != nil {
		t.Fatal(e)
	}
	page := int(binary.BigEndian.Uint32(raw[8:12]))
	frame := 24 + page
	commits := []int{}
	for off := 32; off+frame <= len(raw); off += frame {
		if binary.BigEndian.Uint32(raw[off+4:off+8]) != 0 {
			commits = append(commits, off+frame)
		}
	}
	if len(commits) != 6 {
		t.Fatal("expected intent+data commits", commits)
	}
	payload := bytes.Index(raw[commits[2]:commits[3]], []byte(recoveryAccount(2).Metadata["payload"]))
	if payload < 0 {
		t.Fatal("second committed payload not located")
	}
	payload += commits[2]
	off := 32 + (payload-32)/frame*frame
	t.Logf("page=%d frame=%d second-transaction-offset=%d commit_ends=%v", page, frame, off, commits)
	mutations := []struct {
		name  string
		apply func([]byte) []byte
	}{
		{"middle-content", func(b []byte) []byte { b[payload] ^= 0x01; return b }},
		{"middle-header", func(b []byte) []byte { binary.BigEndian.PutUint32(b[off:], 0); return b }},
		{"middle-salt", func(b []byte) []byte { b[off+8] ^= 0x80; return b }},
		{"invalid-page-length", func(b []byte) []byte { binary.BigEndian.PutUint32(b[8:], 0xffffffff); return b }},
		{"header-checksum", func(b []byte) []byte { b[24] ^= 1; return b }},
		{"deleted-middle-frame", func(b []byte) []byte { return append(b[:off], b[off+frame:]...) }},
	}
	for _, m := range mutations {
		if !t.Run(m.name, func(t *testing.T) {
			p := recoveryCopy(t, source)
			b := m.apply(bytes.Clone(raw))
			if e := os.WriteFile(p+"-wal", b, 0600); e != nil {
				t.Fatal(e)
			}
			recoveryEvidence(t, "corrupt-before", p)
			before, e := os.ReadFile(p)
			if e != nil {
				t.Fatal(e)
			}
			for round := 0; round < 3; round++ {
				s, e := Open(context.Background(), p, options(t))
				if s != nil {
					s.Close()
					t.Fatal("partial writable store published")
				}
				if !codeIs(e, identity.Corrupt) || !strings.Contains(e.Error(), "WAL corruption") {
					t.Fatal("corruption not propagated", e)
				}
				t.Logf("attempt=%d error=%v", round, e)
				after, e := os.ReadFile(p + "-wal")
				if e != nil || !bytes.Equal(after, b) {
					t.Fatal("original WAL changed", e)
				}
				db, e := os.ReadFile(p)
				if e != nil || !bytes.Equal(db, before) {
					t.Fatal("valid database prefix changed", e)
				}
			}
			recoveryEvidence(t, "corrupt-after", p)
		}) {
			return
		}
	}
}
func TestWALRecoverySQLitePrefixBaseline(t *testing.T) {
	source := recoveryChild(t, "committed")
	p := recoveryCopy(t, source)
	b, e := os.ReadFile(p + "-wal")
	if e != nil {
		t.Fatal(e)
	}
	page := int(binary.BigEndian.Uint32(b[8:12]))
	frame := page + 24
	commits := []int{}
	for off := 32; off+frame <= len(b); off += frame {
		if binary.BigEndian.Uint32(b[off+4:off+8]) != 0 {
			commits = append(commits, off+frame)
		}
	}
	if len(commits) != 6 {
		t.Fatal(commits)
	}
	b[commits[1]+24+128] ^= 0x80
	if e = os.WriteFile(p+"-wal", b, 0600); e != nil {
		t.Fatal(e)
	}
	recoveryEvidence(t, "original-corrupt-preserved", p)
	// A sacrificial test copy demonstrates dependency behavior, never the guarded
	// Store API. Preserve the original before SQLite can change this scratch copy.
	scratch := recoveryCopy(t, p)
	db, e := sql.Open("sqlite", scratch)
	if e != nil {
		t.Fatal(e)
	}
	var revision, count int
	if e = db.QueryRow("SELECT committed_revision FROM settings").Scan(&revision); e != nil {
		t.Fatal(e)
	}
	if e = db.QueryRow("SELECT count(*) FROM accounts").Scan(&count); e != nil {
		t.Fatal(e)
	}
	if revision != 1 || count != 1 {
		t.Fatal("baseline changed", revision, count)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	_, walErr := os.Stat(scratch + "-wal")
	t.Logf("SQLite-only baseline returned revision=%d records=%d without error; WAL removed after Close=%v", revision, count, os.IsNotExist(walErr))
	preserved, e := os.ReadFile(p + "-wal")
	if e != nil || !bytes.Equal(preserved, b) {
		t.Fatal("preserved evidence altered", e)
	}
	recoveryEvidence(t, "original-corrupt-after-baseline", p)
}
