package hostnetwork

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// This backend persists synthetic host records, never accesses host networking.
type phase15CrashBackend struct {
	fixtureBackend
	path, stage string
}

func (b *phase15CrashBackend) Write(ctx context.Context, key Record, value *Record) error {
	if err := b.fixtureBackend.Write(ctx, key, value); err != nil {
		return err
	}
	data, err := json.Marshal(b.state)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(b.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if b.stage == "unacknowledged-host-write" || b.stage == "unacknowledged-interface" {
		os.Exit(77)
	}
	return nil
}

type phase15CrashJournal struct {
	*FileStore
	stage string
}

func (s phase15CrashJournal) Save(j *Journal) error {
	if s.stage == "partial-derived-write" {
		f, err := os.CreateTemp(s.directory, ".journal-*")
		if err != nil {
			return err
		}
		if _, err = f.Write([]byte(`{"schema":`)); err != nil {
			return err
		}
		if err = f.Sync(); err != nil {
			return err
		}
		os.Exit(77)
	}
	if err := s.FileStore.Save(j); err != nil {
		return err
	}
	if s.stage == "renamed-journal" {
		os.Exit(77)
	}
	return nil
}

func TestPhase15ProcessJournalCrashRecovery(t *testing.T) {
	if root := os.Getenv("SPLICORE_PHASE15_JOURNAL_ROOT"); root != "" {
		stage := os.Getenv("SPLICORE_PHASE15_JOURNAL_STAGE")
		store, err := OpenStore(filepath.Join(root, "journal"))
		if err != nil {
			t.Fatal(err)
		}
		b := &phase15CrashBackend{fixtureBackend: fixtureBackend{state: map[string]*Record{}}, path: filepath.Join(root, "host.json"), stage: stage}
		m, err := New(b, store)
		if err != nil {
			t.Fatal(err)
		}
		// A previous valid journal is the only authority if a derived temp is partial.
		if err = store.Save(m.journal); err != nil {
			t.Fatal(err)
		}
		m.store = phase15CrashJournal{store, stage}
		plan := []Record{{Kind: "interface", Interface: "synthetic0", MTU: 1500, Addresses: []string{"198.18.0.1/30"}}, route("198.18.0.0/16")}
		if stage == "unacknowledged-host-write" {
			plan = []Record{route("198.18.0.0/16")}
		}
		if _, err = m.Prepare(context.Background(), plan, nil); err != nil {
			t.Fatal(err)
		}
		if stage == "active-tun-metadata" {
			os.Exit(77)
		}
		t.Fatal("crash not reached")
	}
	for _, stage := range []string{"partial-derived-write", "renamed-journal", "unacknowledged-host-write", "unacknowledged-interface", "active-tun-metadata"} {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPhase15ProcessJournalCrashRecovery$")
			cmd.Env = append(os.Environ(), "SPLICORE_PHASE15_JOURNAL_ROOT="+root, "SPLICORE_PHASE15_JOURNAL_STAGE="+stage)
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 77 {
				t.Fatalf("fault not reached: %v\n%s", err, output)
			}
			beforeTemps, err := filepath.Glob(filepath.Join(root, "journal", ".journal-*"))
			if err != nil {
				t.Fatal(err)
			}
			if stage == "partial-derived-write" && len(beforeTemps) != 1 {
				t.Fatal("partial-write crash did not leave its owned temporary", beforeTemps)
			}
			store, err := OpenStore(filepath.Join(root, "journal"))
			if err != nil {
				t.Fatal(err)
			}
			b := &phase15CrashBackend{fixtureBackend: fixtureBackend{state: map[string]*Record{}}, path: filepath.Join(root, "host.json")}
			data, err := os.ReadFile(b.path)
			if err == nil {
				if err = json.Unmarshal(data, &b.state); err != nil {
					t.Fatal(err)
				}
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
			m, err := New(b, store)
			if err != nil {
				store.Close()
				t.Fatal(err)
			}
			defer m.Close()
			if stage == "active-tun-metadata" && m.Status().OwnedInterfaces != 1 {
				t.Fatal("active TUN ownership was not durable")
			}
			if stage == "unacknowledged-interface" {
				if err = m.Recover(ctx); err == nil || m.Status().Recovery != "degraded" || m.Status().OwnedInterfaces != 1 {
					t.Fatal("ambiguous interface ownership did not fail closed", err)
				}
				return
			}
			if err = m.Recover(ctx); err != nil {
				t.Fatal(err)
			}
			for _, value := range b.state {
				if value != nil {
					t.Fatal("synthetic owned state not restored")
				}
			}
			if status := m.Status(); status.ActiveGenerations != 0 || status.Recovery != "clean" {
				t.Fatal(status)
			}
			files, err := filepath.Glob(filepath.Join(root, "journal", ".journal-*"))
			if err != nil || len(files) != 0 {
				t.Fatal("derived crash temporary survived", files, err)
			}
			t.Logf("RESOURCE journal crash=%s temp_files start=0 peak=%d end=%d", stage, len(beforeTemps), len(files))
		})
	}
}

func TestPhase15UnsafeJournalTemporaryFailsClosedAndReleasesLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	temporary := filepath.Join(dir, ".journal-unsafe")
	if err = os.Mkdir(temporary, 0700); err != nil {
		t.Fatal(err)
	}
	if s, err = OpenStore(dir); err == nil {
		s.Close()
		t.Fatal("unsafe reserved temporary accepted")
	}
	if err = os.Remove(temporary); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(dir)
	if err != nil {
		t.Fatal("failed startup leaked exclusive lock", err)
	}
	s.Close()
}
