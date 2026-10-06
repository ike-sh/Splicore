package hostnetwork

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

type FileStore struct {
	directory string
	lock      *os.File
}

func OpenStore(directory string) (*FileStore, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, identity.Err(identity.Invalid, "network journal requires a clean absolute path")
	}
	if err := privateDirectory(directory); err != nil {
		return nil, err
	}
	lock, err := lockDirectory(directory)
	if err != nil {
		return nil, err
	}
	s := &FileStore{directory, lock}
	// The exclusive directory lock proves no live writer owns these reserved
	// temporary names. A crashed temporary is never journal authority.
	if err = s.cleanupTemps(); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return s, nil
}
func (s *FileStore) cleanupTemps() error {
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".journal-") {
			continue
		}
		name := filepath.Join(s.directory, entry.Name())
		info, err := os.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || privateFile(info) != nil || privatePath(name) != nil {
			return identity.Err(identity.Corrupt, "unsafe abandoned network journal temporary")
		}
		if err = os.Remove(name); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return syncDirectory(s.directory)
	}
	return nil
}
func (s *FileStore) Load() (*Journal, error) {
	name := filepath.Join(s.directory, "journal.json")
	info, err := os.Lstat(name)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxJournalBytes || privateFile(info) != nil || privatePath(name) != nil {
		return nil, identity.Err(identity.Corrupt, "unsafe network journal file")
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, identity.Err(identity.Corrupt, "network journal cannot be read")
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return nil, identity.Err(identity.Corrupt, "network journal changed during open")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxJournalBytes+1))
	if err != nil {
		return nil, identity.Err(identity.Corrupt, "network journal cannot be read")
	}
	return DecodeJournal(b)
}
func (s *FileStore) Save(j *Journal) error {
	b, err := json.Marshal(j)
	if err != nil || len(b) > MaxJournalBytes {
		return identity.Err(identity.Invalid, "network journal exceeds bounds")
	}
	if _, err = DecodeJournal(b); err != nil {
		return err
	}
	name := filepath.Join(s.directory, "journal.json")
	if info, e := os.Lstat(name); e == nil {
		if !info.Mode().IsRegular() || privateFile(info) != nil || privatePath(name) != nil {
			return identity.Err(identity.Corrupt, "unsafe network journal destination")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	f, err := os.CreateTemp(s.directory, ".journal-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(append(b, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = replaceFile(temp, name); err != nil {
		return err
	}
	return syncDirectory(s.directory)
}
func (s *FileStore) Close() error { return s.lock.Close() }
