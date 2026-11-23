package sqlite

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

type evidenceFingerprint struct {
	exists bool
	size   int64
	digest [sha256.Size]byte
}

// readOnlyEvidenceSnapshot copies the authoritative SQLite/WAL/witness files
// into a private temporary directory and proves that the source did not change
// during the copy. SQLite may create or update its derived SHM index only in
// that disposable directory, so inspection never changes retained evidence.
func readOnlyEvidenceSnapshot(source string) (string, func() error, error) {
	return readOnlyEvidenceSnapshotWith(source, safeFile)
}

func readOnlyMaintenanceSnapshot(source string) (string, func() error, error) {
	validate := func(path string) error {
		_, err := os.Lstat(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return maintenanceFile(path)
	}
	return readOnlyEvidenceSnapshotWith(source, validate)
}

func readOnlyEvidenceSnapshotWith(source string, validate func(string) error) (string, func() error, error) {
	if !filepath.IsAbs(source) || filepath.Clean(source) != source {
		return "", nil, errors.New("invalid evidence path")
	}
	id, err := identity.NewID()
	if err != nil {
		return "", nil, err
	}
	directory := filepath.Join(os.TempDir(), "splicore-readonly-"+string(id))
	if err = privateDirectory(directory); err != nil {
		return "", nil, err
	}
	cleanup := func() error { return os.RemoveAll(directory) }
	complete := false
	defer func() {
		if !complete {
			_ = cleanup()
		}
	}()
	destination := filepath.Join(directory, "state.db")
	suffixes := []string{"", "-wal", witnessSuffix, pendingSuffix}
	if err = validate(source + "-shm"); err != nil {
		return "", nil, err
	}
	before := make(map[string]evidenceFingerprint, len(suffixes))
	for _, suffix := range suffixes {
		fingerprint, copyErr := copyEvidenceFile(source+suffix, destination+suffix, validate)
		if copyErr != nil {
			return "", nil, copyErr
		}
		if suffix == "" && !fingerprint.exists {
			return "", nil, os.ErrNotExist
		}
		before[suffix] = fingerprint
	}
	for _, suffix := range suffixes {
		after, fingerprintErr := fingerprintEvidenceFile(source+suffix, validate)
		if fingerprintErr != nil {
			return "", nil, fingerprintErr
		}
		if after != before[suffix] {
			return "", nil, identity.Err(identity.Unavailable, "committed storage changed during read-only inspection")
		}
	}
	complete = true
	return destination, cleanup, nil
}

func copyEvidenceFile(source, destination string, validate func(string) error) (evidenceFingerprint, error) {
	if err := validate(source); err != nil {
		return evidenceFingerprint{}, err
	}
	input, err := os.Open(source)
	if os.IsNotExist(err) {
		return evidenceFingerprint{}, nil
	}
	if err != nil {
		return evidenceFingerprint{}, err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return evidenceFingerprint{}, err
	}
	h := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(output, h), input)
	closeErr := output.Close()
	if copyErr != nil {
		return evidenceFingerprint{}, copyErr
	}
	if closeErr != nil {
		return evidenceFingerprint{}, closeErr
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return evidenceFingerprint{exists: true, size: size, digest: digest}, nil
}

func fingerprintEvidenceFile(path string, validate func(string) error) (evidenceFingerprint, error) {
	if err := validate(path); err != nil {
		return evidenceFingerprint{}, err
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return evidenceFingerprint{}, nil
	}
	if err != nil {
		return evidenceFingerprint{}, err
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return evidenceFingerprint{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return evidenceFingerprint{exists: true, size: size, digest: digest}, nil
}
