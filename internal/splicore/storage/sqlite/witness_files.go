package sqlite

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

// durableReplaceFile persists bytes to a new same-directory staging file,
// synchronizes its contents, atomically replaces the destination, and then
// applies the platform directory/rename durability barrier. On any failure the
// staging file is retained as evidence and startup enters fail-closed review.
func durableReplaceFile(staging, destination string, data []byte) error {
	if filepath.Dir(staging) != filepath.Dir(destination) {
		return errors.New("witness staging must share destination directory")
	}
	if err := safeFile(staging); err != nil {
		return err
	}
	f, err := os.OpenFile(staging, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = f.Close()
		}
	}()
	if _, err = io.Copy(f, bytesReader(data)); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = safeFile(staging); err != nil {
		return err
	}
	if err = replaceFileDurable(staging, destination); err != nil {
		return err
	}
	if err = syncParentDirectory(filepath.Dir(destination)); err != nil {
		return err
	}
	complete = true
	return nil
}

type byteReader struct {
	b []byte
	i int
}

func bytesReader(data []byte) *byteReader { return &byteReader{b: data} }
func (r *byteReader) Read(p []byte) (int, error) {
	if r.i == len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
