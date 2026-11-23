//go:build !windows

package sqlite

import "os"

func replaceFileDurable(staging, destination string) error {
	return os.Rename(staging, destination)
}

func syncParentDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
