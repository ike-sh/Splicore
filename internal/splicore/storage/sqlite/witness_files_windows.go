//go:build windows

package sqlite

import "golang.org/x/sys/windows"

func replaceFileDurable(staging, destination string) error {
	from, err := windows.UTF16PtrFromString(staging)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// MOVEFILE_WRITE_THROUGH is the Windows rename durability barrier. Windows
// does not expose a portable directory-fsync contract equivalent to Unix;
// the staging file itself was flushed before this write-through replacement.
func syncParentDirectory(string) error { return nil }
