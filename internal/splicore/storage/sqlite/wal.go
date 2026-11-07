package sqlite

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

const (
	walHeaderSize      = 32
	walFrameHeaderSize = 24
)

// validateWAL runs under the installation lock, before SQLite can recover,
// checkpoint or remove a damaged log. It never writes or publishes a prefix.
// A WAL reset can leave old-salt frames, and an uncommitted spill can have
// checksums pending recomputation. Validate the entire current-generation
// committed chain, not those legal leftovers. See SQLite walFrames/iReCksum.
func validateWAL(ctx context.Context, path string) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return storageError(err)
	}
	defer func() {
		if err := f.Close(); result == nil && err != nil {
			result = storageError(err)
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return storageError(err)
	}
	size := info.Size()
	if size == 0 {
		return nil
	}
	if size < walHeaderSize {
		return corruptWAL("incomplete header", 0)
	}
	var header [walHeaderSize]byte
	if _, err = f.ReadAt(header[:], 0); err != nil {
		return storageError(err)
	}
	magic := binary.BigEndian.Uint32(header[0:4])
	if magic != 0x377f0682 && magic != 0x377f0683 {
		return corruptWAL("invalid header magic", 0)
	}
	if binary.BigEndian.Uint32(header[4:8]) != 3007000 {
		return corruptWAL("unsupported header version", 4)
	}
	pageSize := binary.BigEndian.Uint32(header[8:12])
	if pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		return corruptWAL("invalid page length", 8)
	}
	var order binary.ByteOrder = binary.LittleEndian
	if magic&1 != 0 {
		order = binary.BigEndian
	}
	checksum := walChecksum(order, header[:24], [2]uint32{})
	if checksum[0] != binary.BigEndian.Uint32(header[24:28]) || checksum[1] != binary.BigEndian.Uint32(header[28:32]) {
		return corruptWAL("header checksum mismatch", 24)
	}
	frameSize := int64(walFrameHeaderSize) + int64(pageSize)
	lastCommit := int64(walHeaderSize)
	staleAt := int64(-1)
	// Locate commit markers without trusting their checksums yet. Reject a salt
	// gap followed by current-generation data, rather than mislabeling it reuse.
	for offset := int64(walHeaderSize); offset <= size-walFrameHeaderSize; offset += frameSize {
		if err = ctx.Err(); err != nil {
			return err
		}
		var fh [walFrameHeaderSize]byte
		if _, err = f.ReadAt(fh[:], offset); err != nil {
			return storageError(err)
		}
		active := bytes.Equal(fh[8:16], header[16:24])
		if !active {
			if staleAt < 0 {
				staleAt = offset
			}
		} else {
			if staleAt >= 0 {
				return corruptWAL("middle frame salt mismatch", staleAt)
			}
			if size-offset >= frameSize {
				if binary.BigEndian.Uint32(fh[:4]) == 0 {
					return corruptWAL("invalid frame page number", offset)
				}
				if binary.BigEndian.Uint32(fh[4:8]) != 0 {
					lastCommit = offset + frameSize
				}
			}
		}
		// Avoid overflow and never turn a partial final frame into a commit.
		if size-offset < frameSize {
			break
		}
	}
	frame := make([]byte, int(frameSize)) // <=65560 bytes, independent of file size
	for offset := int64(walHeaderSize); offset < lastCommit; offset += frameSize {
		if err = ctx.Err(); err != nil {
			return err
		}
		if _, err = f.ReadAt(frame, offset); err != nil {
			return storageError(err)
		}
		checksum = walChecksum(order, frame[:8], checksum)
		checksum = walChecksum(order, frame[walFrameHeaderSize:], checksum)
		if checksum[0] != binary.BigEndian.Uint32(frame[16:20]) || checksum[1] != binary.BigEndian.Uint32(frame[20:24]) {
			return corruptWAL("frame checksum mismatch", offset)
		}
	}
	return nil
}

func walChecksum(order binary.ByteOrder, b []byte, s [2]uint32) [2]uint32 {
	for len(b) > 0 {
		s[0] += order.Uint32(b[:4]) + s[1]
		s[1] += order.Uint32(b[4:8]) + s[0]
		b = b[8:]
	}
	return s
}
func corruptWAL(reason string, offset int64) error {
	return identity.Err(identity.Corrupt, fmt.Sprintf("WAL corruption at byte %d: %s; recovery refused; original WAL retained", offset, reason))
}
