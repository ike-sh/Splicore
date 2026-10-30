package device

import (
	"encoding/binary"
	"time"
)

func newTimestampObf(_ string) (obf, error) {
	return &timestampObf{}, nil
}

type timestampObf struct{ now func() time.Time }

func (o *timestampObf) Obfuscate(dst, src []byte) {
	now := o.now
	if now == nil {
		now = time.Now
	}
	t := uint32(now().Unix())
	binary.BigEndian.PutUint32(dst, t)
}

func (o *timestampObf) Deobfuscate(dst, src []byte) bool {
	// replay attack check?
	// requires time to be always synchronized
	return true
}

func (o *timestampObf) ObfuscatedLen(n int) int {
	return 4
}

func (o *timestampObf) DeobfuscatedLen(n int) int {
	return 0
}
