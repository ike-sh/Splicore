package wire

import (
	"crypto/sha256"
	"math/big"
	"sync"
	"time"
)

var bigPaddingBound = big.NewInt(MaxPadding)

type saltEntry struct {
	key    [32]byte
	expiry time.Time
}

// SaltCache rejects admission at capacity. It never evicts an unexpired salt.
// Expiry uses Go's monotonic time; protocol timestamps use wall clock separately.
type SaltCache struct {
	mu       sync.Mutex
	capacity int
	lifetime time.Duration
	values   map[[32]byte]time.Time
	queue    []saltEntry
	head     int
}

func NewSaltCache(capacity int, lifetime time.Duration) *SaltCache {
	return &SaltCache{capacity: capacity, lifetime: lifetime, values: map[[32]byte]time.Time{}}
}
func (c *SaltCache) Check(key *Key, salt []byte, now time.Time) error {
	digest := sha256.New()
	digest.Write(key.Material)
	digest.Write(salt)
	var id [32]byte
	copy(id[:], digest.Sum(nil))
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.head < len(c.queue) && !c.queue[c.head].expiry.After(now) {
		delete(c.values, c.queue[c.head].key)
		c.head++
	}
	if c.head > c.capacity/2 {
		c.queue = append([]saltEntry(nil), c.queue[c.head:]...)
		c.head = 0
	}
	if expiry, ok := c.values[id]; ok && expiry.After(now) {
		return ErrReplay
	}
	if len(c.values) >= c.capacity {
		return ErrCapacity
	}
	expiry := now.Add(c.lifetime)
	c.values[id] = expiry
	c.queue = append(c.queue, saltEntry{id, expiry})
	return nil
}
func (c *SaltCache) Len() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.values) }

// Window is protocol-local mutable session state, protected by the caller's
// session read lock. Authentication and semantic checks precede Commit.
type Window struct {
	high        uint64
	initialized bool
	bits        [16]uint64
}

func (w *Window) Accept(id uint64) bool {
	if !w.initialized || id > w.high {
		return true
	}
	delta := w.high - id
	return delta < 1024 && w.bits[delta/64]&(uint64(1)<<(delta%64)) == 0
}

type udpReplayID struct {
	key     [16]byte
	session uint64
}
type udpReplayEntry struct {
	window Window
	last   time.Time
}

// UDPReplay is shared only by generations of one inbound. It retains authenticated
// windows when a routed socket closes, preventing replay-driven socket recreation.
type UDPReplay struct {
	mu       sync.Mutex
	entries  map[udpReplayID]*udpReplayEntry
	capacity int
}

func NewUDPReplay(capacity int) *UDPReplay {
	return &UDPReplay{entries: map[udpReplayID]*udpReplayEntry{}, capacity: capacity}
}
func (r *UDPReplay) Check(k *Key, p Datagram, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := udpReplayID{k.Hash, p.Session}
	entry := r.entries[id]
	if entry != nil && now.Sub(entry.last) > 90*time.Second {
		delete(r.entries, id)
		entry = nil
	}
	if entry == nil {
		if len(r.entries) >= r.capacity {
			for id, e := range r.entries {
				if now.Sub(e.last) > 90*time.Second {
					delete(r.entries, id)
				}
			}
		}
		if len(r.entries) >= r.capacity {
			return ErrCapacity
		}
		entry = &udpReplayEntry{}
		r.entries[id] = entry
	}
	if !entry.window.Accept(p.Packet) {
		return ErrReplay
	}
	entry.window.Commit(p.Packet)
	entry.last = now
	return nil
}
func (w *Window) Commit(id uint64) {
	if !w.initialized {
		w.initialized = true
		w.high = id
	} else if id > w.high {
		delta := id - w.high
		var shifted [16]uint64
		if delta < 1024 {
			for i := uint64(0); i < 1024-delta; i++ {
				if w.bits[i/64]&(uint64(1)<<(i%64)) != 0 {
					d := i + delta
					shifted[d/64] |= uint64(1) << (d % 64)
				}
			}
		}
		w.bits = shifted
		w.high = id
	}
	delta := w.high - id
	if delta < 1024 {
		w.bits[delta/64] |= uint64(1) << (delta % 64)
	}
}
