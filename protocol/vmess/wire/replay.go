package wire

import (
	"container/heap"
	"crypto/sha256"
	"math"
	"sync"
)

// Replay is compiler-owned, independent of listener generations. It has no
// goroutine/timer/FD; expiry is bounded lazy work. Capacity fails closed, never
// evicting a currently admissible token to admit another one.
type Replay struct {
	mu        sync.Mutex
	entries   map[[32]byte]int64
	expiry    expiryHeap
	capacity  int
	highWater int64
	peak      int
}
type expiration struct {
	token [32]byte
	until int64
}
type expiryHeap []expiration

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].until < h[j].until }
func (h expiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *expiryHeap) Push(v any)        { *h = append(*h, v.(expiration)) }
func (h *expiryHeap) Pop() any {
	a := *h
	v := a[len(a)-1]
	a[len(a)-1] = expiration{}
	*h = a[:len(a)-1]
	return v
}
func NewReplay(capacity int) *Replay {
	if capacity < 3 {
		capacity = 3
	}
	return &Replay{entries: map[[32]byte]int64{}, capacity: capacity}
}
func replayToken(kind byte, parts ...[]byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte{kind})
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	var t [32]byte
	copy(t[:], h.Sum(nil))
	return t
}
func (r *Replay) cleanup(now int64) {
	if now > r.highWater {
		r.highWater = now
	}
	for len(r.expiry) > 0 && r.expiry[0].until < r.highWater {
		item := heap.Pop(&r.expiry).(expiration)
		if r.entries[item.token] == item.until {
			delete(r.entries, item.token)
		}
	}
}
func (r *Replay) reserve(now, timestamp int64, tokens [][32]byte) error {
	if r == nil || timestamp < 0 || timestamp > math.MaxInt64-SkewSeconds || !ValidTime(timestamp, now) {
		return ErrAuth
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanup(now)
	// A backward wall-clock jump cannot make a retired auth window valid again.
	if !ValidTime(timestamp, r.highWater) {
		return ErrAuth
	}
	for i, t := range tokens {
		if _, ok := r.entries[t]; ok {
			return ErrAuth
		}
		for _, other := range tokens[:i] {
			if t == other {
				return ErrAuth
			}
		}
	}
	if len(tokens) > r.capacity-len(r.entries) {
		return ErrAuth
	}
	for _, t := range tokens {
		until := timestamp + SkewSeconds
		r.entries[t] = until
		heap.Push(&r.expiry, expiration{t, until})
	}
	if len(r.entries) > r.peak {
		r.peak = len(r.entries)
	}
	return nil
}
func (r *Replay) Snapshot(now int64) (entries, peak, capacity int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanup(now)
	return len(r.entries), r.peak, r.capacity
}
