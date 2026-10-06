package backend

import (
	"net"
	"sync"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/packetio"
	"github.com/ike-sh/Splicore/protocol/vless/wire"
)

// packetRegistry belongs to the parent. Its lock never covers child Close,
// transport IO, handler callbacks, or worker joins.
type packetRegistry struct {
	mu      sync.Mutex
	entries map[uint16]*packetAssociation
	closed  bool
}

type packetAssociation struct {
	*packetio.Queue
	registry    *packetRegistry
	session     uint16
	destination access.Endpoint // guarded by registry.mu
}

func (p *packetAssociation) Close() error {
	err := p.Queue.Close()
	p.registry.unregister(p)
	return err
}

func (r *packetRegistry) unregister(p *packetAssociation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries[p.session] == p {
		delete(r.entries, p.session)
	}
}

func (r *packetRegistry) lookup(id uint16) *packetAssociation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.entries[id]
}

func (r *packetRegistry) register(id uint16, dst access.Endpoint, create func() *packetio.Queue) (*packetAssociation, access.Endpoint, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, dst, false, net.ErrClosed
	}
	p := r.entries[id]
	if p != nil && p.Context().Err() != nil {
		delete(r.entries, id)
		p = nil
	}
	if dst == (access.Endpoint{}) && p != nil {
		dst = p.destination
	}
	if dst.Validate() != nil {
		return nil, dst, false, wire.ErrFrame
	}
	if p != nil {
		p.destination = dst
		return p, dst, false, nil
	}
	if len(r.entries) >= 128 {
		return nil, dst, false, wire.ErrFrame
	}
	if r.entries == nil {
		r.entries = make(map[uint16]*packetAssociation)
	}
	p = &packetAssociation{Queue: create(), registry: r, session: id, destination: dst}
	r.entries[id] = p
	return p, dst, true, nil
}

func (r *packetRegistry) close() {
	r.mu.Lock()
	r.closed = true
	entries := r.entries
	r.entries = nil
	r.mu.Unlock()
	for _, p := range entries {
		_ = p.Close()
	}
}
