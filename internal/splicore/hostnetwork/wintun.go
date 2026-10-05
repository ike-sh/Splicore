package hostnetwork

import (
	"io"
	"os"
	"sync"

	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
)

type WindowsAdapterIdentity struct {
	GUID       identity.ID `json:"guid"`
	Generation identity.ID `json:"generation"`
	Owner      identity.ID `json:"owner"`
}

func (i WindowsAdapterIdentity) Validate() error {
	if i.GUID.Validate() != nil || i.Generation.Validate() != nil || i.Owner.Validate() != nil {
		return identity.Err(identity.Corrupt, "invalid Wintun ownership identity")
	}
	return nil
}

// Native adapter/session handles never enter the durable journal. Only a random
// GUID and generation/owner identity do. Start failure still returns an owned
// adapter, allowing Manager's reverse compensation to close it.
type WintunDriver interface {
	Create(string, WindowsAdapterIdentity) (WintunAdapter, error)
}
type WintunAdapter interface {
	GUID() (identity.ID, error)
	StartSession() (WintunSession, error)
	Close() error
}
type WintunSession interface {
	ReadPacket() ([]byte, error) // returns an owned copy; driver rings never escape
	WritePacket([]byte) error
	Interrupt() error
	End() error
}

type ownedWintun struct {
	closeMu        sync.Mutex
	mu             sync.Mutex // admission/state only, never held while waiting for a packet
	name           string
	identity       WindowsAdapterIdentity
	adapter        WintunAdapter
	session        WintunSession
	closing        bool
	closed         bool
	sessionStopped bool
	io             sync.WaitGroup
}

func createOwnedWintun(driver WintunDriver, name string, id WindowsAdapterIdentity) (*ownedWintun, error) {
	if id.Validate() != nil {
		return nil, identity.Err(identity.Invalid, "Wintun identity missing")
	}
	a, err := driver.Create(name, id)
	if a == nil {
		if err == nil {
			err = identity.Err(identity.Unavailable, "Wintun driver returned no adapter")
		}
		return nil, err
	}
	d := &ownedWintun{name: name, identity: id, adapter: a}
	if err != nil {
		return d, err
	}
	actual, err := a.GUID()
	if err != nil || actual != id.GUID {
		return d, identity.Err(identity.Conflict, "Wintun GUID differs from durable intent")
	}
	return d, nil
}
func (d *ownedWintun) Name() (string, error) { return d.name, nil }
func (d *ownedWintun) Start() error {
	d.closeMu.Lock()
	defer d.closeMu.Unlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closing || d.closed || d.sessionStopped {
		return os.ErrClosed
	}
	if d.session != nil {
		return nil
	}
	s, err := d.adapter.StartSession()
	if s == nil && err == nil {
		return identity.Err(identity.Unavailable, "Wintun driver returned no session")
	}
	if s != nil {
		d.session = s
	}
	return err
}
func (d *ownedWintun) started() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.session != nil && !d.closing && !d.closed && !d.sessionStopped
}
func (d *ownedWintun) begin() (WintunSession, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closing || d.closed || d.sessionStopped || d.session == nil {
		return nil, os.ErrClosed
	}
	d.io.Add(1)
	return d.session, nil
}
func (d *ownedWintun) Read(p []byte) (int, error) {
	s, err := d.begin()
	if err != nil {
		return 0, err
	}
	defer d.io.Done()
	packet, err := s.ReadPacket()
	if err != nil {
		return 0, err
	}
	if len(packet) > len(p) {
		return 0, io.ErrShortBuffer
	}
	return copy(p, packet), nil
}
func (d *ownedWintun) Write(p []byte) (int, error) {
	if len(p) == 0 || len(p) > 65535 {
		return 0, os.ErrInvalid
	}
	s, err := d.begin()
	if err != nil {
		return 0, err
	}
	defer d.io.Done()
	if err = s.WritePacket(p); err != nil {
		return 0, err
	}
	return len(p), nil
}
func (d *ownedWintun) stopSession() error {
	d.mu.Lock()
	// Ending a session and releasing its auxiliary handles are separate effects.
	// An error can follow EndSession; never reopen I/O admission onto that ring.
	// Retain the session object solely for a subsequent debt-cleanup operation.
	d.sessionStopped = true
	if d.closed || d.session == nil {
		d.mu.Unlock()
		return nil
	}
	if d.closing {
		d.mu.Unlock()
		return identity.Err(identity.Conflict, "Wintun cleanup in progress")
	}
	d.closing = true
	s := d.session
	d.mu.Unlock()
	if err := s.Interrupt(); err != nil {
		d.mu.Lock()
		d.closing = false
		d.mu.Unlock()
		return err
	}
	d.io.Wait()
	err := s.End()
	d.mu.Lock()
	if err == nil {
		d.session = nil
	}
	d.closing = false
	d.mu.Unlock()
	return err
}
func (d *ownedWintun) Close() error {
	// Serialize cleanup independently of I/O admission: concurrent Close callers
	// must join the same close, never end a session or close an adapter twice.
	d.closeMu.Lock()
	defer d.closeMu.Unlock()
	if err := d.stopSession(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	err := d.adapter.Close()
	if err == nil {
		d.closed = true
	}
	return err
}

func (d *ownedWintun) closeSession() error {
	d.closeMu.Lock()
	defer d.closeMu.Unlock()
	return d.stopSession()
}

// Interrupt stops borrowed packet use. The journal retains session/adapter
// release ownership; End is performed only by its later compensation.
func (d *ownedWintun) Interrupt() error {
	d.mu.Lock()
	d.sessionStopped = true
	s := d.session
	d.mu.Unlock()
	if s == nil {
		return nil
	}
	return s.Interrupt()
}

func windowsOwnershipRecords(generation, owner identity.ID, desired []Record) ([]Record, error) {
	var out []Record
	var adapter *WindowsAdapterIdentity
	for _, raw := range desired {
		r := *cloneRecord(&raw)
		if r.WindowsRoute != nil {
			r.WindowsRoute.Generation = generation
			r.WindowsRoute.Owner = owner
		}
		if r.Kind == "interface" {
			guid, err := identity.NewID()
			if err != nil {
				return nil, err
			}
			adapter = &WindowsAdapterIdentity{GUID: guid, Generation: generation, Owner: owner}
			r.Adapter = adapter
			out = append(out, r, Record{Kind: "session", Interface: r.Interface, Adapter: adapter})
			continue
		}
		if r.Kind == "address" {
			if adapter == nil {
				return nil, identity.Err(identity.Invalid, "Windows address has no owned adapter")
			}
			r.Adapter = adapter
		}
		out = append(out, r)
	}
	return out, nil
}
