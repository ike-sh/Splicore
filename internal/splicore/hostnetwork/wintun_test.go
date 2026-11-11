package hostnetwork

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

type wintunFixtureDriver struct {
	adapter       *wintunFixtureAdapter
	failCreate    bool
	partialCreate bool
	wrongGUID     bool
}
type wintunFixtureAdapter struct {
	id           WindowsAdapterIdentity
	session      *wintunFixtureSession
	closed       bool
	failStart    bool
	partialStart bool
	failClose    bool
	closes       int
}
type wintunFixtureSession struct {
	mu            sync.Mutex
	quit          chan struct{}
	blocked       chan struct{}
	once          sync.Once
	ended         bool
	ends          int
	failEnd       bool
	partialEnd    bool
	reads, writes int
}

func (f *wintunFixtureDriver) Create(_ string, id WindowsAdapterIdentity) (WintunAdapter, error) {
	if f.failCreate && !f.partialCreate {
		return nil, errors.New("create failure")
	}
	a := f.adapter
	a.id = id
	if f.wrongGUID {
		a.id.GUID, _ = identity.NewID()
	}
	if f.failCreate {
		return a, errors.New("partial create failure")
	}
	return a, nil
}
func (a *wintunFixtureAdapter) GUID() (identity.ID, error) { return a.id.GUID, nil }
func (a *wintunFixtureAdapter) StartSession() (WintunSession, error) {
	if a.failStart && !a.partialStart {
		return nil, errors.New("session failure")
	}
	a.session = &wintunFixtureSession{quit: make(chan struct{}), blocked: make(chan struct{})}
	if a.failStart {
		return a.session, errors.New("partial session failure")
	}
	return a.session, nil
}
func (a *wintunFixtureAdapter) Close() error {
	a.closes++
	if a.failClose {
		return errors.New("adapter close failure")
	}
	if a.closed {
		return errors.New("invalid double close")
	}
	a.closed = true
	return nil
}
func (s *wintunFixtureSession) ReadPacket() ([]byte, error) {
	s.mu.Lock()
	s.reads++
	s.mu.Unlock()
	s.once.Do(func() { close(s.blocked) })
	<-s.quit
	return nil, os.ErrClosed
}
func (s *wintunFixtureSession) WritePacket([]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes++
	if s.ended {
		return errors.New("invalid session write")
	}
	return nil
}
func (s *wintunFixtureSession) Interrupt() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.quit:
	default:
		close(s.quit)
	}
	return nil
}
func (s *wintunFixtureSession) End() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failEnd {
		if s.partialEnd && !s.ended {
			s.ended = true
			s.ends++
		}
		return errors.New("session end failure")
	}
	if s.ended && !s.partialEnd {
		return errors.New("invalid double end")
	}
	if !s.ended {
		s.ends++
	}
	s.ended = true
	return nil
}

// Stateful host fixture retains adapters across a simulated process crash but
// drops process-only sessions. Recovery checks the journal GUID before deletion.
type windowsHostFixture struct {
	*fixtureBackend
	driver          *wintunFixtureDriver
	device          *ownedWintun
	interfaceRecord *Record
	failStage       string
	crashed         bool
	events          []string
}

func (b *windowsHostFixture) OwnershipRecords(g, o identity.ID, r []Record) ([]Record, error) {
	return windowsOwnershipRecords(g, o, r)
}
func (b *windowsHostFixture) Authorize(Generation) error { return nil }
func (b *windowsHostFixture) Read(ctx context.Context, r Record) (*Record, error) {
	if r.Kind == "interface" {
		return cloneRecord(b.interfaceRecord), nil
	}
	if r.Kind == "session" {
		if b.device == nil || !b.device.started() {
			return nil, nil
		}
		return cloneRecord(&r), nil
	}
	return b.fixtureBackend.Read(ctx, r)
}
func (b *windowsHostFixture) Write(ctx context.Context, r Record, v *Record) error {
	verb := "apply:"
	if v == nil {
		verb = "restore:"
	}
	b.events = append(b.events, verb+r.Kind)
	if b.failStage == verb+r.Kind {
		return errors.New("host stage failure")
	}
	if r.Kind == "interface" {
		if v != nil {
			d, err := createOwnedWintun(b.driver, r.Interface, *r.Adapter)
			b.device = d
			if d != nil {
				b.interfaceRecord = cloneRecord(&r)
				b.interfaceRecord.Index = 42
			}
			return err
		}
		if b.interfaceRecord == nil {
			return nil
		}
		if r.Adapter == nil || b.interfaceRecord.Adapter.GUID != r.Adapter.GUID {
			return errors.New("unowned adapter")
		}
		if b.crashed {
			b.interfaceRecord = nil
			return nil
		}
		if err := b.device.Close(); err != nil {
			return err
		}
		b.device = nil
		b.interfaceRecord = nil
		return nil
	}
	if r.Kind == "session" {
		if v != nil {
			return b.device.Start()
		}
		if b.device != nil {
			return b.device.closeSession()
		}
		return nil
	}
	return b.fixtureBackend.Write(ctx, r, v)
}
func windowsHostPlan() []Record {
	return []Record{{Kind: "interface", Interface: "fixture13", Addresses: []string{"198.18.0.1/30"}, MTU: 1500}, {Kind: "address", Interface: "fixture13", Prefix: "198.18.0.1/30"}, route("198.19.0.0/16")}
}
func newWindowsHostFixture() *windowsHostFixture {
	return &windowsHostFixture{fixtureBackend: &fixtureBackend{state: map[string]*Record{}}, driver: &wintunFixtureDriver{adapter: &wintunFixtureAdapter{}}}
}
func assertWindowsClean(t *testing.T, b *windowsHostFixture) {
	t.Helper()
	if b.interfaceRecord != nil || b.device != nil {
		t.Fatal("adapter retained")
	}
	for _, v := range b.state {
		if v != nil {
			t.Fatal("host mutation retained")
		}
	}
}

func TestWintunPartialFailureMatrix(t *testing.T) {
	for _, fault := range []string{"adapter", "adapter-partial", "guid-mismatch", "session", "session-partial", "address", "route", "journal-intent", "journal-adapter", "journal-session", "journal-active", "health", "dns-data-plane"} {
		t.Run(fault, func(t *testing.T) {
			b := newWindowsHostFixture()
			s := &memoryStore{}
			switch fault {
			case "adapter":
				b.driver.failCreate = true
			case "adapter-partial":
				b.driver.failCreate = true
				b.driver.partialCreate = true
			case "guid-mismatch":
				b.driver.wrongGUID = true
			case "session":
				b.driver.adapter.failStart = true
			case "session-partial":
				b.driver.adapter.failStart = true
				b.driver.adapter.partialStart = true
			case "address":
				b.failStage = "apply:address"
			case "route":
				b.failStage = "apply:route"
			case "journal-intent":
				s.fail = 1
			case "journal-adapter":
				s.fail = 2
			case "journal-session":
				s.fail = 3
			case "journal-active":
				s.fail = 6
			}
			m, err := New(b, s)
			if err != nil {
				t.Fatal(err)
			}
			ready := func() error {
				if fault == "health" || fault == "dns-data-plane" {
					return errors.New("data plane readiness failure")
				}
				return nil
			}
			if _, err = m.Prepare(context.Background(), windowsHostPlan(), ready); err == nil {
				t.Fatal("failure ignored")
			}
			assertWindowsClean(t, b)
			if fault == "journal-intent" && len(b.events) != 0 {
				t.Fatal("mutation before journal")
			}
			if err = m.Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestWintunCrashRecoveryIdentityAndDoubleCleanup(t *testing.T) {
	ctx := context.Background()
	for _, stage := range []string{"adapter", "session", "route"} {
		b := newWindowsHostFixture()
		s := &memoryStore{}
		m, _ := New(b, s)
		l, err := m.Prepare(ctx, windowsHostPlan(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if stage != "route" {
			b.state = map[string]*Record{}
		}
		if b.device != nil && b.device.session != nil {
			b.device.session.Interrupt()
			b.device.closeSession()
		}
		b.device = nil
		b.crashed = true
		j, _ := DecodeJournal(s.data)
		for i := range j.Generations[0].Steps {
			j.Generations[0].Steps[i].State = "pending"
		}
		j.Generations[0].Steps[0].After.Index = 0
		j.Generations[0].State = "pending"
		if stage == "adapter" {
			// Constructor's default MTU survives a crash before configuration/ack.
			b.interfaceRecord.MTU = 1420
		}
		s.Save(j)
		next, e := New(b, s)
		if e != nil {
			t.Fatal(e)
		}
		if e = next.Recover(ctx); e != nil {
			t.Fatal(stage, e)
		}
		assertWindowsClean(t, b)
		if e = next.Recover(ctx); e != nil {
			t.Fatal("double recovery", e)
		}
		if e = l.Restore(ctx); e != nil {
			t.Fatal("recovery then stop", e)
		}
	}
	b := newWindowsHostFixture()
	s := &memoryStore{}
	m, _ := New(b, s)
	l, err := m.Prepare(ctx, windowsHostPlan(), nil)
	if err != nil {
		t.Fatal(err)
	}
	a := b.driver.adapter
	if err = l.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if err = l.Restore(ctx); err != nil || a.closes != 1 || a.session.ends != 1 {
		t.Fatal("double cleanup", err)
	}
	// Unrelated same-name adapter is detected during snapshot, before Create.
	b = newWindowsHostFixture()
	b.interfaceRecord = cloneRecord(&windowsHostPlan()[0])
	s = &memoryStore{}
	m, _ = New(b, s)
	if _, err = m.Prepare(ctx, windowsHostPlan(), nil); err == nil || len(b.events) != 0 {
		t.Fatal("unrelated adapter taken over")
	}
}
func TestWintunRecoveryDebt(t *testing.T) {
	ctx := context.Background()
	b := newWindowsHostFixture()
	s := &memoryStore{}
	m, _ := New(b, s)
	l, err := m.Prepare(ctx, windowsHostPlan(), nil)
	if err != nil {
		t.Fatal(err)
	}
	b.driver.adapter.failClose = true
	if l.Restore(ctx) == nil || b.device == nil {
		t.Fatal("failed close lost handle")
	}
	j, err := DecodeJournal(s.data)
	if err != nil || j.Generations[0].State != "conflict" || j.Generations[0].Steps[0].State == "restored" {
		t.Fatal("exact adapter debt missing", err)
	}
	b.driver.adapter.failClose = false
	if err = m.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	assertWindowsClean(t, b)
}

func TestWintunParentRetainedUntilChildDebtRestored(t *testing.T) {
	b := newWindowsHostFixture()
	s := &memoryStore{}
	m, _ := New(b, s)
	l, err := m.Prepare(context.Background(), windowsHostPlan(), nil)
	if err != nil {
		t.Fatal(err)
	}
	b.failStage = "restore:route"
	if err = l.Restore(context.Background()); err == nil || b.device == nil || b.driver.adapter.closed {
		t.Fatal("parent removed while child route recovery failed", err)
	}
	j, err := DecodeJournal(s.data)
	if err != nil || j.Generations[0].Steps[0].State == "restored" {
		t.Fatal("parent debt missing", err)
	}
	b.failStage = ""
	if err = m.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertWindowsClean(t, b)
}
func TestWintunReadWriteCloseOwnership(t *testing.T) {
	g, _ := identity.NewID()
	o, _ := identity.NewID()
	id := WindowsAdapterIdentity{GUID: g, Generation: g, Owner: o}
	driver := &wintunFixtureDriver{adapter: &wintunFixtureAdapter{}}
	d, err := createOwnedWintun(driver, "fixture", id)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Start(); err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	go func() { _, e := d.Read(make([]byte, 128)); read <- e }()
	<-driver.adapter.session.blocked
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.Write([]byte{1, 2, 3})
			if e := d.Close(); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if !errors.Is(<-read, os.ErrClosed) || driver.adapter.closes != 1 || driver.adapter.session.ends != 1 {
		t.Fatal("session/adapter lifetime")
	}
}

func TestWintunPartialEndNeverReopensIO(t *testing.T) {
	for _, afterEnd := range []bool{false, true} {
		g, _ := identity.NewID()
		o, _ := identity.NewID()
		driver := &wintunFixtureDriver{adapter: &wintunFixtureAdapter{}}
		d, err := createOwnedWintun(driver, "fixture", WindowsAdapterIdentity{GUID: g, Generation: g, Owner: o})
		if err != nil {
			t.Fatal(err)
		}
		if err = d.Start(); err != nil {
			t.Fatal(err)
		}
		s := driver.adapter.session
		s.failEnd, s.partialEnd = true, afterEnd
		if err = d.Close(); err == nil || d.session == nil || driver.adapter.closed {
			t.Fatal("partial close lost cleanup debt")
		}
		if _, err = d.Read(make([]byte, 128)); !errors.Is(err, os.ErrClosed) {
			t.Fatal("read admitted after session stop", err)
		}
		if _, err = d.Write([]byte{1}); !errors.Is(err, os.ErrClosed) {
			t.Fatal("write admitted after session stop", err)
		}
		if err = d.Start(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("stopped descriptor restarted", err)
		}
		if s.reads != 0 || s.writes != 0 {
			t.Fatal("stopped ring accessed", s.reads, s.writes)
		}
		s.failEnd = false
		if err = d.Close(); err != nil || !driver.adapter.closed || d.session != nil {
			t.Fatal("residual cleanup failed", err)
		}
		if err = d.Close(); err != nil || driver.adapter.closes != 1 {
			t.Fatal("double cleanup", err)
		}
		if s.ends != 1 {
			t.Fatal("native session ended twice", s.ends)
		}
	}
}
