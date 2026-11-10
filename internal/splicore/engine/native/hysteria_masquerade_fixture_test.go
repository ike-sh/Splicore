package native

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/hostnetwork"
	module "github.com/ike-sh/Splicore/internal/splicore/tlsconfig"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func masqueradeTLS(t testing.TB) module.Settings {
	return masqueradeTLSForName(t, "hy2.synthetic.test")
}
func masqueradeTLSForName(t testing.TB, name string) module.Settings {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Splicore synthetic CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return module.Settings{ServerName: name, CertificateFile: certPath, PrivateKeyFile: keyPath, CACertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))}
}

type masqueradeUnderlayEvent struct {
	Scope            underlay.Scope
	Network, Address string
}
type masqueradeNetworkBackend struct {
	Removed    chan string
	mu         sync.Mutex
	state      map[string]*hostnetwork.Record
	Events     []masqueradeUnderlayEvent
	Writes     int
	FailWrite  int
	FailVerify bool
}

func (*masqueradeNetworkBackend) Scope() string { return "owned-underlay-runtime-fixture" }
func masqueradeRecordKey(r hostnetwork.Record) string {
	if r.WindowsRoute != nil {
		return "route:" + r.WindowsRoute.Destination
	}
	return r.Kind + ":" + r.Interface + ":" + r.Prefix
}
func masqueradeRecordClone(r *hostnetwork.Record) *hostnetwork.Record {
	if r == nil {
		return nil
	}
	b, _ := json.Marshal(r)
	var out hostnetwork.Record
	_ = json.Unmarshal(b, &out)
	return &out
}
func (b *masqueradeNetworkBackend) Read(_ context.Context, r hostnetwork.Record) (*hostnetwork.Record, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	current := b.state[masqueradeRecordKey(r)]
	if current != nil && r.WindowsRoute != nil && current.WindowsRoute != nil {
		x, y := *current.WindowsRoute, *r.WindowsRoute
		// Kernel routes do not contain Splicore's reasons/owner metadata. The
		// real native readback validates physical fields then returns the key.
		if x.Destination == y.Destination && x.Index == y.Index && x.InterfaceGUID == y.InterfaceGUID && x.NextHop == y.NextHop && x.Metric == y.Metric {
			return masqueradeRecordClone(&r), nil
		}
	}
	return masqueradeRecordClone(current), nil
}
func (b *masqueradeNetworkBackend) Write(_ context.Context, r hostnetwork.Record, v *hostnetwork.Record) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Writes++
	if b.Writes == b.FailWrite {
		return errors.New("fixture provisioning failure")
	}
	b.state[masqueradeRecordKey(r)] = masqueradeRecordClone(v)
	if v == nil && r.WindowsRoute != nil && b.Removed != nil {
		prefix, _ := netip.ParsePrefix(r.WindowsRoute.Destination)
		b.Removed <- prefix.Addr().String()
	}
	return nil
}

func (b *masqueradeNetworkBackend) Protect(_ context.Context, s underlay.Scope, n, a string, _ syscall.RawConn) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.FailVerify {
		return errors.New("fixture verification failure")
	}
	b.Events = append(b.Events, masqueradeUnderlayEvent{s, n, a})
	return nil
}

func (b *masqueradeNetworkBackend) Count(p underlay.Purpose) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, e := range b.Events {
		if e.Scope.Purpose == p {
			n++
		}
	}
	return n
}

func (b *masqueradeNetworkBackend) SnapshotEvents() []masqueradeUnderlayEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]masqueradeUnderlayEvent(nil), b.Events...)
}

func (b *masqueradeNetworkBackend) SetFailure(write int, verify bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if write > 0 {
		b.FailWrite = b.Writes + write
	} else {
		b.FailWrite = 0
	}
	b.FailVerify = verify
}

type masqueradeUnderlayStore struct {
	mu              sync.Mutex
	Data            []byte
	Saves, FailSave int
}

func (s *masqueradeUnderlayStore) Load() (*hostnetwork.Journal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.Data) == 0 {
		return nil, nil
	}
	return hostnetwork.DecodeJournal(s.Data)
}
func (s *masqueradeUnderlayStore) Save(j *hostnetwork.Journal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Saves++
	if s.Saves == s.FailSave {
		return errors.New("fixture journal failure")
	}
	s.Data, _ = json.Marshal(j)
	return nil
}
func (*masqueradeUnderlayStore) Close() error { return nil }

type masqueradeUnderlayFixture struct {
	Factory *underlay.Factory
	Host    *hostnetwork.Manager
	Lease   *hostnetwork.Lease
	Backend *masqueradeNetworkBackend
	Store   *masqueradeUnderlayStore
}

func newMasqueradeUnderlay(t testing.TB) *masqueradeUnderlayFixture {
	t.Helper()
	b := &masqueradeNetworkBackend{state: map[string]*hostnetwork.Record{}, Removed: make(chan string, 1024)}
	s := &masqueradeUnderlayStore{}
	m, e := hostnetwork.New(b, s)
	if e != nil {
		t.Fatal(e)
	}
	l, e := m.Prepare(context.Background(), []hostnetwork.Record{{Kind: "rule", Family: 4, Priority: 12000, Table: 254, Mark: 1}}, func() error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	guid, _ := identity.NewID()
	w := &underlay.WindowsBackend{Lease: l, Underlays: map[bool]hostnetwork.WindowsUnderlay{true: {InterfaceGUID: guid, Index: 42, NextHop: netip.MustParseAddr("192.0.2.254"), Metric: 100}, false: {InterfaceGUID: guid, Index: 42, NextHop: netip.MustParseAddr("2001:db8::ffff"), Metric: 100}}, SocketControl: b.Protect, Readback: l.Verify}
	f := underlay.NewWithBackend(w)
	t.Cleanup(func() {
		if e := l.Restore(context.Background()); e != nil {
			t.Error(e)
		}
		if e := m.Close(); e != nil {
			t.Error(e)
		}
	})
	return &masqueradeUnderlayFixture{f, m, l, b, s}
}
