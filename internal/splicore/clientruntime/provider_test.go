package clientruntime

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/domain/provider"
	"github.com/ike-sh/Splicore/internal/splicore/networkruntime"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/remotesource"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

type providerControl struct {
	scope            underlay.Scope
	network, address string
}
type providerBackend struct {
	calls    atomic.Int64
	controls chan providerControl
	protect  func() error
}

func (*providerBackend) Capabilities() underlay.Capabilities {
	return underlay.Capabilities{PerSocket: true, SystemResolver: true}
}
func (b *providerBackend) Protect(_ context.Context, s underlay.Scope, n, a string, _ syscall.RawConn) error {
	b.calls.Add(1)
	if b.controls != nil {
		b.controls <- providerControl{s, n, a}
	}
	if b.protect != nil {
		return b.protect()
	}
	return nil
}
func (*providerBackend) Reconcile(context.Context, []underlay.Endpoint) error { return nil }
func (*providerBackend) Verify(ctx context.Context) error                     { return ctx.Err() }

func providerManager(t *testing.T, b *providerBackend, dialers map[identity.ID]ports.ClientDialer) (*Manager, *underlay.Factory, *snapshot) {
	t.Helper()
	f := underlay.NewWithBackend(b)
	main, e := f.Begin(context.Background(), true)
	if e != nil {
		t.Fatal(e)
	}
	state := client.Empty()
	// Model an already admitted required generation, without creating a TUN,
	// host routes or a second network stack in this lifecycle test.
	state.LocalInbounds = []client.LocalInbound{{Kind: "tun"}}
	engine, e := networkruntime.NewWithUnderlay(f, main.ID, state.Network, dialers, nil)
	if e != nil {
		t.Fatal(e)
	}
	g := &snapshot{state: state, underlay: main, network: engine, outbounds: dialers}
	g.refs.Store(1)
	m := NewWithUnderlay(f)
	m.current.Store(g)
	t.Cleanup(func() {
		if old := m.current.Swap(nil); old != nil {
			if e := old.release(); e != nil {
				t.Error(e)
			}
		}
		if e := m.Close(context.Background()); e != nil {
			t.Error(e)
		}
	})
	return m, f, g
}
func providerWait(t *testing.T, ch <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("wait", label)
	}
}
func providerWaitSealed(t *testing.T, f *FetchNetwork) {
	t.Helper()
	end := time.NewTimer(3 * time.Second)
	defer end.Stop()
	for {
		_, e := f.Resolve(context.Background(), "127.0.0.1")
		if errors.Is(e, net.ErrClosed) {
			return
		}
		if e != nil {
			t.Fatal(e)
		}
		select {
		case <-end.C:
			t.Fatal("Close never sealed admission")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestProviderFetchLeaseWaitsForProtectedDial(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	b := &providerBackend{controls: make(chan providerControl, 2), protect: func() error {
		close(entered)
		<-release
		return errors.New("synthetic protection refusal before connect")
	}}
	m, f, g := providerManager(t, b, nil)
	n, e := m.OpenFetch(context.Background(), P.Action{Kind: P.Direct})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = n.Close() })
	dialDone := make(chan error, 1)
	go func() {
		_, e := n.Dial(context.Background(), access.Endpoint{Host: "192.0.2.7", Port: 443})
		dialDone <- e
	}()
	providerWait(t, entered, "protected control")
	// Retire the manager's generation while this fetch owns its last reference.
	old := m.current.Swap(nil)
	if e = old.release(); e != nil {
		t.Fatal(e)
	}
	closeDone := make(chan struct{})
	var closeErr error
	go func() { closeErr = n.Close(); close(closeDone) }()
	providerWaitSealed(t, n)
	st := f.Status()
	if st.ActiveLeases != 2 || st.Endpoints != 1 || g.refs.Load() != 1 {
		t.Fatal("pending dial protection retired", st, g.refs.Load())
	}
	select {
	case <-closeDone:
		t.Fatal("Close returned while protection still running")
	default:
	}
	c := <-b.controls
	if c.scope.Purpose != underlay.ProviderFetch || c.scope.Generation != n.lease.ID || c.address != "192.0.2.7:443" || !strings.HasPrefix(c.network, "tcp") {
		t.Fatal("wrong protected capability", c)
	}
	close(release)
	released = true
	select {
	case e = <-dialDone:
		if e == nil {
			t.Fatal("protection error swallowed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dial did not finish")
	}
	providerWait(t, closeDone, "fetch Close")
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if st = f.Status(); st.ActiveLeases != 0 || st.Endpoints != 0 {
		t.Fatal("leases not released after dial exit", st)
	}
	if _, e = n.Dial(context.Background(), access.Endpoint{Host: "127.0.0.1", Port: 1}); !errors.Is(e, net.ErrClosed) {
		t.Fatal("late Dial admitted", e)
	}
	if _, e = n.Resolve(context.Background(), "127.0.0.1"); !errors.Is(e, net.ErrClosed) {
		t.Fatal("late Resolve admitted", e)
	}
	if e = n.Close(); e != nil {
		t.Fatal(e)
	}
	t.Log("protected dial exit precedes temporary lease and final generation retirement; no connection was sent to the documentation address")
}

type providerProxy struct {
	dial   func(context.Context, access.Endpoint) (net.Conn, error)
	closed atomic.Bool
}

func (d *providerProxy) DialContext(ctx context.Context, e access.Endpoint) (net.Conn, error) {
	return d.dial(ctx, e)
}
func (d *providerProxy) Close() error { d.closed.Store(true); return nil }

type providerTrackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *providerTrackedConn) Close() error { c.closed.Store(true); return c.Conn.Close() }

func TestProviderFetchLateProxySocketClosesBeforeGeneration(t *testing.T) {
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	raw, peer := net.Pipe()
	defer peer.Close()
	tracked := &providerTrackedConn{Conn: raw}
	id, _ := identity.NewID()
	var calls atomic.Int64
	proxy := &providerProxy{dial: func(ctx context.Context, e access.Endpoint) (net.Conn, error) {
		calls.Add(1)
		if e.Host != "192.0.2.8" {
			return nil, errors.New("wrong target")
		}
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return tracked, nil // deliberately late success after cancellation
	}}
	m, f, g := providerManager(t, &providerBackend{}, map[identity.ID]ports.ClientDialer{id: proxy})
	n, e := m.OpenFetch(context.Background(), P.Action{Kind: P.Outbound, ID: id})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = n.Close() })
	releasedSafely := make(chan bool, 1)
	g.onReleased = func() { releasedSafely <- tracked.closed.Load() }
	done := make(chan error, 1)
	go func() { _, e := n.Dial(context.Background(), access.Endpoint{Host: "192.0.2.8", Port: 443}); done <- e }()
	providerWait(t, entered, "proxy")
	old := m.current.Swap(nil)
	if e = old.release(); e != nil {
		t.Fatal(e)
	}
	closed := make(chan struct{})
	go func() { _ = n.Close(); close(closed) }()
	providerWait(t, canceled, "proxy cancellation")
	if f.Status().ActiveLeases != 2 {
		t.Fatal("proxy released protection too early")
	}
	close(release)
	released = true
	select {
	case e = <-done:
		if !errors.Is(e, net.ErrClosed) {
			t.Fatal("late socket published", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxy did not exit")
	}
	providerWait(t, closed, "proxy Close")
	if !tracked.closed.Load() || !proxy.closed.Load() || !<-releasedSafely || calls.Load() != 1 {
		t.Fatal("socket/adapter retired out of order")
	}
}
func TestProviderFetchProtectedHTTPAndHTTPS(t *testing.T) {
	for _, kind := range []string{"http", "https-certificate-refusal", "protected-refusal"} {
		if !t.Run(kind, func(t *testing.T) {
			var hits atomic.Int64
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, "provider fixture")
			})
			var server *httptest.Server
			if kind == "https-certificate-refusal" {
				server = httptest.NewTLSServer(h)
			} else {
				server = httptest.NewServer(h)
			}
			defer server.Close()
			b := &providerBackend{controls: make(chan providerControl, 4)}
			if kind == "protected-refusal" {
				b.protect = func() error { return errors.New("synthetic protected failure") }
			}
			m, _, _ := providerManager(t, b, nil)
			n, e := m.OpenFetch(context.Background(), P.Action{Kind: P.Direct})
			if e != nil {
				t.Fatal(e)
			}
			result, e := remotesource.Fetch(context.Background(), n, provider.Provider{AllowPrivate: true}, provider.Source{URL: server.URL})
			if closeErr := n.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if b.calls.Load() != 1 {
				t.Fatal("wrong dial count/default fallback", b.calls.Load())
			}
			control := <-b.controls
			if control.scope.Purpose != underlay.ProviderFetch || control.scope.Generation != n.lease.ID || control.address != server.Listener.Addr().String() {
				t.Fatal("wrong underlay", control)
			}
			if kind == "http" {
				if e != nil || string(result.Body) != "provider fixture" || hits.Load() != 1 {
					t.Fatal("HTTP fetch", e)
				}
			} else if e == nil || hits.Load() != 0 {
				t.Fatal("refusal accepted/fell back", e, hits.Load())
			}
			t.Logf("kind=%s scope=%v network=%s target=%s calls=%d result_error=%v", kind, control.scope, control.network, control.address, b.calls.Load(), e)
		}) {
			return
		}
	}
}

func TestProviderFetchTrustedHTTPS(t *testing.T) {
	// Isolate the process-only fixture roots: rejection tests and the host trust
	// store retain their original certificate verification behavior.
	if os.Getenv("SPLICORE_PROVIDER_TLS_CHILD") != "1" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestProviderFetchTrustedHTTPS$", "-test.v")
		cmd.Env = append(os.Environ(), "SPLICORE_PROVIDER_TLS_CHILD=1")
		out, err := cmd.CombinedOutput()
		t.Logf("trusted HTTPS child:\n%s", out)
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "verified TLS provider")
	}))
	defer server.Close()
	t.Setenv("GODEBUG", "x509usefallbackroots=1")
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	x509.SetFallbackRoots(roots)
	b := &providerBackend{controls: make(chan providerControl, 1)}
	m, _, _ := providerManager(t, b, nil)
	n, err := m.OpenFetch(context.Background(), P.Action{Kind: P.Direct})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.Close() })
	result, err := remotesource.Fetch(context.Background(), n, provider.Provider{AllowPrivate: true}, provider.Source{URL: server.URL})
	if err != nil || string(result.Body) != "verified TLS provider" || b.calls.Load() != 1 {
		t.Fatal("verified protected HTTPS fetch", err, b.calls.Load())
	}
	c := <-b.controls
	if c.scope.Purpose != underlay.ProviderFetch || c.scope.Generation != n.lease.ID || c.address != server.Listener.Addr().String() {
		t.Fatal("HTTPS lost protected underlay", c)
	}
}

func TestProviderFetchCloseOwnsPublishedSocket(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	m, f, g := providerManager(t, &providerBackend{}, nil)
	n, err := m.OpenFetch(context.Background(), P.Action{Kind: P.Direct})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.Close() })
	host, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	conn, err := n.Dial(context.Background(), access.Endpoint{Host: host, Port: uint16(server.Listener.Addr().(*net.TCPAddr).Port)})
	if err != nil {
		t.Fatal(port, err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var socketClosedBeforeRelease bool
	g.onReleased = func() {
		_, e := conn.Read(make([]byte, 1))
		socketClosedBeforeRelease = errors.Is(e, net.ErrClosed)
	}
	if err = m.current.Swap(nil).release(); err != nil {
		t.Fatal(err)
	}
	if err = n.Close(); err != nil || !socketClosedBeforeRelease || f.Status().ActiveLeases != 0 {
		t.Fatal("published socket outlived generation", err, socketClosedBeforeRelease, f.Status())
	}
}
