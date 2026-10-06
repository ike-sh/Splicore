//go:build with_gvisor

package clientruntime

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/nativetun"
)

type failedTUNDevice struct{}

func (failedTUNDevice) Start() error                { return nil }
func (failedTUNDevice) Read([]byte) (int, error)    { return 0, io.ErrUnexpectedEOF }
func (failedTUNDevice) Write(p []byte) (int, error) { return len(p), nil }
func (failedTUNDevice) Interrupt() error            { return nil }
func (failedTUNDevice) Close() error                { return nil }

type emptyTUNDispatcher struct{}

func (emptyTUNDispatcher) TCP(context.Context, net.Conn, netip.AddrPort, netip.AddrPort) {}
func (emptyTUNDispatcher) UDP(context.Context, net.Conn, netip.AddrPort, netip.AddrPort) {}

func TestFailedNativeTUNReportsDegraded(t *testing.T) {
	m := New()
	defer m.Close(context.Background())
	p := hardeningCandidate(t, m)
	defer p.Abort()
	if err := p.Activate(); err != nil {
		t.Fatal(err)
	}
	r, err := nativetun.New(context.Background(), failedTUNDevice{}, nativetun.Options{MTU: 1500, Dispatcher: emptyTUNDispatcher{}})
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Start()
	if err := r.Wait(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	id, _ := identity.NewID()
	state := client.Empty()
	state.Enabled = true
	state.LocalInbounds = []client.LocalInbound{{ID: id, Kind: "tun"}}
	l := &localListener{tun: &tunIngress{stack: r}}
	l.ready.Store(true)
	m.listeners[id] = l
	defer delete(m.listeners, id) // synthetic status fixture owns no host lease
	status := m.Status(state, nil)
	if status.Health != "degraded" || status.LastError != "tun_runtime_failed" {
		t.Fatal("failed packet runtime reported healthy", status.Health, status.LastError)
	}
}
