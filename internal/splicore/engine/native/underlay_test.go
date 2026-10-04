package native

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	module "github.com/sagernet/sing-box/internal/splicore/protocol/mieru"
	"github.com/sagernet/sing-box/internal/splicore/testkit"
	"github.com/sagernet/sing-box/internal/splicore/underlay"
)

func TestUnderlayMieruConcurrentRuntimesAndTransportOwnership(t *testing.T) {
	x := testkit.NewUnderlay(t)
	ctx := context.Background()
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			in := mieruIntent(t, transport)
			if _, err := (MieruCompiler{}).Compile(ctx, in); err == nil {
				t.Fatal("missing server capability accepted")
			}
			h, err := (MieruCompiler{}).Compile(underlay.WithFactory(ctx, x.Factory), in)
			if err != nil {
				t.Fatal(err)
			}
			if err = h.(ports.RuntimeHandle).Start(ctx); err != nil {
				t.Fatal(err)
			}
			h.(ports.RuntimeHandle).Activate()
			defer h.Close(ctx)
			target := mieruTCPFixture(t)
			endpoint := access.Endpoint{Host: "127.0.0.1", Port: uint16(target.Addr().(*net.TCPAddr).Port)}
			type owner struct {
				lease  *underlay.Lease
				dialer ports.ClientDialer
				conn   net.Conn
			}
			owners := []owner{}
			shared := netip.MustParseAddr("192.0.2.19")
			for range 2 {
				id, _ := identity.NewID()
				cid, _ := identity.NewID()
				l, err := x.Factory.Begin(ctx, true)
				if err != nil {
					t.Fatal(err)
				}
				scope := underlay.Scope{Purpose: underlay.ProxyUnderlay, Runtime: id, Generation: l.ID}
				// The route is a synthetic shared infrastructure reference; all
				// actual traffic remains on owned localhost sockets.
				if err = l.AddEndpoint(ctx, scope, []netip.Addr{shared}); err != nil {
					t.Fatal(err)
				}
				data, _ := json.Marshal(module.Settings{Transport: transport, MTU: 1500, Multiplex: "default"})
				n := client.RemoteNode{ID: id, Name: "underlay-owner", Protocol: module.Key(), Endpoint: in.Inbound.Listeners[0].Endpoint, CredentialID: cid, Transport: client.Transport{Kind: transport}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: data}}
				c := in.Credentials[0]
				c.ID = cid
				c.OwnerAccountID = nil
				c.OwnerNodeID = &id
				if _, err = (MieruOutboundFactory{}).Build(ctx, n, c); err == nil {
					t.Fatal("missing client hooks accepted")
				}
				d, err := (MieruOutboundFactory{}).Build(underlay.WithScope(underlay.WithFactory(ctx, x.Factory), scope), n, c)
				if err != nil {
					t.Fatal(err)
				}
				conn, err := d.DialContext(ctx, endpoint)
				if err != nil {
					t.Fatal(err)
				}
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				owners = append(owners, owner{l, d, conn})
			}
			echo := func(c net.Conn) {
				if _, err := c.Write([]byte("shared")); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 6)
				if _, err := io.ReadFull(c, b); err != nil || string(b) != "shared" {
					t.Fatal("echo", err)
				}
			}
			for _, o := range owners {
				echo(o.conn)
			}
			if err := owners[0].dialer.Close(); err != nil {
				t.Fatal(err)
			}
			owners[0].conn.Close()
			if err := owners[0].lease.Close(); err != nil {
				t.Fatal(err)
			}
			if !x.Backend.Has(shared.String()) {
				t.Fatal("A retired B's shared route")
			}
			echo(owners[1].conn)
			owners[1].conn.Close()
			if err := owners[1].dialer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := owners[1].lease.Close(); err != nil {
				t.Fatal(err)
			}
			if x.Backend.Has(shared.String()) {
				t.Fatal("shared route leaked")
			}
			var found bool
			for _, event := range x.Backend.SnapshotEvents() {
				if event.Scope.Purpose == underlay.ProxyUnderlay && strings.HasPrefix(event.Network, transport) {
					found = true
				}
			}
			if !found {
				t.Fatal("official transport hook bypassed")
			}
		})
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		b := make([]byte, 1<<20)
		n := runtime.Stack(b, true)
		if !strings.Contains(string(b[:n]), "github.com/enfein/mieru/v3/pkg/protocol") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Mieru underlay workers leaked\n%s", b[:n])
		}
		runtime.Gosched()
	}
	if x.Factory.Status().ActiveLeases != 0 {
		t.Fatal("underlay leases leaked")
	}
}

func TestUnderlayNativeSystemDNSRejectsIndependentSocketPaths(t *testing.T) {
	x := testkit.NewUnderlay(t)
	l, err := x.Factory.Begin(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	d, _ := x.Factory.New(underlay.Scope{Purpose: underlay.SystemDNS})
	tpt := protectedLocalDNS{f: x.Factory, d: d}
	for _, host := range []string{"printer.local.", "outside.fixture.invalid."} {
		q := new(mDNS.Msg)
		q.SetQuestion(host, mDNS.TypeA)
		if _, err := tpt.Exchange(context.Background(), q); err == nil {
			t.Fatal("unverified system path admitted")
		}
	}
}
