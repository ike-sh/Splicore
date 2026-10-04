package native

import (
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	module "github.com/sagernet/sing-box/internal/splicore/protocol/mieru"
	"github.com/sagernet/sing-box/internal/splicore/underlay"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestMieruOutboundOwnedSocketsAndLoopExit(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		in := mieruIntent(t, transport)
		h, err := (MieruCompiler{}).Compile(underlay.WithFactory(context.Background(), underlay.New()), in)
		if err != nil {
			t.Fatal(err)
		}
		if err = h.(*mieruHandle).Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		h.(*mieruHandle).Activate()
		target := mieruTCPFixture(t)
		endpoint := access.Endpoint{Host: "127.0.0.1", Port: uint16(target.Addr().(*net.TCPAddr).Port)}
		for range 10 {
			id, _ := identity.NewID()
			cid, _ := identity.NewID()
			options, _ := json.Marshal(module.Settings{Transport: transport, MTU: 1500, Multiplex: "default"})
			n := client.RemoteNode{ID: id, Name: "owned-client", Protocol: module.Key(), Endpoint: in.Inbound.Listeners[0].Endpoint, CredentialID: cid, Transport: client.Transport{Kind: transport}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: options}}
			c := in.Credentials[0]
			c.ID = cid
			c.OwnerAccountID = nil
			c.OwnerNodeID = &id
			dialer, err := (MieruOutboundFactory{}).Build(underlay.WithFactory(context.Background(), underlay.New()), n, c)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := dialer.DialContext(context.Background(), endpoint)
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = conn.Write([]byte("ownership"))
			if _, err = io.ReadFull(conn, make([]byte, 9)); err != nil {
				t.Fatal(err)
			}
			// Deliberately retain the caller's logical connection during adapter close.
			if err = dialer.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = conn.Read(make([]byte, 1)); err == nil {
				t.Fatal("logical socket survived Close")
			}
			_ = conn.Close()
		}
		if err = h.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// The official SDK exposes no client loop join. Observe completion driven by
	// raw socket close, allowing scheduling only, without sleep or redial retries.
	deadline := time.Now().Add(3 * time.Second)
	for {
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		if !strings.Contains(string(stack[:n]), "github.com/enfein/mieru/v3/pkg/protocol") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Mieru loop leak\n%s", stack[:n])
		}
		runtime.Gosched()
	}
}
