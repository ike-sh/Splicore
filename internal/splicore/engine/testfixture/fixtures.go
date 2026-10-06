// Package testfixture shares owned localhost fixtures across protocol tests.
package testfixture

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/credential"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/mieru"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func MieruIntent(t *testing.T, transport string) ports.RuntimeIntent {
	t.Helper()
	id := func() identity.ID {
		v, e := identity.NewID()
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	stamp := identity.NewStamp(time.Now())
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	if transport == "udp" {
		packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port = uint16(packet.LocalAddr().(*net.UDPAddr).Port)
		_ = packet.Close()
	}
	data, _ := json.Marshal(module.Settings{Transport: transport, MTU: 1500, Multiplex: "default"})
	in := ports.RuntimeIntent{Inbound: access.Inbound{ID: id(), NodeID: id(), Name: "synthetic-mieru", Protocol: module.Key(), Engine: "native", Enabled: true, Listeners: []access.Listener{{ID: id(), Transport: transport, Endpoint: access.Endpoint{Host: "127.0.0.1", Port: port}}}, DisplayEndpoints: []access.DisplayEndpoint{{ID: id(), Endpoint: access.Endpoint{Host: "localhost", Port: port}}}, Settings: access.Settings{Schema: 1, Data: data}, Stamp: stamp}}
	for _, name := range []string{"Alice", "Bob"} {
		account, cred, binding := id(), id(), id()
		password, e := credential.GeneratePassword()
		if e != nil {
			t.Fatal(e)
		}
		in.Credentials = append(in.Credentials, access.Credential{ID: cred, OwnerAccountID: &account, Kind: access.UsernamePassword, Schema: 1, State: "active", Payload: access.UsernamePasswordPayload{Username: secret.New(name), Password: password}, Stamp: stamp})
		in.Bindings = append(in.Bindings, access.Binding{ID: binding, AccountID: account, InboundID: in.Inbound.ID, CredentialID: cred, Enabled: true, Stamp: stamp})
	}
	return in
}
func TCP(t *testing.T) net.Listener {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	active := map[net.Conn]bool{}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			active[c] = true
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer c.Close()
				_, _ = io.Copy(c, c)
				mu.Lock()
				delete(active, c)
				mu.Unlock()
			}()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		for c := range active {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return l
}
