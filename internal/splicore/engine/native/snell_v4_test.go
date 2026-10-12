package native

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	sm "github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
	"github.com/ike-sh/Splicore/protocol/snell/wire"
	"io"
	"net"
	"testing"
	"time"
)

func TestSnellV4HTTPNativeTCPReuseAndUDPPort(t *testing.T) {
	ctx, in, _ := ownedSnell(t, 4, true)
	nid, _ := identity.NewID()
	cred := in.Credentials[0]
	cred.OwnerAccountID = nil
	cred.OwnerNodeID = &nid
	options, _ := json.Marshal(sm.ClientOptions{Version: 4, Reuse: true, ObfsMode: "http", ObfsHost: "cover.example", ObfsURI: "/resource?test=1"})
	n := client.RemoteNode{ID: nid, Name: "test", Protocol: sm.Key(4), Endpoint: in.Inbound.Listeners[0].Endpoint, CredentialID: cred.ID, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: options}}
	d, e := (SnellOutboundFactory{}).Build(ctx, n, cred)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	target := testfixture.TCP(t)
	dst := access.Endpoint{Host: "127.0.0.1", Port: uint16(target.Addr().(*net.TCPAddr).Port)}
	for i := 0; i < 4; i++ {
		c, e := d.DialContext(ctx, dst)
		if e != nil {
			t.Fatal(e)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		payload := bytes.Repeat([]byte{byte(i), 0, 255}, 200000)
		done := make(chan error, 1)
		go func() {
			_, e := c.Write(payload)
			if e == nil {
				e = c.(interface{ CloseWrite() error }).CloseWrite()
			}
			done <- e
		}()
		got, e := io.ReadAll(c)
		if e != nil || !bytes.Equal(got, payload) {
			t.Fatal("HTTP reusable TCP", e)
		}
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		_ = c.Close()
	}
	pool := d.(*snellDialer).pool
	pool.mu.Lock()
	count := len(pool.all)
	pool.mu.Unlock()
	if count != 1 {
		t.Fatal("HTTP transport not reused", count)
	}
	udp, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, e := udp.ReadFromUDP(b)
			if e != nil {
				return
			}
			_, _ = udp.WriteToUDP(b[:n], a)
		}
	}()
	udpDst := access.Endpoint{Host: "127.0.0.1", Port: uint16(udp.LocalAddr().(*net.UDPAddr).Port)}
	// The optional UDP port is an alternate TCP association endpoint.
	n.Options.Data = []byte(fmt.Sprintf(`{"version":4,"udp_port":%d,"obfs_mode":"http","obfs_host":"cover.example","obfs_uri":"/udp"}`, n.Endpoint.Port))
	n.Endpoint.Port = 1
	d2, e := (SnellOutboundFactory{}).Build(ctx, n, cred)
	if e != nil {
		t.Fatal(e)
	}
	defer d2.Close()
	p, e := d2.(*snellDialer).ListenPacket(ctx, udpDst)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	_ = p.SetDeadline(time.Now().Add(5 * time.Second))
	for _, size := range []int{12, 512, 1200, 1200, 1200, 1200, 1200, 1200, 1200, 1200, 1200, 1200, 8192, 12000} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		if _, e := p.WriteTo(payload, nil); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, 65535)
		n, _, e := p.ReadFrom(b)
		if e != nil || !bytes.Equal(b[:n], payload) {
			t.Fatal("UDP boundaries", size, e)
		}
	}
	disabled := false
	raw, _ := json.Marshal(sm.ClientOptions{Version: 4, UDP: &disabled})
	n.Options.Data = raw
	d3, e := (SnellOutboundFactory{}).Build(ctx, n, cred)
	if e != nil {
		t.Fatal(e)
	}
	defer d3.Close()
	if _, e := d3.(*snellDialer).ListenPacket(ctx, udpDst); e == nil {
		t.Fatal("disabled UDP accepted")
	}
}

func TestSnellV4HTTPUDPDestinationChanges(t *testing.T) {
	_, in, _ := ownedSnell(t, 4, true)
	raw, e := net.Dial("tcp", net.JoinHostPort(in.Inbound.Listeners[0].Endpoint.Host, fmt.Sprint(in.Inbound.Listeners[0].Endpoint.Port)))
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	k, _ := wire.NewKey(4, "SyntheticNativeSnell12345")
	p, e := wire.ClientPacket(wire.HTTPClient(raw, "localhost", "/udp"), k, access.Endpoint{Host: "127.0.0.1", Port: 1})
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	for i := 0; i < 3; i++ {
		udp, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if e != nil {
			t.Fatal(e)
		}
		defer udp.Close()
		_ = udp.SetDeadline(time.Now().Add(time.Second))
		payload := bytes.Repeat([]byte{byte(i), 0, 255}, 100)
		if _, e := p.WriteTo(payload, udp.LocalAddr()); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, 2048)
		n, a, e := udp.ReadFromUDP(b)
		if e != nil || !bytes.Equal(payload, b[:n]) {
			t.Fatal(e)
		}
		_, _ = udp.WriteToUDP(payload, a)
		n, from, e := p.ReadFrom(b)
		if e != nil || !bytes.Equal(payload, b[:n]) || from.String() != udp.LocalAddr().String() {
			t.Fatal("stale destination", from, e)
		}
	}
}
