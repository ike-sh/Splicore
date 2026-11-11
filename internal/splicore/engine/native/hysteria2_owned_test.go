package native

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	hm "github.com/ike-sh/Splicore/internal/splicore/protocol/hysteria2"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func ownedHysteria2(t *testing.T) (context.Context, ports.RuntimeIntent, ports.RuntimeHandle, []ports.ClientDialer) {
	t.Helper()
	in := testfixture.MieruIntentAt(t, "udp", access.Endpoint{Host: "127.0.0.1", Port: 1})
	settings := hm.Settings{TLS: testkit.TLS(t)}
	in.Inbound.Protocol = hm.Key()
	in.Inbound.Settings.Data, _ = json.Marshal(settings)
	for i := range in.Credentials {
		p := in.Credentials[i].Payload.(access.UsernamePasswordPayload)
		in.Credentials[i].Payload = access.PasswordPayload{Password: p.Password}
		in.Credentials[i].Kind = access.Password
	}
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	p, err := (Hysteria2Compiler{}).Compile(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	h := p.(ports.RuntimeHandle)
	h.(*hysteria2Handle).endpoint.Port = 0
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	if err := h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	h.Activate()
	in.Inbound.Listeners[0].Endpoint = netaddrEndpoint(h.(*hysteria2Handle).server.Addr())
	var dialers []ports.ClientDialer
	for _, cred := range in.Credentials {
		nid, _ := identity.NewID()
		cred.OwnerAccountID = nil
		cred.OwnerNodeID = &nid
		n := client.RemoteNode{ID: nid, Name: "synthetic-hy2", Protocol: hm.Key(), Endpoint: in.Inbound.Listeners[0].Endpoint, CredentialID: cred.ID, Transport: client.Transport{Kind: "quic"}, Security: client.Security{Kind: "tls", TLS: access.ClientTLS{Enabled: true, Trust: "explicit_ca", ServerName: settings.TLS.ServerName, CACertificate: settings.TLS.CACertificate, ALPN: []string{"h3"}}}, Options: client.Options{Schema: 1, Data: []byte(`{}`)}}
		n.Endpoint.Host = "localhost"
		d, err := (Hysteria2OutboundFactory{}).Build(ctx, n, cred)
		if err != nil {
			t.Fatal(err)
		}
		dialers = append(dialers, d)
		t.Cleanup(func() { _ = d.Close() })
	}
	return ctx, in, h, dialers
}

func TestOwnedHysteria2ParallelAuthAttributionAndDomainTargets(t *testing.T) {
	ctx, in, h, ds := ownedHysteria2(t)
	l := testfixture.TCP(t)
	dst := access.Endpoint{Host: "localhost", Port: uint16(l.Addr().(*net.TCPAddr).Port)}
	udst := localhostUDP(t)
	ready := make(chan struct{}, len(ds)*10)
	start := make(chan struct{})
	udpFinished := make(chan struct{}, len(ds)*2)
	udpDone := make(chan struct{})
	var wg sync.WaitGroup
	for user, d := range ds {
		for flow := range 8 {
			wg.Go(func() {
				c, e := d.DialContext(ctx, dst)
				if e != nil {
					t.Error(e)
					ready <- struct{}{}
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(15 * time.Second))
				ready <- struct{}{}
				<-start
				want := bytes.Repeat([]byte{byte(user), byte(flow), 0, 73}, 32768)
				written := make(chan error, 1)
				go func() {
					_, e := c.Write(want)
					if e == nil {
						e = c.(interface{ CloseWrite() error }).CloseWrite()
					}
					written <- e
				}()
				got, e := io.ReadAll(c)
				if e != nil || !bytes.Equal(got, want) {
					t.Error("parallel user payload", user, flow, e)
				}
				if e = <-written; e != nil {
					t.Error(e)
				}
				<-udpDone
			})
		}
		for flow := range 2 {
			wg.Go(func() {
				defer func() { udpFinished <- struct{}{} }()
				p, e := d.(ports.ClientPacketDialer).ListenPacket(ctx, udst)
				if e != nil {
					t.Error(e)
					ready <- struct{}{}
					return
				}
				defer p.Close()
				p.SetDeadline(time.Now().Add(15 * time.Second))
				ready <- struct{}{}
				<-start
				want := bytes.Repeat([]byte{byte(user), byte(flow), 71, 0}, 1024)
				if _, e = p.WriteTo(want, nil); e != nil {
					t.Error(e)
					return
				}
				b := make([]byte, 4096)
				n, _, e := p.ReadFrom(b)
				if e != nil || !bytes.Equal(b[:n], want) {
					t.Error("parallel user UDP", user, flow, e)
				}
			})
		}
	}
	for range len(ds) * 10 {
		select {
		case <-ready:
		case <-time.After(10 * time.Second):
			t.Fatal("parallel admission stalled")
		}
	}
	states := h.(*hysteria2Handle).server.Congestion()
	if len(states) != len(ds) {
		t.Fatal("cross-sharing or duplicate pool", states)
	}
	ids := map[string]bool{}
	for _, s := range states {
		ids[s.Identity] = true
	}
	for _, b := range in.Bindings {
		if !ids[string(b.ID)] {
			t.Fatal("credential bleed", states)
		}
	}
	go func() {
		for range len(ds) * 2 {
			<-udpFinished
		}
		close(udpDone)
	}()
	close(start)
	wg.Wait()
	for _, d := range ds {
		d.Close()
	}
	if e := h.Close(ctx); e != nil {
		t.Fatal(e)
	}
	for _, b := range in.Bindings {
		s := h.(ports.AttributedStats).BindingStats(b.ID)
		want := int64(8*131072 + 2*4096)
		if s.Upload != want || s.Download != want {
			t.Fatal("exact parallel attribution", s, want)
		}
	}
	if h.Stats().Active != 0 {
		t.Fatal("parallel resource baseline")
	}
}
func TestOwnedHysteria2HalfCloseAndIndependentCancellation(t *testing.T) {
	ctx, in, h, dialers := ownedHysteria2(t)
	l := testfixture.TCP(t)
	dst := access.Endpoint{Host: "127.0.0.1", Port: uint16(l.Addr().(*net.TCPAddr).Port)}
	for index, d := range dialers {
		c, err := d.DialContext(ctx, dst)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if extra, err := d.DialContext(canceled, dst); err == nil {
			_ = extra.Close()
			t.Fatal("canceled flow accepted")
		}
		payload := bytes.Repeat([]byte(fmt.Sprint(index)+"-synthetic-hy2\x00"), 32768)
		done := make(chan error, 1)
		go func() {
			_, err := c.Write(payload)
			if err == nil {
				err = c.(interface{ CloseWrite() error }).CloseWrite()
			}
			done <- err
		}()
		got, err := io.ReadAll(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
		if !bytes.Equal(payload, got) {
			t.Fatal("response after upload EOF truncated")
		}
		stats := h.(ports.AttributedStats).BindingStats(in.Bindings[index].ID)
		if stats.Upload != int64(len(payload)) || stats.Download != int64(len(payload)) {
			t.Fatalf("user attribution: %+v", stats)
		}
	}
	if err := h.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if h.Stats().Active != 0 {
		t.Fatal("shutdown did not join workers")
	}
}
func TestOwnedHysteria2DatagramsAndShutdown(t *testing.T) {
	ctx, _, h, dialers := ownedHysteria2(t)
	target, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 4096)
		for {
			n, a, err := target.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = target.WriteTo(b[:n], a)
		}
	}()
	t.Cleanup(func() { _ = target.Close(); <-done })
	dst := access.Endpoint{Host: "127.0.0.1", Port: uint16(target.LocalAddr().(*net.UDPAddr).Port)}
	for _, d := range dialers {
		p, err := d.(ports.ClientPacketDialer).ListenPacket(ctx, dst)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		for _, size := range []int{1, 900, 4096, 2048, 4096} {
			_ = p.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte{byte(size), 17}, (size+1)/2)[:size]
			if _, err := p.WriteTo(payload, nil); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 4096)
			n, _, err := p.ReadFrom(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buffer[:n], payload) {
				t.Fatal("fragmented UDP integrity")
			}
		}
	}
	if err := h.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if h.Stats().Active != 0 {
		t.Fatal("UDP session retained after shutdown")
	}
}
