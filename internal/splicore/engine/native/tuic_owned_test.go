package native

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	tm "github.com/ike-sh/Splicore/internal/splicore/protocol/tuic"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"io"
	"net"
	"testing"
	"time"
)

func ownedTUIC(t *testing.T) (context.Context, ports.RuntimeIntent, ports.RuntimeHandle, []ports.ClientDialer) {
	t.Helper()
	in := testfixture.MieruIntent(t, "udp")
	settings := tm.Settings{TLS: testkit.TLS(t), Version: 5, CongestionControl: "cubic", UDPRelayMode: "native"}
	in.Inbound.Protocol = tm.Key()
	in.Inbound.Settings.Data, _ = json.Marshal(settings)
	for i := range in.Credentials {
		p := in.Credentials[i].Payload.(access.UsernamePasswordPayload)
		id, _ := identity.NewID()
		in.Credentials[i].Payload = access.UUIDPasswordPayload{UUID: secret.New(string(id)), Password: p.Password}
		in.Credentials[i].Kind = access.UUIDPassword
	}
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	prepared, err := (TUICCompiler{}).Compile(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	h := prepared.(ports.RuntimeHandle)
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
	var dialers []ports.ClientDialer
	for _, cred := range in.Credentials {
		id, _ := identity.NewID()
		cred.OwnerAccountID = nil
		cred.OwnerNodeID = &id
		n := client.RemoteNode{ID: id, Name: "synthetic-tuic", Protocol: tm.Key(), Endpoint: in.Inbound.Listeners[0].Endpoint, CredentialID: cred.ID, Transport: client.Transport{Kind: "quic"}, Security: client.Security{Kind: "tls", TLS: access.ClientTLS{Enabled: true, Trust: "explicit_ca", ServerName: settings.TLS.ServerName, CACertificate: settings.TLS.CACertificate, ALPN: []string{"h3"}}}, Options: client.Options{Schema: 1, Data: []byte(`{"version":5,"congestion_control":"cubic","udp_relay_mode":"native"}`)}}
		n.Endpoint.Host = "localhost"
		d, err := (TUICOutboundFactory{}).Build(ctx, n, cred)
		if err != nil {
			t.Fatal(err)
		}
		dialers = append(dialers, d)
		t.Cleanup(func() { _ = d.Close() })
	}
	return ctx, in, h, dialers
}
func TestOwnedTUICHalfCloseAndIndependentCancellation(t *testing.T) {
	ctx, in, h, dialers := ownedTUIC(t)
	target := testfixture.TCP(t)
	dst := access.Endpoint{Host: "127.0.0.1", Port: uint16(target.Addr().(*net.TCPAddr).Port)}
	for i, d := range dialers {
		c, err := d.DialContext(ctx, dst)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if extra, err := d.DialContext(canceled, dst); err == nil {
			_ = extra.Close()
			t.Fatal("canceled flow accepted")
		}
		payload := bytes.Repeat([]byte("synthetic-tuic-response-after-EOF"), 32768)
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
		if !bytes.Equal(got, payload) {
			t.Fatal("half-close truncation")
		}
		_ = c.Close()
		stats := h.(ports.AttributedStats).BindingStats(in.Bindings[i].ID)
		if stats.Upload != int64(len(payload)) || stats.Download != int64(len(payload)) {
			t.Fatal("user attribution", stats)
		}
	}
	if err := h.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if h.Stats().Active != 0 {
		t.Fatal("workers not joined")
	}
}
func TestOwnedTUICDatagramsAndShutdown(t *testing.T) {
	ctx, _, h, dialers := ownedTUIC(t)
	target, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
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
		for _, size := range []int{1, 900, 4096, 2048, 8192} {
			_ = p.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte{17}, size)
			if _, err := p.WriteTo(payload, nil); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 65535)
			n, _, err := p.ReadFrom(b)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(b[:n], payload) {
				t.Fatal("UDP fragmented integrity")
			}
		}
	}
	if err := h.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if h.Stats().Active != 0 {
		t.Fatal("UDP session retained")
	}
}
