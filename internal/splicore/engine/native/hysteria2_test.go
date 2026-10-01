package native

import (
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	hm "github.com/sagernet/sing-box/internal/splicore/protocol/hysteria2"
	tm "github.com/sagernet/sing-box/internal/splicore/protocol/tuic"
	"github.com/sagernet/sing-box/internal/splicore/testkit"
	"net"
	"os"
	"runtime"
	"testing"
	"time"
)

func nativeIntent(t *testing.T) ports.RuntimeIntent {
	t.Helper()
	id := func() identity.ID {
		v, e := identity.NewID()
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	data, _ := json.Marshal(hm.Settings{TLS: testkit.TLS(t)})
	p, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := uint16(p.LocalAddr().(*net.UDPAddr).Port)
	p.Close()
	return ports.RuntimeIntent{Inbound: access.Inbound{ID: id(), NodeID: id(), Name: "synthetic", Protocol: hm.Key(), Engine: "native", Enabled: true, Listeners: []access.Listener{{ID: id(), Transport: "udp", Endpoint: access.Endpoint{Host: "127.0.0.1", Port: port}}}, DisplayEndpoints: []access.DisplayEndpoint{{ID: id(), Endpoint: access.Endpoint{Host: "public.synthetic.test", Port: port}}}, Settings: access.Settings{Schema: 1, Data: data}, Stamp: identity.NewStamp(time.Now())}}
}
func TestHysteria2LifecycleMalformedQUICAndPortReuse(t *testing.T) {
	for _, protocol := range []string{"hysteria2", "tuic"} {
		t.Run(protocol, func(t *testing.T) {
			in := nativeIntent(t)
			if protocol == "tuic" {
				s, _ := hm.Decode(in.Inbound.Settings.Data)
				data, _ := json.Marshal(tm.Settings{TLS: s.TLS, Version: 5, CongestionControl: "cubic", UDPRelayMode: "native"})
				in.Inbound.Settings.Data = data
				in.Inbound.Protocol = tm.Key()
			}
			engine, _ := NewEngine(SnellCompiler{}, Hysteria2Compiler{}, TUICCompiler{})
			for range 3 {
				prepared, e := engine.Compile(context.Background(), in)
				if e != nil {
					t.Fatal(e)
				}
				h := prepared.(ports.RuntimeHandle)
				if h.Health(context.Background()) == nil {
					t.Fatal("unstarted health")
				}
				if e = h.Start(context.Background()); e != nil {
					t.Fatal(e)
				}
				if e = h.Health(context.Background()); e != nil {
					t.Fatal(e)
				}
				// No users: malformed/unauthenticated datagrams cannot create routed sessions.
				h.Activate()
				c, e := net.Dial("udp", net.JoinHostPort("127.0.0.1", portString(in.Inbound.Listeners[0].Endpoint.Port)))
				if e != nil {
					t.Fatal(e)
				}
				for range 16 {
					_, _ = c.Write([]byte("synthetic malformed QUIC"))
				}
				c.Close()
				if e = h.Close(context.Background()); e != nil {
					t.Fatal(e)
				}
				if e = h.Close(context.Background()); e != nil {
					t.Fatal(e)
				}
				if h.Health(context.Background()) == nil || h.Stats().Sessions != 0 {
					t.Fatal("closed runtime health/stats")
				}
				p, e := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", portString(in.Inbound.Listeners[0].Endpoint.Port)))
				if e != nil {
					t.Fatal("socket leak", e)
				}
				p.Close()
			}
		})
	}

}
func TestStaticTLSKeyProtection(t *testing.T) {
	in := nativeIntent(t)
	s, _ := hm.Decode(in.Inbound.Settings.Data)
	if runtime.GOOS == "linux" {
		if e := os.Chmod(s.TLS.PrivateKeyFile, 0644); e != nil {
			t.Fatal(e)
		}
		if _, e := (Hysteria2Compiler{}).Compile(context.Background(), in); e == nil {
			t.Fatal("public private-key mode admitted")
		}
		if e := os.Chmod(s.TLS.PrivateKeyFile, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(s.TLS.PrivateKeyFile, []byte("not a key"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := (Hysteria2Compiler{}).Compile(context.Background(), in); e == nil {
		t.Fatal("invalid key admitted")
	}
}

type gatePacket struct {
	net.PacketConn
	packets chan byte
	read    chan struct{}
}

func (p *gatePacket) ReadFrom(b []byte) (int, net.Addr, error) {
	p.read <- struct{}{}
	v := <-p.packets
	b[0] = v
	return 1, &net.UDPAddr{}, nil
}
func TestPendingQUICAdmissionDropsPackets(t *testing.T) {
	h := &Hysteria2Handle{}
	under := &gatePacket{packets: make(chan byte, 2), read: make(chan struct{}, 2)}
	gate := &admissionPacket{PacketConn: under, h: h}
	done := make(chan byte, 1)
	go func() { b := make([]byte, 1); _, _, _ = gate.ReadFrom(b); done <- b[0] }()
	<-under.read
	under.packets <- 1
	<-under.read
	// Wait until the next read: pending packet has been dropped before admission.
	select {
	case <-done:
		t.Fatal("pending packet admitted")
	default:
	}
	h.Activate()
	under.packets <- 2
	select {
	case b := <-done:
		if b != 2 {
			t.Fatal("pending packet retained")
		}
	case <-time.After(time.Second):
		t.Fatal("active packet blocked")
	}
}
