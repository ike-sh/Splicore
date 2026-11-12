package native

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	mm "github.com/ike-sh/Splicore/internal/splicore/protocol/mieru"
	vl "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/testkit/netbench"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func p2Dialer(t *testing.T, s netbench.Scenario) (context.Context, ports.ClientDialer) {
	t.Helper()
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	if s.Protocol == "snell4" || s.Protocol == "snell5" || s.Protocol == "snell6" {
		version := int(s.Protocol[len(s.Protocol)-1] - '0')
		ctx, in, _ := ownedSnellAt(t, version, s.Ingress)
		return ctx, snellV5Client(t, ctx, in, version)
	}
	var in ports.RuntimeIntent
	var n client.RemoteNode
	var c access.Credential
	var h ports.RuntimeHandle
	var d ports.ClientDialer
	var err error
	switch s.Protocol {
	case "vless-tcp", "vless-http", "vless-h2", "vless-quic":
		kind := map[string]string{"vless-tcp": "tcp", "vless-http": "http", "vless-h2": "h2", "vless-quic": "quic-stream"}[s.Protocol]
		in, n, c = sharedIntent(t, "vless", "ws", s.Protocol != "vless-tcp")
		n.Transport.Kind = kind
		if kind == "tcp" || kind == "quic-stream" {
			n.Transport.Path, n.Transport.Host = "", ""
		}
		var settings vl.Settings
		if err := json.Unmarshal(in.Inbound.Settings.Data, &settings); err != nil {
			t.Fatal(err)
		}
		settings.Stream = &n.Transport
		in.Inbound.Settings.Data, _ = json.Marshal(settings)
		in.Inbound.Listeners[0].Transport = n.Transport.Carrier()
		in.Inbound.Listeners[0].Endpoint = access.Endpoint{Host: s.Ingress, Port: uint16(testkit.PeerPortAt(t, "tcp+udp", s.Ingress))}
		n.Endpoint = in.Inbound.Listeners[0].Endpoint
		h = sharedPrepare(t, ctx, "vless", in)
		d = sharedBuild(t, ctx, n, c)
	case "mieru-tcp", "mieru-udp":
		transport := s.Protocol[len("mieru-"):]
		in = testfixture.MieruIntentAt(t, transport, access.Endpoint{Host: s.Ingress, Port: uint16(testkit.PeerPortAt(t, transport, s.Ingress))})
		p, e := (MieruCompiler{}).Compile(ctx, in)
		if e != nil {
			t.Fatal(e)
		}
		h = p.(ports.RuntimeHandle)
		id, _ := identity.NewID()
		cid, _ := identity.NewID()
		options, _ := json.Marshal(mm.Settings{Transport: transport, MTU: 1500, Multiplex: "default"})
		n = client.RemoteNode{ID: id, Name: "performance", Protocol: mm.Key(), Endpoint: in.Inbound.Listeners[0].Endpoint, CredentialID: cid, Transport: client.Transport{Kind: transport}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: options}}
		c = in.Credentials[0]
		c.ID = cid
		c.OwnerAccountID = nil
		c.OwnerNodeID = &id
		d, err = (MieruOutboundFactory{}).Build(ctx, n, c)
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown performance protocol %q", s.Protocol)
	}
	t.Cleanup(func() {
		if e := h.Close(context.Background()); e != nil {
			t.Error(e)
		}
	})
	t.Cleanup(func() {
		if e := d.Close(); e != nil {
			t.Error(e)
		}
	})
	if err = h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	h.Activate()
	return ctx, d
}

// This opt-in test is run by scripts/performance/run.py. Normal test runs do not
// claim a performance qualification. It uses the production compilers, dialers,
// encryption, connection management and UDP session implementations.
func TestP2NetworkBaseline(t *testing.T) {
	path := os.Getenv("SPLICORE_PERF_CONFIG")
	if path == "" {
		t.Skip("NOT EXECUTED: use scripts/performance/run.py")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var scenarios []netbench.Scenario
	if err = json.Unmarshal(b, &scenarios); err != nil || len(scenarios) == 0 {
		t.Fatal("invalid scenarios", err)
	}
	r, err := netbench.NewRecorder(os.Getenv("SPLICORE_PERF_RAW"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	r.Record(map[string]any{"kind": "identity", "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "pid": os.Getpid(), "protocol_handshake_ns": "NOT EXECUTED: readiness includes protocol and target connection"})
	for _, s := range scenarios {
		if err = s.Validate(); err != nil {
			t.Fatal(err)
		}
		stop := netbench.SampleResources(r, s.Name)
		passed := t.Run(s.Name, func(t *testing.T) {
			r.Record(map[string]any{"kind": "scenario", "config": s, "start_ns": time.Now().UnixNano()})
			tcp, udp := netbench.Targets(t, s.Egress, time.Duration(s.TimeoutSeconds)*time.Second)
			endpoint := func(a net.Addr) access.Endpoint {
				host, p, _ := net.SplitHostPort(a.String())
				var port int
				fmt.Sscan(p, &port)
				return access.Endpoint{Host: host, Port: uint16(port)}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.TimeoutSeconds)*time.Second)
			defer cancel()
			var tcpDial netbench.Dial
			var udpDial netbench.PacketDial
			if s.Protocol == "direct" {
				tcpDial = func(ctx context.Context) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", tcp.String())
				}
				udpDial = func(context.Context) (net.PacketConn, error) {
					return net.ListenPacket("udp", net.JoinHostPort(s.Ingress, "0"))
				}
			} else {
				_, d := p2Dialer(t, s)
				tcpDial = func(ctx context.Context) (net.Conn, error) { return d.DialContext(ctx, endpoint(tcp)) }
				pd, ok := d.(ports.ClientPacketDialer)
				if !ok {
					t.Fatal("protocol lacks packet dialer")
				}
				udpDial = func(ctx context.Context) (net.PacketConn, error) { return pd.ListenPacket(ctx, endpoint(udp)) }
			}
			var wg sync.WaitGroup
			start := make(chan struct{})
			errs := make(chan error, s.Connections*2)
			for i := 0; i < s.Connections; i++ {
				if s.Network != "udp" {
					wg.Add(1)
					go func(index int) { defer wg.Done(); <-start; errs <- netbench.RunTCP(ctx, r, s, index, tcpDial) }(i)
				}
				if s.Network != "tcp" {
					wg.Add(1)
					go func(index int) { defer wg.Done(); <-start; errs <- netbench.RunUDP(ctx, r, s, index, udpDial, udp) }(i)
				}
			}
			stamp := time.Now()
			close(start)
			wg.Wait()
			close(errs)
			r.Record(map[string]any{"kind": "group", "scenario": s.Name, "elapsed_ns": time.Since(stamp).Nanoseconds()})
			for e := range errs {
				if e != nil {
					t.Error(e)
				}
			}
		})
		r.Record(map[string]any{"kind": "outcome", "scenario": s.Name, "passed": passed})
		stop()
	}
}
