package backend

import (
	"bytes"
	"context"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	client "github.com/enfein/mieru/v3/apis/client"
	ac "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/model"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"google.golang.org/protobuf/proto"
)

func mieruClient(t *testing.T, in ports.RuntimeIntent, index int) client.Client {
	t.Helper()
	c := client.NewClient()
	p := in.Credentials[index].Payload.(access.UsernamePasswordPayload)
	ep := in.Inbound.Listeners[0].Endpoint
	transport := pb.TransportProtocol_TCP
	if in.Inbound.Listeners[0].Transport == "udp" {
		transport = pb.TransportProtocol_UDP
	}
	profile := &pb.ClientProfile{ProfileName: proto.String("synthetic"), User: &pb.User{Name: proto.String(p.Username.Reveal()), Password: proto.String(p.Password.Reveal())}, Servers: []*pb.ServerEndpoint{{IpAddress: proto.String(ep.Host), PortBindings: []*pb.PortBinding{{Port: proto.Int32(int32(ep.Port)), Protocol: transport.Enum()}}}}}
	factory := &mieruClientSockets{}
	if e := c.Store(&client.ClientConfig{Profile: profile, Dialer: factory, PacketDialer: factory}); e != nil {
		t.Fatal(e)
	}
	if e := c.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		// Own the oracle's raw sockets as well. Official packet Close only sets
		// a deadline, which an in-flight Read can replace before noticing Done.
		factory.close()
		if e := c.Stop(); e != nil {
			t.Error(e)
		}
	})
	return c
}

type mieruClientSockets struct {
	mu  sync.Mutex
	all []io.Closer
}

func (f *mieruClientSockets) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, e := (&net.Dialer{}).DialContext(ctx, network, addr)
	if e == nil {
		f.mu.Lock()
		f.all = append(f.all, c)
		f.mu.Unlock()
	}
	return c, e
}
func (f *mieruClientSockets) ListenPacket(ctx context.Context, network, local, remote string) (net.PacketConn, error) {
	if local == "" {
		host, _, _ := net.SplitHostPort(remote)
		if net.ParseIP(host).To4() != nil {
			local = "127.0.0.1:0"
		} else {
			local = "[::1]:0"
		}
	}
	c, e := (&net.ListenConfig{}).ListenPacket(ctx, network, local)
	if e == nil {
		f.mu.Lock()
		f.all = append(f.all, c)
		f.mu.Unlock()
	}
	return c, e
}
func (f *mieruClientSockets) close() {
	f.mu.Lock()
	all := append([]io.Closer(nil), f.all...)
	f.mu.Unlock()
	for _, c := range all {
		c.Close()
	}
}

func mieruUDPFixture(t *testing.T) net.PacketConn {
	t.Helper()
	c, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			n, a, e := c.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = c.WriteTo(b[:n], a)
		}
	}()
	t.Cleanup(func() { c.Close(); <-done })
	return c
}
func mieruTransfer(c client.Client, dest net.Addr, size int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, e := c.DialContext(ctx, dest)
	if e != nil {
		return e
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("abcdefgh"), size/8+1)[:size]
	if dest.Network() == "udp" {
		packet := ac.NewUDPAssociateWrapper(ac.NewPacketOverStreamTunnel(conn))
		if _, e = packet.WriteTo(payload, dest); e != nil {
			return e
		}
		received := make([]byte, size)
		n, _, e := packet.ReadFrom(received)
		if e != nil {
			return e
		}
		if !bytes.Equal(payload, received[:n]) {
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	write := make(chan error, 1)
	go func() { _, e := conn.Write(payload); write <- e }()
	received := make([]byte, size)
	_, e = io.ReadFull(conn, received)
	we := <-write
	if e != nil {
		return e
	}
	if we != nil {
		return we
	}
	if !bytes.Equal(payload, received) {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func startMieru(t *testing.T, in ports.RuntimeIntent) *mieruHandle {
	t.Helper()
	p, e := (MieruCompiler{}).Compile(underlay.WithFactory(context.Background(), underlay.New()), in)
	if e != nil {
		t.Fatal(e)
	}
	h := p.(*mieruHandle)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if e := h.Close(ctx); e != nil {
			t.Error(e)
		}
	})
	if e = h.Start(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = h.Health(context.Background()); e != nil {
		t.Fatal(e)
	}
	h.Activate()
	return h
}
func TestMieruNativeMultiInboundLifecycle10x(t *testing.T) {
	before := runtime.NumGoroutine()
	for cycle := 0; cycle < 10; cycle++ {
		t.Run(fmt.Sprint(cycle), func(t *testing.T) {
			for _, transport := range []string{"tcp", "udp"} {
				t.Run(transport, func(t *testing.T) {
					echo := mieruTCPFixture(t)
					udp := mieruUDPFixture(t)
					a, b := mieruIntent(t, transport), mieruIntent(t, transport)
					ha, hb := startMieru(t, a), startMieru(t, b)
					clients := []client.Client{mieruClient(t, a, 0), mieruClient(t, a, 1), mieruClient(t, b, 0), mieruClient(t, b, 1)}
					errs := make(chan error, 16)
					for n := 0; n < 16; n++ {
						go func(n int) {
							dst := echo.Addr()
							if n%2 == 1 {
								dst = udp.LocalAddr()
							}
							errs <- mieruTransfer(clients[n%4], dst, 1024)
						}(n)
					}
					for n := 0; n < 16; n++ {
						if e := <-errs; e != nil {
							t.Fatal(e)
						}
					}
					if e := mieruTransfer(clients[0], echo.Addr(), 4<<20); e != nil {
						t.Fatal(e)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					if e := ha.Close(ctx); e != nil {
						t.Fatal(e)
					}
					if e := mieruTransfer(clients[2], echo.Addr(), 1024); e != nil {
						t.Fatal("closing A affected B", e)
					}
					if e := hb.Close(ctx); e != nil {
						t.Fatal(e)
					}
					// Close joins all writers, giving a stable aggregate snapshot.
					for _, pair := range []struct {
						h          *mieruHandle
						in         ports.RuntimeIntent
						aliceBytes int64
					}{{ha, a, (4 << 20) + 4096}, {hb, b, 5120}} {
						stats := pair.h.Stats()
						alice := pair.h.BindingStats(pair.in.Bindings[0].ID)
						bob := pair.h.BindingStats(pair.in.Bindings[1].ID)
						if alice.Upload != pair.aliceBytes || alice.Download != pair.aliceBytes || bob.Upload != 4096 || bob.Download != 4096 || stats.Upload != alice.Upload+bob.Upload || stats.Download != alice.Download+bob.Download || stats.Active != 0 {
							t.Fatal("payload attribution or double counting")
						}
					}
					if ha.Stats().Active != 0 {
						t.Fatal("active sessions leaked")
					}
					if strings.Contains(fmt.Sprintf("%+v %#v", hb, hb), b.Credentials[0].Payload.(access.UsernamePasswordPayload).Password.Reveal()) {
						t.Fatal("runtime support formatting secret leak")
					}
				})
			}
		})
	}
	until := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(until) {
		runtime.Gosched()
	}
	stack := make([]byte, 1<<20)
	n := runtime.Stack(stack, true)
	if strings.Contains(string(stack[:n]), "github.com/enfein/mieru/v3/pkg/protocol") {
		t.Fatalf("Mieru goroutine leak\n%s", stack[:n])
	}
	t.Logf("goroutines baseline=%d final=%d", before, runtime.NumGoroutine())
}
func TestMieruListenerConflictAndUnstartedClose(t *testing.T) {
	in := mieruIntent(t, "tcp")
	l, e := net.Listen("tcp", net.JoinHostPort(in.Inbound.Listeners[0].Endpoint.Host, portString(in.Inbound.Listeners[0].Endpoint.Port)))
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	prepared, e := (MieruCompiler{}).Compile(underlay.WithFactory(context.Background(), underlay.New()), in)
	if e != nil {
		t.Fatal(e)
	}
	h := prepared.(*mieruHandle)
	if e = h.Start(context.Background()); e == nil {
		t.Fatal("port conflict accepted")
	}
	if e = h.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	if h.Stats().Sessions != 0 {
		t.Fatal("failed startup routed traffic")
	}
	prepared, e = (MieruCompiler{}).Compile(underlay.WithFactory(context.Background(), underlay.New()), in)
	if e != nil {
		t.Fatal(e)
	}
	if e = prepared.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
}

func TestMieruRelayPreservesResponseAfterUploadEOF(t *testing.T) {
	// The destination sends its response only after observing upload EOF.
	destination, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	echoDone := make(chan error, 1)
	go func() {
		c, e := destination.Accept()
		if e != nil {
			echoDone <- e
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		data, e := io.ReadAll(c)
		if e == nil {
			_, e = c.Write(data)
		}
		echoDone <- e
	}()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	protected, _ := underlay.New().New(underlay.Scope{Purpose: underlay.ServerTarget})
	h := &mieruHandle{protected: protected, ctx: ctx, total: &meter{}, closers: map[io.Closer]bool{}}
	m := &meter{}
	routeDone := make(chan struct{})
	go func() {
		defer close(routeDone)
		c, e := listener.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		a := destination.Addr().(*net.TCPAddr)
		h.route(c, &model.Request{Command: 1, DstAddr: model.AddrSpec{IP: a.IP, Port: a.Port}}, m)
	}()
	c, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	response := make([]byte, 10)
	if _, err = io.ReadFull(c, response); err != nil || response[1] != 0 {
		t.Fatal("destination handshake failed")
	}
	payload := bytes.Repeat([]byte("response-after-upload-eof"), 1024)
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("upload EOF truncated response", err)
	}
	<-routeDone
	if err = <-echoDone; err != nil {
		t.Fatal(err)
	}
	if h.Stats().Upload != int64(len(payload)) || h.Stats().Download != int64(len(payload)) || h.Stats().Active != 0 {
		t.Fatal("relay accounting mismatch")
	}
}

func TestMieruAdmissionOpensOnlyOnActivate(t *testing.T) {
	in := mieruIntent(t, "tcp")
	prepared, err := (MieruCompiler{}).Compile(underlay.WithFactory(context.Background(), underlay.New()), in)
	if err != nil {
		t.Fatal(err)
	}
	h := prepared.(*mieruHandle)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if e := h.Close(ctx); e != nil {
			t.Error(e)
		}
	})
	if err = h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	endpoint := in.Inbound.Listeners[0].Endpoint
	c, err := net.Dial("tcp", net.JoinHostPort(endpoint.Host, portString(endpoint.Port)))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	_, err = c.Read(b[:])
	c.Close()
	if err != io.EOF {
		t.Fatal("precommit connection was not rejected", err)
	}
	if h.Stats().Sessions != 0 {
		t.Fatal("precommit session counted")
	}
	h.Activate()
	echo := mieruTCPFixture(t)
	client := mieruClient(t, in, 0)
	if err = mieruTransfer(client, echo.Addr(), 1024); err != nil {
		t.Fatal("committed connection rejected", err)
	}
}

func portString(port uint16) string { return fmt.Sprint(port) }

func mieruIntent(t *testing.T, transport string) ports.RuntimeIntent {
	return testfixture.MieruIntent(t, transport)
}
func mieruTCPFixture(t *testing.T) net.Listener { return testfixture.TCP(t) }
