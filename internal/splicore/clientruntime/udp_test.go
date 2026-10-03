package clientruntime

import (
	"bytes"
	"context"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/varbin"
	"github.com/sagernet/sing/protocol/socks/socks5"
	"net"
	"sync"
	"testing"
	"time"
)

func udpFixture(t *testing.T, idle ...time.Duration) (*Manager, client.ProfileState, *registry.Outbounds, *net.UDPConn) {
	t.Helper()
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			n, a, e := echo.ReadFromUDP(b)
			if e != nil {
				return
			}
			_, _ = echo.WriteToUDP(b[:n], a)
		}
	}()
	t.Cleanup(func() { _ = echo.Close(); <-done })
	temp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(temp.Addr().(*net.TCPAddr).Port)
	_ = temp.Close()
	id, _ := identity.NewID()
	state := client.Empty()
	state.LocalInbounds = []client.LocalInbound{{ID: id, Name: "local", Kind: "socks5", Listen: access.Endpoint{Host: "127.0.0.1", Port: port}}}
	r, _ := registry.NewOutbounds()
	m := New()
	if len(idle) > 0 {
		m.udpIdle = idle[0]
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	p, err := m.Prepare(context.Background(), state, nil, r)
	if err != nil {
		t.Fatal(err)
	}
	p.Activate()
	return m, state, r, echo
}
func udpControl(state client.ProfileState, source M.Socksaddr) (net.Conn, M.Socksaddr, error) {
	e := state.LocalInbounds[0].Listen
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", e.Port), time.Second)
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	// The inherited convenience handshake deliberately rewrites UDP source
	// IP/port. Send the actual requested source to test the server contract.
	err = socks5.WriteAuthRequest(c, socks5.AuthRequest{Methods: []byte{socks5.AuthTypeNotRequired}})
	if err == nil {
		_, err = socks5.ReadAuthResponse(varbin.StubReader(c))
	}
	if err == nil {
		err = socks5.WriteRequest(c, socks5.Request{Command: socks5.CommandUDPAssociate, Destination: source})
	}
	var res socks5.Response
	if err == nil {
		res, err = socks5.ReadResponse(varbin.StubReader(c))
	}
	if err == nil && res.ReplyCode != socks5.ReplyCodeSuccess {
		err = fmt.Errorf("SOCKS UDP rejected: %d", res.ReplyCode)
	}
	if err != nil {
		_ = c.Close()
		return nil, M.Socksaddr{}, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, res.Bind, nil
}
func udpRoundtrip(pc *net.UDPConn, relay M.Socksaddr, target net.Addr, payload []byte) error {
	b, err := encodeUDPPacket(target, payload)
	if err != nil {
		return err
	}
	_ = pc.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = pc.WriteToUDP(b, relay.UDPAddr()); err != nil {
		return err
	}
	b = make([]byte, 65535)
	n, _, err := pc.ReadFromUDP(b)
	if err != nil {
		return err
	}
	_, p, err := parseUDPPacket(b[:n])
	if err != nil {
		return err
	}
	if !bytes.Equal(p, payload) {
		return fmt.Errorf("packet cross-talk or integrity mismatch")
	}
	return nil
}
func TestSOCKSUDPAssociationLifecycleAndIsolation(t *testing.T) {
	m, state, r, echo := udpFixture(t)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			control, relay, err := udpControl(state, M.ParseSocksaddr("0.0.0.0:0"))
			if err != nil {
				errs <- err
				return
			}
			defer control.Close()
			pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				errs <- err
				return
			}
			defer pc.Close()
			for j := range 8 {
				if err = udpRoundtrip(pc, relay, echo.LocalAddr(), []byte(fmt.Sprintf("association-%d-packet-%d", i, j))); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.WaitIdle(ctx); err != nil {
		t.Fatal(err)
	}
	st := m.Status(state, nil)
	v := st.Outbounds[0].Stats
	if v.Sessions != 0 || v.UDPAssociations != 16 || v.UDPActive != 0 || v.PacketsUpload != 128 || v.PacketsDownload != 128 {
		t.Fatalf("UDP accounting %+v", v)
	}
	// An association belongs to its TCP control socket. Route reconciliation
	// closes changed associations even if its UDP client socket stays open.
	c, relay, err := udpControl(state, M.ParseSocksaddr("0.0.0.0:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p, err := m.PrepareWithRestart(ctx, state, nil, r, true)
	if err != nil {
		t.Fatal(err)
	}
	p.Activate()
	if err := m.WaitIdle(ctx); err != nil {
		t.Fatal(err)
	}
	released, err := net.ListenUDP("udp4", relay.UDPAddr())
	if err != nil {
		t.Fatal("stale association socket", err)
	}
	_ = released.Close()
}

func TestSOCKSUDPOwnershipFragmentExpiryAndShutdown(t *testing.T) {
	m, state, _, echo := udpFixture(t, 150*time.Millisecond)
	first, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	control, relay, err := udpControl(state, M.ParseSocksaddr("0.0.0.0:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	// A malformed/fragmented packet must not claim an unspecified client port.
	fragment, _ := encodeUDPPacket(echo.LocalAddr(), []byte("fragment"))
	fragment[2] = 1
	_, _ = first.WriteToUDP(fragment, relay.UDPAddr())
	owner, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := udpRoundtrip(owner, relay, echo.LocalAddr(), []byte("owner")); err != nil {
		t.Fatal(err)
	}
	frame, _ := encodeUDPPacket(echo.LocalAddr(), []byte("foreign"))
	_, _ = first.WriteToUDP(frame, relay.UDPAddr())
	_ = first.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	b := make([]byte, 1024)
	if _, _, err = first.ReadFromUDP(b); err == nil {
		t.Fatal("foreign source received relay traffic")
	}
	_ = control.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err = control.Read(b); err == nil {
		t.Fatal("idle association did not expire")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = m.WaitIdle(ctx); err != nil {
		t.Fatal(err)
	}
	released, err := net.ListenUDP("udp4", relay.UDPAddr())
	if err != nil {
		t.Fatal("expired relay leaked", err)
	}
	_ = released.Close()
	c, _, err := udpControl(state, M.SocksaddrFromNet(owner.LocalAddr()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = m.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if len(m.Status(state, nil).Sessions) != 0 {
		t.Fatal("shutdown retained sessions")
	}
}

func FuzzSOCKSUDPAddress(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 1})
	f.Add([]byte{0, 0, 1, 3, 1, 'a', 0, 53})
	f.Fuzz(func(t *testing.T, b []byte) {
		e, p, err := parseUDPPacket(b)
		if err == nil {
			if e.Validate() != nil || len(p) > len(b) {
				t.Fatal("parser admitted invalid address")
			}
		}
	})
}
