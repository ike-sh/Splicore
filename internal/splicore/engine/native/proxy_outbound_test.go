package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func proxyNode(t *testing.T, protocol string, port int, auth bool) (client.RemoteNode, access.Credential) {
	t.Helper()
	id, _ := identity.NewID()
	cid, _ := identity.NewID()
	o, _ := json.Marshal(proxy.Options{Auth: auth, UDP: protocol == "socks5"})
	n := client.RemoteNode{ID: id, Name: "synthetic proxy", CredentialID: cid, Protocol: proxy.Key(protocol), Endpoint: access.Endpoint{Host: "127.0.0.1", Port: uint16(port)}, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: o}}
	c := access.Credential{ID: cid, OwnerNodeID: &id, Kind: access.Password, Schema: 1, State: "active", Payload: access.PasswordPayload{Password: secret.New(proxy.NoAuth)}, Stamp: identity.NewStamp(time.Now())}
	if auth {
		c.Kind = access.UsernamePassword
		c.Payload = access.UsernamePasswordPayload{Username: secret.New("synthetic"), Password: secret.New("fixture")}
	}
	return n, c
}

// This fixture deliberately parses independent RFC byte sequences rather than
// importing the Splicore SOCKS codec. It records DOMAIN without resolving it.
func independentSOCKSPeer(t *testing.T, auth bool) (int, chan string, chan net.Conn) {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	u, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")})
	if e != nil {
		t.Fatal(e)
	}
	hosts := make(chan string, 128)
	controls := make(chan net.Conn, 128)
	var wg sync.WaitGroup
	var mu sync.Mutex
	all := []net.Conn{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		b := make([]byte, 65535)
		for {
			n, a, e := u.ReadFromUDP(b)
			if e != nil {
				return
			}
			_, _ = u.WriteToUDP(b[:n], a)
		}
	}()
	go func() {
		defer wg.Done()
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			all = append(all, c)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var h [4]byte
				if _, e := io.ReadFull(c, h[:3]); e != nil || h[0] != 5 || h[1] != 1 {
					return
				}
				method := byte(0)
				if auth {
					method = 2
				}
				if h[2] != method {
					_, _ = c.Write([]byte{5, 255})
					return
				}
				_, _ = c.Write([]byte{5, method})
				if auth {
					if _, e := io.ReadFull(c, h[:2]); e != nil {
						return
					}
					user := make([]byte, int(h[1]))
					if _, e := io.ReadFull(c, user); e != nil {
						return
					}
					if _, e := io.ReadFull(c, h[:1]); e != nil {
						return
					}
					pass := make([]byte, int(h[0]))
					if _, e := io.ReadFull(c, pass); e != nil {
						return
					}
					if string(user) != "synthetic" || string(pass) != "fixture" {
						_, _ = c.Write([]byte{1, 1})
						return
					}
					_, _ = c.Write([]byte{1, 0})
				}
				if _, e := io.ReadFull(c, h[:4]); e != nil || h[0] != 5 {
					return
				}
				command := h[1]
				size := 0
				switch h[3] {
				case 1:
					size = 4
				case 4:
					size = 16
				case 3:
					if _, e := io.ReadFull(c, h[:1]); e != nil {
						return
					}
					size = int(h[0])
				default:
					return
				}
				addr := make([]byte, size+2)
				if _, e := io.ReadFull(c, addr); e != nil {
					return
				}
				host := string(addr[:size])
				if size == 4 || size == 16 {
					host = net.IP(addr[:size]).String()
				}
				hosts <- host
				if command == 3 {
					port := u.LocalAddr().(*net.UDPAddr).Port
					reply := []byte{5, 0, 0, 1, 127, 0, 0, 2, 0, 0}
					binary.BigEndian.PutUint16(reply[8:], uint16(port))
					_, _ = c.Write(reply)
					_ = c.SetDeadline(time.Time{})
					controls <- c
					_, _ = io.Copy(io.Discard, c)
					return
				}
				_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		_ = u.Close()
		mu.Lock()
		for _, c := range all {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return l.Addr().(*net.TCPAddr).Port, hosts, controls
}
func TestPhase20SOCKSOutboundRemoteDNSRelayLifetime(t *testing.T) {
	var resolutions atomic.Int64
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		resolutions.Add(1)
		return nil, fmt.Errorf("unexpected local DNS resolution")
	}}
	defer func() { net.DefaultResolver = previous }()
	defer func() {
		if resolutions.Load() != 0 {
			t.Fatal("local DNS queries", resolutions.Load())
		}
		t.Logf("controlled local DNS resolution calls=%d; TCP/UDP DOMAIN preserved", resolutions.Load())
	}()
	for _, auth := range []bool{false, true} {
		port, hosts, controls := independentSOCKSPeer(t, auth)
		n, c := proxyNode(t, "socks5", port, auth)
		ctx := underlay.WithFactory(context.Background(), underlay.New())
		d, e := (SOCKS5OutboundFactory{}).Build(ctx, n, c)
		if e != nil {
			t.Fatal(e)
		}
		for _, host := range []string{"127.0.0.1", "::1", "no-local-resolution.invalid"} {
			conn, e := d.DialContext(ctx, access.Endpoint{Host: host, Port: 80})
			if e != nil {
				t.Fatal(e)
			}
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			_, _ = conn.Write([]byte("payload"))
			p := make([]byte, 7)
			if _, e = io.ReadFull(conn, p); e != nil || string(p) != "payload" {
				t.Fatal("payload", e)
			}
			_ = conn.Close()
			if <-hosts != host {
				t.Fatal("DOMAIN was resolved or altered")
			}
		}
		for range 25 {
			dst := access.Endpoint{Host: "remote.invalid", Port: 53}
			pc, e := d.(ports.ClientPacketDialer).ListenPacket(ctx, dst)
			if e != nil {
				t.Fatal(e)
			}
			if <-hosts != "0.0.0.0" {
				t.Fatal("associate source")
			}
			control := <-controls
			_ = pc.SetDeadline(time.Now().Add(time.Second))
			for _, host := range []string{"127.0.0.1", "::1", "remote.invalid"} {
				dst.Host = host
				if _, e = pc.WriteTo([]byte("datagram"), netaddr.UDP(dst)); e != nil {
					t.Fatal(e)
				}
				b := make([]byte, 64)
				n, a, e := pc.ReadFrom(b)
				if e != nil || string(b[:n]) != "datagram" || a.String() != netaddr.UDP(dst).String() {
					t.Fatal("distinct relay payload", e)
				}
			}
			_ = control.Close()
			done := make(chan error, 1)
			go func() { _, _, e := pc.ReadFrom(make([]byte, 1)); done <- e }()
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("dead control reused")
				}
			case <-time.After(time.Second):
				t.Fatal("control EOF did not wake packet read")
			}
			_ = pc.Close()
		}
		_ = d.Close()
	}
}
func TestPhase20HTTPOutboundBoundedResponseAndBufferedPayload(t *testing.T) {
	for _, auth := range []bool{false, true} {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			c, e := l.Accept()
			if e != nil {
				return
			}
			defer c.Close()
			r := bufio.NewReader(c)
			var header bytes.Buffer
			for {
				line, e := r.ReadString('\n')
				if e != nil {
					return
				}
				header.WriteString(line)
				if line == "\r\n" {
					break
				}
			}
			if auth && !bytes.Contains(header.Bytes(), []byte("Proxy-Authorization: Basic ")) {
				return
			}
			for _, b := range []byte("HTTP/1.1 201 Created\r\nContent-Length: 99\r\n\r\nserver-first") {
				_, _ = c.Write([]byte{b})
			}
			_, _ = io.Copy(c, r)
		}()
		n, c := proxyNode(t, "http", l.Addr().(*net.TCPAddr).Port, auth)
		ctx := underlay.WithFactory(context.Background(), underlay.New())
		d, e := (HTTPOutboundFactory{}).Build(ctx, n, c)
		if e != nil {
			t.Fatal(e)
		}
		conn, e := d.DialContext(ctx, access.Endpoint{Host: "remote.invalid", Port: 80})
		if e != nil {
			t.Fatal(e)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		b := make([]byte, 12)
		if _, e = io.ReadFull(conn, b); e != nil || string(b) != "server-first" {
			t.Fatal("coalesced tunnel", e)
		}
		_, _ = conn.Write([]byte("echo"))
		b = make([]byte, 4)
		if _, e = io.ReadFull(conn, b); e != nil || string(b) != "echo" {
			t.Fatal("tunnel", e)
		}
		if d.(ports.ClientNetworkSupport).SupportsNetwork("udp") {
			t.Fatal("HTTP claims UDP")
		}
		_ = d.Close()
		_ = l.Close()
		<-done
	}
}
func TestPhase20ProxyCancellationAndParentClose(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); accepted <- c }()
	n, c := proxyNode(t, "socks5", l.Addr().(*net.TCPAddr).Port, false)
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	d, e := (SOCKS5OutboundFactory{}).Build(ctx, n, c)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := d.DialContext(ctx, access.Endpoint{Host: "remote.invalid", Port: 80}); done <- e }()
	peer := <-accepted
	defer peer.Close()
	closed := make(chan struct{})
	go func() { _ = d.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("parent failed to join handshake")
	}
	if <-done == nil {
		t.Fatal("handshake published after parent close")
	}
}
func TestPhase20MatureUpstreamInterop(t *testing.T) {
	raw := os.Getenv("SPLICORE_P20_PEERS")
	if raw == "" {
		t.Skip("external local mature peers supplied by the evidence runner")
	}
	var config map[string]int
	if json.Unmarshal([]byte(raw), &config) != nil {
		t.Fatal("peer configuration")
	}
	tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	udp := trojanUDP(t)
	for _, protocol := range []string{"socks5", "http"} {
		for _, auth := range []bool{false, true} {
			key := protocol + "-" + strconv.FormatBool(auth)
			n, c := proxyNode(t, protocol, config[key], auth)
			ctx := underlay.WithFactory(context.Background(), underlay.New())
			var f ports.OutboundFactory = SOCKS5OutboundFactory{}
			if protocol == "http" {
				f = HTTPOutboundFactory{}
			}
			d, e := f.Build(ctx, n, c)
			if e != nil {
				t.Fatal(e)
			}
			if protocol == "socks5" {
				vmessTransfer(t, d, tcp, udp, 2048)
			} else {
				conn, e := d.DialContext(ctx, tcp)
				if e != nil {
					t.Fatal(e)
				}
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				_, _ = conn.Write([]byte("mature-http-payload"))
				b := make([]byte, len("mature-http-payload"))
				if _, e = io.ReadFull(conn, b); e != nil || string(b) != "mature-http-payload" {
					t.Fatal("mature payload", e)
				}
				_ = conn.Close()
			}
			_ = d.Close()
			t.Logf("peer=sing-box protocol=%s auth=%t actual TCP payload PASS UDP=%t", protocol, auth, protocol == "socks5")
		}
	}
}
