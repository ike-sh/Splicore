//go:build with_utls

package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	mc "github.com/ike-sh/Splicore/internal/splicore/domain/finalmask"
	sc "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	vl "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type phaseProfile struct {
	name     string
	security vl.Security
	flow     vl.Flow
	masks    []mc.Mask
}

func phaseMask(typ, s string) mc.Mask { return mc.Mask{Type: typ, Settings: json.RawMessage(s)} }
func phaseProfiles() []phaseProfile {
	fragment := phaseMask("fragment", `{"packets":"tlshello","lengths":["17-31"],"delays":[0],"maxSplit":32}`)
	sudoku := phaseMask("sudoku", `{"password":"synthetic-phase22","paddingMin":10,"paddingMax":40}`)
	p := []phaseProfile{{"A", vl.Plain, vl.NoFlow, nil}, {"B", vl.TLS, vl.Vision, nil}, {"C", vl.Reality, vl.Vision, nil}, {"D", vl.TLS, vl.NoFlow, []mc.Mask{fragment}}, {"E", vl.Reality, vl.NoFlow, []mc.Mask{sudoku}}, {"F", vl.Reality, vl.NoFlow, []mc.Mask{fragment, sudoku}}, {"F-reverse", vl.Reality, vl.NoFlow, []mc.Mask{sudoku, fragment}}, {"G", vl.Reality, vl.Vision, []mc.Mask{sudoku}}, {"REALITY-baseline", vl.Reality, vl.NoFlow, nil}, {"TLS-Vision-fragment-sudoku", vl.TLS, vl.Vision, []mc.Mask{fragment, sudoku}}}
	for _, typ := range []string{"array", "str", "hex", "base64"} {
		packet := `[65,66,67]`
		switch typ {
		case "str":
			packet = `"ABC"`
		case "hex":
			packet = `"414243"`
		case "base64":
			packet = `"QUJD"`
		}
		p = append(p, phaseProfile{"header-" + typ, vl.Plain, vl.NoFlow, []mc.Mask{phaseMask("header-custom", fmt.Sprintf(`{"clients":[[{"type":%q,"packet":%s},{"rand":7,"randRange":"1-31","delay":0}],[{"type":"str","packet":"second","delay":1}]],"servers":[[{"type":"str","packet":"reply"}],[{"type":"str","packet":"last"}]],"errors":[[{"type":"str","packet":"ERR"}]]}`, typ, packet))}})
	}
	for _, mode := range []struct{ name, settings string }{{"ascii", `{"password":"synthetic-phase22","ascii":"prefer_ascii","paddingMin":100,"paddingMax":100}`}, {"custom", `{"password":"synthetic-phase22","customTable":"xxppvvvv"}`}, {"multi", `{"password":"synthetic-phase22","customTables":["xxppvvvv","xpxpvvvv","xxppvvvv"],"paddingMin":100,"paddingMax":100}`}} {
		p = append(p, phaseProfile{"sudoku-" + mode.name, vl.Plain, vl.NoFlow, []mc.Mask{phaseMask("sudoku", mode.settings)}})
	}
	p = append(p, phaseProfile{"fragment-stream-alias", vl.Plain, vl.NoFlow, []mc.Mask{phaseMask("fragment", `{"packets":"1-4","length":"13-29","delay":0,"maxSplit":"3-8"}`)}})
	return p
}
func phaseFixture(t *testing.T, p phaseProfile) (ports.RuntimeIntent, client.RemoteNode, access.Credential) {
	in, n, c := sharedIntent(t, "vless", "ws", p.security != vl.Plain)
	var s vl.Settings
	json.Unmarshal(in.Inbound.Settings.Data, &s)
	s.Security = p.security
	s.Flow = p.flow
	s.Stream = &sc.Config{Kind: "tcp"}
	n.Transport = *s.Stream
	if len(p.masks) > 0 {
		m := &mc.Config{TCP: p.masks}
		s.Stream.FinalMask = m
		n.Transport.FinalMask = m
	}
	n.Protocol = vl.Key(p.security)
	in.Inbound.Protocol = n.Protocol
	n.Security.Kind = string(p.security)
	if p.security == vl.Reality {
		cert, _ := os.ReadFile(s.TLS.CertificateFile)
		key, _ := os.ReadFile(s.TLS.PrivateKeyFile)
		pair, e := tls.X509KeyPair(cert, key)
		clear(key)
		if e != nil {
			t.Fatal(e)
		}
		target := vlessEcho(t, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
		private, public, e := vl.GenerateServerKey()
		if e != nil {
			t.Fatal(e)
		}
		s.Reality = &vl.RealitySettings{PublicKey: public, ShortIDs: []vl.ShortID{"abcd"}, ServerName: s.TLS.ServerName, Target: netaddrEndpoint(target.Addr())}
		s.TLS = nil
		sid := in.Credentials[0]
		sid.Payload = private
		sid.Kind = access.PrivateKey
		sid.OwnerAccountID = nil
		sid.OwnerInboundID = &in.Inbound.ID
		in.ServerCredentials = []access.Credential{sid}
		n.Security.TLS = access.ClientTLS{Enabled: true, Trust: "reality", ServerName: s.Reality.ServerName, RealityPublicKey: string(public), RealityShortID: "abcd"}
	}
	n.Options.Data, _ = json.Marshal(vl.ClientOptions{Security: p.security, Flow: p.flow, PacketEncoding: "xudp"})
	in.Inbound.Settings.Data, _ = json.Marshal(s)
	return in, n, c
}
func phasePeer(t *testing.T, root, binary, name string, config any, endpoint access.Endpoint) {
	t.Helper()
	b, _ := json.MarshalIndent(config, "", "  ")
	file := filepath.Join(root, name+".config.json")
	if e := os.WriteFile(file, b, 0600); e != nil {
		t.Fatal(e)
	}
	log, e := os.Create(filepath.Join(root, name+".peer.log"))
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binary, "run", "-config", file)
	cmd.Stdout = log
	cmd.Stderr = log
	cmd.Env = append(os.Environ(), "XRAY_CONE_DISABLED=true")
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	var waitError error
	go func() { waitError = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		exitedBeforeCleanup := false
		select {
		case <-done:
			exitedBeforeCleanup = true
		default:
			cmd.Process.Kill()
		}
		<-done
		log.Close()
		state := map[string]any{"exit_code": cmd.ProcessState.ExitCode(), "process_state": cmd.ProcessState.String(), "exited_before_cleanup": exitedBeforeCleanup, "cleanup_kill_requested": !exitedBeforeCleanup}
		if waitError != nil {
			state["wait_error"] = waitError.Error()
		}
		b, err := json.MarshalIndent(state, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(root, name+".peer-exit.json"), b, 0600)
		}
		if err != nil {
			t.Error("record reference process exit", err)
		}
	})
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		c, e := net.DialTimeout("tcp", net.JoinHostPort(endpoint.Host, portString(endpoint.Port)), 30*time.Millisecond)
		if e == nil {
			c.Close()
			return
		}
		select {
		case <-done:
			t.Fatal("Xray rejected profile", waitError)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("peer startup timeout")
}
func phasePeerConfig(t *testing.T, p phaseProfile, in ports.RuntimeIntent, n client.RemoteNode, c access.Credential, socks access.Endpoint, direction string, root, name string) any {
	key := c.Payload.(access.UUIDPayload).UUID.Reveal()
	flow := ""
	if p.flow == vl.Vision {
		flow = string(p.flow)
	}
	user := map[string]any{"id": key, "flow": flow}
	stream := map[string]any{"network": "raw", "security": string(p.security)}
	if len(p.masks) > 0 {
		stream["finalmask"] = &mc.Config{TCP: p.masks}
	}
	var s vl.Settings
	json.Unmarshal(in.Inbound.Settings.Data, &s)
	if p.security == vl.TLS {
		settings := map[string]any{"serverName": n.Security.TLS.ServerName, "minVersion": "1.3"}
		if direction == "splicore-client" {
			settings["certificates"] = []any{map[string]any{"certificateFile": s.TLS.CertificateFile, "keyFile": s.TLS.PrivateKeyFile}}
		} else {
			ca := filepath.Join(root, name+".ca.pem")
			os.WriteFile(ca, []byte(n.Security.TLS.CACertificate), 0600)
			settings["certificates"] = []any{map[string]any{"certificateFile": ca, "usage": "verify"}}
		}
		stream["tlsSettings"] = settings
	}
	if p.security == vl.Reality {
		if direction == "splicore-client" {
			stream["realitySettings"] = map[string]any{"show": true, "target": net.JoinHostPort(s.Reality.Target.Host, portString(s.Reality.Target.Port)), "serverNames": []string{s.Reality.ServerName}, "privateKey": in.ServerCredentials[0].Payload.(access.PrivateKeyPayload).Material.Reveal(), "shortIds": []string{"abcd"}}
		} else {
			stream["realitySettings"] = map[string]any{"serverName": n.Security.TLS.ServerName, "publicKey": n.Security.TLS.RealityPublicKey, "shortId": "abcd", "fingerprint": "chrome"}
		}
	}
	proxy := map[string]any{"protocol": "vless", "streamSettings": stream}
	config := map[string]any{"log": map[string]any{"loglevel": "debug"}}
	if direction == "splicore-client" {
		proxy["listen"] = n.Endpoint.Host
		proxy["port"] = n.Endpoint.Port
		proxy["settings"] = map[string]any{"clients": []any{user}, "decryption": "none"}
		config["inbounds"] = []any{proxy}
		config["outbounds"] = []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.0/8"}}}}}}
	} else {
		user["encryption"] = "none"
		proxy["settings"] = map[string]any{"vnext": []any{map[string]any{"address": n.Endpoint.Host, "port": n.Endpoint.Port, "users": []any{user}}}}
		config["outbounds"] = []any{proxy}
		config["inbounds"] = []any{map[string]any{"listen": socks.Host, "port": socks.Port, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}}
	}
	return config
}
func phaseExchange(c net.Conn, p []byte) error {
	c.SetDeadline(time.Now().Add(20 * time.Second))
	ch := make(chan error, 1)
	go func() { _, e := c.Write(p); ch <- e }()
	b := make([]byte, len(p))
	_, e := io.ReadFull(c, b)
	we := <-ch
	if e != nil {
		return e
	}
	if we != nil {
		return we
	}
	if !bytes.Equal(b, p) {
		return fmt.Errorf("payload mismatch")
	}
	return nil
}
func TestPhase22XrayInterop(t *testing.T) {
	binary, root := os.Getenv("SPLICORE_PHASE22_XRAY"), os.Getenv("SPLICORE_PHASE22_INTEROP")
	if binary == "" || root == "" {
		t.Skip("pinned external Xray oracle not configured")
	}
	if e := os.MkdirAll(root, 0700); e != nil {
		t.Fatal(e)
	}
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	echo := vlessEcho(t, nil)
	dst := netaddrEndpoint(echo.Addr())
	for _, p := range phaseProfiles() {
		for _, direction := range []string{"splicore-client", "splicore-server"} {
			t.Run(p.name+"/"+direction, func(t *testing.T) {
				name := p.name + "-" + direction
				t.Cleanup(func() {
					if !t.Failed() {
						return
					}
					result := map[string]any{"profile": p.name, "direction": direction, "security": p.security, "flow": p.flow, "masks": p.masks, "result": "FAIL", "application_exact_bytes": false, "error_details": "see raw test output and peer log"}
					b, err := json.MarshalIndent(result, "", "  ")
					if err == nil {
						err = os.WriteFile(filepath.Join(root, name+".result.json"), b, 0600)
					}
					if err != nil {
						t.Error("record failed profile", err)
					}
				})
				if p.name == "F" && direction == "splicore-client" && os.Getenv("SPLICORE_PHASE22_KNOWN_UPSTREAM_FRAGMENT_BUG") == "1" {
					t.Skip("official v26.9.9 REALITY constructor panics on innermost fragment; raw failing evidence retained externally")
				}
				in, n, cred := phaseFixture(t, p)
				reserve, e := net.Listen("tcp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				socks := netaddrEndpoint(reserve.Addr())
				reserve.Close()
				var d ports.ClientDialer
				if direction == "splicore-server" {
					h := sharedPrepare(t, ctx, "vless", in)
					if e = h.Start(ctx); e != nil {
						t.Fatal(e)
					}
					h.Activate()
					t.Cleanup(func() { h.Close(context.Background()) })
				} else {
					d = sharedBuild(t, ctx, n, cred)
					t.Cleanup(func() { d.Close() })
				}
				endpoint := n.Endpoint
				if direction == "splicore-server" {
					endpoint = socks
				}
				phasePeer(t, root, binary, name, phasePeerConfig(t, p, in, n, cred, socks, direction, root, name), endpoint)
				dial := func(target access.Endpoint) (net.Conn, error) {
					if d != nil {
						return d.DialContext(ctx, target)
					}
					return phaseSOCKS(socks, target)
				}
				c, e := dial(dst)
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				if _, e = c.Write(nil); e != nil {
					t.Fatal(e)
				}
				for _, size := range []int{1, 17, 8191, 65537, 4 << 20} {
					payload := bytes.Repeat([]byte{7, 23, 119, 255}, (size+3)/4)[:size]
					if e = phaseExchange(c, payload); e != nil {
						t.Fatal("size", size, e)
					}
				}
				for i := 0; i < 128; i++ {
					if e = phaseExchange(c, []byte{byte(i)}); e != nil {
						t.Fatal("small writes", e)
					}
				}
				if e = c.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
					t.Fatal("half-close", e)
				}
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				var tail [1]byte
				if n, e := c.Read(tail[:]); n != 0 || e != io.EOF {
					t.Fatal("half-close drain", n, e)
				}
				// Four simultaneous connections prove independent tables/session state.
				var wg sync.WaitGroup
				errs := make(chan error, 4)
				for i := 0; i < 4; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						c, e := dial(dst)
						if e == nil {
							defer c.Close()
							e = phaseExchange(c, bytes.Repeat([]byte{113}, 65539))
						}
						errs <- e
					}()
				}
				wg.Wait()
				close(errs)
				for e := range errs {
					if e != nil {
						t.Fatal("concurrent", e)
					}
				}
				for i := 0; i < 2; i++ {
					next, e := dial(dst)
					if e != nil {
						t.Fatal(e)
					}
					e = phaseExchange(next, []byte("sequential application"))
					next.Close()
					if e != nil {
						t.Fatal(e)
					}
				}
				serverDst, serverDrain, serverReady := phaseHalfServer(t)
				half, e := dial(serverDst)
				if e != nil {
					t.Fatal(e)
				}
				half.SetDeadline(time.Now().Add(10 * time.Second))
				reply := make([]byte, len("server-half-close"))
				_, e = io.ReadFull(half, reply)
				if e != nil || string(reply) != "server-half-close" {
					half.Close()
					t.Fatal("server half-close", e)
				}
				<-serverReady
				serverHalfClose := "PASS"
				// Pinned Xray's non-Vision TLS response uses tls.Conn directly as
				// buf.Writer. Closing that writer calls full Close, unlike its
				// SequentialWriter path. Record this upstream lifecycle limit;
				// native peers separately require upload after visible EOF.
				if p.security == vl.TLS && p.flow == vl.NoFlow && direction == "splicore-client" {
					remaining, e := io.ReadAll(half)
					if e != nil || len(remaining) != 0 {
						half.Close()
						t.Fatal("upstream TLS full-close", e)
					}
					if got := <-serverDrain; len(got) != 0 {
						half.Close()
						t.Fatal("unexpected upstream drain")
					}
					serverHalfClose = "UPSTREAM_FULL_CLOSE"
				} else {
					upload := bytes.Repeat([]byte("upload-after-half-close"), 4096)
					if _, e = half.Write(upload); e != nil {
						half.Close()
						t.Fatal(e)
					}
					if e = half.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
						half.Close()
						t.Fatal(e)
					}
					if got := <-serverDrain; !bytes.Equal(got, upload) {
						half.Close()
						t.Fatal("server half-close upload lost")
					}
					if remaining, e := io.ReadAll(half); e != nil || len(remaining) != 0 {
						half.Close()
						t.Fatal("server half-close final EOF", e)
					}
				}
				half.Close()
				idle, e := dial(dst)
				if e != nil {
					t.Fatal(e)
				}
				if e = phaseExchange(idle, []byte("deadline prelude")); e != nil {
					idle.Close()
					t.Fatal(e)
				}
				idle.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
				var idleByte [1]byte
				if _, e = idle.Read(idleByte[:]); e == nil {
					idle.Close()
					t.Fatal("deadline ignored")
				}
				idle.Close()
				early, e := dial(dst)
				if e != nil {
					t.Fatal(e)
				}
				early.Close()
				// An actual inner TLS application forces Vision command 2, then carries a
				// multi-buffer payload through the same underlay masks.
				if p.flow == vl.Vision {
					tlsMaterial := testkit.TLSForName(t, "inner.synthetic.test")
					cert, _ := os.ReadFile(tlsMaterial.CertificateFile)
					key, _ := os.ReadFile(tlsMaterial.PrivateKeyFile)
					pair, e := tls.X509KeyPair(cert, key)
					clear(key)
					if e != nil {
						t.Fatal(e)
					}
					target := vlessEcho(t, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13})
					raw, e := dial(netaddrEndpoint(target.Addr()))
					if e != nil {
						t.Fatal(e)
					}
					inner := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
					defer inner.Close()
					if e = phaseExchange(inner, bytes.Repeat([]byte("proxied inner TLS application"), 50000)); e != nil {
						t.Fatal("inner TLS direct", e)
					}
				}
				if !t.Failed() {
					result := map[string]any{"profile": p.name, "direction": direction, "security": p.security, "flow": p.flow, "result": "PASS", "payload_sizes": []int{1, 17, 8191, 65537, 4 << 20}, "many_small_writes": 128, "concurrent_connections": 4, "sequential_connections": 2, "server_half_close": serverHalfClose, "deadline": "PASS", "early_EOF": "PASS", "client_half_close": "PASS", "application_exact_bytes": true, "real_inner_tls": p.flow == vl.Vision}
					b, _ := json.MarshalIndent(result, "", "  ")
					os.WriteFile(filepath.Join(root, name+".result.json"), b, 0600)
				}
			})
		}
	}
}

// Native peers cover the half-close regression independently of any upstream
// wrapper type assertion defect, in both configured mask orders with REALITY.
func TestPhase22NativeCombinedHalfClose(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	for _, p := range phaseProfiles() {
		if !strings.HasPrefix(p.name, "F") && p.name != "G" {
			continue
		}
		t.Run(p.name, func(t *testing.T) {
			in, n, c := phaseFixture(t, p)
			h := sharedPrepare(t, ctx, "vless", in)
			if e := h.Start(ctx); e != nil {
				t.Fatal(e)
			}
			h.Activate()
			defer h.Close(context.Background())
			d := sharedBuild(t, ctx, n, c)
			defer d.Close()
			echo := vlessEcho(t, nil)
			conn, e := d.DialContext(ctx, netaddrEndpoint(echo.Addr()))
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			if e = phaseExchange(conn, bytes.Repeat([]byte{19}, 65537)); e != nil {
				t.Fatal(e)
			}
			if e = conn.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
				t.Fatal(e)
			}
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			var b [1]byte
			if n, e := conn.Read(b[:]); n != 0 || e != io.EOF {
				t.Fatal("drain", n, e)
			}
		})
	}
}
