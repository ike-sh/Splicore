//go:build with_gvisor

package amneziawgendpoint

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

type oracle struct {
	cmd        *exec.Cmd
	input      io.WriteCloser
	enc        *json.Encoder
	dec        *json.Decoder
	PublicKey  string `json:"public_key"`
	ListenPort int    `json:"listen_port"`
	Revision   string `json:"revision"`
}

func startOracle(t *testing.T, public string, addresses, allowed []string, psk string, keepalive int) *oracle {
	return startOracleProfile(t, public, addresses, allowed, psk, keepalive, E.AmneziaWG{})
}

func startOracleProfile(t *testing.T, public string, addresses, allowed []string, psk string, keepalive int, profile E.AmneziaWG) *oracle {
	t.Helper()
	binary := os.Getenv("SPLICORE_PHASE37_AWG_REFERENCE")
	if binary == "" {
		t.Skip("external official wireguard-go oracle not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	o := &oracle{cmd: exec.CommandContext(ctx, binary)}
	var err error
	o.input, err = o.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := o.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	o.cmd.Stderr = &log
	if root := os.Getenv("SPLICORE_PHASE37_PEER_LOGS"); root != "" {
		if err = os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		f, e := os.CreateTemp(root, "official-*.stderr")
		if e != nil {
			t.Fatal(e)
		}
		deferOnCleanup(t, f)
		o.cmd.Stderr = io.MultiWriter(&log, f)
	}
	if err = o.cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	o.enc = json.NewEncoder(o.input)
	o.dec = json.NewDecoder(stdout)
	t.Cleanup(func() {
		_ = o.enc.Encode(map[string]any{"op": "close"})
		_ = o.input.Close()
		if err := o.cmd.Wait(); err != nil {
			t.Errorf("official fixture failed: %v (%s)", err, log.String())
		}
		cancel()
	})
	if err = o.enc.Encode(map[string]any{"op": "init", "peer_key": public, "addresses": addresses, "allowed_ips": allowed, "psk": psk, "keepalive": keepalive, "obfuscation": obfuscationUAPI(profile)}); err != nil {
		t.Fatal(err)
	}
	if err = o.dec.Decode(o); err != nil {
		t.Fatal(err)
	}
	revision := os.Getenv("SPLICORE_PHASE37_ORACLE_REVISION")
	if revision == "" {
		revision = "b5928efb6ca19f0153958460c3d141f04abc5c2e"
	}
	if o.Revision != revision || o.ListenPort == 0 {
		t.Fatal("incorrect official oracle identity")
	}
	return o
}
func deferOnCleanup(t *testing.T, c io.Closer) { t.Helper(); t.Cleanup(func() { _ = c.Close() }) }
func (o *oracle) endpoint(t *testing.T, port int) {
	t.Helper()
	if err := o.enc.Encode(map[string]any{"op": "endpoint", "endpoint": net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}); err != nil {
		t.Fatal(err)
	}
	var response struct {
		OK bool `json:"ok"`
	}
	if err := o.dec.Decode(&response); err != nil || !response.OK {
		t.Fatalf("oracle endpoint update: %v", err)
	}
}

func (o *oracle) dial(t *testing.T, network, ip string, wantFailure bool) {
	t.Helper()
	payload := bytes.Repeat([]byte("official-interoperability"), 20)
	if err := o.enc.Encode(map[string]any{"op": "dial", "network": network, "target": net.JoinHostPort(ip, "12345"), "payload": payload, "timeout_ms": 700}); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Payload []byte `json:"payload"`
		Error   string `json:"error"`
	}
	if err := o.dec.Decode(&response); err != nil {
		t.Fatal(err)
	}
	if wantFailure {
		if response.Error == "" {
			t.Fatal("unauthorized flow succeeded")
		}
		return
	}
	if response.Error != "" || !bytes.Equal(payload, response.Payload) {
		t.Fatalf("official inbound %s %s failed: %s", network, ip, response.Error)
	}
}

func oracleTCP(t *testing.T, e *Endpoint, ip string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	c, err := e.DialContext(ctx, access.Endpoint{Host: ip, Port: 30034})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	want := bytes.Repeat([]byte("official"), 700)
	if _, err = c.Write(want); err != nil {
		t.Fatal(err)
	}
	if err = c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("official outbound TCP: %v bytes=%d", err, len(got))
	}
}

func oracleUDP(t *testing.T, e *Endpoint, ip string) {
	t.Helper()
	target := access.Endpoint{Host: ip, Port: 30035}
	c, err := e.ListenPacket(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	want := bytes.Repeat([]byte("u"), 1300)
	a, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, "30035"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.WriteTo(want, a); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 1500)
	n, _, err := c.ReadFrom(got)
	if err != nil || !bytes.Equal(got[:n], want) {
		t.Fatalf("official outbound UDP: %v bytes=%d", err, n)
	}
}

func TestOfficialAmneziaWGInterop(t *testing.T) {
	for _, pskEnabled := range []bool{false, true} {
		name := "no-psk"
		if pskEnabled {
			name = "matching-psk"
		}
		t.Run(name, func(t *testing.T) {
			private, public := testKeys(t)
			psk := ""
			var secret E.Secret
			if pskEnabled {
				secret, _ = testKeys(t)
				psk = E.EncodeKey(secret.Reveal())
			}
			first := startOracle(t, public, []string{"10.34.0.2", "fd34::2"}, []string{"10.34.0.1/32", "fd34::1/128"}, psk, 1)
			second := startOracle(t, public, []string{"10.34.0.3", "fd34::3"}, []string{"10.34.0.1/32", "fd34::1/128"}, psk, 0)
			config := E.AmneziaWG{Protocol: "amneziawg", Version: "3.1", Tag: "official", PrivateKey: private, Addresses: []string{"10.34.0.1/32", "fd34::1/128"}, Peers: []E.WireGuardPeer{
				{PublicKey: second.PublicKey, PreSharedKey: secret, Endpoint: net.JoinHostPort("127.0.0.1", itoa(second.ListenPort)), AllowedIPs: []string{"10.34.0.3/32", "fd34::3/128"}},
				{PublicKey: first.PublicKey, PreSharedKey: secret, Endpoint: net.JoinHostPort("127.0.0.1", itoa(first.ListenPort)), AllowedIPs: []string{"10.34.0.0/24", "fd34::/64"}, PersistentKeepaliveInterval: 1},
			}}
			dispatcher := &echoDispatcher{}
			e, err := New(context.Background(), config, Options{Dispatcher: dispatcher, Underlay: underlay.New()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = e.Close() })
			if err = e.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			first.endpoint(t, e.Status().ListenPort)
			second.endpoint(t, e.Status().ListenPort)
			for _, ip := range []string{"10.34.0.2", "fd34::2", "10.34.0.3", "fd34::3"} {
				oracleTCP(t, e, ip)
				oracleUDP(t, e, ip)
			}
			for _, o := range []*oracle{first, second} {
				for _, ip := range []string{"10.34.0.1", "fd34::1"} {
					o.dial(t, "tcp", ip, false)
					o.dial(t, "udp", ip, false)
				}
			}
			status := e.Status()
			if status.Peers[0].LastHandshake.IsZero() || status.Peers[1].LastHandshake.IsZero() {
				t.Fatal("independent peer handshake missing")
			}
			dispatcher.mu.Lock()
			seen := map[string]bool{}
			for _, id := range dispatcher.identities {
				seen[id.PeerPublicKey] = true
			}
			dispatcher.mu.Unlock()
			if !seen[first.PublicKey] || !seen[second.PublicKey] {
				t.Fatal("multi-peer credential identity lost")
			}
			raw, _ := json.Marshal(status)
			if strings.Contains(string(raw), E.EncodeKey(private.Reveal())) || psk != "" && strings.Contains(string(raw), psk) {
				t.Fatal("status leaked secret")
			}
		})
	}
}

func TestOfficialAmneziaWGDisallowedSource(t *testing.T) {
	private, public := testKeys(t)
	o := startOracle(t, public, []string{"10.34.0.99"}, []string{"10.34.0.1/32"}, "", 0)
	config := E.AmneziaWG{Protocol: "amneziawg", Version: "3.1", Tag: "source-negative", PrivateKey: private, Addresses: []string{"10.34.0.1/32"}, Peers: []E.WireGuardPeer{{PublicKey: o.PublicKey, AllowedIPs: []string{"10.34.0.2/32"}}}}
	d := &echoDispatcher{}
	e, err := New(context.Background(), config, Options{Dispatcher: d, Underlay: underlay.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	if err = e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	o.endpoint(t, e.Status().ListenPort)
	o.dial(t, "udp", "10.34.0.1", true)
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.identities) != 0 {
		t.Fatal("disallowed source reached Core dispatcher")
	}
	if e.Status().Peers[0].LastHandshake.IsZero() {
		t.Fatal("negative test did not authenticate the peer")
	}
}

// Ensure the fixture remains an external executable, rather than an alternate
// production stack linked into the Core process.
func TestOracleIsExternal(t *testing.T) {
	if p := os.Getenv("SPLICORE_PHASE37_AWG_REFERENCE"); p != "" && !filepath.IsAbs(p) {
		t.Fatal("oracle path must be absolute")
	}
}
