package native

// This opt-in localhost oracle harness executes official reference binaries.
// Production AnyTLS has no subprocess or reference-core dependency.
import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/anytls"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func anytlsFree(t *testing.T) access.Endpoint {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return netaddrEndpoint(l.Addr())
}
func anytlsReference(t *testing.T, binary, dir string, endpoint access.Endpoint, args ...string) {
	t.Helper()
	log, err := os.Create(filepath.Join(dir, "reference.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, args...)
	cmd.Dir = dir
	cmd.Stdout = log
	cmd.Stderr = log
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("reference process did not join")
		}
		log.Close()
		b, _ := os.ReadFile(log.Name())
		t.Logf("reference output: %s", b)
	})
	end := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(endpoint.Host, fmt.Sprint(endpoint.Port)), 50*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(end) {
			t.Fatal("reference listener did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func anytlsConfigFile(t *testing.T, dir string, c any) string {
	t.Helper()
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func anytlsProxyOracle(t *testing.T, ctx context.Context, in ports.RuntimeIntent, endpoint access.Endpoint) ports.ClientDialer {
	t.Helper()
	settings, err := module.Decode(in.Inbound.Settings.Data)
	if err != nil {
		t.Fatal(err)
	}
	n, c := anytlsNode(t, in, settings.TLS, 0)
	n.Endpoint = endpoint
	n.Protocol = proxy.Key("socks5")
	n.Security.Kind = "none"
	n.Security.TLS = access.ClientTLS{}
	n.Options.Data = json.RawMessage(`{"auth":false,"udp":true}`)
	c.Payload = access.PasswordPayload{Password: secret.New(proxy.NoAuth)}
	d, err := (SOCKS5OutboundFactory{}).Build(ctx, n, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestAnyTLSOfficialCompatibility(t *testing.T) {
	root := os.Getenv("SPLICORE_ANYTLS_ORACLES")
	if root == "" {
		t.Skip("opt-in official localhost oracle matrix")
	}
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	sing := filepath.Join(root, "tools/singbox/sing-box-1.14.2-linux-amd64/sing-box")
	anyServer := filepath.Join(root, "tools/anytls/anytls-server")
	anyClient := filepath.Join(root, "tools/anytls/anytls-client")
	for _, oracle := range []string{"anytls-go", "sing-box"} {
		for _, direction := range []string{"native-client", "native-server"} {
			for _, variant := range []string{"default", "custom-padding", "native-v1"} {
				if oracle == "anytls-go" && variant == "custom-padding" {
					continue
				}
				t.Run(oracle+"/"+direction+"/"+variant, func(t *testing.T) {
					dir, err := os.MkdirTemp(root, "interop-")
					if err != nil {
						t.Fatal(err)
					}
					in, s := anytlsIntent(t)
					password := in.Credentials[0].Payload.(access.PasswordPayload).Password.Reveal()
					tcp := netaddrEndpoint(testfixture.TCP(t).Addr())
					udp := trojanUDP(t)
					var d ports.ClientDialer
					if direction == "native-client" {
						endpoint := anytlsFree(t)
						in.Inbound.Listeners[0].Endpoint = endpoint
						n, c := anytlsNode(t, in, s, 0)
						o := module.ClientOptions{UDP: true, MultiplexStreams: 64}
						if variant == "native-v1" {
							o.Version = 1
						}
						if oracle == "anytls-go" {
							n.Security.TLS.Trust = "system"
							n.Security.TLS.CACertificate = ""
							o.Insecure = true
							anytlsReference(t, anyServer, dir, endpoint, "-l", net.JoinHostPort(endpoint.Host, fmt.Sprint(endpoint.Port)), "-p", password)
						} else {
							ib := map[string]any{"type": "anytls", "tag": "server", "listen": endpoint.Host, "listen_port": endpoint.Port, "users": []any{map[string]any{"name": "synthetic", "password": password}}, "tls": map[string]any{"enabled": true, "certificate_path": s.CertificateFile, "key_path": s.PrivateKeyFile}}
							if variant == "custom-padding" {
								ib["padding_scheme"] = []string{"stop=4", "0=13-13", "1=150-200", "2=100-200,c,300-400", "3=7-7,100-100"}
							}
							file := anytlsConfigFile(t, dir, map[string]any{"log": map[string]any{"level": "debug"}, "inbounds": []any{ib}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}})
							anytlsReference(t, sing, dir, endpoint, "run", "-c", file)
						}
						n.Options.Data, _ = json.Marshal(o)
						d, err = (AnyTLSOutboundFactory{}).Build(ctx, n, c)
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { d.Close() })
					} else {
						settings := module.Settings{TLS: s}
						if variant == "native-v1" {
							settings.Version = 1
						}
						if variant == "custom-padding" {
							settings.PaddingScheme = "stop=4\n0=13-13\n1=150-200\n2=100-200,c,300-400\n3=7-7,100-100"
						}
						in.Inbound.Settings.Data, _ = json.Marshal(settings)
						anytlsStart(t, ctx, in)
						endpoint := anytlsFree(t)
						if oracle == "anytls-go" {
							anytlsReference(t, anyClient, dir, endpoint, "-l", net.JoinHostPort(endpoint.Host, fmt.Sprint(endpoint.Port)), "-s", net.JoinHostPort(in.Inbound.Listeners[0].Endpoint.Host, fmt.Sprint(in.Inbound.Listeners[0].Endpoint.Port)), "-p", password, "-sni", s.ServerName)
						} else {
							ob := map[string]any{"type": "anytls", "tag": "proxy", "server": in.Inbound.Listeners[0].Endpoint.Host, "server_port": in.Inbound.Listeners[0].Endpoint.Port, "password": password, "client_metadata": "", "tls": map[string]any{"enabled": true, "server_name": s.ServerName, "certificate": []string{s.CACertificate}}}
							file := anytlsConfigFile(t, dir, map[string]any{"log": map[string]any{"level": "debug"}, "inbounds": []any{map[string]any{"type": "socks", "tag": "socks", "listen": endpoint.Host, "listen_port": endpoint.Port}}, "outbounds": []any{ob}})
							anytlsReference(t, sing, dir, endpoint, "run", "-c", file)
						}
						d = anytlsProxyOracle(t, ctx, in, endpoint)
					}
					for _, host := range []string{"127.0.0.1", "localhost"} {
						target := tcp
						target.Host = host
						anytlsTCP(t, d, target)
					}
					udpMax := 8192
					if direction == "native-client" {
						udpMax = 16384
					}
					anytlsUDP(t, d, udp, 0, 1, 512, 4096, udpMax)
					// Sequential streams are actual application requests on the retained client.
					for i := 0; i < 5; i++ {
						anytlsTCP(t, d, tcp)
					}
					if direction == "native-client" {
						var wg sync.WaitGroup
						for i := 0; i < 10; i++ {
							wg.Add(1)
							go func() { defer wg.Done(); anytlsTCP(t, d, tcp) }()
						}
						wg.Wait()
					}
					if native, ok := d.(*anytlsDialer); ok {
						state := native.pool.State()
						if state.LastSequence != 1 {
							t.Fatal("session reuse", state)
						}
						t.Logf("native session state %+v", state)
					}
					if c, err := d.DialContext(context.Background(), access.Endpoint{Host: "127.0.0.1", Port: 1}); err == nil {
						c.SetDeadline(time.Now().Add(time.Second))
						_, err = c.Read(make([]byte, 1))
						c.Close()
						if err == nil {
							t.Fatal("destination failure missing")
						}
					}
					t.Logf("oracle=%s direction=%s variant=%s TCP payloads=1,93,65535,65536,131073,3145728 UDP=0,1,512,4096,%d exact=true logs=%s", oracle, direction, variant, udpMax, dir)
				})
			}
		}
	}
}
