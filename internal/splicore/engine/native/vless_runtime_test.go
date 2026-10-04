//go:build with_utls

package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/underlay"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	v "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
	"github.com/sagernet/sing-box/internal/splicore/testkit"
	"github.com/sagernet/sing-box/option"
	upstream "github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// Every endpoint is owned by this test and bound to loopback. Cleanup closes
// accepted sockets and joins all workers; no retry or timing workaround is used.
func vlessEcho(t *testing.T, tlsConfig *tls.Config) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig != nil {
		l = tls.NewListener(l, tlsConfig)
	}
	var access sync.Mutex
	connections := map[net.Conn]bool{}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			access.Lock()
			connections[c] = true
			workers.Add(1)
			access.Unlock()
			go func() {
				defer workers.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(15 * time.Second))
				_, _ = io.Copy(c, c)
				access.Lock()
				delete(connections, c)
				access.Unlock()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		access.Lock()
		for c := range connections {
			_ = c.Close()
		}
		access.Unlock()
		workers.Wait()
	})
	return l
}

func TestVLESSNonVisionDefaultRaceTraffic(t *testing.T) {
	for _, security := range []v.Security{v.Plain, v.TLS, v.Reality} {
		t.Run(string(security), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			id := func() identity.ID {
				value, err := identity.NewID()
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			stamp := identity.NewStamp(time.Now())
			sni := "target.synthetic.test"
			tlsMaterial := testkit.TLSForName(t, sni)
			certPEM, _ := os.ReadFile(tlsMaterial.CertificateFile)
			keyPEM, _ := os.ReadFile(tlsMaterial.PrivateKeyFile)
			certificate, err := tls.X509KeyPair(certPEM, keyPEM)
			clear(keyPEM)
			if err != nil {
				t.Fatal(err)
			}
			target := vlessEcho(t, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
			echo := vlessEcho(t, nil)
			reserve, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			endpoint := access.Endpoint{Host: "127.0.0.1", Port: uint16(reserve.Addr().(*net.TCPAddr).Port)}
			_ = reserve.Close()
			settings := v.Settings{Security: security, Flow: v.NoFlow, Transport: "tcp", PacketEncoding: "xudp"}
			private, public, err := v.GenerateServerKey()
			if err != nil {
				t.Fatal(err)
			}
			if security == v.TLS {
				settings.TLS = &tlsMaterial
			}
			if security == v.Reality {
				settings.Reality = &v.RealitySettings{PublicKey: public, ServerName: sni, ShortIDs: []v.ShortID{"abcd"},
					Target: access.Endpoint{Host: "127.0.0.1", Port: uint16(target.Addr().(*net.TCPAddr).Port)}}
			}
			data, _ := json.Marshal(settings)
			in := ports.RuntimeIntent{Inbound: access.Inbound{ID: id(), NodeID: id(), Name: "synthetic", Protocol: v.Key(security), Engine: "native", Enabled: true,
				Listeners: []access.Listener{{ID: id(), Transport: "tcp", Endpoint: endpoint}}, DisplayEndpoints: []access.DisplayEndpoint{{ID: id(), Endpoint: endpoint}},
				Settings: access.Settings{Schema: 1, Data: data}, Stamp: stamp}}
			if security == v.Reality {
				in.ServerCredentials = []access.Credential{{ID: id(), OwnerInboundID: &in.Inbound.ID, Kind: access.PrivateKey, Schema: 1, State: "active", Payload: private, Stamp: stamp}}
			}
			for range 2 {
				accountID, credentialID := id(), id()
				in.Credentials = append(in.Credentials, access.Credential{ID: credentialID, OwnerAccountID: &accountID, Kind: access.UUID, Schema: 1, State: "active", Payload: access.UUIDPayload{UUID: secret.New(string(id()))}, Stamp: stamp})
				in.Bindings = append(in.Bindings, access.Binding{ID: id(), AccountID: accountID, InboundID: in.Inbound.ID, CredentialID: credentialID, Enabled: true, Stamp: stamp})
			}
			prepared, err := (VLESSCompiler{}).Compile(underlay.WithFactory(ctx, underlay.New()), in)
			if err != nil {
				t.Fatal(err)
			}
			h := prepared.(*vlessHandle)
			defer func() {
				if err := h.Close(context.Background()); err != nil {
					t.Error(err)
				}
			}()
			if err := h.Start(ctx); err != nil {
				t.Fatal(err)
			}
			h.Activate()
			var tlsConfig boxtls.Config
			if security != v.Plain {
				options := option.OutboundTLSOptions{Enabled: true, ServerName: sni}
				if security == v.TLS {
					options.Certificate = []string{tlsMaterial.CACertificate}
				}
				if security == v.Reality {
					options.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}
					options.Reality = &option.OutboundRealityOptions{Enabled: true, PublicKey: string(public), ShortID: "abcd"}
				}
				tlsConfig, err = boxtls.NewClient(h.ctx, logger.NOP(), endpoint.Host, options)
				if err != nil {
					t.Fatal(err)
				}
			}
			dial := func(user int) (net.Conn, error) {
				raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(endpoint.Host, portString(endpoint.Port)))
				if err != nil {
					return nil, err
				}
				_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
				var c net.Conn = raw
				if tlsConfig != nil {
					c, err = boxtls.ClientHandshake(ctx, raw, tlsConfig)
					if err != nil {
						_ = raw.Close()
						return nil, err
					}
				}
				client, err := upstream.NewClient(in.Credentials[user].Payload.(access.UUIDPayload).UUID.Reveal(), "", logger.NOP())
				if err == nil {
					c, err = client.DialConn(c, M.SocksaddrFromNet(echo.Addr()))
				}
				if err != nil {
					_ = raw.Close()
					return nil, err
				}
				return c, nil
			}
			transfer := func(user, size int) error {
				c, err := dial(user)
				if err != nil {
					return err
				}
				defer c.Close()
				payload := bytes.Repeat([]byte{byte(user + 1), 7, 29, 113}, 8192)
				for remaining := size; remaining > 0; {
					chunk := payload
					if remaining < len(chunk) {
						chunk = chunk[:remaining]
					}
					if _, err := c.Write(chunk); err != nil {
						return err
					}
					received := make([]byte, len(chunk))
					if _, err := io.ReadFull(c, received); err != nil {
						return err
					}
					if !bytes.Equal(chunk, received) {
						return io.ErrUnexpectedEOF
					}
					remaining -= len(chunk)
				}
				return nil
			}
			t.Run("single-user", func(t *testing.T) {
				if err := transfer(0, 65536); err != nil {
					t.Fatal(err)
				}
			})
			t.Run("dual-user-16-concurrent", func(t *testing.T) {
				start := make(chan struct{})
				errors := make(chan error, 16)
				for n := range 16 {
					go func() { <-start; errors <- transfer(n%2, 65536) }()
				}
				close(start)
				for range 16 {
					if err := <-errors; err != nil {
						t.Error(err)
					}
				}
			})
			t.Run("4-MiB", func(t *testing.T) {
				for user := range 2 {
					if err := transfer(user, 4<<20); err != nil {
						t.Fatal(err)
					}
				}
			})
			t.Run("reconnect", func(t *testing.T) {
				for range 3 {
					if err := transfer(0, 65536); err != nil {
						t.Fatal(err)
					}
				}
			})
			t.Run("abnormal-close", func(t *testing.T) {
				c, err := dial(0)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = c.Write([]byte("synthetic-abnormal-close"))
				_ = c.Close()
				if err := transfer(1, 65536); err != nil {
					t.Fatal(err)
				}
				if err := h.Health(ctx); err != nil {
					t.Fatal(err)
				}
			})
			for _, b := range in.Bindings {
				stats := h.BindingStats(b.ID)
				if stats.Upload < 4<<20 || stats.Download < 4<<20 || stats.Sessions == 0 {
					t.Fatal("authenticated binding attribution missing")
				}
			}
		})
	}
}
