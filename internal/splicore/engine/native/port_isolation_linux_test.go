//go:build with_quic && with_utls

package native

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/shadowquic"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func TestCrossProtocolListenerSocketOwnership(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			ctx := underlay.WithFactory(context.Background(), underlay.New())
			tcp, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			address := tcp.Addr().String()
			udp, err := net.ListenPacket("udp", address)
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			endpoint := access.Endpoint{Host: host, Port: uint16(tcp.Addr().(*net.TCPAddr).Port)}
			in := testfixture.MieruIntentAt(t, "udp", endpoint)
			in.Inbound.Protocol = module.Key()
			in.Inbound.Settings.Data, _ = json.Marshal(module.Settings{ServerName: sqName, Camouflage: access.Endpoint{Host: "127.0.0.1", Port: 9}})
			in.Credentials[0].Payload = access.UsernamePasswordPayload{Username: secret.New(sqUser), Password: secret.New(sqPass)}
			prepared, err := (ShadowQUICCompiler{}).Compile(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			quic := prepared.(*shadowQUICHandle)
			defer quic.Close(ctx)
			_ = udp.Close()
			if err := quic.Start(ctx); err != nil {
				t.Fatal(err)
			}
			quic.Activate()
			api := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "listener-health") }))
			_ = api.Listener.Close()
			api.Listener = tcp
			api.Start()
			defer api.Close()
			checkHTTP := func() {
				t.Helper()
				response, err := api.Client().Get(api.URL)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || string(body) != "listener-health" {
					t.Fatal("unrelated HTTP listener disturbed", err)
				}
			}
			checkHTTP()
			v4 := listenerSnell(t, ctx, endpoint, 4)
			v5 := listenerSnell(t, ctx, endpoint, 5)
			for _, h := range []*Handle{v4, v5} {
				var domain *identity.Error
				if err := h.Start(ctx); !errors.As(err, &domain) || domain.Code != identity.PortConflict {
					t.Fatal("TCP owner was ignored", err)
				}
			}
			checkHTTP()
			api.Close()
			if err := v4.Start(ctx); err != nil {
				t.Fatal("Snell v4 TCP cannot coexist with ShadowQUIC UDP", err)
			}
			if err := quic.Health(ctx); err != nil {
				t.Fatal("TCP start disturbed distinct UDP owner", err)
			}
			_ = v4.Close(ctx)
			var domain *identity.Error
			var op *net.OpError
			err = v5.Start(ctx)
			if !errors.As(err, &domain) || domain.Code != identity.PortConflict || !errors.As(err, &op) || op.Net != "udp" {
				t.Fatal("UDP owner ignored or confused with released TCP owner", err)
			}
			ssIn := shadowsocksIntentFrom(t, "2022-blake3-aes-128-gcm", false, testfixture.MieruIntentAt(t, "tcp", endpoint))
			ssPrepared, err := NewShadowsocksCompiler().Compile(ctx, ssIn)
			if err != nil {
				t.Fatal(err)
			}
			ss := ssPrepared.(*shadowsocksHandle)
			defer ss.Close(ctx)
			if err := ss.Start(ctx); !errors.As(err, &domain) || domain.Code != identity.PortConflict {
				t.Fatal("Shadowsocks UDP ignored existing ShadowQUIC owner", err)
			}
			probe, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatal("failed dual-listener attempt retained TCP", err)
			}
			_ = probe.Close()
			if err := quic.Health(ctx); err != nil {
				t.Fatal("failed sibling disturbed original UDP runtime", err)
			}
			_ = quic.Close(ctx)
			if err := v5.Start(ctx); err != nil {
				t.Fatal("released exact UDP object still excludes Snell", err)
			}
			_ = v5.Close(ctx)
			if err := ss.Start(ctx); err != nil {
				t.Fatal("released Snell objects still exclude Shadowsocks", err)
			}
			if err := ss.Health(ctx); err != nil {
				t.Fatal(err)
			}
			t.Logf("address=%s http_tcp+shadowquic_udp=PASS snell_v4_tcp+shadowquic_udp=PASS udp_conflict=typed partial_tcp_rollback=PASS object_release_and_explicit_recovery=PASS", fmt.Sprint(endpoint))
		})
	}
}
