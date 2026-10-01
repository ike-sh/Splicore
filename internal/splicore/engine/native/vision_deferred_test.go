package native

import (
	"context"
	"errors"
	"github.com/gofrs/uuid/v5"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-vmess"
	upstream "github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestVisionCompilerHardGateBeforeMaterialOrConstruction(t *testing.T) {
	for _, security := range []string{"none", "tls", "reality"} {
		in := ports.RuntimeIntent{Inbound: access.Inbound{Engine: "native", Settings: access.Settings{Schema: 1,
			Data: []byte(`{"security":"` + security + `","flow":"xtls-rprx-vision","transport":"tcp","packet_encoding":"xudp"}`)}}}
		prepared, err := (VLESSCompiler{}).Compile(context.Background(), in)
		var typed *identity.Error
		if prepared != nil || !errors.As(err, &typed) || typed.Code != identity.NotImplemented {
			t.Fatalf("hard gate failed for %s", security)
		}
	}
}

type rejectedVisionHandler struct{ calls atomic.Int64 }

func (h *rejectedVisionHandler) NewConnectionEx(context.Context, net.Conn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
	h.calls.Add(1)
}
func (h *rejectedVisionHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
	h.calls.Add(1)
}

func TestVisionWireRequestCannotReachConstructor(t *testing.T) {
	user, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	handler := &rejectedVisionHandler{}
	service := upstream.NewService[string](logger.NOP(), handler)
	service.UpdateUsers([]string{"Alice"}, []string{string(user)}, []string{""})
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() { done <- service.NewConnection(context.Background(), server, M.Socksaddr{}, nil) }()
	// Write only the existing request header. NewConn does not create VisionConn.
	credential, _ := uuid.FromString(string(user))
	conn := upstream.NewConn(client, credential, vmess.CommandTCP, M.ParseSocksaddr("127.0.0.1:12345"), upstream.FlowVision)
	if _, err := conn.Write(nil); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "flow mismatch") || handler.calls.Load() != 0 {
		t.Fatal("Vision request reached runtime")
	}
}
