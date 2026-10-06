package native

import (
	"context"
	"errors"
	"github.com/gofrs/uuid/v5"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/protocol/vless/wire"
)

func TestVisionCompilerHardGateBeforeMaterialOrConstruction(t *testing.T) {
	for _, security := range []string{"none", "tls", "reality"} {
		in := ports.RuntimeIntent{Inbound: access.Inbound{Engine: "native", Settings: access.Settings{Schema: 1,
			Data: []byte(`{"security":"` + security + `","flow":"xtls-rprx-vision","transport":"tcp","packet_encoding":"xudp"}`)}}}
		prepared, err := (VLESSCompiler{}).Compile(underlay.WithFactory(context.Background(), underlay.New()), in)
		var typed *identity.Error
		if prepared != nil || !errors.As(err, &typed) || typed.Code != identity.NotImplemented {
			t.Fatalf("hard gate failed for %s", security)
		}
	}
}

func TestVisionWireRequestCannotReachConstructor(t *testing.T) {
	user, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	var constructors atomic.Int64
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() {
		_, err := wire.ReadRequest(server)
		if err == nil {
			constructors.Add(1)
		}
		done <- err
	}()
	// An actual protobuf flow addon is rejected before any runtime constructor.
	credential, _ := uuid.FromString(string(user))
	addon := append([]byte{0x0a, byte(len("xtls-rprx-vision"))}, "xtls-rprx-vision"...)
	header := append([]byte{0}, credential[:]...)
	header = append(header, byte(len(addon)))
	header = append(header, addon...)
	if err := wire.Write(client, header); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, wire.ErrFlow) || constructors.Load() != 0 {
		t.Fatal("Vision request reached runtime")
	}
}
