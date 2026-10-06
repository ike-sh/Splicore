package native

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	sm "github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/snell/wire"
)

func ownedSnell(t *testing.T, version int) (context.Context, ports.RuntimeIntent, ports.RuntimeHandle) {
	t.Helper()
	in := testfixture.MieruIntent(t, "tcp")
	in.Inbound.Protocol = sm.Key(version)
	in.Inbound.Settings.Data = []byte(fmt.Sprintf(`{"version":%d}`, version))
	in.Bindings = in.Bindings[:1]
	in.Credentials = in.Credentials[:1]
	in.Credentials[0].Kind = access.PSK
	in.Credentials[0].Payload = access.PSKPayload{Key: secret.New("SyntheticNativeSnell12345")}
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	p, err := (SnellCompiler{}).Compile(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	h := p.(ports.RuntimeHandle)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	if err := h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	h.Activate()
	return ctx, in, h
}

// Command 1 is emitted by the independent Mihomo peer. The managed client uses
// reusable command 5, so self-interop alone cannot protect this server path.
func TestSnellCommandOnePayloadAndEOF(t *testing.T) {
	for _, version := range []int{5, 6} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			_, in, h := ownedSnell(t, version)
			target := testfixture.TCP(t)
			dst := access.Endpoint{Host: "127.0.0.1", Port: uint16(target.Addr().(*net.TCPAddr).Port)}
			endpoint := in.Inbound.Listeners[0].Endpoint
			raw, err := net.Dial("tcp", net.JoinHostPort(endpoint.Host, fmt.Sprint(endpoint.Port)))
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
			clientVersion, _ := sm.ClientVersion(version)
			key, _ := wire.NewKey(clientVersion, "SyntheticNativeSnell12345")
			writer, reader := wire.NewEncoder(raw, key), wire.NewDecoder(raw, key)
			request, _ := wire.EncodeRequest(wire.Request{Command: 1, Destination: dst})
			payload := bytes.Repeat([]byte("synthetic command one\x00"), 2048)
			if _, err := writer.Write(append(request, payload...)); err != nil {
				t.Fatal(err)
			}
			if err := writer.Record(nil); err != nil {
				t.Fatal(err)
			}
			var got []byte
			for first := true; ; first = false {
				p, err := reader.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if first {
					if len(p) == 0 || p[0] != 0 {
						t.Fatal("missing success reply")
					}
					p = p[1:]
				}
				got = append(got, p...)
			}
			if !bytes.Equal(payload, got) {
				t.Fatal("command 1 payload truncated")
			}
			if err := h.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if s := h.Stats(); s.Active != 0 || s.Upload != int64(len(payload)) || s.Download != int64(len(payload)) {
				t.Fatalf("unjoined payload accounting: %+v", s)
			}
		})
	}
}

func TestSnellManagedHalfCloseAndAdapterShutdown(t *testing.T) {
	for _, version := range []int{5, 6} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			ctx, in, _ := ownedSnell(t, version)
			target := testfixture.TCP(t)
			dst := access.Endpoint{Host: "127.0.0.1", Port: uint16(target.Addr().(*net.TCPAddr).Port)}
			nid, _ := identity.NewID()
			cred := in.Credentials[0]
			cred.OwnerAccountID = nil
			cred.OwnerNodeID = &nid
			n := client.RemoteNode{ID: nid, Name: "synthetic", Protocol: sm.Key(version), Endpoint: in.Inbound.Listeners[0].Endpoint, CredentialID: cred.ID, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: in.Inbound.Settings.Data}}
			d, err := (SnellOutboundFactory{}).Build(ctx, n, cred)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			c, err := d.DialContext(ctx, dst)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte("joined half close\x00"), 8192)
			written := make(chan error, 1)
			go func() {
				_, err := c.Write(payload)
				if err == nil {
					err = c.(interface{ CloseWrite() error }).CloseWrite()
				}
				written <- err
			}()
			got, err := io.ReadAll(c)
			if err != nil {
				t.Fatal(err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("response after upload EOF truncated")
			}
			blocked, err := d.DialContext(ctx, dst)
			if err != nil {
				t.Fatal(err)
			}
			readDone := make(chan error, 1)
			go func() { _, err := blocked.Read(make([]byte, 1)); readDone <- err }()
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-readDone:
				if err == nil {
					t.Fatal("shutdown retained blocked read")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("adapter shutdown did not unblock read")
			}
			if _, err := d.DialContext(ctx, dst); err == nil {
				t.Fatal("closed adapter opened socket")
			}
		})
	}
}
