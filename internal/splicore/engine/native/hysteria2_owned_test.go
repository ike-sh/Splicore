package native

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	hm "github.com/ike-sh/Splicore/internal/splicore/protocol/hysteria2"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func ownedHysteria2(t *testing.T) (context.Context, ports.RuntimeIntent, ports.RuntimeHandle, []ports.ClientDialer) {
	t.Helper()
	in := testfixture.MieruIntentAt(t, "udp", access.Endpoint{Host: "127.0.0.1", Port: 1})
	settings := hm.Settings{TLS: testkit.TLS(t)}
	in.Inbound.Protocol = hm.Key()
	in.Inbound.Settings.Data, _ = json.Marshal(settings)
	for i := range in.Credentials {
		p := in.Credentials[i].Payload.(access.UsernamePasswordPayload)
		in.Credentials[i].Payload = access.PasswordPayload{Password: p.Password}
		in.Credentials[i].Kind = access.Password
	}
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	p, err := (Hysteria2Compiler{}).Compile(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	h := p.(ports.RuntimeHandle)
	h.(*hysteria2Handle).endpoint.Port = 0
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
	in.Inbound.Listeners[0].Endpoint = netaddrEndpoint(h.(*hysteria2Handle).server.Addr())
	var dialers []ports.ClientDialer
	for _, cred := range in.Credentials {
		nid, _ := identity.NewID()
		cred.OwnerAccountID = nil
		cred.OwnerNodeID = &nid
		n := client.RemoteNode{ID: nid, Name: "synthetic-hy2", Protocol: hm.Key(), Endpoint: in.Inbound.Listeners[0].Endpoint, CredentialID: cred.ID, Transport: client.Transport{Kind: "quic"}, Security: client.Security{Kind: "tls", TLS: access.ClientTLS{Enabled: true, Trust: "explicit_ca", ServerName: settings.TLS.ServerName, CACertificate: settings.TLS.CACertificate, ALPN: []string{"h3"}}}, Options: client.Options{Schema: 1, Data: []byte(`{}`)}}
		n.Endpoint.Host = "localhost"
		d, err := (Hysteria2OutboundFactory{}).Build(ctx, n, cred)
		if err != nil {
			t.Fatal(err)
		}
		dialers = append(dialers, d)
		t.Cleanup(func() { _ = d.Close() })
	}
	return ctx, in, h, dialers
}

type hysteria2ParallelFixture struct {
	ctx           context.Context
	cancel        context.CancelFunc
	start         chan struct{}
	udpFinished   chan struct{}
	udpDone       chan struct{}
	collectorDone chan struct{}
	stop          func() error
	workers       sync.WaitGroup
	mu            sync.Mutex
	sealed        bool
	started       bool
	closed        bool
	closeOnce     sync.Once
	closeDone     chan struct{}
	closeErr      error
}

func newHysteria2ParallelFixture(parent context.Context, udpWorkers int, stop func() error) *hysteria2ParallelFixture {
	ctx, cancel := context.WithCancel(parent)
	f := &hysteria2ParallelFixture{
		ctx:           ctx,
		cancel:        cancel,
		start:         make(chan struct{}),
		udpFinished:   make(chan struct{}, udpWorkers),
		udpDone:       make(chan struct{}),
		collectorDone: make(chan struct{}),
		stop:          stop,
		closeDone:     make(chan struct{}),
	}
	go func() {
		defer close(f.collectorDone)
		for range udpWorkers {
			select {
			case <-f.ctx.Done():
				return
			case <-f.udpFinished:
			}
		}
		close(f.udpDone)
	}()
	return f
}

func (f *hysteria2ParallelFixture) Go(worker func(context.Context)) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sealed || f.closed {
		return false
	}
	f.workers.Add(1)
	go func() {
		defer f.workers.Done()
		worker(f.ctx)
	}()
	return true
}

func (f *hysteria2ParallelFixture) Start() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.started || f.closed {
		return false
	}
	f.sealed = true
	f.started = true
	close(f.start)
	return true
}

func (f *hysteria2ParallelFixture) WaitStart() bool {
	if f.ctx.Err() != nil {
		return false
	}
	select {
	case <-f.ctx.Done():
		return false
	case <-f.start:
		return f.ctx.Err() == nil
	}
}

func (f *hysteria2ParallelFixture) UDPFinished() {
	select {
	case f.udpFinished <- struct{}{}:
	case <-f.ctx.Done():
	}
}

func (f *hysteria2ParallelFixture) WaitUDP() bool {
	select {
	case <-f.ctx.Done():
		return false
	case <-f.udpDone:
		return f.ctx.Err() == nil
	}
}

func (f *hysteria2ParallelFixture) Wait() {
	f.mu.Lock()
	f.sealed = true
	f.mu.Unlock()
	f.workers.Wait()
}

func (f *hysteria2ParallelFixture) Close() error {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		f.sealed = true
		f.closed = true
		f.mu.Unlock()
		f.cancel()
		if f.stop != nil {
			f.closeErr = f.stop()
		}
		f.workers.Wait()
		<-f.collectorDone
		close(f.closeDone)
	})
	<-f.closeDone
	return f.closeErr
}

func TestOwnedHysteria2ParallelAuthAttributionAndDomainTargets(t *testing.T) {
	ctx, in, h, ds := ownedHysteria2(t)
	l := testfixture.TCP(t)
	dst := access.Endpoint{Host: "localhost", Port: uint16(l.Addr().(*net.TCPAddr).Port)}
	udst := localhostUDP(t)
	ready := make(chan struct{}, len(ds)*10)
	fixture := newHysteria2ParallelFixture(ctx, len(ds)*2, func() error {
		for _, d := range ds {
			_ = d.Close()
		}
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return h.Close(stopCtx)
	})
	defer func() { _ = fixture.Close() }()
	for user, d := range ds {
		for flow := range 8 {
			if !fixture.Go(func(flowCtx context.Context) {
				c, e := d.DialContext(flowCtx, dst)
				if e != nil {
					if flowCtx.Err() == nil {
						t.Error(e)
						ready <- struct{}{}
					}
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(15 * time.Second))
				ready <- struct{}{}
				if !fixture.WaitStart() {
					return
				}
				want := bytes.Repeat([]byte{byte(user), byte(flow), 0, 73}, 32768)
				written := make(chan error, 1)
				go func() {
					_, e := c.Write(want)
					if e == nil {
						e = c.(interface{ CloseWrite() error }).CloseWrite()
					}
					written <- e
				}()
				got, e := io.ReadAll(c)
				if e != nil || !bytes.Equal(got, want) {
					t.Error("parallel user payload", user, flow, e)
				}
				if e = <-written; e != nil {
					t.Error(e)
				}
				_ = fixture.WaitUDP()
			}) {
				t.Fatal("parallel fixture sealed before TCP worker admission")
			}
		}
		for flow := range 2 {
			if !fixture.Go(func(flowCtx context.Context) {
				defer fixture.UDPFinished()
				p, e := d.(ports.ClientPacketDialer).ListenPacket(flowCtx, udst)
				if e != nil {
					if flowCtx.Err() == nil {
						t.Error(e)
						ready <- struct{}{}
					}
					return
				}
				defer p.Close()
				p.SetDeadline(time.Now().Add(15 * time.Second))
				ready <- struct{}{}
				if !fixture.WaitStart() {
					return
				}
				want := bytes.Repeat([]byte{byte(user), byte(flow), 71, 0}, 1024)
				if _, e = p.WriteTo(want, nil); e != nil {
					t.Error(e)
					return
				}
				b := make([]byte, 4096)
				n, _, e := p.ReadFrom(b)
				if e != nil || !bytes.Equal(b[:n], want) {
					t.Error("parallel user UDP", user, flow, e)
				}
			}) {
				t.Fatal("parallel fixture sealed before UDP worker admission")
			}
		}
	}
	for range len(ds) * 10 {
		select {
		case <-ready:
		case <-time.After(10 * time.Second):
			t.Fatal("parallel admission stalled")
		}
	}
	states := h.(*hysteria2Handle).server.Congestion()
	if len(states) != len(ds) {
		t.Fatal("cross-sharing or duplicate pool", states)
	}
	ids := map[string]bool{}
	for _, s := range states {
		ids[s.Identity] = true
	}
	for _, b := range in.Bindings {
		if !ids[string(b.ID)] {
			t.Fatal("credential bleed", states)
		}
	}
	if !fixture.Start() {
		t.Fatal("parallel fixture start rejected")
	}
	fixture.Wait()
	if e := fixture.Close(); e != nil {
		t.Fatal(e)
	}
	for _, b := range in.Bindings {
		s := h.(ports.AttributedStats).BindingStats(b.ID)
		want := int64(8*131072 + 2*4096)
		if s.Upload != want || s.Download != want {
			t.Fatal("exact parallel attribution", s, want)
		}
	}
	if h.Stats().Active != 0 {
		t.Fatal("parallel resource baseline")
	}
}
func TestOwnedHysteria2HalfCloseAndIndependentCancellation(t *testing.T) {
	ctx, in, h, dialers := ownedHysteria2(t)
	l := testfixture.TCP(t)
	dst := access.Endpoint{Host: "127.0.0.1", Port: uint16(l.Addr().(*net.TCPAddr).Port)}
	for index, d := range dialers {
		c, err := d.DialContext(ctx, dst)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if extra, err := d.DialContext(canceled, dst); err == nil {
			_ = extra.Close()
			t.Fatal("canceled flow accepted")
		}
		payload := bytes.Repeat([]byte(fmt.Sprint(index)+"-synthetic-hy2\x00"), 32768)
		done := make(chan error, 1)
		go func() {
			_, err := c.Write(payload)
			if err == nil {
				err = c.(interface{ CloseWrite() error }).CloseWrite()
			}
			done <- err
		}()
		got, err := io.ReadAll(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
		if !bytes.Equal(payload, got) {
			t.Fatal("response after upload EOF truncated")
		}
		stats := h.(ports.AttributedStats).BindingStats(in.Bindings[index].ID)
		if stats.Upload != int64(len(payload)) || stats.Download != int64(len(payload)) {
			t.Fatalf("user attribution: %+v", stats)
		}
	}
	if err := h.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if h.Stats().Active != 0 {
		t.Fatal("shutdown did not join workers")
	}
}
func TestOwnedHysteria2DatagramsAndShutdown(t *testing.T) {
	ctx, _, h, dialers := ownedHysteria2(t)
	target, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 4096)
		for {
			n, a, err := target.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = target.WriteTo(b[:n], a)
		}
	}()
	t.Cleanup(func() { _ = target.Close(); <-done })
	dst := access.Endpoint{Host: "127.0.0.1", Port: uint16(target.LocalAddr().(*net.UDPAddr).Port)}
	for _, d := range dialers {
		p, err := d.(ports.ClientPacketDialer).ListenPacket(ctx, dst)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		for _, size := range []int{1, 900, 4096, 2048, 4096} {
			_ = p.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte{byte(size), 17}, (size+1)/2)[:size]
			if _, err := p.WriteTo(payload, nil); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 4096)
			n, _, err := p.ReadFrom(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buffer[:n], payload) {
				t.Fatal("fragmented UDP integrity")
			}
		}
	}
	if err := h.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if h.Stats().Active != 0 {
		t.Fatal("UDP session retained after shutdown")
	}
}

func waitHysteria2FixtureSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal("parallel fixture signal timeout", name)
	}
}

func requireHysteria2FixtureClosed(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	default:
		t.Fatal("parallel fixture did not join", name)
	}
}

func TestHysteria2ParallelFixtureAbortCleanup(t *testing.T) {
	t.Run("partial ready with admission pending", func(t *testing.T) {
		var exchanges, resources, stops atomic.Int32
		f := newHysteria2ParallelFixture(context.Background(), 1, func() error {
			stops.Add(1)
			return nil
		})
		defer func() { _ = f.Close() }()
		ready := make(chan struct{})
		admissionEntered := make(chan struct{})
		if !f.Go(func(context.Context) {
			defer resources.Add(1)
			close(ready)
			if f.WaitStart() {
				exchanges.Add(1)
			}
		}) || !f.Go(func(ctx context.Context) {
			close(admissionEntered)
			<-ctx.Done()
		}) {
			t.Fatal("fixture rejected pre-start worker")
		}
		waitHysteria2FixtureSignal(t, ready, "ready worker")
		waitHysteria2FixtureSignal(t, admissionEntered, "pending admission")
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if exchanges.Load() != 0 || resources.Load() != 1 || stops.Load() != 1 {
			t.Fatal("partial-ready abort state", exchanges.Load(), resources.Load(), stops.Load())
		}
		requireHysteria2FixtureClosed(t, f.collectorDone, "collector")
		requireHysteria2FixtureClosed(t, f.closeDone, "cleanup")
	})

	t.Run("all ready before start", func(t *testing.T) {
		var exchanges, resources atomic.Int32
		f := newHysteria2ParallelFixture(context.Background(), 1, nil)
		defer func() { _ = f.Close() }()
		ready := make(chan struct{}, 2)
		if !f.Go(func(context.Context) {
			defer resources.Add(1)
			ready <- struct{}{}
			if f.WaitStart() {
				exchanges.Add(1)
			}
		}) || !f.Go(func(context.Context) {
			defer resources.Add(1)
			defer f.UDPFinished()
			ready <- struct{}{}
			if f.WaitStart() {
				exchanges.Add(1)
			}
		}) {
			t.Fatal("fixture rejected ready worker")
		}
		<-ready
		<-ready
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if exchanges.Load() != 0 || resources.Load() != 2 || f.started {
			t.Fatal("all-ready abort started exchange", exchanges.Load(), resources.Load(), f.started)
		}
		requireHysteria2FixtureClosed(t, f.collectorDone, "collector")
	})

	t.Run("admission failure", func(t *testing.T) {
		var exchanges, resources atomic.Int32
		f := newHysteria2ParallelFixture(context.Background(), 1, nil)
		defer func() { _ = f.Close() }()
		ready := make(chan struct{}, 2)
		if !f.Go(func(context.Context) {
			defer resources.Add(1)
			ready <- struct{}{}
			if f.WaitStart() {
				exchanges.Add(1)
			}
		}) || !f.Go(func(context.Context) {
			defer f.UDPFinished()
			ready <- struct{}{}
		}) {
			t.Fatal("fixture rejected admission-failure worker")
		}
		<-ready
		<-ready
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if exchanges.Load() != 0 || resources.Load() != 1 {
			t.Fatal("admission-failure cleanup state", exchanges.Load(), resources.Load())
		}
		requireHysteria2FixtureClosed(t, f.collectorDone, "collector")
	})

	for _, check := range []string{"pool mismatch", "identity mismatch"} {
		t.Run(check, func(t *testing.T) {
			var exchanges, resources atomic.Int32
			f := newHysteria2ParallelFixture(context.Background(), 1, nil)
			defer func() { _ = f.Close() }()
			ready := make(chan struct{}, 2)
			for range 2 {
				if !f.Go(func(context.Context) {
					defer resources.Add(1)
					ready <- struct{}{}
					if f.WaitStart() {
						exchanges.Add(1)
					}
				}) {
					t.Fatal("fixture rejected validation worker")
				}
			}
			<-ready
			<-ready
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			if exchanges.Load() != 0 || resources.Load() != 2 || f.started {
				t.Fatal(check, exchanges.Load(), resources.Load(), f.started)
			}
			requireHysteria2FixtureClosed(t, f.collectorDone, "collector")
		})
	}

	t.Run("UDP incomplete abort", func(t *testing.T) {
		var exchanges, resources, afterUDP atomic.Int32
		f := newHysteria2ParallelFixture(context.Background(), 2, nil)
		defer func() { _ = f.Close() }()
		ready := make(chan struct{}, 3)
		firstFinished := make(chan struct{})
		secondBlocked := make(chan struct{})
		tcpWaiting := make(chan struct{})
		if !f.Go(func(context.Context) {
			defer resources.Add(1)
			ready <- struct{}{}
			if !f.WaitStart() {
				return
			}
			exchanges.Add(1)
			f.UDPFinished()
			close(firstFinished)
		}) || !f.Go(func(ctx context.Context) {
			defer resources.Add(1)
			ready <- struct{}{}
			if !f.WaitStart() {
				return
			}
			exchanges.Add(1)
			close(secondBlocked)
			<-ctx.Done()
		}) || !f.Go(func(context.Context) {
			defer resources.Add(1)
			ready <- struct{}{}
			if !f.WaitStart() {
				return
			}
			exchanges.Add(1)
			close(tcpWaiting)
			if f.WaitUDP() {
				afterUDP.Add(1)
			}
		}) {
			t.Fatal("fixture rejected incomplete-UDP worker")
		}
		<-ready
		<-ready
		<-ready
		if !f.Start() {
			t.Fatal("fixture rejected normal start")
		}
		waitHysteria2FixtureSignal(t, firstFinished, "first UDP completion")
		waitHysteria2FixtureSignal(t, secondBlocked, "second UDP blocked")
		waitHysteria2FixtureSignal(t, tcpWaiting, "TCP UDP wait")
		beforeAbort := exchanges.Load()
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if beforeAbort != 3 || exchanges.Load() != beforeAbort || afterUDP.Load() != 0 || resources.Load() != 3 {
			t.Fatal("incomplete-UDP abort state", beforeAbort, exchanges.Load(), afterUDP.Load(), resources.Load())
		}
		requireHysteria2FixtureClosed(t, f.collectorDone, "collector")
	})

	t.Run("normal success", func(t *testing.T) {
		var exchanges, resources, udpFinished, afterUDP, badOrder atomic.Int32
		f := newHysteria2ParallelFixture(context.Background(), 2, nil)
		defer func() { _ = f.Close() }()
		ready := make(chan struct{}, 3)
		for range 2 {
			if !f.Go(func(context.Context) {
				defer resources.Add(1)
				ready <- struct{}{}
				if !f.WaitStart() {
					return
				}
				exchanges.Add(1)
				udpFinished.Add(1)
				f.UDPFinished()
			}) {
				t.Fatal("fixture rejected UDP worker")
			}
		}
		if !f.Go(func(context.Context) {
			defer resources.Add(1)
			ready <- struct{}{}
			if !f.WaitStart() {
				return
			}
			exchanges.Add(1)
			if f.WaitUDP() {
				if udpFinished.Load() != 2 {
					badOrder.Add(1)
				}
				afterUDP.Add(1)
			}
		}) {
			t.Fatal("fixture rejected TCP worker")
		}
		<-ready
		<-ready
		<-ready
		if !f.Start() {
			t.Fatal("fixture rejected normal start")
		}
		workersDone := make(chan struct{})
		go func() {
			f.Wait()
			close(workersDone)
		}()
		waitHysteria2FixtureSignal(t, workersDone, "normal workers")
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if exchanges.Load() != 3 || udpFinished.Load() != 2 || afterUDP.Load() != 1 || badOrder.Load() != 0 || resources.Load() != 3 {
			t.Fatal("normal coordination state", exchanges.Load(), udpFinished.Load(), afterUDP.Load(), badOrder.Load(), resources.Load())
		}
		requireHysteria2FixtureClosed(t, f.collectorDone, "collector")
	})

	t.Run("repeated cleanup", func(t *testing.T) {
		var resources, stops atomic.Int32
		f := newHysteria2ParallelFixture(context.Background(), 1, func() error {
			stops.Add(1)
			return nil
		})
		ready := make(chan struct{})
		if !f.Go(func(context.Context) {
			defer resources.Add(1)
			close(ready)
			_ = f.WaitStart()
		}) {
			t.Fatal("fixture rejected repeated-cleanup worker")
		}
		waitHysteria2FixtureSignal(t, ready, "cleanup worker")
		callers := make(chan error, 2)
		go func() { callers <- f.Close() }()
		go func() { callers <- f.Close() }()
		if err := <-callers; err != nil {
			t.Fatal(err)
		}
		if err := <-callers; err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if stops.Load() != 1 || resources.Load() != 1 || f.Start() || f.Go(func(context.Context) {}) {
			t.Fatal("repeated cleanup state", stops.Load(), resources.Load())
		}
		requireHysteria2FixtureClosed(t, f.collectorDone, "collector")
		requireHysteria2FixtureClosed(t, f.closeDone, "cleanup")
	})
}
