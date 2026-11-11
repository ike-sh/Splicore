//go:build linux && with_gvisor

package wireguardendpoint

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestPhase36ConcurrentOperations(t *testing.T) {
	requireFastpath(t)
	a, b := fastPair(t, E.Kernel, E.Kernel, false, "127.0.0.1")
	var work sync.WaitGroup
	ready := make(chan struct{})
	for range 16 {
		work.Go(func() {
			<-ready
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			c, err := a.DialContext(ctx, access.Endpoint{Host: "10.36.0.2", Port: 12345})
			if err == nil {
				_ = c.Close()
			}
			p, err := a.ListenPacket(ctx, access.Endpoint{Host: "fd36::2", Port: 12345})
			if err == nil {
				_ = p.Close()
			}
			_ = a.Status()
		})
	}
	close(ready)
	closedStatus(t, a)
	closedStatus(t, b)
	work.Wait()
	for range 4 {
		c := fastConfig(t)
		e, err := New(context.Background(), c, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
		if err != nil {
			t.Fatal(err)
		}
		started := make(chan error, 1)
		go func() { started <- e.Start(context.Background()) }()
		closedStatus(t, e)
		<-started
	}
}

type rollbackErrorBackend struct{ WireGuardBackend }

func (b rollbackErrorBackend) Close() error {
	return errors.Join(b.WireGuardBackend.Close(), &BackendError{Class: CleanupFailure, Operation: "injected rollback failure"})
}

func TestPhase36TransactionalAuto(t *testing.T) {
	requireFastpath(t)
	for _, mode := range []string{"available-error", "runtime-error", "cleanup-error", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			c := fastConfig(t)
			c.Backend = E.Auto
			e, err := New(context.Background(), c, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var k *kernelBackend
			e.kernelFactory = func(e *Endpoint, c E.WireGuard) (WireGuardBackend, error) {
				raw, err := newKernelBackend(e, c)
				if err != nil {
					return nil, err
				}
				k = raw.(*kernelBackend)
				k.fault = func(step string) error {
					if step != "listener" {
						return nil
					}
					if mode == "canceled" {
						cancel()
						return ctx.Err()
					}
					if mode == "runtime-error" {
						return &BackendError{Class: RuntimeFailure, Operation: "injected invariant"}
					}
					return &BackendError{Class: InsufficientPrivilege, Operation: "injected restricted listener", Cause: unix.EPERM}
				}
				if mode == "cleanup-error" {
					return rollbackErrorBackend{raw}, nil
				}
				return raw, nil
			}
			err = e.Start(ctx)
			if mode == "available-error" {
				if err != nil || e.Status().Selected != E.Userspace {
					t.Fatalf("fallback failed: %v", err)
				}
			} else if err == nil || e.Status().Selected == E.Userspace {
				t.Fatalf("unsafe fallback %s", mode)
			}
			if k.ns != -1 {
				t.Fatal("fallback before namespace cleanup")
			}
			if _, err := netlink.LinkByName(k.name); err == nil {
				t.Fatal("stale interface")
			}
			closeErr := e.Close()
			if mode != "cleanup-error" && closeErr != nil {
				t.Fatal(closeErr)
			}
		})
	}
}

func TestPhase36ProcessDeath(t *testing.T) {
	requireFastpath(t)
	if os.Getenv("SPLICORE_PHASE36_CRASH_CHILD") == "1" {
		e := fastEndpoint(t, fastConfig(t), Options{})
		meta := e.Status()
		raw, _ := json.Marshal(map[string]any{"name": meta.InterfaceName, "port": meta.ListenPort, "namespace": meta.Namespace})
		os.Stdout.Write(append(raw, '\n'))
		select {}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestPhase36ProcessDeath$")
	cmd.Env = append(os.Environ(), "SPLICORE_PHASE36_CRASH_CHILD=1")
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	scanner := bufio.NewScanner(output)
	var meta struct {
		Name      string `json:"name"`
		Port      int    `json:"port"`
		Namespace uint64 `json:"namespace"`
	}
	ready := make(chan bool, 1)
	go func() {
		for scanner.Scan() {
			if json.Unmarshal(scanner.Bytes(), &meta) == nil && meta.Port > 0 {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child activation failed")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child activation timeout")
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	until := time.Now().Add(3 * time.Second)
	for {
		socket, err := net.ListenUDP("udp4", &net.UDPAddr{Port: meta.Port})
		if err == nil {
			socket.Close()
			break
		}
		if time.Now().After(until) {
			t.Fatal("kernel encrypted socket survived child death")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err = netlink.LinkByName(meta.Name); err == nil {
		t.Fatal("crash left host link")
	}
	t.Logf("killed child: anonymous namespace=%d, birth UDP port released, stale host links=0", meta.Namespace)
}
