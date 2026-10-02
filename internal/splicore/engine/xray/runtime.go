package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
)

type Handle struct {
	engine       *Engine
	endpoint     access.Endpoint
	lifecycle    sync.Mutex
	mu           sync.Mutex
	config       []byte // immutable snapshot until Start writes and clears it
	status       ports.RuntimeStatus
	cmd          *exec.Cmd
	child        *ownedProcess
	listener     net.Listener
	privatePort  uint16
	active       bool
	closed       bool
	connections  map[net.Conn]bool
	workers      sync.WaitGroup
	done         chan struct{} // closed by the sole Wait owner, after cleanup
	doneOnce     sync.Once
	logs         discardLog
	cleanupError error
}

func (*Handle) Format(f fmt.State, verb rune) { _, _ = f.Write([]byte("XrayRuntime{[REDACTED]}")) }

type discardLog struct{ bytes atomic.Int64 }

func (d *discardLog) Write(p []byte) (int, error) {
	for {
		before := d.bytes.Load()
		after := min(int64(1<<20), before+int64(len(p)))
		if d.bytes.CompareAndSwap(before, after) {
			break
		}
	}
	return len(p), nil
}
func newHandle(e *Engine, endpoint access.Endpoint, b []byte) *Handle {
	return &Handle{engine: e, endpoint: endpoint, config: b, connections: map[net.Conn]bool{}, done: make(chan struct{}), status: ports.RuntimeStatus{Engine: "xray", Version: ReferenceVersion, Health: "prepared"}}
}
func (h *Handle) RuntimeStatus() ports.RuntimeStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.status
	if s.ExitCode != nil {
		code := *s.ExitCode
		s.ExitCode = &code
	}
	s.DiscardedLogBytes = h.logs.bytes.Load()
	return s
}
func (h *Handle) Stats() ports.Stats { return ports.Stats{} }
func (h *Handle) Start(ctx context.Context) (result error) {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	h.mu.Lock()
	invalid := h.closed || h.cmd != nil
	h.mu.Unlock()
	if invalid {
		return unavailable("Xray runtime already started or closed")
	}
	defer func() {
		if result != nil {
			h.closeLocked(context.Background())
			h.mu.Lock()
			h.status.Health = "failed"
			h.mu.Unlock()
		}
	}()
	if err := h.engine.ValidateAvailability(ctx); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(h.endpoint.Host, strconv.Itoa(int(h.endpoint.Port))))
	if err != nil {
		return identity.Err(identity.PortConflict, "Xray public listener unavailable")
	}
	h.mu.Lock()
	h.listener = listener
	h.mu.Unlock()
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return unavailable("Xray private listener unavailable")
	}
	defer reservation.Close()
	port := uint16(reservation.Addr().(*net.TCPAddr).Port)
	id, dir, err := h.engine.generation()
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.status.Generation = id
	h.status.RuntimeDirectory = dir
	h.status.ConfigArtifact = filepath.Join(dir, "config.json")
	h.privatePort = port
	h.mu.Unlock()
	var c configuration
	if json.Unmarshal(h.config, &c) != nil {
		return unavailable("Xray config snapshot invalid")
	}
	c.Inbounds[0].Port = port
	b, err := json.Marshal(c)
	if err != nil {
		return unavailable("Xray config rendering failed")
	}
	defer clear(b)
	clear(h.config)
	h.config = nil
	artifact := filepath.Join(dir, "config.json")
	f, err := os.OpenFile(artifact, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return unavailable("Xray private config unavailable")
	}
	_, err = f.Write(b)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return unavailable("Xray private config write failed")
	}
	if secureFile(artifact) != nil {
		return unavailable("unsafe Xray artifact permissions")
	}
	testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	check := h.engine.commandContext(testCtx, h.engine.options.BinaryPath, "run", "-test", "-config", artifact)
	check.Env = childEnvironment()
	check.Dir = dir
	check.Stdout = &h.logs
	check.Stderr = &h.logs
	err = runOwned(check)
	cancel()
	if err != nil {
		return unavailable("Xray config validation failed")
	}
	if ctx.Err() != nil {
		return unavailable("Xray start cancelled")
	}
	cmd := h.engine.command(h.engine.options.BinaryPath, "run", "-config", artifact)
	cmd.Env = childEnvironment()
	cmd.Dir = dir
	cmd.Stdout = &h.logs
	cmd.Stderr = &h.logs
	child, err := prepareProcess(cmd)
	if err != nil {
		return unavailable("Xray process ownership unavailable")
	}
	_ = reservation.Close()
	if err = cmd.Start(); err != nil {
		child.release()
		return unavailable("Xray child start failed")
	}
	if err = child.attach(cmd); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		child.release()
		return unavailable("Xray process ownership failed")
	}
	h.mu.Lock()
	h.cmd = cmd
	h.child = child
	h.status.PID = cmd.Process.Pid
	h.status.StartedAt = time.Now().UTC()
	h.status.Health = "starting"
	h.workers.Add(1)
	h.mu.Unlock()
	go h.accept(listener)
	go h.wait(cmd, child)
	// Health observes readiness with a deadline; it never restarts a failed child.
	ready, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if h.Health(ready) == nil {
			return nil
		}
		select {
		case <-h.done:
			return unavailable("Xray child exited before health")
		case <-ready.Done():
			return unavailable("Xray child health timeout")
		case <-ticker.C:
		}
	}
}
func (h *Handle) Health(ctx context.Context) error {
	if ctx.Err() != nil {
		return unavailable("Xray health cancelled")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.cmd == nil || h.status.ExitCode != nil {
		return unavailable("Xray child unavailable")
	}
	if !listenerOwned(h.status.PID, h.privatePort) {
		return unavailable("Xray expected child listener unavailable")
	}
	h.status.Health = "healthy"
	return nil
}
func (h *Handle) Activate() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.closed && h.cmd != nil && h.status.ExitCode == nil && h.status.Health == "healthy" {
		h.active = true
	}
}
func (h *Handle) accept(listener net.Listener) {
	defer h.workers.Done()
	for {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		h.mu.Lock()
		if !h.active || h.closed {
			h.mu.Unlock()
			_ = c.Close()
			continue
		}
		h.connections[c] = true
		h.workers.Add(1)
		port := h.privatePort
		h.mu.Unlock()
		go h.relay(c, port)
	}
}
func (h *Handle) relay(public net.Conn, port uint16) {
	defer h.workers.Done()
	defer func() { _ = public.Close(); h.mu.Lock(); delete(h.connections, public); h.mu.Unlock() }()
	private, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), time.Second)
	if err != nil {
		return
	}
	defer private.Close()
	h.mu.Lock()
	if h.closed || !h.active {
		h.mu.Unlock()
		return
	}
	h.connections[private] = true
	h.mu.Unlock()
	defer func() { h.mu.Lock(); delete(h.connections, private); h.mu.Unlock() }()
	done := make(chan struct{})
	go func() {
		_, err := io.Copy(private, public)
		if err != nil {
			_ = private.Close()
			_ = public.Close()
		} else {
			halfClose(private)
		}
		close(done)
	}()
	_, err = io.Copy(public, private)
	if err != nil {
		_ = private.Close()
		_ = public.Close()
	}
	halfClose(public)
	<-done
}
func halfClose(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}
func (h *Handle) stopSockets() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.active = false
	if h.listener != nil {
		_ = h.listener.Close()
	}
	for c := range h.connections {
		_ = c.Close()
	}
}
func (h *Handle) wait(cmd *exec.Cmd, child *ownedProcess) {
	_ = cmd.Wait()
	h.mu.Lock()
	code := cmd.ProcessState.ExitCode()
	h.status.ExitCode = &code
	if h.closed {
		h.status.Health = "stopped"
	} else {
		h.status.Health = "failed"
	}
	h.mu.Unlock()
	h.stopSockets()
	h.workers.Wait()
	child.release()
	err := h.engine.removeGeneration(h.RuntimeStatus().Generation)
	h.mu.Lock()
	h.cleanupError = err
	h.mu.Unlock()
	h.doneOnce.Do(func() { close(h.done) })
}
func (h *Handle) Close(ctx context.Context) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	return h.closeLocked(ctx)
}
func (h *Handle) closeLocked(ctx context.Context) error {
	h.mu.Lock()
	h.closed = true
	child := h.child
	cmd := h.cmd
	h.mu.Unlock()
	h.stopSockets()
	if cmd == nil {
		clear(h.config)
		h.config = nil
		h.mu.Lock()
		h.status.Health = "stopped"
		h.mu.Unlock()
		id := h.RuntimeStatus().Generation
		if id != "" {
			err := h.engine.removeGeneration(id)
			h.mu.Lock()
			h.cleanupError = err
			h.mu.Unlock()
		}
		h.doneOnce.Do(func() { close(h.done) })
	} else {
		child.terminate(false)
		timer := time.NewTimer(time.Second)
		select {
		case <-h.done:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
			child.terminate(true)
			<-h.done
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			child.terminate(true)
			<-h.done
		}
	}
	h.engine.mu.Lock()
	delete(h.engine.handles, h)
	h.engine.mu.Unlock()
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cleanupError
}
func (h *Handle) Stop(ctx context.Context) error { return h.Close(ctx) }

// Wait joins the sole process reaper and artifact/socket cleanup.
func (h *Handle) Wait(ctx context.Context) error {
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return unavailable("Xray wait cancelled")
	}
}
