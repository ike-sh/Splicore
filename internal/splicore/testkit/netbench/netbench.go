// Package netbench measures real sockets. It is test infrastructure, not a
// production transport. Instrumentation and application acknowledgements are
// deliberately included in the reported timings.
package netbench

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"time"
)

type Scenario struct {
	Name             string `json:"name"`
	Protocol         string `json:"protocol"`
	Ingress          string `json:"ingress"`
	Egress           string `json:"egress"`
	Network          string `json:"network"`
	Mode             string `json:"mode"`
	Connections      int    `json:"connections"`
	Bytes            int    `json:"bytes"`
	PacketBytes      int    `json:"packet_bytes"`
	PacketsPerSecond int    `json:"packets_per_second"`
	Probes           int    `json:"probes"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
}

func (s Scenario) Validate() error {
	if s.Name == "" || s.Connections < 1 || s.Connections > 100 || s.Bytes < 1 || s.Bytes > 64<<20 || s.Probes < 1 || s.TimeoutSeconds < 1 {
		return errors.New("invalid benchmark size, concurrency, probes or timeout")
	}
	if s.Ingress != "127.0.0.1" && s.Ingress != "::1" || s.Egress != "127.0.0.1" && s.Egress != "::1" {
		return errors.New("benchmark endpoints must be explicit loopback addresses")
	}
	if s.Network != "tcp" && s.Network != "udp" && s.Network != "mixed" {
		return errors.New("invalid benchmark network")
	}
	if s.Mode != "upload" && s.Mode != "download" && s.Mode != "duplex" {
		return errors.New("invalid TCP direction")
	}
	if s.PacketBytes < 32 || s.PacketBytes > 60000 || s.PacketsPerSecond < 1 {
		return errors.New("invalid UDP configuration")
	}
	return nil
}

type Recorder struct {
	mu   sync.Mutex
	file *os.File
	err  error
}

func NewRecorder(path string) (*Recorder, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &Recorder{file: f}, nil
}
func (r *Recorder) Record(value any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err == nil {
		r.err = json.NewEncoder(r.file).Encode(value)
	}
}
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return errors.Join(r.err, r.file.Sync(), r.file.Close())
}

// SampleResources records cumulative process CPU time, current RSS, live OS
// descriptors/handles and Go runtime counters. CPU percent is derived from two
// samples, with one fully used logical CPU equal to 100 percent.
func SampleResources(r *Recorder, label string) func() {
	done, joined := make(chan struct{}), make(chan struct{})
	take := func() {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		rss, cpu, handles, err := processResources()
		r.Record(map[string]any{"kind": "resources", "label": label, "time_ns": time.Now().UnixNano(), "rss_bytes": rss, "cpu_ns": cpu, "os_resources": handles, "goroutines": runtime.NumGoroutine(), "heap_bytes": mem.Alloc, "allocated_bytes": mem.TotalAlloc, "gc_cycles": mem.NumGC, "error": err})
	}
	take()
	go func() {
		defer close(joined)
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				take()
			case <-done:
				return
			}
		}
	}()
	return func() { close(done); <-joined; take() }
}

var pattern = func() []byte {
	b := make([]byte, 32768)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}()

func transfer(w io.Writer, rd io.Reader, size int) error {
	buf := make([]byte, len(pattern))
	for offset := 0; offset < size; {
		n := min(size-offset, len(pattern))
		if w != nil {
			if err := writeFull(w, pattern[:n]); err != nil {
				return err
			}
		}
		if rd != nil {
			if got, err := io.ReadFull(rd, buf[:n]); err != nil {
				return fmt.Errorf("TCP payload received %d/%d bytes: %w", offset+got, size, err)
			}
			if !bytes.Equal(buf[:n], pattern[:n]) {
				return errors.New("TCP application payload mismatch")
			}
		}
		offset += n
	}
	return nil
}
func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

// ServeTCP uses an application readiness acknowledgement, RTT echo probes, then
// independently generated upload/download data. Duplex is concurrent in both
// directions, rather than inferring bidirectional goodput from a serial echo.
func ServeTCP(c net.Conn) error {
	defer c.Close()
	header := make([]byte, 13)
	if _, err := io.ReadFull(c, header); err != nil {
		return err
	}
	size := int(binary.BigEndian.Uint64(header[1:9]))
	probes := int(binary.BigEndian.Uint32(header[9:]))
	if size < 1 || size > 64<<20 || probes < 1 || probes > 10000 {
		return errors.New("invalid measurement request")
	}
	if err := writeFull(c, []byte{0xac}); err != nil {
		return err
	}
	ping := make([]byte, 32)
	for range probes {
		if _, e := io.ReadFull(c, ping); e != nil {
			return e
		}
		if e := writeFull(c, ping); e != nil {
			return e
		}
	}
	switch header[0] {
	case 'U':
		if e := transfer(nil, c, size); e != nil {
			return e
		}
	case 'D':
		if e := transfer(c, nil, size); e != nil {
			return e
		}
	case 'B':
		done := make(chan error, 1)
		go func() { done <- transfer(c, nil, size) }()
		e := transfer(nil, c, size)
		if e != nil {
			c.Close()
		}
		if other := <-done; e != nil || other != nil {
			return errors.Join(e, other)
		}
	default:
		return errors.New("invalid measurement direction")
	}
	return writeFull(c, []byte{0xad})
}

type Dial func(context.Context) (net.Conn, error)
type PacketDial func(context.Context) (net.PacketConn, error)

func RunTCP(ctx context.Context, r *Recorder, s Scenario, index int, dial Dial) (err error) {
	start := time.Now()
	result := map[string]any{"kind": "connection", "scenario": s.Name, "network": "tcp", "index": index, "status": "BASELINE", "start_ns": start.UnixNano()}
	defer func() {
		result["total_ns"] = time.Since(start).Nanoseconds()
		if err != nil {
			result["status"] = "FAIL"
			result["error"] = err.Error()
		}
		r.Record(result)
	}()
	c, err := dial(ctx)
	if err != nil {
		return err
	}
	result["dial_ns"] = time.Since(start).Nanoseconds()
	defer c.Close()
	if err = c.SetDeadline(time.Now().Add(time.Duration(s.TimeoutSeconds) * time.Second)); err != nil {
		return err
	}
	header := make([]byte, 13)
	header[0] = map[string]byte{"upload": 'U', "download": 'D', "duplex": 'B'}[s.Mode]
	binary.BigEndian.PutUint64(header[1:9], uint64(s.Bytes))
	binary.BigEndian.PutUint32(header[9:], uint32(s.Probes))
	if err = writeFull(c, header); err != nil {
		return err
	}
	ack := make([]byte, 1)
	if _, err = io.ReadFull(c, ack); err != nil {
		return err
	}
	if ack[0] != 0xac {
		return errors.New("bad readiness acknowledgement")
	}
	result["ready_ns"] = time.Since(start).Nanoseconds()
	for probe := range s.Probes {
		stamp := time.Now()
		if err = writeFull(c, pattern[:32]); err != nil {
			return err
		}
		ping := make([]byte, 32)
		if _, err = io.ReadFull(c, ping); err != nil {
			return err
		}
		if !bytes.Equal(ping, pattern[:32]) {
			return errors.New("RTT payload mismatch")
		}
		r.Record(map[string]any{"kind": "rtt", "scenario": s.Name, "network": "tcp", "index": index, "probe": probe, "ns": time.Since(stamp).Nanoseconds()})
	}
	stamp := time.Now()
	result["phase"] = "payload"
	switch s.Mode {
	case "upload":
		err = transfer(c, nil, s.Bytes)
	case "download":
		err = transfer(nil, c, s.Bytes)
	case "duplex":
		done := make(chan error, 1)
		go func() { done <- transfer(c, nil, s.Bytes) }()
		err = transfer(nil, c, s.Bytes)
		if err != nil {
			c.Close()
		}
		err = errors.Join(err, <-done)
	}
	if err != nil {
		return err
	}
	result["phase"] = "final-acknowledgement"
	if _, err = io.ReadFull(c, ack); err != nil {
		return err
	}
	if ack[0] != 0xad {
		return errors.New("server did not validate payload")
	}
	result["transfer_ns"] = time.Since(stamp).Nanoseconds()
	result["bytes_per_direction"] = s.Bytes
	result["mode"] = s.Mode
	result["phase"] = "close"
	stamp = time.Now()
	err = c.Close()
	result["close_ns"] = time.Since(stamp).Nanoseconds()
	return err
}

// RunUDP sends each sequence once. Missing replies are measured, never retried.
// The fixed settling window bounds observation; it is not a delivery guarantee.
func RunUDP(ctx context.Context, r *Recorder, s Scenario, index int, dial PacketDial, target net.Addr) (err error) {
	start := time.Now()
	result := map[string]any{"kind": "connection", "scenario": s.Name, "network": "udp", "index": index, "status": "BASELINE", "start_ns": start.UnixNano()}
	defer func() {
		result["total_ns"] = time.Since(start).Nanoseconds()
		if err != nil {
			result["status"] = "FAIL"
			result["error"] = err.Error()
		}
		r.Record(result)
	}()
	c, err := dial(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	result["dial_ns"] = time.Since(start).Nanoseconds()
	count := (s.Bytes + s.PacketBytes - 1) / s.PacketBytes
	seen := make([]bool, count)
	received, duplicates := 0, 0
	readDone := make(chan error, 1)
	if err = c.SetDeadline(time.Now().Add(time.Duration(s.TimeoutSeconds) * time.Second)); err != nil {
		return err
	}
	go func() {
		b := make([]byte, 65535)
		for {
			n, _, e := c.ReadFrom(b)
			if e != nil {
				if ne, ok := e.(net.Error); ok && ne.Timeout() {
					readDone <- nil
				} else {
					readDone <- e
				}
				return
			}
			if n != s.PacketBytes {
				readDone <- fmt.Errorf("UDP payload length %d, expected %d", n, s.PacketBytes)
				return
			}
			seq := binary.BigEndian.Uint64(b[:8])
			stamp := int64(binary.BigEndian.Uint64(b[8:16]))
			if seq >= uint64(count) {
				readDone <- errors.New("invalid UDP sequence")
				return
			}
			for _, v := range b[16:n] {
				if v != byte(seq%251) {
					readDone <- errors.New("UDP payload mismatch")
					return
				}
			}
			if seen[seq] {
				duplicates++
			} else {
				seen[seq] = true
				received++
			}
			r.Record(map[string]any{"kind": "rtt", "scenario": s.Name, "network": "udp", "index": index, "probe": seq, "ns": time.Now().UnixNano() - stamp})
			if received == count {
				readDone <- nil
				return
			}
		}
	}()
	stamp := time.Now()
	tick := time.NewTicker(time.Second / time.Duration(s.PacketsPerSecond))
	defer tick.Stop()
	b := make([]byte, s.PacketBytes)
	sent := 0
	for seq := 0; seq < count; seq++ {
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-tick.C:
		}
		if err != nil {
			break
		}
		binary.BigEndian.PutUint64(b[:8], uint64(seq))
		binary.BigEndian.PutUint64(b[8:16], uint64(time.Now().UnixNano()))
		for j := 16; j < len(b); j++ {
			b[j] = byte(seq % 251)
		}
		var n int
		n, err = c.WriteTo(b, target)
		if err == nil && n != len(b) {
			err = io.ErrShortWrite
		}
		if err != nil {
			break
		}
		sent++
	}
	result["send_ns"] = time.Since(stamp).Nanoseconds()
	// Wake a blocked receiver after all in-flight packets have had a fixed
	// two-second window. Loss is preserved in the raw sent/received counts.
	if err != nil {
		c.Close()
	} else {
		err = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	}
	readErr := <-readDone
	err = errors.Join(err, readErr)
	result["sent_packets"] = sent
	result["received_packets"] = received
	result["duplicate_packets"] = duplicates
	result["packet_bytes"] = s.PacketBytes
	result["transfer_ns"] = time.Since(stamp).Nanoseconds()
	return err
}
