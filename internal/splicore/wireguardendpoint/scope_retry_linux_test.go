//go:build linux && with_gvisor

package wireguardendpoint

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// RawConn's bool means wait for readiness. Record that contract independently of
// the retry loop; syscall errors come from each test's local, bounded sequence.
type retryRecordingRaw struct {
	syscall.RawConn
	writes, waits int
}

func (r *retryRecordingRaw) Write(fn func(uintptr) bool) error {
	r.writes++
	return r.RawConn.Write(func(fd uintptr) bool {
		done := fn(fd)
		if !done {
			r.waits++
		}
		return done
	})
}

type retrySequenceRaw struct{ waits int }

func (*retrySequenceRaw) Control(func(uintptr)) error   { return errors.New("unexpected control") }
func (*retrySequenceRaw) Read(func(uintptr) bool) error { return errors.New("unexpected read") }
func (r *retrySequenceRaw) Write(fn func(uintptr) bool) error {
	for range 8 {
		if fn(73) {
			return nil
		}
		r.waits++
	}
	return errors.New("test readiness sequence exhausted")
}

func TestPhase36UDPRetryStates(t *testing.T) {
	many := make([]error, 100)
	for i := range many {
		many[i] = unix.EINTR
	}
	cases := []struct {
		name     string
		sequence []error
		waits    int
		fatal    error
	}{
		{"single", []error{unix.EINTR}, 0, nil},
		{"three", []error{unix.EINTR, unix.EINTR, unix.EINTR}, 0, nil},
		{"many", many, 0, nil},
		{"eintr-eagain", []error{unix.EINTR, unix.EAGAIN}, 1, nil},
		{"eagain-eintr", []error{unix.EAGAIN, unix.EINTR}, 1, nil},
		{"wouldblock", []error{unix.EWOULDBLOCK}, 1, nil},
		{"wrapped-eintr", []error{fmt.Errorf("send: %w", unix.EINTR)}, 0, nil},
		{"wrapped-eagain", []error{fmt.Errorf("send: %w", unix.EAGAIN)}, 1, nil},
		{"eintr-fatal", []error{unix.EINTR, fmt.Errorf("send: %w", unix.ENETUNREACH)}, 0, unix.ENETUNREACH},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for range 100 {
				raw := &retrySequenceRaw{}
				attempts, delivered := 0, 0
				n, err := writeRawDatagram(raw, func(fd uintptr) (int, error) {
					if fd != 73 {
						t.Fatal("changed FD", fd)
					}
					attempts++
					if attempts <= len(tc.sequence) {
						return 0, tc.sequence[attempts-1]
					}
					if attempts != len(tc.sequence)+1 {
						t.Fatal("duplicate datagram attempt")
					}
					delivered++
					return 19, nil
				})
				expectedAttempts, expectedN, expectedDelivered := len(tc.sequence)+1, 19, 1
				if tc.fatal != nil {
					expectedAttempts--
					expectedN, expectedDelivered = 0, 0
				}
				if !errors.Is(err, tc.fatal) || attempts != expectedAttempts || n != expectedN || delivered != expectedDelivered || raw.waits != tc.waits {
					t.Fatalf("attempts=%d/%d waits=%d/%d n=%d/%d delivered=%d/%d error=%v", attempts, expectedAttempts, raw.waits, tc.waits, n, expectedN, delivered, expectedDelivered, err)
				}
			}
			t.Log("100/100 deterministic sequences; EINTR never requests writable wait")
		})
	}
}

func retryUDP(t *testing.T) (*net.UDPConn, *net.UDPConn, syscall.RawConn) {
	t.Helper()
	a, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	b, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		_ = a.Close()
		t.Fatal(err)
	}
	raw, err := a.SyscallConn()
	if err != nil {
		_ = a.Close()
		_ = b.Close()
		t.Fatal(err)
	}
	return a, b, raw
}

func retryDatagram(t *testing.T, interruptions int) {
	t.Helper()
	a, b, raw := retryUDP(t)
	defer a.Close()
	defer b.Close()
	if err := a.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	port := b.LocalAddr().(*net.UDPAddr).Port
	dest := &unix.SockaddrInet6{Addr: [16]byte{15: 1}, Port: port}
	payload := bytes.Repeat([]byte{0, 1, 128, 255}, 1024)
	recorder := &retryRecordingRaw{RawConn: raw}
	calls := 0
	start := time.Now()
	n, err := writeRawDatagram(recorder, func(fd uintptr) (int, error) {
		calls++
		if calls <= interruptions {
			return 0, unix.EINTR
		}
		return unix.SendmsgN(int(fd), payload, nil, dest, 0)
	})
	if err != nil || n != len(payload) || calls != interruptions+1 || recorder.waits != 0 || time.Since(start) > time.Second {
		t.Fatalf("n=%d attempts=%d waits=%d elapsed=%s err=%v", n, calls, recorder.waits, time.Since(start), err)
	}
	if err = b.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(payload)+1)
	n, _, err = b.ReadFromUDP(buffer)
	if err != nil || !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("payload n=%d err=%v", n, err)
	}
	if err = b.SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err = b.ReadFromUDP(buffer); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("duplicate datagram or wrong error: %v", err)
	}
}

func TestPhase36UDPRetryDatagrams(t *testing.T) {
	for _, count := range []int{1, 3, 100} {
		t.Run(fmt.Sprintf("eintr-%d", count), func(t *testing.T) {
			for range 100 {
				retryDatagram(t, count)
			}
			t.Logf("100/100: %d EINTR then one complete, byte-identical datagram; zero duplicates, zero waits", count)
		})
	}
}

func retryUnixPair(t *testing.T) (*net.UnixConn, *net.UnixConn, syscall.RawConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	wrap := func(fd int) (net.Conn, error) {
		file := os.NewFile(uintptr(fd), "retry-datagram")
		defer file.Close()
		return net.FileConn(file)
	}
	a, ea := wrap(fds[0])
	b, eb := wrap(fds[1])
	if ea != nil || eb != nil {
		if a != nil {
			_ = a.Close()
		}
		if b != nil {
			_ = b.Close()
		}
		t.Fatalf("socketpair wrap: %v %v", ea, eb)
	}
	raw, err := a.(*net.UnixConn).SyscallConn()
	if err != nil {
		_ = a.Close()
		_ = b.Close()
		t.Fatal(err)
	}
	return a.(*net.UnixConn), b.(*net.UnixConn), raw
}

// Fill a real nonblocking datagram queue. This control exercises Go's real
// writable wait, not a synthetic readiness result or an EINTR-only mock.
func retryReady(t *testing.T, mode string) {
	t.Helper()
	a, b, raw := retryUnixPair(t)
	defer a.Close()
	defer b.Close()
	padding := bytes.Repeat([]byte("queue-padding"), 32)
	queued := 0
	if err := raw.Control(func(fd uintptr) {
		for range 1024 {
			_, err := unix.SendmsgN(int(fd), padding, nil, nil, 0)
			if errors.Is(err, unix.EAGAIN) {
				return
			}
			if err != nil {
				t.Error(err)
				return
			}
			queued++
		}
		t.Error("fixture did not fill the real send queue")
	}); err != nil {
		t.Fatal(err)
	}
	if queued == 0 {
		t.Fatal("empty queue fixture")
	}
	if err := a.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := b.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("EINTR/EAGAIN atomic target datagram")
	blocked := make(chan struct{})
	received := make(chan error, 1)
	var once sync.Once
	go func() {
		<-blocked
		time.Sleep(5 * time.Millisecond)
		buffer := make([]byte, 1024)
		targets := 0
		for range queued + 1 {
			n, err := b.Read(buffer)
			if err != nil {
				received <- err
				return
			}
			if bytes.Equal(buffer[:n], payload) {
				targets++
			} else if !bytes.Equal(buffer[:n], padding) {
				received <- errors.New("unexpected datagram")
				return
			}
		}
		if targets != 1 {
			received <- fmt.Errorf("targets=%d", targets)
			return
		}
		received <- nil
	}()
	recorder := &retryRecordingRaw{RawConn: raw}
	calls := 0
	interrupted := false
	sawEAGAIN := false
	n, err := writeRawDatagram(recorder, func(fd uintptr) (int, error) {
		calls++
		if !interrupted && (mode == "eintr-eagain" || sawEAGAIN) {
			interrupted = true
			return 0, unix.EINTR
		}
		n, err := unix.SendmsgN(int(fd), payload, nil, nil, 0)
		if errors.Is(err, unix.EAGAIN) {
			sawEAGAIN = true
			once.Do(func() { close(blocked) })
		}
		return n, err
	})
	once.Do(func() { close(blocked) })
	receiveErr := <-received
	if err != nil || receiveErr != nil || n != len(payload) || !interrupted || !sawEAGAIN || recorder.waits == 0 || calls > 20 {
		t.Fatalf("mode=%s calls=%d waits=%d n=%d err=%v receive=%v", mode, calls, recorder.waits, n, err, receiveErr)
	}
}

func TestPhase36UDPRetryWritable(t *testing.T) {
	for _, mode := range []string{"eintr-eagain", "eagain-eintr"} {
		t.Run(mode, func(t *testing.T) {
			for range 100 {
				retryReady(t, mode)
			}
			t.Log("100/100 real queue EAGAIN -> Go writable wait -> one datagram; EINTR uses a fresh Write without waiting")
		})
	}
}

func retryLifecycle(t *testing.T, mode string) {
	t.Helper()
	a, b, raw := retryUDP(t)
	defer a.Close()
	defer b.Close()
	entered := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		calls := 0
		_, err := writeRawDatagram(raw, func(uintptr) (int, error) {
			calls++
			if calls == 1 {
				close(entered)
			}
			if calls > 10_000_000 {
				return 0, errors.New("bounded injection exhausted")
			}
			return 0, unix.EINTR
		})
		done <- err
	}()
	<-entered
	var expected error
	if mode == "close" {
		time.Sleep(time.Millisecond)
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		expected = net.ErrClosed
	} else {
		if err := a.SetWriteDeadline(time.Now().Add(5 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		expected = os.ErrDeadlineExceeded
	}
	select {
	case err := <-done:
		if !errors.Is(err, expected) || errors.Is(err, unix.EINTR) {
			t.Fatalf("mode=%s error=%v expected=%v", mode, err, expected)
		}
		if mode != "close" {
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				t.Fatalf("noncanonical timeout: %v", err)
			}
		}
	case <-time.After(2 * time.Second):
		_ = a.Close()
		t.Fatal("retry did not honor lifecycle state")
	}
}

func TestPhase36UDPRetryLifecycle(t *testing.T) {
	for _, mode := range []string{"close", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			for range 100 {
				retryLifecycle(t, mode)
			}
			t.Log("100/100 bounded EINTR injection; canonical close/absolute deadline error; no readiness wait")
		})
	}
}

func TestPhase36UDPRetryResources(t *testing.T) {
	a, b, _ := retryUDP(t)
	_ = a.Close()
	_ = b.Close()
	runtime.GC()
	baseFD, baseG := fdCount(), runtime.NumGoroutine()
	beforeTasks, _ := os.ReadDir("/proc/self/task")
	for range 25 {
		retryDatagram(t, 3)
		retryLifecycle(t, "close")
		retryLifecycle(t, "deadline")
	}
	runtime.GC()
	until := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > baseG && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	afterTasks, _ := os.ReadDir("/proc/self/task")
	if fdCount() != baseFD || runtime.NumGoroutine() > baseG {
		t.Fatalf("FD=%d/%d goroutines=%d/%d", baseFD, fdCount(), baseG, runtime.NumGoroutine())
	}
	t.Logf("retry resource baseline FD=%d/%d goroutines=%d/%d tasks=%d/%d; no new production goroutine or OS-thread ownership", baseFD, fdCount(), baseG, runtime.NumGoroutine(), len(beforeTasks), len(afterTasks))
}
