//go:build linux && with_gvisor

package nativetun

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func descriptors(t *testing.T) (total, eventfd int) {
	t.Helper()
	files, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", f.Name()))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		total++
		if target == "anon_inode:[eventfd]" {
			eventfd++
		}
	}
	return
}

func TestNativeCompleteLifetimeFD25x(t *testing.T) {
	cycle := func() {
		// A real pollable descriptor models the borrowed device lifetime. Actual
		// kernel TUN and journal compensation are covered by the isolated lab.
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		device := &pipeDevice{reader: reader, writer: writer}
		r, _ := New(context.Background(), device, Options{MTU: 1500, Dispatcher: testDispatcher{}})
		if err := r.Start(); err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		if err := device.Close(); err != nil {
			t.Fatal(err)
		}
	}
	cycle()
	runtime.GC()
	startFD, startEvent := descriptors(t)
	startGo := runtime.NumGoroutine()
	peakFD, peakEvent, peakGo := startFD, startEvent, startGo
	for i := range 25 {
		cycle()
		fd, event := descriptors(t)
		peakFD, peakEvent, peakGo = max(peakFD, fd), max(peakEvent, event), max(peakGo, runtime.NumGoroutine())
		if fd != startFD || event != startEvent {
			t.Fatalf("cycle %d: FD=%d eventfd=%d baseline=%d/%d", i+1, fd, event, startFD, startEvent)
		}
	}
	runtime.GC()
	endFD, endEvent := descriptors(t)
	endGo := runtime.NumGoroutine()
	t.Logf("cycles=25 FD=%d/%d/%d eventfd=%d/%d/%d goroutine=%d/%d/%d", startFD, peakFD, endFD, startEvent, peakEvent, endEvent, startGo, peakGo, endGo)
	if endFD != startFD || endEvent != startEvent || endGo != startGo {
		t.Fatal("lifetime resource mismatch")
	}
}

type pipeDevice struct{ reader, writer *os.File }

func (d *pipeDevice) Start() error                { return nil }
func (d *pipeDevice) Read(p []byte) (int, error)  { return d.reader.Read(p) }
func (d *pipeDevice) Write(p []byte) (int, error) { return d.writer.Write(p) }
func (d *pipeDevice) Interrupt() error            { return d.reader.SetReadDeadline(time.Unix(1, 0)) }
func (d *pipeDevice) Close() error {
	err := d.reader.Close()
	other := d.writer.Close()
	if err != nil {
		return err
	}
	return other
}
