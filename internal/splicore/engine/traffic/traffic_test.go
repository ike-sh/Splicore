package traffic

import (
	"io"
	"net"
	"sync"
	"testing"
)

func TestPayloadCountersAndConcurrentRelease(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	total, user := &Counter{}, &Counter{}
	meters := []*Counter{total, user}
	c := Conn(a, meters...)
	meters[0] = nil // Caller mutation cannot remove this session's owner.
	wrote := make(chan error, 1)
	go func() { _, err := b.Write([]byte("upload")); wrote <- err }()
	if _, err := io.ReadFull(c, make([]byte, 6)); err != nil {
		t.Fatal(err)
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	go func() { _, err := io.ReadFull(b, make([]byte, 8)); read <- err }()
	if _, err := io.Copy(c, &limitedReader{}); err != nil {
		t.Fatal(err)
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() { _ = c.Close() })
	}
	wg.Wait()
	for _, m := range []*Counter{total, user} {
		s := m.Snapshot()
		if s.Upload != 6 || s.Download != 8 || s.Sessions != 1 || s.TCPSessions != 1 || s.Active != 0 || s.TCPActive != 0 {
			t.Fatalf("accounting: %+v", s)
		}
	}
}

type limitedReader struct{ sent bool }

func (r *limitedReader) Read(b []byte) (int, error) {
	if r.sent {
		return 0, io.EOF
	}
	r.sent = true
	return copy(b, "download"), nil
}

func TestDatagramSessionRelease(t *testing.T) {
	m := &Counter{}
	release := Open(false, m)
	CountUpload(3, m)
	CountDownload(2, m)
	release()
	release()
	s := m.Snapshot()
	if s.UDPSessions != 1 || s.UDPActive != 0 || s.Active != 0 || s.Upload != 3 || s.Download != 2 {
		t.Fatal(s)
	}
}
