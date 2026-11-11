package wire

import (
	"bytes"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"testing"
	"time"
)

func TestAssemblyExpirySessionIsolationAndCapacity(t *testing.T) {
	now := time.Unix(12, 0)
	a := Assembly{Now: func() time.Time { return now }}
	dst := access.Endpoint{Host: "localhost", Port: 1234}
	first := Datagram{Session: 1, Packet: 65535, Count: 2, Destination: dst, Payload: []byte("first")}
	a.Add(first)
	duplicate := first
	duplicate.Payload = []byte("ignored")
	a.Add(duplicate)
	other := first
	other.Session = 2
	other.Index = 1
	other.Payload = []byte("second")
	if _, ok := a.Add(other); ok {
		t.Fatal("cross session assembly")
	}
	second := first
	second.Index = 1
	second.Payload = []byte("second")
	if d, ok := a.Add(second); !ok || !bytes.Equal(d.Payload, []byte("firstsecond")) {
		t.Fatal("ordering/duplicate")
	}
	now = now.Add(5 * time.Second)
	a.Sweep(now)
	if len(a.pending) != 0 {
		t.Fatal("expired retained")
	}
	for i := range 128 {
		first.Session = uint32(i)
		a.Add(first)
	}
	first.Session = 129
	a.Add(first)
	if len(a.pending) != 128 {
		t.Fatal("capacity")
	}
	a.ForgetSession(0)
	if len(a.pending) != 127 {
		t.Fatal("session release")
	}
	a.Clear()
	if len(a.pending) != 0 {
		t.Fatal("parent release")
	}
	for _, limit := range []int{1200, 1197, 900, 576, 64} {
		frames, e := FragmentsAt(1, 1, dst, make([]byte, MaxUDP), limit)
		if e != nil {
			t.Fatal(e)
		}
		for _, f := range frames {
			if len(f) > limit {
				t.Fatal("peer datagram limit")
			}
		}
	}
	if _, e := FragmentsAt(1, 1, dst, make([]byte, MaxUDP), 30); e == nil {
		t.Fatal("fragment count overflow")
	}
}
