package wire

import (
	"bytes"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"testing"
	"time"
)

func TestSelectedFragmentLossExpiryAndSessionRecovery(t *testing.T) {
	now := time.Unix(123, 0)
	a := Assembly{Now: func() time.Time { return now }}
	dst := access.Endpoint{Host: "localhost", Port: 443}
	want := bytes.Repeat([]byte{73, 0, 31, 17}, 1024)
	parts, e := FragmentsAt(77, 1, dst, want, 900)
	if e != nil || len(parts) < 3 {
		t.Fatal(e)
	}
	// Index 1 is lost. Surviving fragments are reversed and duplicated.
	for i := len(parts) - 1; i >= 0; i-- {
		if i == 1 {
			continue
		}
		d, e := DecodeDatagram(parts[i])
		if e != nil {
			t.Fatal(e)
		}
		if _, ok := a.Add(d); ok {
			t.Fatal("incomplete delivered")
		}
		if _, ok := a.Add(d); ok {
			t.Fatal("duplicate repaired loss")
		}
	}
	if a.Pending() != 1 {
		t.Fatal("missing loss state")
	}
	a.Sweep(now.Add(4999 * time.Millisecond))
	if a.Pending() != 1 {
		t.Fatal("early expiry")
	}
	now = now.Add(5 * time.Second)
	a.Sweep(now)
	if a.Pending() != 0 {
		t.Fatal("partial leak")
	}
	parts, e = FragmentsAt(77, 2, dst, want, 900)
	if e != nil {
		t.Fatal(e)
	}
	for i := len(parts) - 1; i >= 0; i-- {
		d, _ := DecodeDatagram(parts[i])
		out, ok := a.Add(d)
		if ok && (i != 0 || !bytes.Equal(out.Payload, want)) {
			t.Fatal("later packet contaminated")
		}
		if i == 0 && !ok {
			t.Fatal("session poisoned")
		}
	}
	if a.Pending() != 0 {
		t.Fatal("completion leaked")
	}
}
