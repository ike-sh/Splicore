package padding

import (
	"bytes"
	"github.com/ike-sh/Splicore/protocol/anytls/wire"
	"io"
	"strings"
	"testing"
)

type lowRandom struct{}

func (lowRandom) Between(a, b int) (int, error) { return a, nil }

type highRandom struct{}

func (highRandom) Between(a, b int) (int, error) { return b, nil }

type recorder struct{ writes [][]byte }

func (r *recorder) Write(b []byte) (int, error) {
	r.writes = append(r.writes, append([]byte(nil), b...))
	return len(b), nil
}
func TestDefaultAuthAndRangeSelection(t *testing.T) {
	s, err := Parse(Default)
	if err != nil {
		t.Fatal(err)
	}
	for _, rng := range []Random{lowRandom{}, highRandom{}} {
		if n, err := s.AuthLength(rng); err != nil || n != 30 {
			t.Fatal("padding zero", err)
		}
	}
	custom, _ := Parse("stop=2\n0=10-20\n1=100-200")
	if n, _ := custom.AuthLength(lowRandom{}); n != 10 {
		t.Fatal("low range")
	}
	if n, _ := custom.AuthLength(highRandom{}); n != 20 {
		t.Fatal("high range")
	}
}
func TestPaddingPlaintextCounterFragmentationCheckAndStop(t *testing.T) {
	s, _ := Parse("stop=3\n0=0-0\n1=20-20,30-30\n2=10-10,c,40-40")
	r := &recorder{}
	w := NewWriter(r, s, lowRandom{})
	data, _ := wire.AppendFrame(nil, wire.Frame{Command: wire.Data, Stream: 1, Payload: bytes.Repeat([]byte{42}, 16)})
	if err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if len(r.writes) != 2 || len(r.writes[0]) != 20 || len(r.writes[1]) != 30 || w.PacketCount() != 2 {
		t.Fatal("plaintext write policy/counter")
	}
	reader := bytes.NewReader(bytes.Join(r.writes, nil))
	f, err := wire.ReadFrame(reader)
	if err != nil || !bytes.Equal(f.Payload, bytes.Repeat([]byte{42}, 16)) {
		t.Fatal("payload damaged by fragmented frame", err)
	}
	if f, err = wire.ReadFrame(reader); err != nil || f.Command != wire.Waste {
		t.Fatal("padding not a Waste frame", err)
	}
	r.writes = nil
	heart, _ := wire.AppendFrame(nil, wire.Frame{Command: wire.Heartbeat})
	if err = w.Write(heart); err != nil {
		t.Fatal(err)
	}
	if len(r.writes) != 1 || len(r.writes[0]) != 7 {
		t.Fatal("check marker sent extra padding")
	}
	r.writes = nil
	large := bytes.Repeat([]byte{7}, 100)
	if err = w.Write(large); err != nil || len(r.writes) != 1 || !bytes.Equal(r.writes[0], large) {
		t.Fatal("padding stop")
	}
}
func TestPaddingRemainingDataAndUndefinedRule(t *testing.T) {
	s, _ := Parse("stop=4\n0=0-0\n1=10-10,c,12-12")
	r := &recorder{}
	w := NewWriter(r, s, lowRandom{})
	input := bytes.Repeat([]byte{9}, 50)
	if w.Write(input) != nil || len(r.writes) != 3 || !bytes.Equal(bytes.Join(r.writes, nil), input) {
		t.Fatal("remaining plaintext lost")
	}
	r.writes = nil
	if w.Write(input) != nil || len(r.writes) != 1 {
		t.Fatal("undefined rule must pass through")
	}
}
func TestPaddingParserRejectsMalformedAndAmplification(t *testing.T) {
	for _, bad := range []string{"", "0=0-0", "stop=-1", "stop=65536", "stop=65", "stop=2\nstop=3", "stop=1\n1=10-20", "stop=2\n0=1-2,3-4", "stop=2\n1=c,1-2", "stop=2\n1=1-2,c", "stop=2\n1=2-1", "stop=2\n1=0-0", "stop=2\n1=1-65536", "stop=2\n1=1-2,c,c,2-3", "stop=2\n1=1-2\n1=3-4", strings.Repeat("x", MaxScheme+1), "stop=2\n1=+1-2", "stop=2\n1=1-2\r", "stop=2\n1=" + strings.Repeat("65535-65535,", 31) + "65535-65535"} {
		if _, err := Parse(bad); err == nil {
			t.Fatal("bad padding accepted")
		}
	}
	if _, err := Parse("stop=0"); err != nil {
		t.Fatal("explicit no padding scheme", err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestPaddingWriteErrorIsTerminal(t *testing.T) {
	if NewWriter(failWriter{}, MustDefault(), lowRandom{}).Write([]byte("x")) == nil {
		t.Fatal("write failure hidden")
	}
}
