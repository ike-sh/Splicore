package mkcp

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestWireGoldenAndConcatenation(t *testing.T) {
	rows := []struct {
		r   record
		hex string
	}{
		{record{token: 0x1234, code: dataCode, stamp: 0x01020304, sequence: 9, floor: 7, data: []byte{0xaa, 0xbb}}, "123401000102030400000009000000070002aabb"},
		{record{token: 0x1234, code: ackCode, edge: 100, next: 3, stamp: 0x01020304, numbers: []uint32{3, 8, 11}}, "123400000000006400000003010203040300000003000000080000000b"},
		{record{token: 0x1234, code: helloCode, closing: true, floor: 3, next: 5, interval: 100}, "12340301000000030000000500000064"},
		{record{token: 0x1234, code: endCode, floor: 3, next: 5, interval: 100}, "12340200000000030000000500000064"},
	}
	var combined []byte
	for _, row := range rows {
		want, _ := hex.DecodeString(row.hex)
		got := encode(row.r)
		if !bytes.Equal(got, want) {
			t.Fatalf("wire %x != %x", got, want)
		}
		parsed, e := decode(got, 1460)
		if e != nil || len(parsed) != 1 || !reflect.DeepEqual(parsed[0], row.r) {
			t.Fatal("roundtrip", parsed, e)
		}
		combined = append(combined, got...)
	}
	if got, e := decode(combined, 1460); e != nil || len(got) != 4 {
		t.Fatal("concatenation", e)
	}
	for _, n := range []int{0, 1, 2, 128, 255} {
		r := record{token: 1, code: ackCode, numbers: make([]uint32, n)}
		for i := range r.numbers {
			r.numbers[i] = uint32(i * 3)
		}
		got, e := decode(encode(r), 1460)
		if e != nil || len(got[0].numbers) != n {
			t.Fatal("ACK set", n, e)
		}
	}
}

func TestMalformedDatagrams(t *testing.T) {
	data := encode(record{token: 1, code: dataCode, data: []byte("payload")})
	ack := encode(record{token: 1, code: ackCode, numbers: []uint32{1, 2, 3}})
	for _, good := range [][]byte{data, ack, encode(record{token: 1, code: helloCode})} {
		for i := 0; i < len(good); i++ {
			if _, e := decode(good[:i], 1460); e == nil {
				t.Fatal("accepted truncation", i)
			}
		}
	}
	bad := [][]byte{{0, 1, 99, 0}, {0, 1, 1, 3}, make([]byte, 1461), append(data, 0)}
	mixed := append(append([]byte{}, data...), encode(record{token: 2, code: helloCode})...)
	bad = append(bad, mixed)
	empty := encode(record{token: 1, code: dataCode})
	bad = append(bad, empty)
	over := append([]byte{}, data...)
	over[16], over[17] = 255, 255
	bad = append(bad, over)
	count := append([]byte{}, ack...)
	count[16] = 255
	bad = append(bad, count)
	futureFloor := append([]byte{}, data...)
	futureFloor[15] = 1
	bad = append(bad, futureFloor)
	for _, b := range bad {
		if _, e := decode(b, 1460); e == nil {
			t.Fatalf("accepted malformed %x", b)
		}
	}
}

func TestSerialArithmeticWrap(t *testing.T) {
	if !earlier(0xffffffff, 0) || earlier(0, 0xffffffff) || earlier(3, 3) {
		t.Fatal("serial order")
	}
	if !within(0, 0xfffffffe, 4) || within(2, 0xfffffffe, 4) {
		t.Fatal("wrapped receive interval")
	}
}
