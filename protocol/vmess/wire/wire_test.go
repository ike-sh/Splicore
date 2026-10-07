package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Synthetic oracle inputs/results come from pinned Xray-core v26.3.27
// (Go module v1.260327.0), run outside this module. No live credential is used.
func unhex(t *testing.T, s string) []byte {
	t.Helper()
	v, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func oracleRequest() Request {
	r := Request{Destination: access.Endpoint{Host: "example.test", Port: 443}, Command: TCP, Security: AESGCM, Options: ChunkStream | LengthMask | GlobalPadding, response: 42}
	for i := range 16 {
		r.key[i] = byte(i + 1)
		r.iv[i] = byte(i + 17)
	}
	return r
}
func oracleKey() Key { var id [16]byte; id[6] = 0x10; id[8] = 0x80; id[15] = 1; return CommandKey(id) }
func TestXrayOracle(t *testing.T) {
	key := oracleKey()
	check := func(name string, b []byte, want string) {
		t.Helper()
		if hex.EncodeToString(b) != want {
			t.Fatalf("oracle mismatch: %s", name)
		}
	}
	check("command key", key[:], "ecb91c068f97a7a89b746e42614e6da0")
	root := KDF(key[:])
	check("root", root[:], "77625c6d629fd49c69a5c017100a6799c362d4fa1e2d84b5cfe229b21c4af443")
	id, err := AuthID(key, time.Unix(1710000000, 0), bytes.NewReader([]byte{1, 2, 3, 4}))
	if err != nil {
		t.Fatal(err)
	}
	check("AuthID", id[:], "17618d584b2ce6450b0360f01801b427")
	nonce := []byte{5, 6, 7, 8, 9, 10, 11, 12}
	for label, want := range map[string]string{
		"VMess Header AEAD Key":          "bf283ce2c0cfcb7a1080209fe439f5e0dbe1b7d67817cd807233b44c49c14665",
		"VMess Header AEAD Key_Length":   "b5f02ac96ad5a581ecd300fbf7e2f1be24fd21f32e9d60766057d094a90910ac",
		"VMess Header AEAD Nonce":        "228d6074b3ec987ade77d5a3959b4853aac7f809c58eec24df72a586d7bfe555",
		"VMess Header AEAD Nonce_Length": "db3ec99262426814dbf0e404d774e8e9cb076d5babe46a8ae76a88e41d060bc8",
	} {
		v := KDF(key[:], []byte(label), id[:], nonce)
		check(label, v[:], want)
	}
	r := oracleRequest()
	k, iv := r.Material(true)
	check("response key", k[:], "5dfbabeedf318bf33c0927c43d7630f5")
	check("response IV", iv[:], "72055d73b96127ded060a77d59fcf874")
	for label, want := range map[string]string{
		"AEAD Resp Header Len Key": "f881d4331ceee985f4299e77b2f3a7dc750fb94494157163d9d8b53bf1dd32bf",
		"AEAD Resp Header Key":     "48ddabe22d7a1b6ffabde4a58895de52c1ab771ba466cd8bb8ed4bf336de2156",
	} {
		v := KDF(k[:], []byte(label))
		check(label, v[:], want)
	}
	for label, want := range map[string]string{
		"AEAD Resp Header Len IV": "bec4fc255faf7d656928fa77a77865a21a79b87b6071fac275bdd5edd527d8d9",
		"AEAD Resp Header IV":     "651956a6fcce8c385e3351bc6531af7c1e2651fe44c101a980ccb28966c9845e",
	} {
		v := KDF(iv[:], []byte(label))
		check(label, v[:], want)
	}
	c, _ := NewChunk(r, false, nil)
	if c.next()%64 != 63 || c.next() != 0x2f3c {
		t.Fatal("SHAKE oracle mismatch")
	}
	r.Security = ChaCha
	chacha, _ := NewChunk(r, false, nil)
	expected, _ := chacha20poly1305.New(unhex(t, "190c4c105786a2121d85018939108a6c4916d5eb30e8784d0744ac2dfc9f1528"))
	var n [12]byte
	copy(n[2:], r.iv[2:12])
	payload := []byte("independent ChaCha expansion oracle")
	if !bytes.Equal(chacha.aead.Seal(nil, n[:], payload, nil), expected.Seal(nil, n[:], payload, nil)) {
		t.Fatal("ChaCha oracle mismatch")
	}
	u, ts, err := match(id, []User{NewUser("synthetic", key)}, time.Unix(1710000000, 0))
	if err != nil || ts != 1710000000 || u.ID != "synthetic" {
		t.Fatal("timestamp/CRC/user oracle mismatch")
	}
}
func TestClockAndReplayBoundaries(t *testing.T) {
	for _, offset := range []int64{-121, -120, -119, 0, 119, 120, 121} {
		if ValidTime(1000+offset, 1000) != (offset >= -120 && offset <= 120) {
			t.Fatal(offset)
		}
	}
	for _, pair := range [][2]int64{{-1, 0}, {0, -1}, {math.MinInt64, math.MaxInt64}, {math.MaxInt64, 1}, {1, math.MaxInt64}} {
		if ValidTime(pair[0], pair[1]) {
			t.Fatal("wrapped clock accepted")
		}
	}
	r := NewReplay(3)
	token := [][32]byte{{1}, {2}, {3}}
	if r.reserve(1000, 1120, token) != nil {
		t.Fatal("future boundary rejected")
	}
	if r.reserve(1000, 1000, [][32]byte{{4}}) == nil {
		t.Fatal("capacity did not fail closed")
	}
	if r.reserve(1240, 1120, token) == nil {
		t.Fatal("replay at inclusive boundary")
	}
	n, _, _ := r.Snapshot(1240)
	if n != 3 {
		t.Fatal("expired too early")
	}
	n, _, _ = r.Snapshot(1241)
	if n != 0 {
		t.Fatal("TTL retained")
	}
	if r.reserve(1000, 1120, token) == nil {
		t.Fatal("rollback resurrected authentication")
	}
	if r.reserve(math.MaxInt64, math.MaxInt64, token) == nil {
		t.Fatal("overflow expiry accepted")
	}
}
func TestConcurrentReplay(t *testing.T) {
	r := NewReplay(64)
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if r.reserve(1000, 1000, [][32]byte{{9}}) == nil {
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("accepted %d duplicates", wins.Load())
	}
}

type fragment struct{ io.Reader }

func (f fragment) Read(b []byte) (int, error) { return f.Reader.Read(b[:min(1, len(b))]) }
func TestRequestResponseAndReplay(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "example.test"} {
		r, err := NewRequest(access.Endpoint{Host: host, Port: 53}, UDP, ChaCha, ChunkStream|LengthMask, nil)
		if err != nil {
			t.Fatal(err)
		}
		key := oracleKey()
		now := time.Unix(1710000000, 0)
		b, err := EncodeRequest(key, r, now, nil)
		if err != nil {
			t.Fatal(err)
		}
		coalesced := bytes.NewReader(append(bytes.Clone(b), []byte("first")...))
		bank := NewReplay(100)
		got, user, err := ReadRequest(fragment{coalesced}, []User{NewUser("A", key), NewUser("B", Key{7})}, bank, now)
		if err != nil || user != "A" || got.Destination != r.Destination {
			t.Fatal("fragmented auth failed", err)
		}
		rest, _ := io.ReadAll(coalesced)
		if string(rest) != "first" {
			t.Fatal("coalesced payload consumed")
		}
		if _, _, err = ReadRequest(bytes.NewReader(b), []User{NewUser("A", key)}, bank, now); err == nil {
			t.Fatal("duplicate request accepted")
		}
		fresh, _ := EncodeRequest(key, r, now, nil)
		if _, _, err = ReadRequest(bytes.NewReader(fresh), []User{NewUser("A", key)}, bank, now); err == nil {
			t.Fatal("fresh AuthID reused session nonce")
		}
		response := EncodeResponse(r)
		if ReadResponse(fragment{bytes.NewReader(response)}, r) != nil {
			t.Fatal("fragmented response")
		}
		for _, pos := range []int{0, 17, 18, len(response) - 1} {
			bad := bytes.Clone(response)
			bad[pos] ^= 1
			if ReadResponse(bytes.NewReader(bad), r) == nil {
				t.Fatal("bad response accepted")
			}
		}
		for _, pos := range []int{0, 16, 33, 42, len(b) - 1} {
			bad := bytes.Clone(b)
			bad[pos] ^= 1
			if _, _, err = ReadRequest(bytes.NewReader(bad), []User{NewUser("A", key)}, NewReplay(100), now); err == nil {
				t.Fatal("bad header accepted")
			}
		}
	}
}
func TestChunkModes(t *testing.T) {
	for _, security := range []byte{AESGCM, ChaCha, None} {
		for _, options := range []byte{ChunkStream, ChunkStream | LengthMask, ChunkStream | LengthMask | GlobalPadding} {
			if security == None && options&GlobalPadding != 0 {
				continue
			}
			r := oracleRequest()
			r.Security = security
			r.Options = options
			for _, response := range []bool{false, true} {
				tx, _ := NewChunk(r, response, nil)
				rx, _ := NewChunk(r, response, nil)
				for _, size := range []int{1, 128, tx.MaxPayload()} {
					payload := bytes.Repeat([]byte{37}, size)
					b, err := tx.Encode(payload)
					if err != nil {
						t.Fatal(err)
					}
					got, err := rx.Read(fragment{bytes.NewReader(b)})
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatal("chunk boundary", security, options, err)
					}
				}
				b, _ := tx.Encode(nil)
				if _, err := rx.Read(bytes.NewReader(b)); err != io.EOF {
					t.Fatal("EOF marker")
				}
			}
		}
	}
}

type failingRandom struct{}

func (failingRandom) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestCounterRandomnessAndOptions(t *testing.T) {
	r := oracleRequest()
	tx, _ := NewChunk(r, false, nil)
	rx, _ := NewChunk(r, false, nil)
	tx.counter = 65535
	rx.counter = 65535
	b, err := tx.Encode([]byte("last"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = rx.Read(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Encode([]byte("wrap")); !errors.Is(err, ErrCounter) {
		t.Fatal("write counter wrapped")
	}
	if _, err = rx.Read(bytes.NewReader(nil)); !errors.Is(err, ErrCounter) {
		t.Fatal("read counter wrapped")
	}
	if _, err = NewRequest(r.Destination, TCP, AESGCM, ChunkStream, failingRandom{}); err == nil {
		t.Fatal("session entropy failure ignored")
	}
	if _, err = AuthID(oracleKey(), time.Now(), failingRandom{}); err == nil {
		t.Fatal("auth entropy failure ignored")
	}
	if _, err = EncodeRequest(oracleKey(), r, time.Now(), failingRandom{}); err == nil {
		t.Fatal("padding entropy failure ignored")
	}
	c, _ := NewChunk(r, false, failingRandom{})
	if _, err = c.Encode([]byte("x")); err == nil {
		t.Fatal("global padding entropy failure ignored")
	}
	for _, o := range []byte{2, 16, 32, 64, 128, ChunkStream | GlobalPadding} {
		r.Options = o
		if r.Validate() == nil {
			t.Fatal("unsupported option", o)
		}
	}
}
func TestBoundsAndChecksum(t *testing.T) {
	r := oracleRequest()
	plain, _ := r.encode(nil)
	for i := range plain {
		bad := bytes.Clone(plain)
		bad[i] ^= 1
		if _, err := DecodeRequest(bad); err == nil {
			t.Fatal("checksum mutation accepted")
		}
	}
	for _, b := range [][]byte{nil, make([]byte, 46), make([]byte, MaxHeader+1)} {
		if _, err := DecodeRequest(b); err == nil {
			t.Fatal("length bound")
		}
	}
	for _, security := range []byte{AESGCM, ChaCha} {
		r.Security = security
		c, _ := NewChunk(r, false, nil)
		b, _ := c.Encode([]byte("verified"))
		b[3] ^= 1
		d, _ := NewChunk(r, false, nil)
		v, err := d.Read(bytes.NewReader(b))
		if err == nil || len(v) != 0 {
			t.Fatal("unauthenticated data exposed")
		}
	}
}
func FuzzRequestModel(f *testing.F) {
	r := oracleRequest()
	b, _ := r.encode(nil)
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeRequest(b)
		if err == nil && r.Validate() != nil {
			t.Fatal("invalid accepted model")
		}
	})
}
func FuzzAEADHeader(f *testing.F) {
	b, _ := EncodeRequest(oracleKey(), oracleRequest(), time.Unix(1710000000, 0), nil)
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		var auth [16]byte
		if len(b) >= 16 {
			copy(auth[:], b[:16])
			b = b[16:]
		}
		v, err := OpenHeader(bytes.NewReader(b), oracleKey(), auth)
		if err == nil {
			if len(v) > MaxHeader {
				t.Fatal("header bound")
			}
			_, _ = DecodeRequest(v)
		}
	})
}

func TestValidChecksumMalformedFields(t *testing.T) {
	plain, _ := oracleRequest().encode(bytes.NewReader(make([]byte, 16)))
	for name, mutation := range map[string]func([]byte){
		"version": func(b []byte) { b[0] = 2 }, "reserved": func(b []byte) { b[36] = 1 },
		"option": func(b []byte) { b[34] = 2 }, "authenticated-length": func(b []byte) { b[34] |= 16 },
		"security": func(b []byte) { b[35] = 2 }, "command": func(b []byte) { b[37] = 3 },
		"port": func(b []byte) { b[38] = 0; b[39] = 0 }, "address-kind": func(b []byte) { b[40] = 4 },
		"domain-length": func(b []byte) { b[41] = 255 }, "padding": func(b []byte) { b[35] |= 0xf0 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := bytes.Clone(plain)
			mutation(bad)
			binary.BigEndian.PutUint32(bad[len(bad)-4:], checksum(bad[:len(bad)-4]))
			if _, err := DecodeRequest(bad); err == nil {
				t.Fatal("malformed fields accepted")
			}
		})
	}
	for _, size := range []uint16{0, 46, MaxHeader + 1, 65535} {
		var auth [16]byte
		var nonce [8]byte
		lc, ln := headerCipher(oracleKey(), "VMess Header AEAD Key_Length", auth, nonce)
		prefix := lc.Seal(nil, ln[:], binary.BigEndian.AppendUint16(nil, size), auth[:])
		prefix = append(prefix, nonce[:]...)
		input := bytes.NewReader(append(prefix, []byte("unread")...))
		if _, err := OpenHeader(input, oracleKey(), auth); err == nil || input.Len() != 6 {
			t.Fatal("allocation before length validation")
		}
	}
}
func TestResponseOptionDeclarations(t *testing.T) {
	r := oracleRequest()
	for _, option := range []byte{0, r.Options, 2, 16, 128} {
		b := EncodeResponse(r)
		k, n := responseCipher(r, "AEAD Resp Header Key", "AEAD Resp Header IV")
		b = gcm(k[:]).Seal(b[:18], n[:], []byte{r.response, option, 0, 0}, nil)
		err := ReadResponse(bytes.NewReader(b), r)
		if (err == nil) != (option == 0 || option == r.Options) {
			t.Fatal("response options", option, err)
		}
	}
}
func TestAuthenticationReplayCapacityStress(t *testing.T) {
	const attempts = 22000
	now := time.Unix(1710000000, 0)
	bank := NewReplay(65536)
	users := make([]User, 16)
	for i := range users {
		users[i] = NewUser("synthetic", Key{byte(i + 1)})
	}
	begin := time.Now()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	invalid := 0
	for i := range 5000 {
		var auth [16]byte
		binary.BigEndian.PutUint64(auth[:], uint64(i))
		if _, _, err := match(auth, users, now); err == nil {
			t.Fatal("invalid AuthID accepted")
		}
		invalid++
	}
	accepted, duplicates, clockInvalid, full := 0, 0, 0, 0
	for i := range attempts {
		r, err := NewRequest(access.Endpoint{Host: "127.0.0.1", Port: 80}, TCP, AESGCM, ChunkStream, nil)
		if err != nil {
			t.Fatal(err)
		}
		key := users[i%16].key
		b, err := EncodeRequest(key, r, now, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = ReadRequest(bytes.NewReader(b), users, bank, now)
		if err == nil {
			accepted++
		} else {
			full++
		}
		if _, _, err = ReadRequest(bytes.NewReader(b), users, bank, now); err == nil {
			t.Fatal("duplicate accepted")
		}
		duplicates++
		if _, _, err = ReadRequest(bytes.NewReader(b), users, bank, now.Add(121*time.Second)); err == nil {
			t.Fatal("clock-invalid accepted")
		}
		clockInvalid++
	}
	entries, peak, capacity := bank.Snapshot(now.Unix())
	final, _, _ := bank.Snapshot(now.Add(241 * time.Second).Unix())
	runtime.ReadMemStats(&after)
	if accepted != 21845 || entries != 65535 || peak > capacity || final != 0 {
		t.Fatal("replay capacity/expiry", accepted, entries, peak, final)
	}
	t.Logf("duration=%s max_users=16 invalid_auth_rejected=%d valid_authentications=%d duplicate_rejected=%d clock_invalid_rejected=%d capacity_rejected=%d replay_peak=%d final=%d unexpected_accepts=0 allocated_bytes=%d", time.Since(begin), invalid, accepted, duplicates, clockInvalid, full, peak, final, after.TotalAlloc-before.TotalAlloc)
}
func FuzzResponse(f *testing.F) {
	r := oracleRequest()
	f.Add(EncodeResponse(r))
	f.Fuzz(func(t *testing.T, b []byte) { _ = ReadResponse(bytes.NewReader(b), r) })
}
func fuzzChunk(f *testing.F, security byte) {
	r := oracleRequest()
	r.Security = security
	if security == None {
		r.Options = ChunkStream | LengthMask
	}
	c, _ := NewChunk(r, false, nil)
	seed, _ := c.Encode([]byte("mutation"))
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		c, _ := NewChunk(r, false, nil)
		v, _ := c.Read(bytes.NewReader(b))
		if len(v) > MaxChunk {
			t.Fatal("chunk bound")
		}
	})
}
func FuzzAESChunk(f *testing.F)    { fuzzChunk(f, AESGCM) }
func FuzzChaChaChunk(f *testing.F) { fuzzChunk(f, ChaCha) }
func FuzzNoneChunk(f *testing.F)   { fuzzChunk(f, None) }
func FuzzAuthID(f *testing.F) {
	f.Add(make([]byte, 16), int64(1710000000))
	f.Fuzz(func(t *testing.T, b []byte, now int64) {
		if len(b) != 16 {
			return
		}
		var auth [16]byte
		copy(auth[:], b)
		_, ts, err := match(auth, []User{NewUser("synthetic", oracleKey())}, time.Unix(now, 0))
		if err == nil && !ValidTime(ts, now) {
			t.Fatal("invalid time accepted")
		}
	})
}

// UDP is a sequence of indivisible bounded chunks, rather than a byte stream
// that can discard packet boundaries. Exercise coalesced/fragmented sequences.
func FuzzUDPChunks(f *testing.F) {
	r := oracleRequest()
	r.Command = UDP
	r.Options = ChunkStream | LengthMask
	tx, _ := NewChunk(r, false, nil)
	one, _ := tx.Encode([]byte("first datagram"))
	two, _ := tx.Encode([]byte("second datagram"))
	f.Add(append(one, two...))
	f.Fuzz(func(t *testing.T, b []byte) {
		reader := bytes.NewReader(b)
		rx, _ := NewChunk(r, false, nil)
		for range 64 {
			before := reader.Len()
			v, err := rx.Read(fragment{reader})
			if err != nil {
				return
			}
			if len(v) > MaxChunk || reader.Len() >= before {
				t.Fatal("UDP chunk bounds/progress")
			}
			if reader.Len() == 0 {
				return
			}
		}
	})
}
