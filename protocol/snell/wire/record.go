// Package wire owns Snell records, commands and logical tunnel lifetimes.
// It uses standard cryptographic primitives and no third-party network types.
package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/bits"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

var (
	ErrFrame          = errors.New("invalid Snell frame")
	ErrAuthentication = errors.New("Snell authentication failed")
	ErrExhausted      = errors.New("Snell direction exhausted")
)

type Key struct {
	version int
	psk     []byte
	shape   *recipe
}

func NewKey(version int, psk string) (*Key, error) {
	if version != 4 && version != 5 && version != 6 || len(psk) < 12 || len(psk) > 255 {
		return nil, ErrFrame
	}
	k := &Key{version: version, psk: []byte(psk)}
	if version == 6 {
		k.shape = makeRecipe(k.psk)
	}
	return k, nil
}

type cryptoState struct {
	aead  cipher.AEAD
	nonce [12]byte
	used  uint32
}

func (s *cryptoState) initialize(k *Key, salt []byte) error {
	digest := argon2.IDKey(k.psk, salt, 3, 8, 1, 32)
	block, err := aes.NewCipher(digest[:16])
	clear(digest)
	if err != nil {
		return err
	}
	s.aead, err = cipher.NewGCM(block)
	return err
}
func (s *cryptoState) advance() error {
	for i := range s.nonce {
		s.nonce[i]++
		if s.nonce[i] != 0 {
			return nil
		}
	}
	return ErrExhausted
}
func exactWrite(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func readBytes(r io.Reader, n int) ([]byte, error) {
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	return p, err
}

// Decoder serializes record reads. Returned slices are fresh owned allocations;
// subsequent reads and raw socket Close never mutate or release them. EOF is a
// logical delimiter; Next can be called by the next tunnel after ownership joins.
type Decoder struct {
	mu    sync.Mutex
	input io.Reader
	key   *Key
	cryptoState
	failed error
}

func NewDecoder(r io.Reader, k *Key) *Decoder { return &Decoder{input: r, key: k} }
func (d *Decoder) Next() (p []byte, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failed != nil {
		return nil, d.failed
	}
	defer func() {
		if err != nil && !errors.Is(err, io.EOF) {
			d.failed = err
		}
	}()
	if d.used == math.MaxUint32 {
		return nil, ErrExhausted
	}
	shape := d.key.shape
	if d.aead == nil {
		size := 16
		if shape != nil {
			size = shape.saltSize
		}
		block, e := readBytes(d.input, size)
		if e != nil {
			return nil, e
		}
		salt := block
		if shape != nil {
			salt = make([]byte, 16)
			for i, pos := range shape.saltPositions {
				salt[i] = block[pos] ^ shape.saltMasks[i]
			}
		}
		if e = d.initialize(d.key, salt); e != nil {
			return nil, e
		}
	}
	prefixSize := 0
	if shape != nil {
		prefixSize = shape.rangeAt(33, d.used, 0, shape.v[14], shape.v[15])
	}
	head, e := readBytes(d.input, prefixSize+23)
	if e != nil {
		return nil, e
	}
	prefix := head[:prefixSize]
	if shape == nil {
		prefix = nil
	}
	header, e := d.aead.Open(nil, d.nonce[:], head[prefixSize:], prefix)
	if e != nil {
		return nil, ErrAuthentication
	}
	if e = d.advance(); e != nil {
		return nil, e
	}
	if header[0] != 4 {
		return nil, ErrFrame
	}
	paddingSize := int(binary.BigEndian.Uint16(header[3:5]))
	size := int(binary.BigEndian.Uint16(header[5:7]))
	seq := d.used
	d.used++
	if size == 0 {
		if shape != nil {
			if _, e = readBytes(d.input, paddingSize); e != nil {
				return nil, e
			}
		}
		return nil, io.EOF
	}
	region, e := readBytes(d.input, paddingSize+size+16)
	if e != nil {
		return nil, e
	}
	padding, body := region[:paddingSize], region[paddingSize:]
	if shape != nil {
		shape.swap(seq, padding, body)
	} else {
		classicSwap(padding, body)
	}
	aad := padding
	if shape == nil {
		aad = nil
	}
	p, e = d.aead.Open(nil, d.nonce[:], body, aad)
	if e != nil {
		return nil, ErrAuthentication
	}
	if e = d.advance(); e != nil {
		return nil, e
	}
	return p, nil
}

// Encoder has a narrow direction lock covering its sequence and socket write.
// No other connection or read direction shares that lock or its scratch state.
type Encoder struct {
	mu     sync.Mutex
	output io.Writer
	key    *Key
	cryptoState
	failed                         error
	firstPadding                   int
	last                           int64
	budget, batchBudget, batchLeft int
}

func NewEncoder(w io.Writer, k *Key) *Encoder { return &Encoder{output: w, key: k} }
func (w *Encoder) initializeWriter() error {
	if w.aead != nil {
		return nil
	}
	salt, e := readBytes(rand.Reader, 16)
	if e != nil {
		return e
	}
	if e = w.initialize(w.key, salt); e != nil {
		return e
	}
	if w.key.shape == nil {
		b, e := readBytes(rand.Reader, 1)
		if e != nil {
			return e
		}
		w.firstPadding = 256 + int(b[0])
		return exactWrite(w.output, salt)
	}
	r := w.key.shape
	block := make([]byte, r.saltSize)
	r.fill(math.MaxUint32, block)
	for i, pos := range r.saltPositions {
		block[pos] = salt[i] ^ r.saltMasks[i]
	}
	return exactWrite(w.output, block)
}
func (w *Encoder) limit(now int64) int {
	shape := w.key.shape
	if shape != nil {
		if w.last == 0 || now-w.last > int64(shape.v[27]) {
			w.budget = shape.v[22]
		}
		size := w.budget
		switch shape.v[21] {
		case 1:
			size = shape.buckets[0][shape.prf(38, w.used, uint32(size))%8]
		case 2:
			size += shape.rangeAt(39, w.used, uint32(size), -shape.v[25], shape.v[25])
		}
		size = max(64, min(size, shape.v[23]))
		if w.used == 0 {
			size = min(size, shape.firstCap)
		}
		w.budget = min(w.budget+shape.v[24], shape.v[23])
		w.last = now
		return size
	}
	size := w.budget
	if w.used == 0 && w.last == 0 {
		size = 1460 - 55 - w.firstPadding
	} else if w.last == 0 || now-w.last >= 31 {
		size = 1421
	}
	w.budget = min(size+1421, 16383)
	w.last = now
	return size
}
func (w *Encoder) emit(payload []byte) error {
	if len(payload) > 65535 {
		return ErrFrame
	}
	if w.used == math.MaxUint32 {
		return ErrExhausted
	}
	prefixSize, paddingSize := 0, 0
	shape := w.key.shape
	if shape != nil {
		prefixSize, paddingSize = shape.layout(w.used, len(payload), w.used == 0)
	} else if w.used == 0 && len(payload) > 0 {
		paddingSize = w.firstPadding
	}
	prefix := make([]byte, prefixSize)
	if shape != nil {
		shape.fill(w.used, prefix)
	} else {
		prefix = nil
	}
	header := []byte{4, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(header[3:5], uint16(paddingSize))
	binary.BigEndian.PutUint16(header[5:7], uint16(len(payload)))
	cipherHeader := w.aead.Seal(nil, w.nonce[:], header, prefix)
	if e := w.advance(); e != nil {
		return e
	}
	padding := make([]byte, paddingSize)
	if shape != nil {
		shape.fill(w.used, padding)
	}
	var body []byte
	if len(payload) > 0 {
		aad := padding
		if shape == nil {
			aad = nil
		}
		body = w.aead.Seal(nil, w.nonce[:], payload, aad)
		if e := w.advance(); e != nil {
			return e
		}
		if shape != nil {
			shape.swap(w.used, padding, body)
		} else {
			if e := densityPadding(padding, body); e != nil {
				return e
			}
			classicSwap(padding, body)
		}
	}
	w.used++
	out := make([]byte, 0, len(prefix)+23+len(padding)+len(body))
	out = append(out, prefix...)
	out = append(out, cipherHeader...)
	out = append(out, padding...)
	out = append(out, body...)
	return exactWrite(w.output, out)
}

// Record preserves a datagram boundary, or emits one logical EOF for nil data.
func (w *Encoder) Record(p []byte) (err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed != nil {
		return w.failed
	}
	defer func() {
		if err != nil && !errors.Is(err,ErrFrame) {
			w.failed = err
		}
	}()
	maximum := 65535
	if w.key.shape == nil { maximum = 16383 }
	if len(p) > maximum {
		return ErrFrame
	}
	if err = w.initializeWriter(); err != nil {
		return err
	}
	oldBudget,oldLast := w.budget,w.last
	limit := w.limit(time.Now().Unix())
	if w.key.shape == nil && len(p)>limit {
		w.budget,w.last = oldBudget,oldLast
		return ErrFrame
	}
	if w.key.version == 5 { w.batchLeft = 0 }
	return w.emit(p)
}
func (w *Encoder) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed != nil {
		return 0, w.failed
	}
	if len(p) == 0 {
		return 0, nil
	}
	defer func() {
		if err != nil {
			w.failed = err
		}
	}()
	if err = w.initializeWriter(); err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	callBudget := 0
	if w.key.version == 4 {
		callBudget = w.limit(now)
	}
	for len(p) > 0 {
		size := callBudget
		if w.key.shape != nil {
			size = w.limit(now)
		} else if w.key.version == 5 {
			if w.batchLeft == 0 || now-w.last >= 31 {
				w.batchBudget = w.limit(now)
				w.batchLeft = 192 * 1024
			}
			size = min(w.batchBudget, w.batchLeft)
			w.last = now
		}
		size = min(size, len(p))
		if err = w.emit(p[:size]); err != nil {
			return n, err
		}
		if w.key.version == 5 {
			w.batchLeft -= size
		}
		n += size
		p = p[size:]
	}
	return n, nil
}

func classicSwap(a, b []byte) {
	for i := 0; i < min(len(a), len(b)); i += 2 {
		a[i], b[i] = b[i], a[i]
	}
}
func random31() (int, error) {
	var b [4]byte
	_, err := io.ReadFull(rand.Reader, b[:])
	return int(binary.LittleEndian.Uint32(b[:]) & 0x7fffffff), err
}
func densityPadding(p, ciphertext []byte) error {
	if len(p) == 0 {
		return nil
	}
	ones := 0
	for _, b := range ciphertext[:len(ciphertext)&^3] {
		ones += bits.OnesCount8(b)
	}
	zeros := 8*len(ciphertext) - ones
	fallback := func() error { _, e := io.ReadFull(rand.Reader, p); return e }
	if zeros == 0 || float64(ones)/float64(zeros) <= 0.5 || float64(ones)/float64(zeros) >= 1.6 {
		return fallback()
	}
	random, e := random31()
	if e != nil {
		return e
	}
	ratio := 1.6
	if ones > zeros {
		ratio = 0.4
	}
	ratio += float64(random) / 2147483647 / 10
	wanted := int(float64(8*(len(ciphertext)+len(p)))*ratio/(1+ratio) - float64(ones))
	if wanted < 0 || wanted > 8*len(p) {
		return fallback()
	}
	positions := make([]int, 8*len(p))
	for i := range positions {
		positions[i] = i
	}
	for i := 0; i < len(positions)-1; i++ {
		random, e = random31()
		if e != nil {
			return e
		}
		j := i + random/(2147483647/(len(positions)-i)+1)
		positions[i], positions[j] = positions[j], positions[i]
	}
	// Equivalently shuffle a bit vector whose first wanted entries are ones.
	for packed, original := range positions {
		if original < wanted {
			p[packed/8] |= 1 << uint(packed%8)
		}
	}
	return nil
}
