package streamtransport

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"golang.org/x/net/http/httpguts"
)

// Range is the bounded integer/range dialect shared by XHTTP controls.
// Zero is retained as an explicit default/unlimited sentinel, as appropriate.
type Range struct{ Min, Max int32 }

// First data shares the existing association budget. Allow one leg's response
// admission and a separate upload leg's dial/security admission before packet
// coalescing. Keep these transport budgets independent of proxy authentication.
const XHTTPAdmissionTimeout = 30 * time.Second
const XHTTPLegAdmissionTimeout = 5 * time.Second
const XHTTPMaxFirstPacketIntervalMs = int32((XHTTPAdmissionTimeout - 2*XHTTPLegAdmissionTimeout) / time.Millisecond)
const XHTTPMinSessionEntropyBits = 122 // Matches the default UUIDv4's random bits.

var rangeText = regexp.MustCompile(`^(-?[0-9]+)(?:-(-?[0-9]+))?$`)

func (r *Range) UnmarshalJSON(b []byte) error {
	var s string
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		return bad()
	}
	if json.Unmarshal(b, &s) != nil {
		s = string(b)
	}
	if s == "" {
		*r = Range{}
		return nil
	}
	m := rangeText.FindStringSubmatch(s)
	if m == nil {
		return bad()
	}
	a, e := strconv.ParseInt(m[1], 10, 32)
	if e != nil {
		return bad()
	}
	z := a
	if m[2] != "" {
		z, e = strconv.ParseInt(m[2], 10, 32)
		if e != nil {
			return bad()
		}
	}
	if a > z {
		return bad()
	}
	*r = Range{int32(a), int32(z)}
	return nil
}
func (r Range) MarshalJSON() ([]byte, error) {
	if r.Min == r.Max {
		return json.Marshal(r.Min)
	}
	return json.Marshal(fmt.Sprintf("%d-%d", r.Min, r.Max))
}
func (r Range) Within(lo, hi int32) bool { return r.Min >= lo && r.Min <= r.Max && r.Max <= hi }
func (r Range) Default(a, b int32) Range {
	if r == (Range{}) {
		return Range{a, b}
	}
	return r
}
func (r Range) Pick(entropy io.Reader) (int, error) {
	if r.Min > r.Max {
		return 0, bad()
	}
	n, e := rand.Int(entropy, big.NewInt(int64(r.Max)-int64(r.Min)+1))
	if e != nil {
		return 0, e
	}
	return int(int64(r.Min) + n.Int64()), nil
}

type XMUX struct {
	MaxConcurrency Range `json:"maxConcurrency,omitempty"`
	MaxConnections Range `json:"maxConnections,omitempty"`
	Reuse          Range `json:"cMaxReuseTimes,omitempty"`
	Requests       Range `json:"hMaxRequestTimes,omitempty"`
	Lifetime       Range `json:"hMaxReusableSecs,omitempty"`
	KeepAlive      int64 `json:"hKeepAlivePeriod,omitempty"`
}

func (m *XMUX) UnmarshalJSON(b []byte) error {
	type plain XMUX
	var fields map[string]json.RawMessage
	if jsonstrict.Decode(b, &fields) != nil || fields == nil {
		return bad()
	}
	allowed := map[string]bool{"maxConcurrency": true, "maxConnections": true, "cMaxReuseTimes": true, "hMaxRequestTimes": true, "hMaxReusableSecs": true, "hKeepAlivePeriod": true}
	for k, v := range fields {
		if !allowed[k] || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return bad()
		}
	}
	var p plain
	if jsonstrict.Decode(b, &p) != nil {
		return bad()
	}
	*m = XMUX(p)
	return nil
}

type Download struct {
	Endpoint  access.Endpoint  `json:"endpoint"`
	Transport Config           `json:"transport"`
	Security  string           `json:"security"`
	TLS       access.ClientTLS `json:"tls"`
}

// XHTTP contains transport controls only. Common path/authority/headers live in
// Config; a download leg uses the same canonical transport and public security.
type XHTTP struct {
	Mode              string    `json:"mode,omitempty"`
	Padding           Range     `json:"xPaddingBytes,omitempty"`
	PaddingObfs       bool      `json:"xPaddingObfsMode,omitempty"`
	PaddingKey        string    `json:"xPaddingKey,omitempty"`
	PaddingHeader     string    `json:"xPaddingHeader,omitempty"`
	PaddingPlacement  string    `json:"xPaddingPlacement,omitempty"`
	PaddingMethod     string    `json:"xPaddingMethod,omitempty"`
	Method            string    `json:"uplinkHTTPMethod,omitempty"`
	SessionPlacement  string    `json:"sessionIDPlacement,omitempty"`
	SessionKey        string    `json:"sessionIDKey,omitempty"`
	SessionTable      string    `json:"sessionIDTable,omitempty"`
	SessionLength     Range     `json:"sessionIDLength,omitempty"`
	SequencePlacement string    `json:"seqPlacement,omitempty"`
	SequenceKey       string    `json:"seqKey,omitempty"`
	DataPlacement     string    `json:"uplinkDataPlacement,omitempty"`
	DataKey           string    `json:"uplinkDataKey,omitempty"`
	Chunk             Range     `json:"uplinkChunkSize,omitempty"`
	NoGRPC            bool      `json:"noGRPCHeader,omitempty"`
	NoSSE             bool      `json:"noSSEHeader,omitempty"`
	PacketBytes       Range     `json:"scMaxEachPostBytes,omitempty"`
	Interval          Range     `json:"scMinPostsIntervalMs,omitempty"`
	Buffered          int64     `json:"scMaxBufferedPosts,omitempty"`
	KeepAlive         Range     `json:"scStreamUpServerSecs,omitempty"`
	HeaderBytes       int32     `json:"serverMaxHeaderBytes,omitempty"`
	XMUX              *XMUX     `json:"xmux,omitempty"`
	Download          *Download `json:"downloadSettings,omitempty"`
}

func (x *XHTTP) UnmarshalJSON(b []byte) error {
	type plain XHTTP
	var fields map[string]json.RawMessage
	if len(b) > 65536 || bytes.Count(b, []byte(`"downloadSettings"`)) > 1 || jsonstrict.Decode(b, &fields) != nil || fields == nil {
		return bad()
	}
	allowed := map[string]bool{}
	// Optional fields are enumerated explicitly so folded spellings never pass.
	for _, k := range strings.Fields("mode xPaddingBytes xPaddingObfsMode xPaddingKey xPaddingHeader xPaddingPlacement xPaddingMethod uplinkHTTPMethod sessionIDPlacement sessionIDKey sessionIDTable sessionIDLength seqPlacement seqKey uplinkDataPlacement uplinkDataKey uplinkChunkSize noGRPCHeader noSSEHeader scMaxEachPostBytes scMinPostsIntervalMs scMaxBufferedPosts scStreamUpServerSecs serverMaxHeaderBytes xmux downloadSettings") {
		allowed[k] = true
	}
	for k, v := range fields {
		if !allowed[k] || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return bad()
		}
	}
	var p plain
	if jsonstrict.Decode(b, &p) != nil {
		return bad()
	}
	*x = XHTTP(p)
	return nil
}
func (x XHTTP) Clone() XHTTP {
	if x.XMUX != nil {
		m := *x.XMUX
		x.XMUX = &m
	}
	if x.Download != nil {
		d := *x.Download
		d.Transport = d.Transport.Clone()
		d.TLS.ALPN = append([]string(nil), d.TLS.ALPN...)
		x.Download = &d
	}
	return x
}
func (x XHTTP) Normalized() XHTTP {
	if x.Mode == "" {
		x.Mode = "auto"
	}
	x.Padding = x.Padding.Default(100, 1000)
	if x.PaddingKey == "" {
		x.PaddingKey = "x_padding"
	}
	if x.PaddingHeader == "" {
		x.PaddingHeader = "X-Padding"
	}
	if x.PaddingPlacement == "" {
		x.PaddingPlacement = "queryInHeader"
	}
	if x.PaddingMethod == "" {
		x.PaddingMethod = "repeat-x"
	}
	if x.Method == "" {
		x.Method = "POST"
	}
	x.Method = strings.ToUpper(x.Method)
	if x.SessionPlacement == "" {
		x.SessionPlacement = "path"
	}
	if x.SequencePlacement == "" {
		x.SequencePlacement = "path"
	}
	for _, v := range []struct {
		place string
		key   *string
		stem  string
	}{{x.SessionPlacement, &x.SessionKey, "session"}, {x.SequencePlacement, &x.SequenceKey, "seq"}} {
		if *v.key == "" {
			if v.place == "header" {
				*v.key = "X-" + strings.Title(v.stem)
			} else if v.place != "path" {
				*v.key = "x_" + v.stem
			}
		}
	}
	if x.DataPlacement == "" {
		x.DataPlacement = "auto"
	}
	if x.DataKey == "" {
		x.DataKey = "X-Data"
		if x.DataPlacement == "cookie" {
			x.DataKey = "x_data"
		}
	}
	x.PacketBytes = x.PacketBytes.Default(1000000, 1000000)
	x.Interval = x.Interval.Default(30, 30)
	if x.Buffered == 0 {
		x.Buffered = 30
	}
	x.KeepAlive = x.KeepAlive.Default(20, 80)
	if x.HeaderBytes == 0 {
		x.HeaderBytes = 8192
	}
	if x.Chunk == (Range{}) {
		switch x.DataPlacement {
		case "header":
			x.Chunk = Range{3000, 4000}
		case "cookie":
			x.Chunk = Range{2048, 3072}
		default:
			x.Chunk = x.PacketBytes
		}
	}
	x.Chunk.Min = max(x.Chunk.Min, 64)
	x.Chunk.Max = max(x.Chunk.Max, 64)
	if x.XMUX == nil || *x.XMUX == (XMUX{}) {
		x.XMUX = &XMUX{MaxConnections: Range{3, 3}, Requests: Range{600, 900}, Lifetime: Range{1800, 3000}}
	}
	return x
}
func (x XHTTP) SelectMode(reality bool) string {
	mode := x.Normalized().Mode
	if mode == "auto" {
		mode = "packet-up"
		if reality {
			mode = "stream-one"
			if x.Download != nil {
				mode = "stream-up"
			}
		}
	}
	return mode
}
func (c Config) XHTTPPath() (string, string) {
	x := XHTTP{}
	if c.XHTTP != nil {
		x = *c.XHTTP
	}
	x = x.Normalized()
	p, q, _ := strings.Cut(c.Path, "?")
	if decoded, err := url.PathUnescape(p); err == nil {
		p = decoded
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if (x.SessionPlacement == "path" || x.SequencePlacement == "path") && !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p, q
}

var tables = map[string]string{"ALPHABET": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "Alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "BASE36": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", "Base62": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "HEX": "0123456789ABCDEF", "alphabet": "abcdefghijklmnopqrstuvwxyz", "base36": "0123456789abcdefghijklmnopqrstuvwxyz", "hex": "0123456789abcdef", "number": "0123456789"}

func (x XHTTP) Alphabet() string {
	if v, ok := tables[x.SessionTable]; ok {
		return v
	}
	return x.SessionTable
}
func placement(p string) bool { return p == "path" || p == "header" || p == "query" || p == "cookie" }
func (x XHTTP) Validate() error {
	n := x.Normalized()
	if !x.PaddingObfs && (x.PaddingKey != "" || x.PaddingHeader != "" || x.PaddingPlacement != "") {
		return bad()
	}
	if !x.Chunk.Within(0, 8<<20) {
		return bad()
	}
	if x.Chunk != (Range{}) && n.DataPlacement != "header" && n.DataPlacement != "cookie" {
		return bad()
	}
	if x.SessionPlacement == "path" && x.SessionKey != "" || x.SequencePlacement == "path" && x.SequenceKey != "" || x.DataPlacement == "body" && x.DataKey != "" {
		return bad()
	}
	if n.Mode != "auto" && n.Mode != "packet-up" && n.Mode != "stream-up" && n.Mode != "stream-one" {
		return bad()
	}
	if !n.Padding.Within(1, 16384) || !n.PacketBytes.Within(1, 8<<20) || !n.Interval.Within(-1, XHTTPMaxFirstPacketIntervalMs) || !n.KeepAlive.Within(-1, 3600) || !n.Chunk.Within(64, 8<<20) || n.Buffered < 1 || n.Buffered > 1024 || n.HeaderBytes < 1024 || n.HeaderBytes > 1<<20 {
		return bad()
	}
	if n.PaddingMethod != "repeat-x" && n.PaddingMethod != "tokenish" {
		return bad()
	}
	if n.PaddingPlacement != "queryInHeader" && n.PaddingPlacement != "query" && n.PaddingPlacement != "cookie" && n.PaddingPlacement != "header" {
		return bad()
	}
	if !placement(n.SessionPlacement) || !placement(n.SequencePlacement) {
		return bad()
	}
	if n.DataPlacement != "auto" && n.DataPlacement != "body" && n.DataPlacement != "header" && n.DataPlacement != "cookie" {
		return bad()
	}
	if (n.DataPlacement == "header" || n.DataPlacement == "cookie" || n.Method == "GET") && n.Mode != "packet-up" {
		return bad()
	}
	if !httpguts.ValidHeaderFieldName(n.Method) || n.Method == "OPTIONS" || n.Method == "CONNECT" || n.Method == "TRACE" || n.Method == "HEAD" {
		return bad()
	}
	for _, s := range []string{n.PaddingKey, n.PaddingHeader, n.SessionKey, n.SequenceKey, n.DataKey} {
		if len(s) > 128 || s != "" && !httpguts.ValidHeaderFieldName(s) {
			return bad()
		}
	}
	for _, v := range []struct{ placement, key string }{{"header", n.PaddingHeader}, {n.SessionPlacement, n.SessionKey}, {n.SequencePlacement, n.SequenceKey}, {n.DataPlacement, n.DataKey}} {
		if v.placement == "header" && reservedHeader(v.key) {
			return bad()
		}
	}
	if n.PaddingObfs {
		padPlace, padKey := n.PaddingPlacement, n.PaddingKey
		if padPlace == "queryInHeader" || padPlace == "header" {
			padPlace, padKey = "header", n.PaddingHeader
		}
		for _, v := range []struct{ placement, key string }{{n.SessionPlacement, n.SessionKey}, {n.SequencePlacement, n.SequenceKey}} {
			if v.placement == padPlace && strings.EqualFold(v.key, padKey) {
				return bad()
			}
		}
	}
	if n.SessionPlacement != "path" && n.SessionPlacement == n.SequencePlacement && (n.SessionKey == n.SequenceKey || n.SessionPlacement == "header" && strings.EqualFold(n.SessionKey, n.SequenceKey)) {
		return bad()
	}
	// The data namespace is generated as key-N headers. Include auto because
	// receive-side auto accepts header data even though its client sends a body.
	keys := []string{}
	if n.SessionPlacement == "header" {
		keys = append(keys, n.SessionKey)
	}
	if n.SequencePlacement == "header" {
		keys = append(keys, n.SequenceKey)
	}
	if !n.PaddingObfs {
		keys = append(keys, "Referer", "X-Padding")
	} else if n.PaddingPlacement == "header" || n.PaddingPlacement == "queryInHeader" {
		keys = append(keys, n.PaddingHeader)
	}
	for i, key := range keys {
		for _, other := range keys[:i] {
			if strings.EqualFold(key, other) {
				return bad()
			}
		}
		if (n.DataPlacement == "auto" || n.DataPlacement == "header") && strings.HasPrefix(strings.ToLower(key), strings.ToLower(n.DataKey)+"-") {
			return bad()
		}
	}
	// Cookie names are case sensitive and chunks use key_N. Preserve that wire
	// identity while preventing metadata from sharing an encoded data cookie.
	if n.DataPlacement == "auto" || n.DataPlacement == "cookie" {
		for _, v := range []struct{ place, key string }{{n.SessionPlacement, n.SessionKey}, {n.SequencePlacement, n.SequenceKey}, {n.PaddingPlacement, n.PaddingKey}} {
			if v.place == "cookie" && strings.HasPrefix(v.key, n.DataKey+"_") {
				return bad()
			}
		}
	}
	if x.SessionTable != "" {
		a := x.Alphabet()
		if !x.SessionLength.Within(1, 256) || len(a) < 2 || len(a) > 128 {
			return bad()
		}
		seen := map[byte]bool{}
		for _, b := range []byte(a) {
			if seen[b] {
				return bad()
			}
			seen[b] = true
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-' || b == '.' || b == '~') {
				return bad()
			}
		}
		// Length is chosen uniformly, so the shortest generated length must
		// independently have enough entropy. A union of lengths is insufficient.
		space := new(big.Int).Exp(big.NewInt(int64(len(a))), big.NewInt(int64(x.SessionLength.Min)), nil)
		if space.Cmp(new(big.Int).Lsh(big.NewInt(1), XHTTPMinSessionEntropyBits)) < 0 {
			return bad()
		}
	} else if x.SessionLength != (Range{}) {
		return bad()
	}
	m := n.XMUX
	if !m.MaxConcurrency.Within(0, 512) || !m.MaxConnections.Within(0, 128) || !m.Reuse.Within(0, 1<<30) || !m.Requests.Within(0, 1<<30) || !m.Lifetime.Within(0, 86400) || m.KeepAlive < -1 || m.KeepAlive > 3600 || m.MaxConcurrency.Max > 0 && m.MaxConnections.Max > 0 {
		return bad()
	}
	if x.Download != nil {
		d := x.Download
		if n.Mode == "stream-one" || d.Endpoint.Validate() != nil || d.Transport.Type() != "xhttp" || d.Transport.XHTTP != nil && d.Transport.XHTTP.Download != nil || d.Transport.ValidateClient() != nil || d.TLS.Validate(d.Security) != nil || d.Transport.ValidateALPN(d.TLS.ALPN) != nil {
			return bad()
		}
		if v := d.Transport.XHTTP; v != nil && (v.Mode != "" && v.Mode != "auto" || v.NoGRPC || v.PacketBytes != (Range{}) || v.Interval != (Range{}) || v.Chunk != (Range{}) || v.SessionTable != "" || v.SessionLength != (Range{})) {
			return bad()
		}
		if d.Security == "reality" {
			key, e := base64.RawURLEncoding.Strict().DecodeString(d.TLS.RealityPublicKey)
			sid, e2 := hex.DecodeString(d.TLS.RealityShortID)
			if e != nil || len(key) != 32 || e2 != nil || len(sid) > 8 {
				return bad()
			}
		}
	}
	return nil
}
func (c Config) ValidateClient() error {
	if c.Validate() != nil {
		return bad()
	}
	if c.Type() == "xhttp" && c.XHTTP != nil {
		x := c.XHTTP
		if x.NoSSE || x.Buffered != 0 || x.KeepAlive != (Range{}) || x.HeaderBytes != 0 || x.Mode == "packet-up" && x.NoGRPC || x.Mode != "" && x.Mode != "auto" && x.Mode != "packet-up" && (x.PacketBytes != (Range{}) || x.Interval != (Range{})) || x.Mode == "stream-one" && x.SessionTable != "" {
			return bad()
		}
	}
	return nil
}

func reservedHeader(k string) bool {
	switch strings.ToLower(k) {
	case "host", "connection", "content-length", "content-type", "transfer-encoding", "te", "trailer", "cookie", "referer", "upgrade", "cache-control", "x-accel-buffering", "access-control-allow-origin", "access-control-allow-credentials", "access-control-allow-methods", "access-control-allow-headers":
		return true
	}
	return false
}

// MetadataHeader identifies the actual request/response keys and uplink
// namespace owned by this XHTTP configuration. HTTP names are case insensitive.
func (x XHTTP) MetadataHeader(k string) bool {
	n := x.Normalized()
	if reservedHeader(k) {
		return true
	}
	switch strings.ToLower(k) {
	case "cache-control", "x-accel-buffering", "access-control-allow-origin", "access-control-allow-credentials", "access-control-allow-methods", "access-control-allow-headers":
		return true
	}
	if n.SessionPlacement == "header" && strings.EqualFold(k, n.SessionKey) || n.SequencePlacement == "header" && strings.EqualFold(k, n.SequenceKey) {
		return true
	}
	if (n.DataPlacement == "auto" || n.DataPlacement == "header") && strings.HasPrefix(strings.ToLower(k), strings.ToLower(n.DataKey)+"-") {
		return true
	}
	if !n.PaddingObfs {
		return strings.EqualFold(k, "X-Padding")
	}
	return (n.PaddingPlacement == "header" || n.PaddingPlacement == "queryInHeader") && strings.EqualFold(k, n.PaddingHeader)
}
func (c Config) validateXHTTP() error {
	if c.ServiceName != "" || len(c.Path) > 2048 || len(c.Host) > 255 || strings.ContainsAny(c.Host, "/\\?#@") || strings.IndexFunc(c.Host, unicode.IsSpace) >= 0 || strings.IndexFunc(c.Host, unicode.IsControl) >= 0 || strings.IndexFunc(c.Path, unicode.IsSpace) >= 0 || strings.IndexFunc(c.Path, unicode.IsControl) >= 0 {
		return bad()
	}
	if c.Host != "" {
		u, e := url.Parse("http://" + c.Host)
		if e != nil || u.Hostname() == "" || u.Path != "" || u.User != nil {
			return bad()
		}
		if u.Port() != "" {
			port, e := strconv.ParseUint(u.Port(), 10, 16)
			if e != nil || port == 0 {
				return bad()
			}
		}
	}
	p, query, _ := strings.Cut(c.Path, "?")
	if _, e := url.ParseQuery(query); e != nil {
		return bad()
	}
	u, e := url.ParseRequestURI("/" + strings.TrimPrefix(p, "/"))
	if e != nil || u.Fragment != "" {
		return bad()
	}
	for _, s := range strings.Split(u.Path, "/") {
		if s == "." || s == ".." || strings.Contains(s, "\\") {
			return bad()
		}
	}
	if strings.ContainsAny(c.Path, "\r\n#") {
		return bad()
	}
	x := XHTTP{}
	if c.XHTTP != nil {
		x = *c.XHTTP
	}
	if x.Validate() != nil || len(c.Headers) > 32 {
		return bad()
	}
	size := 0
	seen := map[string]bool{}
	n := x.Normalized()
	for k, v := range c.Headers {
		key := http.CanonicalHeaderKey(k)
		if seen[key] || !httpguts.ValidHeaderFieldName(k) || !httpguts.ValidHeaderFieldValue(v) {
			return bad()
		}
		if n.MetadataHeader(k) {
			return bad()
		}
		seen[key] = true
		size += len(k) + len(v) + 4
	}
	if size > MaxHeaders/2 {
		return bad()
	}
	return nil
}
