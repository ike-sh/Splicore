// Package xhttp carries arbitrary application streams over bounded HTTP legs.
// Underlay sockets and security handshakes are supplied by the shared adapter.
package xhttp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"golang.org/x/net/http2/hpack"
)

var errEnvelope = errors.New("invalid XHTTP envelope")

const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func options(c cfg.Config) cfg.XHTTP {
	if c.XHTTP != nil {
		return c.XHTTP.Normalized()
	}
	return (cfg.XHTTP{}).Normalized()
}
func randomText(r io.Reader, n int, table string) (string, error) {
	b := make([]byte, n)
	for i := range b {
		v, e := (cfg.Range{Min: 0, Max: int32(len(table) - 1)}).Pick(r)
		if e != nil {
			return "", e
		}
		b[i] = table[v]
	}
	return string(b), nil
}
func sessionToken(x cfg.XHTTP, r io.Reader) (string, error) {
	if x.SessionTable != "" {
		n, e := x.SessionLength.Pick(r)
		if e != nil {
			return "", e
		}
		return randomText(r, n, x.Alphabet())
	}
	var b [16]byte
	if _, e := io.ReadFull(r, b[:]); e != nil {
		return "", e
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	s := hex.EncodeToString(b[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}
func padding(x cfg.XHTTP, r io.Reader) (string, error) {
	n, e := x.Padding.Pick(r)
	if e != nil {
		return "", e
	}
	if x.PaddingMethod == "repeat-x" {
		return strings.Repeat("X", n), nil
	}
	// Build a random token to a Huffman bit budget. Eight identical characters
	// expose each symbol's bit width through the generic HPACK library.
	b := make([]byte, 0, 2*n)
	bits := 0
	for (bits+7)/8 < n {
		v, e := randomText(r, 1, alphabet)
		if e != nil {
			return "", e
		}
		bits += int(hpack.HuffmanEncodeLength(strings.Repeat(v, 8)))
		b = append(b, v[0])
	}
	return string(b), nil
}
func putValue(r *http.Request, place, key, value string) {
	if value == "" {
		return
	}
	switch place {
	case "path":
		r.URL.Path = strings.TrimSuffix(r.URL.Path, "/") + "/" + value
	case "header":
		r.Header.Set(key, value)
	case "query":
		q := r.URL.Query()
		q.Set(key, value)
		r.URL.RawQuery = q.Encode()
	case "cookie":
		r.AddCookie(&http.Cookie{Name: key, Value: value})
	}
}
func getValue(r *http.Request, place, key string, parts *[]string) (string, error) {
	switch place {
	case "path":
		if len(*parts) > 0 {
			v := (*parts)[0]
			*parts = (*parts)[1:]
			return v, nil
		}
	case "header":
		return singleHeaderValue(r.Header, key), nil
	case "query":
		values := r.URL.Query()[key]
		if len(values) > 1 {
			return "", errEnvelope
		}
		if len(values) == 1 {
			return values[0], nil
		}
	case "cookie":
		value := ""
		seen := false
		for _, c := range r.Cookies() {
			if c.Name == key {
				if seen {
					return "", errEnvelope
				}
				seen = true
				value = c.Value
			}
		}
		return value, nil
	}
	return "", nil
}
func decorate(r *http.Request, c cfg.Config, sid, seq string, stream bool, entropy io.Reader) error {
	x := options(c)
	for k, v := range c.Headers {
		r.Header.Set(k, v)
	}
	if stream && !x.NoGRPC {
		r.Header.Set("Content-Type", "application/grpc")
	}
	pad, e := padding(x, entropy)
	if e != nil {
		return e
	}
	if !x.PaddingObfs {
		u := *r.URL
		u.RawQuery = "x_padding=" + pad
		r.Header.Set("Referer", u.String())
	} else {
		switch x.PaddingPlacement {
		case "queryInHeader":
			u := *r.URL
			u.RawQuery = x.PaddingKey + "=" + pad
			r.Header.Set(x.PaddingHeader, u.String())
		case "header":
			r.Header.Set(x.PaddingHeader, pad)
		default:
			putValue(r, x.PaddingPlacement, x.PaddingKey, pad)
		}
	}
	putValue(r, x.SessionPlacement, x.SessionKey, sid)
	putValue(r, x.SequencePlacement, x.SequenceKey, seq)
	return nil
}
func parseEnvelope(r *http.Request, c cfg.Config) (string, string, error) {
	x := options(c)
	if validateMetadataHeaders(r, x) != nil {
		return "", "", errEnvelope
	}
	path, _ := c.XHTTPPath()
	if !strings.HasPrefix(r.URL.Path, path) {
		return "", "", errEnvelope
	}
	if x.SessionPlacement != "path" && x.SequencePlacement != "path" && r.URL.Path != path {
		return "", "", errEnvelope
	}
	if c.Host != "" && !hostEqual(r.Host, c.Host) {
		return "", "", errEnvelope
	}
	var pad string
	if !x.PaddingObfs {
		if s := singleHeaderValue(r.Header, "Referer"); s != "" {
			u, e := url.Parse(s)
			if e == nil {
				pad = u.Query().Get("x_padding")
			}
		} else {
			pad = r.URL.Query().Get("x_padding")
		}
	} else {
		if k, e := r.Cookie(x.PaddingKey); e == nil {
			pad = k.Value
		}
		if pad == "" {
			v := singleHeaderValue(r.Header, x.PaddingHeader)
			if x.PaddingPlacement == "header" {
				pad = v
			} else if u, e := url.Parse(v); e == nil {
				pad = u.Query().Get(x.PaddingKey)
			}
		}
		if pad == "" {
			pad = r.URL.Query().Get(x.PaddingKey)
		}
	}
	n := len(pad)
	tolerance := 0
	if x.PaddingMethod == "tokenish" {
		n = int(hpack.HuffmanEncodeLength(pad))
		tolerance = 2
	}
	if pad == "" || n < int(x.Padding.Min)-tolerance || n > int(x.Padding.Max)+tolerance {
		return "", "", errEnvelope
	}
	parts := []string{}
	if x.SessionPlacement == "path" || x.SequencePlacement == "path" {
		parts = strings.Split(strings.TrimPrefix(r.URL.Path, path), "/")
	}
	sid, e := getValue(r, x.SessionPlacement, x.SessionKey, &parts)
	if e != nil {
		return "", "", e
	}
	seq, e := getValue(r, x.SequencePlacement, x.SequenceKey, &parts)
	if e != nil {
		return "", "", e
	}
	if len(sid) > 256 || strings.ContainsAny(sid, "/\\\r\n\x00") {
		return "", "", errEnvelope
	}
	for _, v := range sid {
		if !(v >= 'a' && v <= 'z' || v >= 'A' && v <= 'Z' || v >= '0' && v <= '9' || strings.ContainsRune("-_.~", v)) {
			return "", "", errEnvelope
		}
	}
	for _, v := range parts {
		if v != "" {
			return "", "", errEnvelope
		}
	}
	return sid, seq, nil
}
func hostEqual(a, b string) bool {
	// An explicit port is part of authority; absent configured port accepts the
	// request's endpoint port, including bracketed IPv6 host spelling.
	if strings.EqualFold(a, b) {
		return true
	}
	u, e := url.Parse("http://" + a)
	if e != nil {
		return false
	}
	v, e := url.Parse("http://" + b)
	return e == nil && v.Port() == "" && strings.EqualFold(u.Hostname(), v.Hostname())
}
func placePacket(r *http.Request, c cfg.Config, b []byte, entropy io.Reader) error {
	x := options(c)
	if x.DataPlacement == "body" || x.DataPlacement == "auto" {
		return nil
	}
	text := base64.RawURLEncoding.EncodeToString(b)
	for i := 0; len(text) > 0; i++ {
		n, e := x.Chunk.Pick(entropy)
		if e != nil {
			return e
		}
		n = min(n, len(text))
		if x.DataPlacement == "header" {
			r.Header.Set(fmt.Sprintf("%s-%d", x.DataKey, i), text[:n])
		} else {
			r.AddCookie(&http.Cookie{Name: fmt.Sprintf("%s_%d", x.DataKey, i), Value: text[:n]})
		}
		text = text[n:]
	}
	r.Body = nil
	r.ContentLength = 0
	r.GetBody = nil
	return nil
}
func packetPayload(r *http.Request, c cfg.Config) ([]byte, error) {
	x := options(c)
	if validateMetadataHeaders(r, x) != nil {
		return nil, errEnvelope
	}
	limit := int(x.PacketBytes.Max)
	out := make([]byte, 0)
	for _, p := range []string{"header", "cookie", "body"} {
		if x.DataPlacement != "auto" && x.DataPlacement != p {
			continue
		}
		if p == "body" {
			if r.ContentLength > int64(limit) {
				return nil, errEnvelope
			}
			b, e := io.ReadAll(io.LimitReader(r.Body, int64(limit-len(out))+1))
			if e != nil || len(b)+len(out) > limit {
				return nil, errEnvelope
			}
			out = append(out, b...)
			continue
		}
		var encoded strings.Builder
		for i := 0; i < 4096; i++ {
			var s string
			if p == "header" {
				s = singleHeaderValue(r.Header, x.DataKey+"-"+strconv.Itoa(i))
			} else if k, e := r.Cookie(x.DataKey + "_" + strconv.Itoa(i)); e == nil {
				s = k.Value
			}
			if s == "" {
				break
			}
			if encoded.Len()+len(s) > (limit+2)/3*4 {
				return nil, errEnvelope
			}
			encoded.WriteString(s)
		}
		b, e := base64.RawURLEncoding.Strict().DecodeString(encoded.String())
		if e != nil || len(b)+len(out) > limit {
			return nil, errEnvelope
		}
		out = append(out, b...)
	}
	return out, nil
}

func validateMetadataHeaders(r *http.Request, x cfg.XHTTP) error {
	seen := map[string]bool{}
	chunks := map[int]bool{}
	for k, values := range r.Header {
		if !x.MetadataHeader(k) {
			continue
		}
		key := strings.ToLower(k)
		if seen[key] || len(values) != 1 {
			return errEnvelope
		}
		seen[key] = true
		// Association and encoded data metadata are single tokens, not lists.
		if x.SessionPlacement == "header" && strings.EqualFold(k, x.SessionKey) || x.SequencePlacement == "header" && strings.EqualFold(k, x.SequenceKey) || x.PaddingObfs && x.PaddingPlacement == "header" && strings.EqualFold(k, x.PaddingHeader) || (x.DataPlacement == "auto" || x.DataPlacement == "header") && strings.HasPrefix(key, strings.ToLower(x.DataKey)+"-") {
			if values[0] == "" || strings.Contains(values[0], ",") {
				return errEnvelope
			}
		}
		if x.PaddingObfs && x.PaddingPlacement == "queryInHeader" && strings.EqualFold(k, x.PaddingHeader) {
			// This carrier is one URL, not a comma-separated token list. Validate
			// the decoded padding query alone; comma is legal in URL paths.
			u, err := url.Parse(values[0])
			if err != nil || u.Fragment != "" {
				return errEnvelope
			}
			q, err := url.ParseQuery(u.RawQuery)
			if err != nil || len(q[x.PaddingKey]) != 1 || q.Get(x.PaddingKey) == "" || strings.Contains(q.Get(x.PaddingKey), ",") {
				return errEnvelope
			}
		}
		if (x.DataPlacement == "auto" || x.DataPlacement == "header") && strings.HasPrefix(key, strings.ToLower(x.DataKey)+"-") {
			suffix := strings.TrimPrefix(key, strings.ToLower(x.DataKey)+"-")
			i, err := strconv.Atoi(suffix)
			if err != nil || i < 0 || i >= 4096 || strconv.Itoa(i) != suffix {
				return errEnvelope
			}
			chunks[i] = true
		}
	}
	for i := 0; i < len(chunks); i++ {
		if !chunks[i] {
			return errEnvelope
		}
	}
	return nil
}

func singleHeaderValue(h http.Header, key string) string {
	for k, v := range h {
		if strings.EqualFold(k, key) && len(v) == 1 {
			return v[0]
		}
	}
	return ""
}
func responseHeaders(w http.ResponseWriter, r *http.Request, c cfg.Config) error {
	x := options(c)
	for k, v := range c.Headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if s := r.Header.Get("Origin"); s != "" {
		w.Header().Set("Access-Control-Allow-Origin", s)
	}
	if x.SessionPlacement == "cookie" || x.SequencePlacement == "cookie" || x.DataPlacement == "cookie" || x.PaddingPlacement == "cookie" {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	pad, e := padding(x, rand.Reader)
	if e != nil {
		return e
	}
	if !x.PaddingObfs {
		w.Header().Set("X-Padding", pad)
	} else {
		switch x.PaddingPlacement {
		case "header":
			w.Header().Set(x.PaddingHeader, pad)
		case "queryInHeader":
			w.Header().Set(x.PaddingHeader, "?"+x.PaddingKey+"="+pad)
		case "cookie":
			http.SetCookie(w, &http.Cookie{Name: x.PaddingKey, Value: pad, Path: "/"})
		}
	}
	return nil
}
