// Package httpproxy owns bounded HTTP/1.1 proxy parsing, without routing or I/O ownership.
package httpproxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks5"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const MaxHeader = 64 << 10
const MaxLine = 8 << 10

var ErrProtocol = errors.New("invalid or unsupported HTTP proxy message")

func ReadHeader(r *bufio.Reader) ([]byte, error) {
	var raw, line bytes.Buffer
	for count := 0; count < 129; {
		b, e := r.ReadSlice('\n')
		if raw.Len()+len(b) > MaxHeader || line.Len()+len(b) > MaxLine {
			return nil, ErrProtocol
		}
		raw.Write(b)
		line.Write(b)
		if e == bufio.ErrBufferFull {
			continue
		}
		if e != nil {
			return nil, e
		}
		if !bytes.HasSuffix(line.Bytes(), []byte("\r\n")) {
			return nil, ErrProtocol
		}
		count++
		if bytes.Equal(line.Bytes(), []byte("\r\n")) {
			return raw.Bytes(), nil
		}
		line.Reset()
	}
	return nil, ErrProtocol
}
func Authority(s string) (access.Endpoint, error) {
	if len(s) > 320 || strings.ContainsAny(s, " /\\\t\r\n@?#%") {
		return access.Endpoint{}, ErrProtocol
	}
	host, port, e := net.SplitHostPort(s)
	if e != nil || port == "" {
		return access.Endpoint{}, ErrProtocol
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return access.Endpoint{}, ErrProtocol
		}
	}
	p, e := strconv.ParseUint(port, 10, 16)
	dst := access.Endpoint{Host: host, Port: uint16(p)}
	if e != nil || dst.Validate() != nil {
		return access.Endpoint{}, ErrProtocol
	}
	return dst, nil
}

// Reject ambiguous framing before net/http normalizes duplicate fields.
func ReadRequest(r *bufio.Reader) (*http.Request, *bufio.Reader, error) {
	raw, e := ReadHeader(r)
	if e != nil {
		return nil, r, e
	}
	lines := bytes.Split(raw, []byte("\r\n"))
	seen := map[string]int{}
	for _, line := range lines[1 : len(lines)-2] {
		if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
			return nil, r, ErrProtocol
		}
		name, _, ok := strings.Cut(string(line), ":")
		if !ok || name == "" || strings.TrimSpace(name) != name {
			return nil, r, ErrProtocol
		}
		name = strings.ToLower(name)
		seen[name]++
		if seen[name] > 1 && (name == "host" || name == "proxy-authorization" || name == "content-length" || name == "transfer-encoding") {
			return nil, r, ErrProtocol
		}
	}
	if seen["content-length"] > 0 && seen["transfer-encoding"] > 0 {
		return nil, r, ErrProtocol
	}
	next := bufio.NewReader(io.MultiReader(bytes.NewReader(raw), r))
	req, e := http.ReadRequest(next)
	if e != nil {
		return nil, next, ErrProtocol
	}
	if req.ProtoMajor != 1 || req.ProtoMinor != 1 || req.Method == "" {
		return nil, next, ErrProtocol
	}
	if req.Method == http.MethodConnect {
		if req.ContentLength > 0 || len(req.TransferEncoding) > 0 {
			return nil, next, ErrProtocol
		}
		if _, e = Authority(req.RequestURI); e != nil {
			return nil, next, e
		}
		for _, line := range lines[1 : len(lines)-2] {
			name, v, _ := strings.Cut(string(line), ":")
			if strings.EqualFold(name, "Host") && !strings.EqualFold(strings.TrimSpace(v), req.RequestURI) {
				return nil, next, ErrProtocol
			}
		}
	} else {
		if req.URL.Scheme != "http" || req.URL.Host == "" || req.URL.User != nil || req.URL.Fragment != "" {
			return nil, next, ErrProtocol
		}
		// Absolute-form Host is authoritative, but a conflicting raw Host is rejected.
		for _, line := range lines[1 : len(lines)-2] {
			name, v, _ := strings.Cut(string(line), ":")
			if strings.EqualFold(name, "Host") && !strings.EqualFold(strings.TrimSpace(v), req.URL.Host) {
				return nil, next, ErrProtocol
			}
		}
	}
	return req, next, nil
}
func Basic(s string) (socks5.Credentials, error) {
	kind, value, ok := strings.Cut(s, " ")
	if !ok || !strings.EqualFold(kind, "Basic") || len(value) > 684 {
		return socks5.Credentials{}, ErrProtocol
	}
	raw, e := base64.StdEncoding.DecodeString(value)
	defer clear(raw)
	if e != nil {
		return socks5.Credentials{}, ErrProtocol
	}
	u, p, ok := strings.Cut(string(raw), ":")
	c := socks5.Credentials{Username: u, Password: p}
	if !ok || c.Validate() != nil {
		return c, ErrProtocol
	}
	return c, nil
}
func StripHeaders(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate", "Proxy-Authentication-Info", "Keep-Alive", "TE", "Trailer", "Upgrade"} {
		h.Del(name)
	}
}

// Connect preserves all coalesced tunnel bytes. CONNECT success has no HTTP body,
// regardless of Content-Length/Transfer-Encoding advertised by the proxy.
func Connect(c net.Conn, dst access.Endpoint, cred *socks5.Credentials) (*bufio.Reader, error) {
	authority := net.JoinHostPort(dst.Host, strconv.Itoa(int(dst.Port)))
	if _, e := Authority(authority); e != nil {
		return nil, e
	}
	var b strings.Builder
	b.WriteString("CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n")
	if cred != nil {
		if cred.Validate() != nil || strings.Contains(cred.Username, ":") {
			return nil, ErrProtocol
		}
		b.WriteString("Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(cred.Username+":"+cred.Password)) + "\r\n")
	}
	b.WriteString("\r\n")
	if e := socks5.WriteFull(c, []byte(b.String())); e != nil {
		return nil, e
	}
	r := bufio.NewReader(c)
	for range 8 {
		raw, e := ReadHeader(r)
		if e != nil {
			return nil, e
		}
		resp, e := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), &http.Request{Method: http.MethodConnect})
		if e != nil || resp.ProtoMajor != 1 {
			return nil, ErrProtocol
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return r, nil
		}
		if resp.StatusCode < 100 || resp.StatusCode >= 200 || resp.StatusCode == 101 {
			return nil, ErrProtocol
		}
	}
	return nil, ErrProtocol
}

// Detect peeks at most 33 bytes and never consumes greeting/request bytes.
// The caller supplies the handshake deadline.
func Detect(r *bufio.Reader) (string, error) {
	b, e := r.Peek(1)
	if e != nil {
		return "", e
	}
	if b[0] == 5 {
		return "socks5", nil
	}
	for n := 1; n <= 33; n++ {
		b, e = r.Peek(n)
		if e != nil {
			return "", e
		}
		c := b[n-1]
		if c == ' ' && n > 1 {
			return "http", nil
		}
		if !token(c) {
			return "", ErrProtocol
		}
	}
	return "", ErrProtocol
}
func token(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))
}
