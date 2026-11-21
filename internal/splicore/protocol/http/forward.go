package httpproxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
)

// forwardHTTPTrailers owns the declaration map used by the forwarding writer.
// Only declared end-to-end fields can receive values when the incoming body
// reaches EOF. The incoming parser never has access to this outgoing map.
func forwardHTTPTrailers(header, trailer http.Header) http.Header {
	allowed := make(http.Header)
	for name := range trailer {
		if validTrailerName(name) {
			allowed[textproto.CanonicalMIMEHeaderKey(name)] = nil
		}
	}
	// Apply the existing proxy/hop policy, including names nominated by the
	// original Connection header, before that header is removed.
	for name, values := range header {
		if strings.EqualFold(name, "Connection") {
			allowed["Connection"] = append(allowed["Connection"], values...)
		}
	}
	StripHeaders(allowed)
	// Framing and routing fields cannot be represented as HTTP trailers.
	for _, name := range []string{"Content-Length", "Transfer-Encoding", "Host"} {
		allowed.Del(name)
	}
	return allowed
}

func validTrailerName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}

func ForwardRequest(req *http.Request) *http.Request {
	out := req.Clone(req.Context())
	out.Trailer = forwardHTTPTrailers(req.Header, req.Trailer)
	StripHeaders(out.Header)
	out.Body = forwardHTTPBody(req.Body, req.Trailer, out.Trailer)
	return out
}

func forwardHTTPBody(body io.ReadCloser, source, outgoing http.Header) io.ReadCloser {
	if len(outgoing) == 0 || body == nil || body == http.NoBody {
		return body
	}
	return &trailerBody{ReadCloser: body, source: source, outgoing: outgoing}
}

type trailerBody struct {
	io.ReadCloser
	source, outgoing http.Header
	once             sync.Once
}

func (b *trailerBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		// net/http fills source before returning EOF and writes outgoing only
		// after this Read returns. Close and error paths never publish trailers.
		b.once.Do(func() {
			for name := range b.outgoing {
				b.outgoing[name] = append([]string(nil), b.source.Values(name)...)
			}
		})
	}
	return n, err
}

// ForwardResponse owns the downstream header and trailer maps. The upstream
// HTTP reader only publishes trailer values after reading the body to EOF.
func ForwardResponse(resp *http.Response) *http.Response {
	out := new(http.Response)
	*out = *resp
	out.Header = resp.Header.Clone()
	out.Trailer = forwardHTTPTrailers(resp.Header, resp.Trailer)
	out.Body = forwardHTTPBody(resp.Body, resp.Trailer, out.Trailer)
	StripHeaders(out.Header)
	out.Close = true
	return out
}

func NewResponseHeaderConn(conn net.Conn) net.Conn {
	return &responseHeaderConn{Conn: conn, reader: bufio.NewReader(conn), headers: true}
}

// net/http removes Connection: close during parsing. Remove every nominated
// field first, while the original bounded response header is still available.
type responseHeaderConn struct {
	net.Conn
	reader  *bufio.Reader
	pending *bytes.Reader
	headers bool
}

func (c *responseHeaderConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.pending != nil && c.pending.Len() > 0 {
		return c.pending.Read(p)
	}
	if !c.headers {
		return c.reader.Read(p)
	}
	raw, err := ReadHeader(c.reader)
	if err != nil {
		return 0, err
	}
	parsed := bufio.NewReader(bytes.NewReader(raw))
	status, err := parsed.ReadString('\n')
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(status)
	if len(fields) < 2 {
		return 0, fmt.Errorf("invalid HTTP response status")
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil || code < 100 || code > 999 {
		return 0, fmt.Errorf("invalid HTTP response status")
	}
	header, err := textproto.NewReader(parsed).ReadMIMEHeader()
	if err != nil {
		return 0, err
	}
	closeConnection := false
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "close") {
				closeConnection = true
			}
		}
	}
	// Preserve safe trailer declarations for the response parser. Late values
	// are copied separately by forwardHTTPBody; nominated fields stay excluded.
	declared := make(http.Header)
	for _, value := range header.Values("Trailer") {
		for _, name := range strings.Split(value, ",") {
			declared[strings.TrimSpace(name)] = nil
		}
	}
	trailers := forwardHTTPTrailers(http.Header(header), declared)
	StripHeaders(http.Header(header))
	for name := range trailers {
		header.Add("Trailer", name)
	}
	if closeConnection {
		header.Set("Connection", "close")
	}
	var filtered bytes.Buffer
	filtered.WriteString(status)
	if err = http.Header(header).Write(&filtered); err != nil {
		return 0, err
	}
	filtered.WriteString("\r\n")
	c.headers = code >= 100 && code < 200 && code != 101
	c.pending = bytes.NewReader(filtered.Bytes())
	return c.pending.Read(p)
}
