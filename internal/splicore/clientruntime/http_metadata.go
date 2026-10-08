package clientruntime

import (
	"io"
	"net/http"
	"net/textproto"
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
	stripProxyHeaders(allowed)
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

func forwardHTTPRequest(req *http.Request) *http.Request {
	out := req.Clone(req.Context())
	out.Trailer = forwardHTTPTrailers(req.Header, req.Trailer)
	stripProxyHeaders(out.Header)
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
