package streamtransport

import (
	"bytes"
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"strings"

	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"golang.org/x/net/http/httpguts"
)

// Hysteria is specialized transport intent. Credentials remain in the existing
// credential/binding model; proxy targets and UDP framing remain protocol data.
type Hysteria struct {
	Version        int           `json:"version"`
	UDPIdleTimeout int           `json:"udp_idle_timeout,omitempty"`
	DisableUDP     bool          `json:"disable_udp,omitempty"`
	QUIC           QUIC          `json:"quic,omitempty"`
	Masquerade     *Masquerade   `json:"masquerade,omitempty"`
	Obfs           *HysteriaObfs `json:"obfs,omitempty"`
	UDP            *HysteriaUDP  `json:"udp,omitempty"`
}

// QUIC is carrier tuning, independent of proxy protocol semantics. All time
// values are seconds; window values are bytes. Unsupported controllers fail
// validation instead of silently selecting the library's Reno controller.
type QUIC struct {
	InitialStreamWindow     uint64 `json:"initial_stream_window,omitempty"`
	MaxStreamWindow         uint64 `json:"max_stream_window,omitempty"`
	InitialConnectionWindow uint64 `json:"initial_connection_window,omitempty"`
	MaxConnectionWindow     uint64 `json:"max_connection_window,omitempty"`
	MaxIdleTimeout          int    `json:"max_idle_timeout,omitempty"`
	KeepAlivePeriod         int    `json:"keep_alive_period,omitempty"`
	MaxIncomingStreams      int64  `json:"max_incoming_streams,omitempty"`
	DisablePathMTUDiscovery bool   `json:"disable_path_mtu_discovery,omitempty"`
	Congestion              string `json:"congestion,omitempty"`
	BrutalUp                string `json:"brutal_up,omitempty"`
	BrutalDown              string `json:"brutal_down,omitempty"`
}
type Masquerade struct {
	Type        string            `json:"type"`
	Directory   string            `json:"directory,omitempty"`
	URL         string            `json:"url,omitempty"`
	RewriteHost bool              `json:"rewrite_host,omitempty"`
	Insecure    bool              `json:"insecure,omitempty"`
	Content     string            `json:"content,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Status      int               `json:"status,omitempty"`
}

func exact(b []byte, dst any, members ...string) error {
	var fields map[string]json.RawMessage
	if jsonstrict.Decode(b, &fields) != nil || fields == nil {
		return bad()
	}
	allowed := map[string]bool{}
	for _, k := range members {
		allowed[k] = true
	}
	for k, v := range fields {
		if !allowed[k] || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return bad()
		}
	}
	if jsonstrict.Decode(b, dst) != nil {
		return bad()
	}
	return nil
}
func (h *Hysteria) UnmarshalJSON(b []byte) error {
	type plain Hysteria
	var p plain
	if exact(b, &p, "version", "udp_idle_timeout", "disable_udp", "quic", "masquerade", "obfs", "udp") != nil {
		return bad()
	}
	*h = Hysteria(p)
	return h.Validate()
}
func (q *QUIC) UnmarshalJSON(b []byte) error {
	type plain QUIC
	var p plain
	if exact(b, &p, "initial_stream_window", "max_stream_window", "initial_connection_window", "max_connection_window", "max_idle_timeout", "keep_alive_period", "max_incoming_streams", "disable_path_mtu_discovery", "congestion", "brutal_up", "brutal_down") != nil {
		return bad()
	}
	*q = QUIC(p)
	return q.Validate()
}
func (m *Masquerade) UnmarshalJSON(b []byte) error {
	type plain Masquerade
	var p plain
	if exact(b, &p, "type", "directory", "url", "rewrite_host", "insecure", "content", "headers", "status") != nil {
		return bad()
	}
	*m = Masquerade(p)
	return m.Validate()
}
func (h Hysteria) Clone() Hysteria {
	if h.Obfs != nil {
		o := *h.Obfs
		h.Obfs = &o
	}
	if h.UDP != nil {
		u := *h.UDP
		h.UDP = &u
	}
	if h.Masquerade != nil {
		m := *h.Masquerade
		m.Headers = maps.Clone(m.Headers)
		h.Masquerade = &m
	}
	return h
}
func (c Config) HysteriaSettings() Hysteria {
	if c.Hysteria != nil {
		return c.Hysteria.Clone()
	}
	return Hysteria{Version: 2}
}
func (h Hysteria) IdleSeconds() int {
	if h.UDPIdleTimeout == 0 {
		return 60
	}
	return h.UDPIdleTimeout
}
func (h Hysteria) Validate() error {
	if h.Version != 2 || h.UDPIdleTimeout != 0 && (h.UDPIdleTimeout < 2 || h.UDPIdleTimeout > 600) || h.QUIC.Validate() != nil {
		return bad()
	}
	if h.Obfs != nil && h.Obfs.Validate() != nil || h.UDP != nil && h.UDP.Validate() != nil {
		return bad()
	}
	if h.Masquerade != nil {
		return h.Masquerade.Validate()
	}
	return nil
}
func (q QUIC) Defaults() QUIC {
	if q.InitialStreamWindow == 0 {
		q.InitialStreamWindow = 8 << 20
	}
	if q.MaxStreamWindow == 0 {
		q.MaxStreamWindow = 8 << 20
	}
	if q.InitialConnectionWindow == 0 {
		q.InitialConnectionWindow = 20 << 20
	}
	if q.MaxConnectionWindow == 0 {
		q.MaxConnectionWindow = 20 << 20
	}
	if q.MaxIdleTimeout == 0 {
		q.MaxIdleTimeout = 30
	}
	if q.MaxIncomingStreams == 0 {
		q.MaxIncomingStreams = 256
	}
	if q.Congestion == "" {
		q.Congestion = "reno"
	}
	return q
}
func (q QUIC) Validate() error {
	q = q.Defaults()
	up, ue := RateBytes(q.BrutalUp)
	down, de := RateBytes(q.BrutalDown)
	if ue != nil || de != nil {
		return bad()
	}
	switch q.Congestion {
	case "reno", "bbr":
		if up != 0 || down != 0 {
			return bad()
		}
	case "brutal":
	case "force-brutal":
		if up == 0 {
			return bad()
		}
	default:
		return bad()
	}
	if q.MaxIdleTimeout < 4 || q.MaxIdleTimeout > 120 || q.KeepAlivePeriod < 0 || q.KeepAlivePeriod > q.MaxIdleTimeout/2 || q.MaxIncomingStreams < 8 || q.MaxIncomingStreams > 4096 {
		return bad()
	}
	if q.InitialStreamWindow < 16384 || q.MaxStreamWindow < q.InitialStreamWindow || q.MaxStreamWindow > 1<<30 || q.InitialConnectionWindow < q.InitialStreamWindow || q.MaxConnectionWindow < q.InitialConnectionWindow || q.MaxConnectionWindow > 1<<30 {
		return bad()
	}
	return nil
}
func (m Masquerade) Validate() error {
	if len(m.Content) > 8192 || len(m.Directory) > 4096 || len(m.URL) > 2048 || len(m.Headers) > 32 {
		return bad()
	}
	switch m.Type {
	case "", "404":
		if m.Directory != "" || m.URL != "" || m.Content != "" || len(m.Headers) > 0 || m.Status != 0 || m.RewriteHost || m.Insecure {
			return bad()
		}
	case "string":
		if m.Directory != "" || m.URL != "" || m.RewriteHost || m.Insecure || m.Status != 0 && (m.Status < 200 || m.Status > 599 || m.Status == 233) {
			return bad()
		}
		size := 0
		seen := map[string]bool{}
		for k, v := range m.Headers {
			lower := strings.ToLower(k)
			size += len(k) + len(v)
			if !httpguts.ValidHeaderFieldName(k) || !httpguts.ValidHeaderFieldValue(v) || seen[lower] || strings.HasPrefix(lower, "hysteria-") {
				return bad()
			}
			seen[lower] = true
			switch http.CanonicalHeaderKey(k) {
			case "Connection", "Transfer-Encoding", "Content-Length", "Trailer", "Upgrade":
				return bad()
			}
		}
		if size > 4096 {
			return bad()
		}
	case "file":
		if m.Directory == "" || m.URL != "" || m.Content != "" || len(m.Headers) > 0 || m.Status != 0 || m.RewriteHost || m.Insecure {
			return bad()
		}
	case "proxy":
		u, e := url.Parse(m.URL)
		if e != nil || u.Scheme != "http" && u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || m.Directory != "" || m.Content != "" || len(m.Headers) > 0 || m.Status != 0 {
			return bad()
		}
	default:
		return bad()
	}
	return nil
}
