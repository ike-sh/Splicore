package streamtransport

// H3 contains bounded XHTTP QUIC controls. Names match the upstream quicParams
// dialect; this intent is projected into Xray's finalmask.quicParams boundary.
// ChromeParrot pins initial windows, idle timeout and stream credits itself;
// disable it explicitly when these fields must control the client hello.
type H3 struct {
	InitialStreamWindow     uint64 `json:"initStreamReceiveWindow,omitempty"`
	MaxStreamWindow         uint64 `json:"maxStreamReceiveWindow,omitempty"`
	InitialConnectionWindow uint64 `json:"initConnectionReceiveWindow,omitempty"`
	MaxConnectionWindow     uint64 `json:"maxConnectionReceiveWindow,omitempty"`
	MaxIdleTimeout          int64  `json:"maxIdleTimeout,omitempty"`
	KeepAlivePeriod         int64  `json:"keepAlivePeriod,omitempty"`
	MaxIncomingStreams      int64  `json:"maxIncomingStreams,omitempty"`
	DisablePathMTUDiscovery bool   `json:"disablePathMTUDiscovery,omitempty"`
	DisableChromeParrot     bool   `json:"disableChromeParrot,omitempty"`
	DisableGSO              bool   `json:"disableGSO,omitempty"`
	DisableStatelessReset   bool   `json:"disableStatelessReset,omitempty"`
}

func (h *H3) UnmarshalJSON(b []byte) error {
	type plain H3
	var p plain
	if exact(b, &p, "initStreamReceiveWindow", "maxStreamReceiveWindow", "initConnectionReceiveWindow", "maxConnectionReceiveWindow", "maxIdleTimeout", "keepAlivePeriod", "maxIncomingStreams", "disablePathMTUDiscovery", "disableChromeParrot", "disableGSO", "disableStatelessReset") != nil {
		return bad()
	}
	*h = H3(p)
	return h.Validate()
}

func (h H3) Validate() error {
	for _, w := range []uint64{h.InitialStreamWindow, h.MaxStreamWindow, h.InitialConnectionWindow, h.MaxConnectionWindow} {
		if w != 0 && (w < 16384 || w > 64<<20) {
			return bad()
		}
	}
	if h.InitialStreamWindow > 0 && h.MaxStreamWindow > 0 && h.InitialStreamWindow > h.MaxStreamWindow || h.InitialConnectionWindow > 0 && h.MaxConnectionWindow > 0 && h.InitialConnectionWindow > h.MaxConnectionWindow {
		return bad()
	}
	if h.MaxIdleTimeout != 0 && (h.MaxIdleTimeout < 4 || h.MaxIdleTimeout > 120) || h.KeepAlivePeriod != 0 && (h.KeepAlivePeriod < 2 || h.KeepAlivePeriod > 60) || h.MaxIncomingStreams != 0 && (h.MaxIncomingStreams < 8 || h.MaxIncomingStreams > 1024) {
		return bad()
	}
	return nil
}
