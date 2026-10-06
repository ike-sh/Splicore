package hostnetwork

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

// WinINETSnapshot is LAN user intent, queried through PER_CONNECTION_OPTION.
// A nil connection name selects LAN. RAS connections and detection cache are not
// modified. Flags is queried with FLAGS_UI and restored using FLAGS, as required
// by the Windows 7+ contract. Detection cache/effective flags are not user intent.
type WinINETSnapshot struct {
	Flags         uint32 `json:"flags"`
	Server        string `json:"server"`
	Bypass        string `json:"bypass"`
	PAC           string `json:"pac"`
	AutoDiscovery uint32 `json:"auto_discovery"`
	SecondaryPAC  string `json:"secondary_pac"`
	ReloadMinutes uint32 `json:"reload_minutes"`
}

const (
	WinINETDirect     uint32 = 1
	WinINETManual     uint32 = 2
	WinINETPAC        uint32 = 4
	WinINETAutoDetect uint32 = 8
)

func (s WinINETSnapshot) Validate() error {
	if s.Flags & ^uint32(15) != 0 || s.AutoDiscovery & ^uint32(127) != 0 {
		return identity.Err(identity.Corrupt, "unsupported WinINET flags")
	}
	for _, v := range []string{s.Server, s.Bypass, s.PAC, s.SecondaryPAC} {
		if len(v) > 4096 || strings.ContainsAny(v, "\x00\r\n@") {
			return identity.Err(identity.Corrupt, "unsupported or sensitive WinINET state")
		}
	}
	for _, pac := range []string{s.PAC, s.SecondaryPAC} {
		if pac != "" {
			u, err := url.Parse(pac)
			if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return identity.Err(identity.Corrupt, "sensitive WinINET PAC state")
			}
		}
	}
	return nil
}
func (s WinINETSnapshot) Fingerprint() string {
	b, _ := json.Marshal(s)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func WinINETPlan(endpoint string) ([]Record, error) {
	host, port, err := net.SplitHostPort(endpoint)
	ip, e := netip.ParseAddr(host)
	n, p := strconv.ParseUint(port, 10, 16)
	if err != nil || e != nil || !ip.Unmap().IsLoopback() || p != nil || n == 0 {
		return nil, identity.Err(identity.Invalid, "system proxy requires literal loopback listener")
	}
	s := WinINETSnapshot{Flags: WinINETDirect | WinINETManual, Server: endpoint, Bypass: "<local>"}
	return []Record{{Kind: "wininet", WinINET: &s}}, nil
}

// WinINETAPI is replaced by a stateful fixture in tests. Set changes one option;
// this makes every possible partial write an explicit, durable journal state.
type WinINETAPI interface {
	Capture(context.Context) (WinINETSnapshot, error)
	Set(context.Context, uint32, WinINETSnapshot) error
	Notify(context.Context, uint32) error
}

var winINETOptions = []uint32{2, 3, 4, 6, 7, 5, 1}

func winINETNext(from, to WinINETSnapshot, option uint32) WinINETSnapshot {
	switch option {
	case 1:
		from.Flags = to.Flags
	case 2:
		from.Server = to.Server
	case 3:
		from.Bypass = to.Bypass
	case 4:
		from.PAC = to.PAC
	case 5:
		from.AutoDiscovery = to.AutoDiscovery
	case 6:
		from.SecondaryPAC = to.SecondaryPAC
	case 7:
		from.ReloadMinutes = to.ReloadMinutes
	}
	return from
}
func winINETTransitions(from, to WinINETSnapshot) []WinINETSnapshot {
	var out []WinINETSnapshot
	for _, option := range winINETOptions {
		next := winINETNext(from, to, option)
		if next != from {
			out = append(out, next)
			from = next
		}
	}
	return out
}

func applyWinINET(ctx context.Context, api WinINETAPI, from, to WinINETSnapshot) error {
	if from.Validate() != nil || to.Validate() != nil {
		return identity.Err(identity.Invalid, "invalid WinINET transition")
	}
	for _, option := range winINETOptions {
		next := winINETNext(from, to, option)
		if next == from {
			continue
		}
		current, err := api.Capture(ctx)
		if err != nil {
			return err
		}
		if current != from {
			return identity.Err(identity.Conflict, "external WinINET mutation preserved")
		}
		if err = api.Set(ctx, option, next); err != nil {
			return err
		}
		current, err = api.Capture(ctx)
		if err != nil {
			return err
		}
		if current != next {
			return identity.Err(identity.Conflict, "WinINET write verification failed")
		}
		from = next
	}
	return notifyWinINET(ctx, api)
}
func notifyWinINET(ctx context.Context, api WinINETAPI) error {
	// The per-connection setter is followed by SETTINGS_CHANGED then REFRESH.
	for _, option := range []uint32{39, 37} {
		if err := api.Notify(ctx, option); err != nil {
			return err
		}
	}
	return nil
}

// TransitionBackend describes states that an interrupted multi-call operation
// can leave. Manager persists them before the first call and before restoration.
type TransitionBackend interface {
	Transitions(Record, *Record, *Record) ([]*Record, error)
	FinalizeRestore(context.Context, Record) error
}

func winINETRecordTransitions(key Record, before, after *Record) ([]*Record, error) {
	if key.Kind != "wininet" {
		return nil, nil
	}
	if before == nil || after == nil || before.WinINET == nil || after.WinINET == nil {
		return nil, identity.Err(identity.Invalid, "missing WinINET snapshot")
	}
	var out []*Record
	for _, s := range winINETTransitions(*before.WinINET, *after.WinINET) {
		r := cloneRecord(after)
		r.WinINET = &s
		out = append(out, r)
	}
	return out, nil
}
func knownTransition(current *Record, s Step) bool {
	if equal(current, s.After) {
		return true
	}
	if s.State == "pending" && current != nil && s.After != nil && s.Key.Kind == "interface" && s.After.Adapter != nil {
		// Creation can crash before applying MTU or acknowledging an index. The
		// backend has verified the durable random GUID; constructor defaults are
		// still owned. Applied interfaces retain exact-state conflict detection.
		candidate := cloneRecord(current)
		candidate.Index = s.After.Index
		candidate.MTU = s.After.MTU
		if equal(candidate, s.After) {
			return true
		}
	}
	if current != nil && s.After != nil && s.After.Adapter != nil && current.Index > 0 && s.After.Index == 0 {
		candidate := cloneRecord(current)
		candidate.Index = 0
		if equal(candidate, s.After) {
			return true
		}
	}
	if current != nil && s.After != nil && s.Key.Kind == "interface" && s.After.Adapter != nil && current.Index == 0 {
		candidate := cloneRecord(current)
		candidate.Index = s.After.Index
		if equal(candidate, s.After) {
			return true
		}
	}
	for _, r := range s.Intermediates {
		if reflect.DeepEqual(current, r) {
			return true
		}
	}
	return false
}
