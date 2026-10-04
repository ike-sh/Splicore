package nodeimport

import (
	"encoding/base64"
	"encoding/json"
	"github.com/enfein/mieru/v3/pkg/appctl"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"net/url"
	"strings"
)

func unknownProto(m protoreflect.Message) bool {
	if len(m.GetUnknown()) > 0 {
		return true
	}
	bad := false
	m.Range(func(f protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if f.Message() != nil {
			if f.IsList() {
				l := v.List()
				for i := 0; i < l.Len(); i++ {
					if unknownProto(l.Get(i).Message()) {
						bad = true
						break
					}
				}
			} else {
				bad = unknownProto(v.Message())
			}
		}
		return !bad
	})
	return bad
}
func parseMieruURI(raw string) (Candidate, error) {
	var zero Candidate
	u, e := url.Parse(raw)
	if e != nil {
		return zero, invalid()
	}
	var config []byte
	if u.Scheme == "mierus" {
		if u.Path != "" || u.Fragment != "" || u.Port() != "" {
			return zero, errUnsupported
		}
		q, e := url.ParseQuery(u.RawQuery)
		if e != nil {
			return zero, invalid()
		}
		for k, v := range q {
			if len(v) != 1 {
				return zero, errUnsupported
			}
			switch k {
			case "profile", "mtu", "multiplexing", "port", "protocol":
			default:
				return zero, errUnsupported
			}
		}
		if q.Get("protocol") != "TCP" && q.Get("protocol") != "UDP" {
			return zero, errUnsupported
		}
		switch q.Get("multiplexing") {
		case "", "MULTIPLEXING_DEFAULT", "MULTIPLEXING_OFF", "MULTIPLEXING_LOW", "MULTIPLEXING_MIDDLE", "MULTIPLEXING_HIGH":
		default:
			return zero, errUnsupported
		}
		p, e := appctl.URLToClientProfile(raw)
		if e != nil {
			return zero, invalid()
		}
		b, e := protojson.Marshal(p)
		if e != nil {
			return zero, invalid()
		}
		config, _ = json.Marshal(map[string]any{"profiles": []json.RawMessage{b}, "activeProfile": p.GetProfileName()})
	} else {
		if !strings.HasPrefix(raw, "mieru://") {
			return zero, invalid()
		}
		b, e := base64.StdEncoding.Strict().DecodeString(raw[8:])
		if e != nil || len(b) > 4096 {
			return zero, invalid()
		}
		clear(b)
		c, e := appctl.URLToClientConfig(raw)
		if e != nil {
			return zero, invalid()
		}
		if unknownProto(c.ProtoReflect()) {
			return zero, errUnsupported
		}
		config, e = protojson.Marshal(c)
		if e != nil {
			return zero, invalid()
		}
	}
	result, e := parseMieru(config)
	if e != nil {
		return zero, errUnsupported
	}
	if len(result.Candidates) != 1 || len(result.Issues) != 0 {
		return zero, errUnsupported
	}
	return result.Candidates[0], nil
}
