package endpoint

import (
	"encoding/hex"
	"strconv"
	"strings"
)

// MaxCPSPacket fits the IPv6 minimum MTU (1280 minus 40 IP and 8 UDP).
// This also bounds handshake junk, signature allocation and netlink messages.
const (
	MaxCPSPacket = 1232
	maxCPSTags   = 128
)

type CPSTag struct {
	Kind   string
	Length int
	Data   []byte
}
type CPS struct {
	Tags []CPSTag
	Size int
}

// ParseCPS accepts only the tags present in the pinned 3.1 engine. d/ds/dz
// operate on the empty source of I packets. No surrounding text is ignored.
func ParseCPS(spec string) (CPS, error) {
	var result CPS
	if len(spec) > 8192 || strings.ContainsAny(spec, "\r\n\x00") {
		return result, awgField("CPS text length")
	}
	remaining := strings.TrimSpace(spec)
	for remaining != "" {
		if remaining[0] != '<' || len(result.Tags) >= maxCPSTags {
			return CPS{}, awgField("CPS syntax/tag limit")
		}
		end := strings.IndexByte(remaining, '>')
		if end < 0 {
			return CPS{}, awgField("CPS unterminated tag")
		}
		parts := strings.Fields(remaining[1:end])
		if len(parts) < 1 || len(parts) > 2 {
			return CPS{}, awgField("CPS tag arguments")
		}
		tag := CPSTag{Kind: parts[0]}
		switch tag.Kind {
		case "b":
			if len(parts) != 2 {
				return CPS{}, awgField("CPS binary argument")
			}
			value := strings.TrimPrefix(parts[1], "0x")
			if len(value) == 0 || len(value) > MaxCPSPacket*2 || len(value)%2 != 0 {
				return CPS{}, awgField("CPS binary length")
			}
			b, e := hex.DecodeString(value)
			if e != nil {
				return CPS{}, awgField("CPS binary hex")
			}
			tag.Data, tag.Length = b, len(b)
		case "t", "d", "ds":
			if len(parts) != 1 {
				return CPS{}, awgField("CPS tag arguments")
			}
			if tag.Kind == "t" {
				tag.Length = 4
			}
		case "r", "rc", "rd", "dz":
			if len(parts) != 2 {
				return CPS{}, awgField("CPS length")
			}
			n, e := strconv.ParseUint(parts[1], 10, 16)
			if e != nil || n > 1000 || strings.HasPrefix(parts[1], "+") {
				return CPS{}, awgField("CPS length 0..1000")
			}
			tag.Length = int(n)
		default:
			return CPS{}, awgField("CPS unknown tag")
		}
		result.Size += tag.Length
		if result.Size > MaxCPSPacket {
			return CPS{}, awgField("CPS packet size")
		}
		result.Tags = append(result.Tags, tag)
		remaining = strings.TrimSpace(remaining[end+1:])
	}
	return result, nil
}
