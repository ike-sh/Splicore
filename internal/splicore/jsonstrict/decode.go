package jsonstrict

import (
	"bytes"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"io"
)

func Decode(b []byte, v any) error {
	return DecodeLimit(b, v, 65536)
}

// DecodeLimit retains strict field/depth/duplicate validation for bounded larger aggregates.
func DecodeLimit(b []byte, v any, limit int) error {
	if len(b) > limit {
		return identity.Err(identity.Invalid, "document exceeds limit")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return identity.Err(identity.Invalid, "document too deep")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		if delim != '{' && delim != '[' {
			return identity.Err(identity.Invalid, "invalid structure")
		}
		seen := map[string]bool{}
		for d.More() {
			if delim == '{' {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return identity.Err(identity.Invalid, "duplicate JSON field")
				}
				seen[s] = true
			}
			if e := walk(depth + 1); e != nil {
				return e
			}
		}
		_, e = d.Token()
		return e
	}
	if walk(0) != nil || d.Decode(new(any)) != io.EOF {
		return identity.Err(identity.Invalid, "invalid JSON document")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return identity.Err(identity.Invalid, "unknown or invalid document field")
	}
	return nil
}
