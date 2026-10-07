package vmess

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
)

// validationError carries a fixed machine reason while preserving the existing
// domain error contract. Neither the reason nor its message contains input.
type validationError struct {
	reason string
	cause  error
}

func (e *validationError) Error() string { return e.cause.Error() }
func (e *validationError) Unwrap() error { return e.cause }
func reasonError(kind identity.Code, reason string) error {
	return &validationError{reason, identity.Err(kind, reason)}
}
func ConflictingField() error  { return reasonError(identity.Invalid, "conflicting_field") }
func InvalidCredential() error { return reasonError(identity.Invalid, "invalid_credential") }

// ImportError translates a typed protocol cause into the existing import issue
// vocabulary. Callers never inspect human messages or expose protocol objects.
func ImportError(err error) (kind, code string, ok bool) {
	var e *validationError
	if !errors.As(err, &e) {
		return "", "", false
	}
	switch e.reason {
	case "unsupported_legacy_vmess", "unsupported_transport", "unsupported_security":
		return "Unsupported", e.reason, true
	case "conflicting_field", "invalid_credential":
		return "Invalid", e.reason, true
	default:
		return "", "", false
	}
}

// Object preserves member identity and presence before any struct decoding.
// Managed case variants remain compatible only when their JSON values agree.
// Exact duplicate names always fail closed. External and URI keys remain exact.
func Object(b []byte, names []string, folded bool) (map[string]json.RawMessage, error) {
	return objectLimit(b, names, folded, 16384)
}
func objectLimit(b []byte, names []string, folded bool, limit int) (map[string]json.RawMessage, error) {
	if len(b) > limit {
		return nil, invalid()
	}
	d := json.NewDecoder(bytes.NewReader(b))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, invalid()
	}
	out := make(map[string]json.RawMessage)
	seen := make(map[string]bool)
	for count := 0; d.More(); count++ {
		if count >= 64 {
			return nil, invalid()
		}
		t, err = d.Token()
		key, ok := t.(string)
		if err != nil || !ok {
			return nil, invalid()
		}
		canonical := ""
		for _, name := range names {
			if key == name || folded && strings.EqualFold(key, name) {
				canonical = name
				break
			}
		}
		if canonical == "" {
			return nil, invalid()
		}
		if seen[key] {
			return nil, ConflictingField()
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, invalid()
		}
		if previous, present := out[canonical]; present {
			if !equalJSON(previous, value) {
				return nil, ConflictingField()
			}
			continue
		}
		out[canonical] = value
	}
	if t, err = d.Token(); err != nil || t != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return nil, invalid()
	}
	return out, nil
}

func equalJSON(a, b []byte) bool {
	decode := func(raw []byte) (any, error) {
		// Keep depth and exact-duplicate rejection even in a repeated value.
		if err := jsonstrict.Decode(raw, new(any)); err != nil {
			return nil, err
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber() // never round distinct large integers to the same float
		var v any
		err := d.Decode(&v)
		return v, err
	}
	x, aerr := decode(a)
	y, berr := decode(b)
	return aerr == nil && berr == nil && reflect.DeepEqual(x, y)
}

func managedJSON(b []byte, names []string) ([]byte, error) {
	fields, err := Object(b, names, true)
	if err != nil {
		return nil, err
	}
	if tls, present := fields["tls"]; present {
		fields["tls"], err = managedJSON(tls, []string{"server_name", "certificate_file", "private_key_file", "ca_certificate"})
		if err != nil {
			return nil, err
		}
	}
	return json.Marshal(fields)
}

func creationJSON(b []byte) ([]byte, error) {
	fields, err := objectLimit(b, []string{"schema", "name", "listener", "display_endpoint", "settings", "policy_mode", "users"}, true, 65536)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"listener", "display_endpoint"} {
		if raw, ok := fields[name]; ok {
			fields[name], err = managedJSON(raw, []string{"host", "port"})
			if err != nil {
				return nil, err
			}
		}
	}
	var users []json.RawMessage
	if json.Unmarshal(fields["users"], &users) != nil || len(users) > 16 {
		return nil, invalid()
	}
	for i, raw := range users {
		u, err := Object(raw, []string{"account_name", "enabled", "account_enabled", "uuid", "traffic_policy"}, true)
		if err != nil {
			return nil, err
		}
		if p, present := u["traffic_policy"]; present && !bytes.Equal(bytes.TrimSpace(p), []byte("null")) {
			u["traffic_policy"], err = managedJSON(p, []string{"quota_bytes", "upload_bps", "download_bps"})
			if err != nil {
				return nil, err
			}
		}
		users[i], _ = json.Marshal(u)
	}
	fields["users"], _ = json.Marshal(users)
	return json.Marshal(fields)
}
