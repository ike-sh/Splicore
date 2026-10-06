package distribution

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
)

// decodeReceipt recognizes the retired metadata key only in an owned installed
// receipt. Corrected package manifests remain strict and contain no engine pins.
func decodeReceipt(r io.Reader) (Manifest, error) {
	b, err := io.ReadAll(io.LimitReader(r, (2<<20)+1))
	if err != nil || len(b) > 2<<20 {
		return Manifest{}, fmt.Errorf("invalid receipt size")
	}
	var fields map[string]json.RawMessage
	if jsonstrict.DecodeLimit(b, &fields, 2<<20) != nil || fields == nil {
		return Manifest{}, fmt.Errorf("invalid receipt")
	}
	if legacy, ok := fields["optional_xray"]; ok {
		var reference struct {
			Version  string            `json:"version"`
			Strategy string            `json:"strategy"`
			Hashes   map[string]string `json:"sha256"`
		}
		if jsonstrict.DecodeLimit(legacy, &reference, 4096) != nil || reference.Version == "" || reference.Strategy != "separate-pinned-artifact" || len(reference.Hashes) > 8 {
			return Manifest{}, fmt.Errorf("invalid retired receipt metadata")
		}
		delete(fields, "optional_xray")
	}
	clean, err := json.Marshal(fields)
	if err != nil {
		return Manifest{}, err
	}
	return Decode(bytes.NewReader(clean))
}
