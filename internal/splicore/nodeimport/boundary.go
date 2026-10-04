package nodeimport

import (
	"encoding/json"
	"strings"
)

// retiredCapability recognizes forbidden annotations before canonical decoding,
// so a preview can classify them without producing a runnable stripped node.
// Input has already passed the bounded strict JSON structure check.
func retiredCapability(raw []byte) bool {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	var walk func(any) bool
	walk = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			for k, value := range x {
				switch strings.ToLower(k) {
				case "finalmask", "sudoku", "engine_options", "transport_requirements":
					return true
				case "engine":
					if value == "xray" {
						return true
					}
				}
				if k != "metadata" && walk(value) {
					return true
				}
			}
		case []any:
			for _, value := range x {
				if walk(value) {
					return true
				}
			}
		}
		return false
	}
	return walk(v)
}
