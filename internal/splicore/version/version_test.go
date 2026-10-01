package version

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIndependentIdentity(t *testing.T) {
	v := Current()
	if v.Product != "Splicore" || v.Version == v.UpstreamTag || len(v.UpstreamCommit) != 40 || v.APIVersion != "v1" || ConfigSchema != 1 || DatabaseSchema != 4 || ProtocolABI != 1 {
		t.Fatal("product identity invalid")
	}
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "D:\\") || strings.Contains(string(b), "C:\\") {
		t.Fatal("identity includes local path")
	}
}
