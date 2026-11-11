package distribution

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRetiredMetadataOnlyAcceptedInInstallationReceipt(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(fixture(t), "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := Decode(strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	fields["optional_xray"] = json.RawMessage(`{"version":"26.3.27","strategy":"separate-pinned-artifact","sha256":{"linux-amd64":"unused"}}`)
	legacy, _ := json.Marshal(fields)
	got, err := decodeReceipt(strings.NewReader(string(legacy)))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("native receipt metadata changed", err)
	}
	if _, err := Decode(strings.NewReader(string(legacy))); err == nil {
		t.Fatal("corrected package accepted retired artifact metadata")
	}
	for _, value := range []string{`null`, `[]`, `{"version":"26.3.27","strategy":"download"}`, `{"version":"26.3.27","strategy":"separate-pinned-artifact","unknown":true}`} {
		fields["optional_xray"] = json.RawMessage(value)
		bad, _ := json.Marshal(fields)
		if _, err := decodeReceipt(strings.NewReader(string(bad))); err == nil {
			t.Fatal("invalid retired receipt accepted")
		}
	}
}
