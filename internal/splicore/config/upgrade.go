package config

import (
	"bytes"
	"io"
	"path/filepath"

	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"gopkg.in/yaml.v3"
)

// DecodeForUpgrade accepts only the retired bootstrap section for installation
// preflight. Serve uses Decode and rejects it. No artifact is opened or launched.
func DecodeForUpgrade(r io.Reader) (Config, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil || len(b) > MaxBytes {
		return Config{}, identity.Err(identity.Invalid, "invalid upgrade bootstrap")
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	var root yaml.Node
	if d.Decode(&root) != nil || d.Decode(new(yaml.Node)) != io.EOF || checkNode(&root, 0) != nil || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return Config{}, identity.Err(identity.Invalid, "invalid upgrade bootstrap")
	}
	m := root.Content[0]
	for i := 0; i < len(m.Content); i += 2 {
		if m.Content[i].Value != "xray" {
			continue
		}
		v := m.Content[i+1]
		if v.Kind != yaml.MappingNode {
			return Config{}, identity.Err(identity.Invalid, "invalid retired bootstrap section")
		}
		for n := 0; n < len(v.Content); n += 2 {
			key, path := v.Content[n].Value, v.Content[n+1]
			if (key != "binary_path" && key != "runtime_directory") || path.Kind != yaml.ScalarNode || path.Tag != "!!str" || path.Value != "" && (!filepath.IsAbs(path.Value) || filepath.Clean(path.Value) != path.Value || !identity.Label(path.Value, 1024)) {
				return Config{}, identity.Err(identity.Invalid, "invalid retired bootstrap section")
			}
		}
		m.Content = append(m.Content[:i], m.Content[i+2:]...)
		break
	}
	clean, err := yaml.Marshal(&root)
	if err != nil {
		return Config{}, err
	}
	return Decode(bytes.NewReader(clean))
}
