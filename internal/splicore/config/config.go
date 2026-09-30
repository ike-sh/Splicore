// Package config defines strict Config Schema 1 process bootstrap settings.
package config

import (
	"bytes"
	"io"
	"path/filepath"

	"github.com/sagernet/sing-box/internal/splicore/domain/identity"

	"gopkg.in/yaml.v3"
)

const MaxBytes = 1 << 20

type API struct {
	UnixSocket string `json:"unix_socket" yaml:"unix_socket"`
}
type Config struct {
	Schema         int    `json:"schema" yaml:"schema"`
	StateDirectory string `json:"state_directory" yaml:"state_directory"`
	API            API    `json:"api" yaml:"api"`
}

func Default() Config {
	return Config{Schema: 1, StateDirectory: "/var/lib/splicore", API: API{UnixSocket: "/run/splicore/splicore.sock"}}
}

func Decode(r io.Reader) (Config, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil || len(b) > MaxBytes {
		return Config{}, identity.Err(identity.Invalid, "bootstrap config exceeds limit or cannot be read")
	}
	var node yaml.Node
	if yaml.Unmarshal(b, &node) != nil || checkNode(&node, 0) != nil {
		return Config{}, identity.Err(identity.Invalid, "invalid bootstrap YAML structure")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true)
	var c Config
	if decoder.Decode(&c) != nil {
		return Config{}, identity.Err(identity.Invalid, "unknown or invalid bootstrap field")
	}
	var extra yaml.Node
	if decoder.Decode(&extra) != io.EOF {
		return Config{}, identity.Err(identity.Invalid, "multiple bootstrap documents prohibited")
	}
	if err = c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func checkNode(n *yaml.Node, depth int) error {
	if depth > 16 || n.Kind == yaml.AliasNode || n.Anchor != "" || n.Kind == yaml.ScalarNode && n.Tag != "!!str" && n.Tag != "!!int" {
		return identity.Err(identity.Invalid, "unsupported YAML structure")
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || seen[k.Value] {
				return identity.Err(identity.Invalid, "duplicate or invalid YAML key")
			}
			seen[k.Value] = true
		}
	}
	for _, child := range n.Content {
		if err := checkNode(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) Validate() error {
	if c.Schema != 1 {
		return identity.Err(identity.Invalid, "unsupported bootstrap schema")
	}
	if !filepath.IsAbs(c.StateDirectory) || !filepath.IsAbs(c.API.UnixSocket) || !identity.Label(c.StateDirectory, 1024) || !identity.Label(c.API.UnixSocket, 1024) {
		return identity.Err(identity.Invalid, "bootstrap paths must be absolute")
	}
	return nil
}
