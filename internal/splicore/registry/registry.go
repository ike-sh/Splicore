// Package registry composes immutable compiled extension registries.
package registry

import (
	"reflect"
	"slices"
	"sort"

	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
)

// Registration happens only in constructors. Concurrent reads require no locks.
type Protocols struct {
	entries map[access.ProtocolKey]ports.Protocol
	order   []access.ProtocolKey
}

func NewProtocols(entries ...ports.Protocol) (*Protocols, error) {
	r := &Protocols{entries: make(map[access.ProtocolKey]ports.Protocol)}
	for _, p := range entries {
		if nilEntry(p) {
			return nil, identity.Err(identity.Invalid, "nil protocol registration")
		}
		m := p.Metadata()
		if err := m.Key.Validate(); err != nil {
			return nil, err
		}
		if m.ABI != 1 {
			return nil, identity.Err(identity.Invalid, "unsupported protocol ABI")
		}
		if _, ok := r.entries[m.Key]; ok {
			return nil, identity.Err(identity.Duplicate, "duplicate protocol registration")
		}
		r.entries[m.Key] = p
		r.order = append(r.order, m.Key)
	}
	sort.Slice(r.order, func(i, j int) bool { return r.order[i].String() < r.order[j].String() })
	return r, nil
}

func (r *Protocols) Get(key access.ProtocolKey) (ports.Protocol, error) {
	p, ok := r.entries[key]
	if !ok {
		return nil, identity.Err(identity.NotFound, "unknown protocol")
	}
	return p, nil
}

func (r *Protocols) Keys() []access.ProtocolKey { return append([]access.ProtocolKey{}, r.order...) }

type Engines struct {
	entries map[string]ports.Engine
	order   []string
}

func NewEngines(entries ...ports.Engine) (*Engines, error) {
	r := &Engines{entries: make(map[string]ports.Engine)}
	for _, e := range entries {
		if nilEntry(e) {
			return nil, identity.Err(identity.Invalid, "nil engine registration")
		}
		m := e.Metadata()
		if !identity.Label(m.ID, 64) || m.ABI != 1 {
			return nil, identity.Err(identity.Invalid, "invalid engine registration")
		}
		if _, ok := r.entries[m.ID]; ok {
			return nil, identity.Err(identity.Duplicate, "duplicate engine registration")
		}
		r.entries[m.ID] = e
		r.order = append(r.order, m.ID)
	}
	sort.Strings(r.order)
	return r, nil
}

func (r *Engines) Get(id string) (ports.Engine, error) {
	e, ok := r.entries[id]
	if !ok {
		return nil, identity.Err(identity.NotFound, "unknown engine")
	}
	return e, nil
}
func (r *Engines) Keys() []string { return append([]string{}, r.order...) }

type Exporters struct {
	entries map[ports.Format]ports.Exporter
	order   []ports.Format
}

func NewExporters(entries ...ports.Exporter) (*Exporters, error) {
	r := &Exporters{entries: make(map[ports.Format]ports.Exporter)}
	for _, e := range entries {
		if nilEntry(e) || !identity.Label(string(e.Format()), 64) {
			return nil, identity.Err(identity.Invalid, "invalid exporter registration")
		}
		key := e.Format()
		if _, ok := r.entries[key]; ok {
			return nil, identity.Err(identity.Duplicate, "duplicate exporter registration")
		}
		r.entries[key] = e
		r.order = append(r.order, key)
	}
	slices.Sort(r.order)
	return r, nil
}

func nilEntry(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Func, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func (r *Exporters) Get(format ports.Format) (ports.Exporter, error) {
	e, ok := r.entries[format]
	if !ok {
		return nil, identity.Err(identity.NotFound, "unknown exporter")
	}
	return e, nil
}
func (r *Exporters) Keys() []ports.Format { return append([]ports.Format{}, r.order...) }
