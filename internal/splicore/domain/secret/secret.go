// Package secret makes accidental formatting and JSON disclosure fail closed.
package secret

import (
	"encoding/json"
	"fmt"
)

const Redacted = "[REDACTED]"

type Value struct{ value string }

func New(value string) Value { return Value{value: value} }

// Reveal is explicit sensitive access for a scoped runtime/export/storage adapter.
func (v Value) Reveal() string                { return v.value }
func (v Value) Empty() bool                   { return v.value == "" }
func (v Value) String() string                { return Redacted }
func (v Value) GoString() string              { return Redacted }
func (v Value) Format(s fmt.State, verb rune) { _, _ = s.Write([]byte(Redacted)) }
func (v Value) MarshalJSON() ([]byte, error)  { return json.Marshal(Redacted) }
