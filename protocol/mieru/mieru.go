// Package mieru integrates the official Mieru SDK behind owned runtime ports.
// Registration, validation, credential/config mapping, lifecycle and plaintext
// statistics belong here; SDK types remain private to the backend package.
package mieru

import "github.com/ike-sh/Splicore/protocol/mieru/backend"

type Compiler = backend.MieruCompiler
type OutboundFactory = backend.MieruOutboundFactory
