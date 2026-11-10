package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
)

func check(ctx context.Context, args []string, out, errOut io.Writer, deps Dependencies) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "bootstrap file")
	protocol := fs.String("protocol", "", "additional inbound protocol")
	file := fs.String("file", "", "additional canonical inbound document")
	if fs.Parse(args) != nil || fs.NArg() > 1 || *path != "" && fs.NArg() != 0 || (*protocol == "") != (*file == "") {
		_, _ = fmt.Fprintln(errOut, "usage: splicore check --config <bootstrap> [--protocol <name> --file <inbound.json>]")
		return 1
	}
	if fs.NArg() == 1 {
		*path = fs.Arg(0)
	}
	if *path == "" {
		_, _ = fmt.Fprintln(errOut, "check requires an explicit bootstrap file")
		return 1
	}
	c, err := readConfig(*path)
	if err == nil && deps.Check != nil {
		err = deps.Check(ctx, c)
	}
	if err != nil {
		return configurationFailure(errOut, err)
	}
	if *file != "" {
		b, err := boundedFile(*file)
		if err == nil {
			p, e, _, initErr := registry.NativeCore()
			err = initErr
			if err == nil {
				err = p.CheckCreation(e, *protocol, b)
			}
		}
		if err != nil {
			_, _ = fmt.Fprintln(errOut, "invalid protocol configuration or unavailable resources; check the protocol, listener, credentials and TLS files")
			return 1
		}
	}
	_, err = fmt.Fprintln(out, "configuration valid; no listeners started")
	if err != nil {
		return 1
	}
	return 0
}

// Only fixed local guidance crosses this boundary. Domain messages from network
// responses and arbitrary dependency errors retain the normal redaction policy.
func configurationFailure(out io.Writer, err error) int {
	var e *identity.Error
	if errors.As(err, &e) {
		switch e.Message {
		case "cannot read bootstrap file", "bootstrap config exceeds limit or cannot be read", "invalid bootstrap YAML structure", "unknown or invalid bootstrap field", "multiple bootstrap documents prohibited", "key file must be an absolute path", "unsupported bootstrap schema", "bootstrap paths must be absolute", "run requires explicit --config bootstrap file", "stop requires explicit --config bootstrap file", "control directory must have mode 0700", "control directory owner mismatch", "control socket already exists; operator review required", "key directory must be private", "key file must be a private regular 32-byte file", "private directory owner or permissions invalid", "private file owner or permissions invalid", "committed state schema incompatible", "pending operations require startup recovery", "invalid or corrupt committed state", "production control transport unavailable", "cannot bind private control pipe", "control socket path must be absolute and fit the Unix socket limit":
			_, _ = fmt.Fprintln(out, string(e.Code)+": "+e.Message)
			return 1
		}
	}
	return failure(out, err)
}
