package cli

import (
	"context"
	"flag"
	"io"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
)

func wireGuardCLI(ctx context.Context, args []string, out, errOut io.Writer, deps Dependencies) int {
	bad := func() int {
		return failure(errOut, identity.Err(identity.Invalid, "invalid WireGuard command arguments"))
	}
	if len(args) == 1 && args[0] == "keygen" {
		private, public, err := application.GenerateWireGuardKeys()
		if err != nil {
			return failure(errOut, err)
		}
		return outputJSON(out, map[string]string{"PrivateKey": private, "PublicKey": public})
	}
	if len(args) == 0 || args[0] == "keygen" {
		return bad()
	}
	fs := flag.NewFlagSet("wireguard", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := fs.String("config", "", "bootstrap file")
	file := fs.String("file", "", "WireGuard endpoint JSON")
	tag := fs.String("tag", "", "endpoint tag")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
		return bad()
	}
	service, ok := deps.Queries.(application.WireGuardCommands)
	if !ok {
		if *cfg == "" {
			return bad()
		}
		config, err := readConfig(*cfg)
		if err != nil {
			return failure(errOut, err)
		}
		control := transport.UnixClient(config.API.UnixSocket)
		defer control.Close()
		service = control
	}
	var result any
	var err error
	switch args[0] {
	case "validate", "create", "replace":
		if *file == "" || *tag != "" {
			return bad()
		}
		var raw []byte
		raw, err = networkFile(*file)
		var config E.WireGuard
		if err == nil {
			err = application.StrictClientJSON(raw, &config)
		}
		if err == nil {
			switch args[0] {
			case "validate":
				err = service.ValidateWireGuardEndpoint(ctx, config)
				result = map[string]bool{"valid": err == nil}
			case "replace":
				result, err = service.ReplaceWireGuardEndpoint(ctx, config)
			default:
				result, err = service.CreateWireGuardEndpoint(ctx, config)
			}
		}
	case "list":
		if *tag != "" || *file != "" {
			return bad()
		}
		result, err = service.WireGuardEndpoints(ctx)
	case "status", "start", "close":
		if *tag == "" || *file != "" {
			return bad()
		}
		switch args[0] {
		case "status":
			result, err = service.WireGuardEndpointStatus(ctx, *tag)
		case "start":
			result, err = service.StartWireGuardEndpoint(ctx, *tag)
		case "close":
			result, err = service.CloseWireGuardEndpoint(ctx, *tag)
		}
	default:
		return bad()
	}
	if err != nil {
		return failure(errOut, err)
	}
	return outputJSON(out, result)
}
