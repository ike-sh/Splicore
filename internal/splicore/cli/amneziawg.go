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

func amneziaWGCLI(ctx context.Context, args []string, out, errOut io.Writer, deps Dependencies) int {
	bad := func() int {
		return failure(errOut, identity.Err(identity.Invalid, "invalid AmneziaWG command arguments"))
	}
	if len(args) == 1 && args[0] == "keygen" {
		private, public, err := application.GenerateAmneziaWGKeys()
		if err != nil {
			return failure(errOut, err)
		}
		return outputJSON(out, map[string]string{"PrivateKey": private, "PublicKey": public})
	}
	if len(args) == 0 || args[0] == "keygen" {
		return bad()
	}
	fs := flag.NewFlagSet("amneziawg", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := fs.String("config", "", "bootstrap file")
	file := fs.String("file", "", "AmneziaWG endpoint JSON")
	tag := fs.String("tag", "", "endpoint tag")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
		return bad()
	}
	service, ok := deps.Queries.(application.AmneziaWGCommands)
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
		var config E.AmneziaWG
		if err == nil {
			err = application.StrictClientJSON(raw, &config)
		}
		if err == nil {
			switch args[0] {
			case "validate":
				err = service.ValidateAmneziaWGEndpoint(ctx, config)
				result = map[string]bool{"valid": err == nil}
			case "replace":
				result, err = service.ReplaceAmneziaWGEndpoint(ctx, config)
			default:
				result, err = service.CreateAmneziaWGEndpoint(ctx, config)
			}
		}
	case "list":
		if *tag != "" || *file != "" {
			return bad()
		}
		result, err = service.AmneziaWGEndpoints(ctx)
	case "status", "start", "close":
		if *tag == "" || *file != "" {
			return bad()
		}
		switch args[0] {
		case "status":
			result, err = service.AmneziaWGEndpointStatus(ctx, *tag)
		case "start":
			result, err = service.StartAmneziaWGEndpoint(ctx, *tag)
		case "close":
			result, err = service.CloseAmneziaWGEndpoint(ctx, *tag)
		}
	default:
		return bad()
	}
	if err != nil {
		return failure(errOut, err)
	}
	return outputJSON(out, result)
}
