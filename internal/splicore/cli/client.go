package cli

import (
	"context"
	"encoding/json"
	"flag"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
	"io"
)

func clientCLI(ctx context.Context, args []string, out, errOut io.Writer, deps Dependencies) int {
	if len(args) < 2 {
		return failure(errOut, identity.Err(identity.Invalid, "client subcommand required"))
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := fs.String("config", "", "bootstrap file")
	file := fs.String("file", "", "canonical client mutation document")
	planFile := fs.String("plan", "", "saved plan")
	id := fs.String("id", "", "immutable resource ID")
	if fs.Parse(args[2:]) != nil || fs.NArg() != 0 {
		return failure(errOut, identity.Err(identity.Invalid, "invalid client arguments"))
	}
	s, ok := deps.Queries.(application.ClientCommands)
	if !ok {
		if *cfg == "" {
			return failure(errOut, identity.Err(identity.Invalid, "explicit bootstrap file required"))
		}
		c, err := readConfig(*cfg)
		if err != nil {
			return failure(errOut, err)
		}
		ctl := transport.UnixClient(c.API.UnixSocket)
		defer ctl.Close()
		s = ctl
	}
	var result any
	var err error
	if args[1] == "status" && (args[0] == "client" || args[0] == "tun") || args[1] == "list" || args[1] == "get" {
		status, e := s.ClientStatus(ctx)
		err = e
		if err == nil {
			if args[0] == "client" {
				result = status
			} else if args[0] == "tun" {
				items := []any{}
				for _, i := range status.State.LocalInbounds {
					if i.Kind == "tun" {
						items = append(items, i)
					}
				}
				result = map[string]any{"inbounds": items, "host_network": status.Host}
			} else {
				var items []any
				switch args[0] {
				case "node":
					for _, n := range status.State.Nodes {
						if args[1] == "list" || string(n.ID) == *id {
							items = append(items, n)
						}
					}
				case "outbound":
					for _, o := range status.State.Outbounds {
						if args[1] == "list" || string(o.ID) == *id {
							items = append(items, o)
						}
					}
				case "local-binding":
					for _, i := range status.State.LocalInbounds {
						for _, b := range i.Bindings {
							if args[1] == "list" || string(b.ID) == *id {
								items = append(items, b)
							}
						}
					}
				case "local-inbound":
					for _, i := range status.State.LocalInbounds {
						if args[1] == "list" || string(i.ID) == *id {
							items = append(items, i)
						}
					}
				case "route":
					result = status.State.Route
				}
				if result == nil {
					if args[1] == "get" {
						if len(items) != 1 {
							err = identity.Err(identity.NotFound, "client resource not found")
						} else {
							result = items[0]
						}
					} else {
						if items == nil {
							items = []any{}
						}
						result = items
					}
				}
			}
		}
	} else if args[0] == "client" && (args[1] == "start" || args[1] == "stop" || args[1] == "restart") || args[0] == "network" && args[1] == "repair" {
		actions := []string{args[1]}
		for _, action := range actions {
			resource := "runtime"
			if args[0] == "network" {
				resource = "host-network"
			}
			b, _ := json.Marshal(application.ClientMutation{Resource: resource, Action: action})
			p, e := s.PlanClient(ctx, b)
			if e != nil {
				err = e
				break
			}
			result, err = s.ApplyClient(ctx, application.ApplyRequest{Document: b, Digest: p.Digest, Revision: p.Revision})
			if err != nil {
				break
			}
		}
	} else {
		var b []byte
		b, err = boundedFile(*file)
		var m application.ClientMutation
		if err == nil {
			err = application.StrictJSON(b, &m)
		}
		expected := args[0]
		if expected == "tun" {
			expected = "local-inbound"
		}
		if err == nil && args[0] == "tun" && m.LocalInbound != nil && m.LocalInbound.Kind != "tun" {
			err = identity.Err(identity.Invalid, "tun requires a TUN local inbound")
		}
		if err == nil && args[0] != "client" && m.Resource != expected {
			err = identity.Err(identity.Invalid, "client document resource mismatch")
		}
		if err == nil {
			switch args[1] {
			case "validate":
				err = s.ValidateClient(ctx, b)
				result = map[string]bool{"valid": true}
			case "plan":
				result, err = s.PlanClient(ctx, b)
			case "apply":
				var raw []byte
				raw, err = boundedFile(*planFile)
				var p ports.ClientPlan
				if err == nil {
					err = application.StrictJSON(raw, &p)
				}
				if err == nil {
					result, err = s.ApplyClient(ctx, application.ApplyRequest{Document: b, Digest: p.Digest, Revision: p.Revision})
				}
			default:
				err = identity.Err(identity.Invalid, "use validate, plan and apply for client mutations")
			}
		}
	}
	if err != nil {
		return failure(errOut, err)
	}
	return outputJSON(out, result)
}
