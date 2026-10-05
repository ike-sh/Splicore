package cli

import (
	"context"
	"encoding/json"
	"flag"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"github.com/sagernet/sing-box/internal/splicore/networkruntime"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/transport"
	"io"
	"os"
)

func networkFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, identity.Err(identity.Unavailable, "network input file unavailable")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, application.ClientDocumentLimit+1))
	if err != nil || len(b) > application.ClientDocumentLimit {
		return nil, identity.Err(identity.Invalid, "network input exceeds limit")
	}
	return b, nil
}
func networkCLI(ctx context.Context, args []string, out, errOut io.Writer, deps Dependencies) int {
	if len(args) < 2 {
		return failure(errOut, identity.Err(identity.Invalid, "network subcommand required"))
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := fs.String("config", "", "bootstrap file")
	file := fs.String("file", "", "canonical document")
	planFile := fs.String("plan", "", "saved plan")
	id := fs.String("id", "", "immutable ID")
	domain := fs.String("domain", "", "explicit DNS lookup")
	if fs.Parse(args[2:]) != nil || fs.NArg() != 0 {
		return failure(errOut, identity.Err(identity.Invalid, "invalid network arguments"))
	}
	s, ok := deps.Queries.(application.ClientCommands)
	n, networkOK := deps.Queries.(application.NetworkQueries)
	if !ok || !networkOK {
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
		n = ctl
	}
	var result any
	var err error
	switch {
	case args[0] == "route" && args[1] == "explain":
		var b []byte
		b, err = networkFile(*file)
		var q networkruntime.Query
		if err == nil {
			err = application.StrictClientJSON(b, &q)
		}
		if err == nil {
			result, err = n.RouteExplain(ctx, q)
		}
	case args[0] == "dns" && args[1] == "lookup":
		result, err = n.DNSLookup(ctx, *domain)
	case args[0] == "dns" && args[1] == "flush":
		err = n.FlushDNS(ctx)
		result = map[string]bool{"flushed": err == nil}
	case args[0] == "policy" && args[1] == "select":
		var b []byte
		b, err = networkFile(*file)
		var selected P.Action
		if err == nil {
			err = application.StrictClientJSON(b, &selected)
		}
		if err == nil {
			b, _ = json.Marshal(application.ClientMutation{Resource: "policy-group", Action: "select", ID: identity.ID(*id), Selected: &selected})
			var plan ports.ClientPlan
			plan, err = s.PlanClient(ctx, b)
			if err == nil {
				result, err = s.ApplyClient(ctx, application.ApplyRequest{Document: b, Digest: plan.Digest, Revision: plan.Revision})
			}
		}
	case args[1] == "status" || args[1] == "list" || args[1] == "export":
		var statusErr error
		status, statusErr := s.ClientStatus(ctx)
		err = statusErr
		if err == nil {
			switch args[0] {
			case "route":
				result = status.State.Network.Route
			case "policy":
				if args[1] == "status" {
					result = status.Network.Groups
				} else {
					result = status.State.Network.Groups
				}
			case "dns":
				if args[1] == "status" {
					result = status.Network.DNS
				} else {
					result = map[string]any{"profile": status.State.Network.DNS, "servers": status.State.Network.Servers, "rules": status.State.Network.DNSRules}
				}
			case "rule-set":
				result = status.State.Network.RuleSets
			case "route-rule":
				result = status.State.Network.Route.Rules
			case "network":
				result = status.State.Network
			}
		}
	default:
		var b []byte
		b, err = networkFile(*file)
		var m application.ClientMutation
		if err == nil {
			err = application.StrictClientJSON(b, &m)
			if err != nil && args[0] == "network" {
				var canonical P.Config
				if decodeErr := application.StrictClientJSON(b, &canonical); decodeErr == nil {
					m = application.ClientMutation{Resource: "network", Action: "replace", Network: &canonical}
					b, err = json.Marshal(m)
				}
			}
		}
		allowed := map[string]map[string]bool{"network": {"network": true}, "policy": {"policy-group": true}, "dns": {"dns-server": true, "dns-rule": true, "dns-profile": true}, "rule-set": {"rule-set": true}, "route-rule": {"route-rule": true}}
		if err == nil && !allowed[args[0]][m.Resource] {
			err = identity.Err(identity.Invalid, "network command resource mismatch")
		}
		if err == nil {
			switch args[1] {
			case "validate":
				err = s.ValidateClient(ctx, b)
				result = map[string]bool{"valid": err == nil}
			case "plan":
				result, err = s.PlanClient(ctx, b)
			case "apply":
				var raw []byte
				raw, err = networkFile(*planFile)
				var plan ports.ClientPlan
				if err == nil {
					err = application.StrictClientJSON(raw, &plan)
				}
				if err == nil {
					result, err = s.ApplyClient(ctx, application.ApplyRequest{Document: b, Digest: plan.Digest, Revision: plan.Revision})
				}
			default:
				err = identity.Err(identity.Invalid, "use validate, plan, apply, status or explicit lookup")
			}
		}
	}
	if err != nil {
		return failure(errOut, err)
	}
	return outputJSON(out, result)
}
