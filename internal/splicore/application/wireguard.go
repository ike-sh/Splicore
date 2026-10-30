package application

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"

	"github.com/ike-sh/Splicore/internal/splicore/clientruntime"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/wireguardendpoint"
)

type WireGuardCommands interface {
	ValidateWireGuardEndpoint(context.Context, E.WireGuard) error
	CreateWireGuardEndpoint(context.Context, E.WireGuard) (wireguardendpoint.Status, error)
	ReplaceWireGuardEndpoint(context.Context, E.WireGuard) (wireguardendpoint.Status, error)
	StartWireGuardEndpoint(context.Context, string) (wireguardendpoint.Status, error)
	WireGuardEndpointStatus(context.Context, string) (wireguardendpoint.Status, error)
	WireGuardEndpoints(context.Context) ([]wireguardendpoint.Status, error)
	CloseWireGuardEndpoint(context.Context, string) (wireguardendpoint.Status, error)
}

func GenerateWireGuardKeys() (string, string, error) { return wireguardendpoint.GenerateKeys() }
func (s *Service) ValidateWireGuardEndpoint(_ context.Context, config E.WireGuard) error {
	if config.Validate() != nil {
		return identity.Err(identity.Invalid, "invalid WireGuard endpoint configuration")
	}
	return nil
}

func (s *Service) CreateWireGuardEndpoint(ctx context.Context, config E.WireGuard) (wireguardendpoint.Status, error) {
	if err := s.ValidateWireGuardEndpoint(ctx, config); err != nil {
		return wireguardendpoint.Status{}, err
	}
	s.endpointOperation.Lock()
	defer s.endpointOperation.Unlock()
	s.endpointMu.Lock()
	closed := s.endpointsClosed
	existing := s.endpoints[config.Tag]
	awgExisting := s.awgEndpoints[config.Tag]
	count := len(s.endpoints) + len(s.awgEndpoints)
	s.endpointMu.Unlock()
	if closed {
		return wireguardendpoint.Status{}, identity.Err(identity.Unavailable, "network endpoint registry closed")
	}
	if count >= 64 {
		return wireguardendpoint.Status{}, identity.Err(identity.Invalid, "network endpoint registry limit exceeded")
	}
	if existing != nil || awgExisting != nil {
		return wireguardendpoint.Status{}, identity.Err(identity.Conflict, "network endpoint tag already exists")
	}
	endpoint, err := s.newWireGuardEndpoint(config)
	if err != nil {
		return wireguardendpoint.Status{}, identity.Err(identity.Unavailable, "WireGuard endpoint unavailable")
	}
	s.endpointMu.Lock()
	if s.endpoints == nil {
		s.endpoints = map[string]*wireguardendpoint.Endpoint{}
	}
	s.endpoints[config.Tag] = endpoint
	s.endpointMu.Unlock()
	return endpoint.Status(), nil
}

// ReplaceWireGuardEndpoint closes and joins the complete old generation before
// creating a new one. Old flows end; identity tables never change on a live Device.
func (s *Service) ReplaceWireGuardEndpoint(ctx context.Context, config E.WireGuard) (wireguardendpoint.Status, error) {
	if err := s.ValidateWireGuardEndpoint(ctx, config); err != nil {
		return wireguardendpoint.Status{}, err
	}
	s.endpointOperation.Lock()
	defer s.endpointOperation.Unlock()
	old, err := s.wireGuardEndpoint(config.Tag)
	if err != nil {
		return wireguardendpoint.Status{}, err
	}
	if err = old.Close(); err != nil {
		return old.Status(), err
	}
	replacement, err := s.newWireGuardEndpoint(config)
	if err != nil {
		return old.Status(), err
	}
	s.endpointMu.Lock()
	s.endpoints[config.Tag] = replacement
	s.endpointMu.Unlock()
	if err = replacement.Start(ctx); err != nil {
		return replacement.Status(), wireGuardStartError(err, "replacement WireGuard endpoint could not start")
	}
	return replacement.Status(), nil
}

func (s *Service) newWireGuardEndpoint(config E.WireGuard) (*wireguardendpoint.Endpoint, error) {
	return wireguardendpoint.New(context.Background(), config, wireguardendpoint.Options{Dispatcher: wireGuardIngress{s, config.Tag}, Underlay: s.underlay, LookupEndpoint: func(ctx context.Context, host string) ([]netip.Addr, error) {
		if s.client == nil {
			return nil, identity.Err(identity.Unavailable, "Core DNS runtime unavailable")
		}
		return s.client.manager.BootstrapHost(ctx, host)
	}, LookupHost: func(ctx context.Context, host string) ([]netip.Addr, error) {
		if s.client == nil {
			return nil, identity.Err(identity.Unavailable, "Core DNS runtime unavailable")
		}
		return s.client.manager.LookupHost(ctx, host)
	}})
}

func (s *Service) wireGuardEndpoint(tag string) (*wireguardendpoint.Endpoint, error) {
	s.endpointMu.Lock()
	defer s.endpointMu.Unlock()
	e := s.endpoints[tag]
	if e == nil || s.endpointsClosed {
		return nil, identity.Err(identity.NotFound, "network endpoint not found")
	}
	return e, nil
}

func (s *Service) lookupEndpoint(tag string) (ports.ClientDialer, error) {
	s.endpointMu.Lock()
	defer s.endpointMu.Unlock()
	if !s.endpointsClosed {
		if e := s.endpoints[tag]; e != nil {
			return e, nil
		}
		if e := s.awgEndpoints[tag]; e != nil {
			return e, nil
		}
	}
	return nil, identity.Err(identity.NotFound, "network endpoint not found")
}

func (s *Service) borrowEndpoint(tag string) (ports.ClientDialer, error) {
	if _, err := s.lookupEndpoint(tag); err != nil {
		return nil, err
	}
	return clientruntime.BorrowedEndpoint{Lookup: func() (ports.ClientDialer, error) { return s.lookupEndpoint(tag) }}, nil
}

func (s *Service) StartWireGuardEndpoint(ctx context.Context, tag string) (wireguardendpoint.Status, error) {
	e, err := s.wireGuardEndpoint(tag)
	if err != nil {
		return wireguardendpoint.Status{}, err
	}
	if err = e.Start(ctx); err != nil {
		return e.Status(), wireGuardStartError(err, "WireGuard endpoint could not start")
	}
	return e.Status(), nil
}

func wireGuardStartError(cause error, message string) error {
	err := identity.Err(identity.Unavailable, message)
	if _, ok := errors.AsType[*wireguardendpoint.BackendError](cause); ok {
		return errors.Join(err, cause)
	}
	return err
}

func (s *Service) WireGuardEndpointStatus(_ context.Context, tag string) (wireguardendpoint.Status, error) {
	e, err := s.wireGuardEndpoint(tag)
	if err != nil {
		return wireguardendpoint.Status{}, err
	}
	return e.Status(), nil
}

func (s *Service) WireGuardEndpoints(_ context.Context) ([]wireguardendpoint.Status, error) {
	s.endpointMu.Lock()
	list := make([]*wireguardendpoint.Endpoint, 0, len(s.endpoints))
	for _, e := range s.endpoints {
		list = append(list, e)
	}
	s.endpointMu.Unlock()
	out := make([]wireguardendpoint.Status, 0, len(list))
	for _, e := range list {
		out = append(out, e.Status())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tag < out[j].Tag })
	return out, nil
}

func (s *Service) CloseWireGuardEndpoint(_ context.Context, tag string) (wireguardendpoint.Status, error) {
	s.endpointOperation.Lock()
	defer s.endpointOperation.Unlock()
	e, err := s.wireGuardEndpoint(tag)
	if err != nil {
		return wireguardendpoint.Status{}, err
	}
	err = e.Close()
	return e.Status(), err
}

func (s *Service) CloseWireGuardEndpoints(_ context.Context) error {
	s.endpointOperation.Lock()
	defer s.endpointOperation.Unlock()
	s.endpointMu.Lock()
	s.endpointsClosed = true
	list := make([]*wireguardendpoint.Endpoint, 0, len(s.endpoints))
	for _, e := range s.endpoints {
		list = append(list, e)
	}
	s.endpointMu.Unlock()
	var err error
	for _, e := range list {
		err = errors.Join(err, e.Close())
	}
	return err
}

type wireGuardIngress struct {
	service *Service
	tag     string
}

func (d wireGuardIngress) TCP(ctx context.Context, c net.Conn, source, destination netip.AddrPort) {
	if d.service.client == nil {
		_ = c.Close()
		return
	}
	d.service.client.manager.EndpointTCP(ctx, d.tag, c, source, destination)
}

func (d wireGuardIngress) UDP(ctx context.Context, c net.Conn, source, destination netip.AddrPort) {
	if d.service.client == nil {
		_ = c.Close()
		return
	}
	d.service.client.manager.EndpointUDP(ctx, d.tag, c, source, destination)
}
