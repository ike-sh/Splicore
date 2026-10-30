package application

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"

	"github.com/ike-sh/Splicore/internal/splicore/amneziawgendpoint"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

type AmneziaWGCommands interface {
	ValidateAmneziaWGEndpoint(context.Context, E.AmneziaWG) error
	CreateAmneziaWGEndpoint(context.Context, E.AmneziaWG) (amneziawgendpoint.Status, error)
	ReplaceAmneziaWGEndpoint(context.Context, E.AmneziaWG) (amneziawgendpoint.Status, error)
	StartAmneziaWGEndpoint(context.Context, string) (amneziawgendpoint.Status, error)
	AmneziaWGEndpointStatus(context.Context, string) (amneziawgendpoint.Status, error)
	AmneziaWGEndpoints(context.Context) ([]amneziawgendpoint.Status, error)
	CloseAmneziaWGEndpoint(context.Context, string) (amneziawgendpoint.Status, error)
}

func GenerateAmneziaWGKeys() (string, string, error) { return amneziawgendpoint.GenerateKeys() }
func (s *Service) ValidateAmneziaWGEndpoint(_ context.Context, config E.AmneziaWG) error {
	if config.Validate() != nil {
		return identity.Err(identity.Invalid, "invalid AmneziaWG endpoint configuration")
	}
	return nil
}

func (s *Service) CreateAmneziaWGEndpoint(ctx context.Context, config E.AmneziaWG) (amneziawgendpoint.Status, error) {
	if err := s.ValidateAmneziaWGEndpoint(ctx, config); err != nil {
		return amneziawgendpoint.Status{}, err
	}
	s.endpointOperation.Lock()
	defer s.endpointOperation.Unlock()
	s.endpointMu.Lock()
	closed := s.endpointsClosed
	existing := s.awgEndpoints[config.Tag]
	wgExisting := s.endpoints[config.Tag]
	count := len(s.endpoints) + len(s.awgEndpoints)
	s.endpointMu.Unlock()
	if closed {
		return amneziawgendpoint.Status{}, identity.Err(identity.Unavailable, "network endpoint registry closed")
	}
	if count >= 64 {
		return amneziawgendpoint.Status{}, identity.Err(identity.Invalid, "network endpoint registry limit exceeded")
	}
	if existing != nil || wgExisting != nil {
		return amneziawgendpoint.Status{}, identity.Err(identity.Conflict, "network endpoint tag already exists")
	}
	endpoint, err := s.newAmneziaWGEndpoint(config)
	if err != nil {
		return amneziawgendpoint.Status{}, identity.Err(identity.Unavailable, "AmneziaWG endpoint unavailable")
	}
	s.endpointMu.Lock()
	if s.awgEndpoints == nil {
		s.awgEndpoints = map[string]*amneziawgendpoint.Endpoint{}
	}
	s.awgEndpoints[config.Tag] = endpoint
	s.endpointMu.Unlock()
	return endpoint.Status(), nil
}

// ReplaceAmneziaWGEndpoint closes and joins the complete old generation before
// creating a new one. Old flows end; identity tables never change on a live Device.
func (s *Service) ReplaceAmneziaWGEndpoint(ctx context.Context, config E.AmneziaWG) (amneziawgendpoint.Status, error) {
	if err := s.ValidateAmneziaWGEndpoint(ctx, config); err != nil {
		return amneziawgendpoint.Status{}, err
	}
	s.endpointOperation.Lock()
	defer s.endpointOperation.Unlock()
	old, err := s.amneziaWGEndpoint(config.Tag)
	if err != nil {
		return amneziawgendpoint.Status{}, err
	}
	if err = old.Close(); err != nil {
		return old.Status(), err
	}
	replacement, err := s.newAmneziaWGEndpoint(config)
	if err != nil {
		return old.Status(), err
	}
	s.endpointMu.Lock()
	s.awgEndpoints[config.Tag] = replacement
	s.endpointMu.Unlock()
	if err = replacement.Start(ctx); err != nil {
		return replacement.Status(), amneziaWGStartError(err, "replacement AmneziaWG endpoint could not start")
	}
	return replacement.Status(), nil
}

func (s *Service) newAmneziaWGEndpoint(config E.AmneziaWG) (*amneziawgendpoint.Endpoint, error) {
	return amneziawgendpoint.New(context.Background(), config, amneziawgendpoint.Options{Dispatcher: amneziaWGIngress{s, config.Tag}, Underlay: s.underlay, LookupEndpoint: func(ctx context.Context, host string) ([]netip.Addr, error) {
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

func (s *Service) amneziaWGEndpoint(tag string) (*amneziawgendpoint.Endpoint, error) {
	s.endpointMu.Lock()
	defer s.endpointMu.Unlock()
	e := s.awgEndpoints[tag]
	if e == nil || s.endpointsClosed {
		return nil, identity.Err(identity.NotFound, "network endpoint not found")
	}
	return e, nil
}

func (s *Service) StartAmneziaWGEndpoint(ctx context.Context, tag string) (amneziawgendpoint.Status, error) {
	e, err := s.amneziaWGEndpoint(tag)
	if err != nil {
		return amneziawgendpoint.Status{}, err
	}
	if err = e.Start(ctx); err != nil {
		return e.Status(), amneziaWGStartError(err, "AmneziaWG endpoint could not start")
	}
	return e.Status(), nil
}

func amneziaWGStartError(cause error, message string) error {
	err := identity.Err(identity.Unavailable, message)
	if _, ok := errors.AsType[*amneziawgendpoint.BackendError](cause); ok {
		return errors.Join(err, cause)
	}
	return err
}

func (s *Service) AmneziaWGEndpointStatus(_ context.Context, tag string) (amneziawgendpoint.Status, error) {
	e, err := s.amneziaWGEndpoint(tag)
	if err != nil {
		return amneziawgendpoint.Status{}, err
	}
	return e.Status(), nil
}

func (s *Service) AmneziaWGEndpoints(_ context.Context) ([]amneziawgendpoint.Status, error) {
	s.endpointMu.Lock()
	list := make([]*amneziawgendpoint.Endpoint, 0, len(s.endpoints)+len(s.awgEndpoints))
	for _, e := range s.awgEndpoints {
		list = append(list, e)
	}
	s.endpointMu.Unlock()
	out := make([]amneziawgendpoint.Status, 0, len(list))
	for _, e := range list {
		out = append(out, e.Status())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tag < out[j].Tag })
	return out, nil
}

func (s *Service) CloseAmneziaWGEndpoint(_ context.Context, tag string) (amneziawgendpoint.Status, error) {
	s.endpointOperation.Lock()
	defer s.endpointOperation.Unlock()
	e, err := s.amneziaWGEndpoint(tag)
	if err != nil {
		return amneziawgendpoint.Status{}, err
	}
	err = e.Close()
	return e.Status(), err
}

func (s *Service) CloseAmneziaWGEndpoints(_ context.Context) error {
	s.endpointOperation.Lock()
	defer s.endpointOperation.Unlock()
	s.endpointMu.Lock()
	s.endpointsClosed = true
	list := make([]*amneziawgendpoint.Endpoint, 0, len(s.endpoints)+len(s.awgEndpoints))
	for _, e := range s.awgEndpoints {
		list = append(list, e)
	}
	s.endpointMu.Unlock()
	var err error
	for _, e := range list {
		err = errors.Join(err, e.Close())
	}
	return err
}

type amneziaWGIngress struct {
	service *Service
	tag     string
}

func (d amneziaWGIngress) TCP(ctx context.Context, c net.Conn, source, destination netip.AddrPort) {
	if d.service.client == nil {
		_ = c.Close()
		return
	}
	d.service.client.manager.EndpointTCP(ctx, d.tag, c, source, destination)
}

func (d amneziaWGIngress) UDP(ctx context.Context, c net.Conn, source, destination netip.AddrPort) {
	if d.service.client == nil {
		_ = c.Close()
		return
	}
	d.service.client.manager.EndpointUDP(ctx, d.tag, c, source, destination)
}
