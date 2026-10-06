package clientruntime

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/hostnetwork"
	"github.com/ike-sh/Splicore/internal/splicore/nativetun"
)

type hostController struct {
	capabilities  *hostnetwork.Capabilities // injected adapter snapshot; nil uses real platform
	manager       *hostnetwork.Manager
	platform      *hostnetwork.Platform
	proxy         *hostnetwork.Lease
	proxyListener *localListener // protected by Manager.mu
	lastError     string
}

// Counter maps are fixed before a staged TUN can dispatch a flow.
func (m *Manager) prepareCounters(s *snapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s.inCounters = map[identity.ID]*counter{}
	s.outCounters = map[identity.ID]*counter{}
	s.nodeCounters = map[identity.ID]*counter{}
	for _, i := range s.state.LocalInbounds {
		c := m.inStats[i.ID]
		if c == nil {
			c = &counter{}
		}
		s.inCounters[i.ID] = c
	}
	for _, o := range s.state.Outbounds {
		c := m.outStats[o.ID]
		if c == nil {
			c = &counter{}
		}
		s.outCounters[o.ID] = c
	}
	for _, n := range s.state.Nodes {
		c := m.nodeStats[n.ID]
		if c == nil {
			c = &counter{}
		}
		s.nodeCounters[n.ID] = c
	}
}

// ConfigureHost acquires the private operational journal and reconciles it before
// restoring SQLite intent. Opening it never enables a route, proxy or TUN.
func (m *Manager) ConfigureHost(ctx context.Context, directory string) error {
	platform := hostnetwork.NewPlatform()
	store, err := hostnetwork.OpenStore(directory)
	if err != nil {
		return err
	}
	manager, err := hostnetwork.New(platform, store)
	if manager == nil {
		store.Close()
		return err
	}
	m.host = &hostController{manager: manager, platform: platform}
	if err != nil {
		return err
	}
	return manager.Recover(ctx)
}
func (m *Manager) HostStatus() hostnetwork.Status {
	if m.host == nil {
		return hostnetwork.Status{Recovery: "unconfigured"}
	}
	out := m.host.manager.Status()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.host.lastError != "" {
		out.LastError = m.host.lastError
		out.Recovery = "degraded"
	}
	return out
}
func (m *Manager) RepairHost(ctx context.Context) error {
	m.mu.Lock()
	active := len(m.listeners) > 0
	m.mu.Unlock()
	if active {
		return identity.Err(identity.Conflict, "stop client runtime before network repair")
	}
	if m.host == nil {
		return identity.Err(identity.Unavailable, "host recovery unavailable")
	}
	err := m.host.manager.Recover(ctx)
	if err == nil {
		m.mu.Lock()
		m.host.lastError = ""
		m.mu.Unlock()
	}
	return err
}
func tunSpec(state client.ProfileState) *client.LocalInbound {
	for _, i := range state.LocalInbounds {
		if i.Kind == "tun" {
			copy := i
			return &copy
		}
	}
	return nil
}
func (m *Manager) validateHostChange(state client.ProfileState, old *snapshot) error {
	if !state.Enabled {
		return nil
	}
	spec := tunSpec(state)
	capabilities := hostnetwork.PlatformCapabilities()
	if m.host != nil && m.host.capabilities != nil {
		capabilities = *m.host.capabilities
	}
	if spec != nil && capabilities.TUN == "blocked-partial-construction" {
		return identity.Err(identity.NotImplemented, "Windows TUN requires recoverable partial-construction ownership")
	}
	if state.Host.SystemProxy.Enabled && capabilities.SystemProxy == "blocked-incomplete-ownership" {
		return identity.Err(identity.NotImplemented, "Windows system proxy requires complete WinINET connection-state ownership")
	}
	if spec != nil {
		if !nativetun.Included {
			return identity.Err(identity.NotImplemented, "TUN requires a build with with_gvisor")
		}
		if spec.TUN.Stack != "" && spec.TUN.Stack != "gvisor" {
			return identity.Err(identity.NotImplemented, "owned TUN integration uses the official gvisor stack")
		}
	}
	if (spec != nil || state.Host.SystemProxy.Enabled) && m.host == nil {
		return identity.Err(identity.Unavailable, "durable host recovery must be configured before enabling host integration")
	}
	if old != nil && old.state.Enabled {
		prior := tunSpec(old.state)
		if prior != nil && spec != nil && (prior.ID != spec.ID || !reflect.DeepEqual(prior.TUN, spec.TUN)) {
			return identity.Err(identity.Conflict, "stop TUN before editing interface settings")
		}
		if old.state.Host.SystemProxy.Enabled && state.Host.SystemProxy.Enabled && !reflect.DeepEqual(old.state.Host, state.Host) {
			return identity.Err(identity.Conflict, "disable system proxy before changing its listener")
		}
		if old.state.Host.SystemProxy.Enabled && state.Host.SystemProxy.Enabled {
			for _, i := range old.state.LocalInbounds {
				if i.ID == state.Host.SystemProxy.LocalInbound {
					for _, j := range state.LocalInbounds {
						if j.ID == i.ID && (i.Kind != j.Kind || i.Listen != j.Listen) {
							return identity.Err(identity.Conflict, "disable system proxy before editing its listener")
						}
					}
				}
			}
		}
	}
	return nil
}
func (p *Prepared) prepareHost(ctx context.Context) error {
	m := p.m
	if spec := tunSpec(p.s.state); spec != nil {
		if p.listeners[spec.ID] == nil {
			endpoints := []netip.Addr{}
			for _, n := range p.s.state.Nodes {
				if ip, e := netip.ParseAddr(n.Endpoint.Host); e == nil {
					endpoints = append(endpoints, ip)
				} else {
					ips, e := p.s.network.Bootstrap(ctx, n.Endpoint.Host)
					if e != nil {
						return identity.Err(identity.Unavailable, "TUN endpoint bootstrap failed")
					}
					endpoints = append(endpoints, ips...)
				}
			}
			plan, err := m.host.platform.Plan(ctx, *spec.TUN, endpoints)
			if err != nil {
				return err
			}
			ingress := newTUNIngress(m, *spec, p.s)
			listener := &localListener{spec: *spec, tun: ingress, done: make(chan struct{})}
			lease, err := m.host.manager.Prepare(ctx, plan.Records, func() error {
				device, e := m.host.platform.Device(spec.TUN.Interface)
				if e != nil {
					return e
				}
				if e = device.Start(); e != nil {
					return e
				}
				return ingress.start(device)
			}, ingress.stop)
			ingress.lease = lease
			if err != nil {
				ingress.stop()
				return errors.Join(err, m.host.platform.CloseOwnedDevice(spec.TUN.Interface))
			}
			listener.ready.Store(true)
			if err = lease.Verify(ctx); err != nil {
				listener.ready.Store(false)
				ingress.stop()
				return errors.Join(err, lease.Restore(context.WithoutCancel(ctx)), m.host.platform.CloseOwnedDevice(spec.TUN.Interface))
			}
			m.underlay.SetHostVerifier(lease.Verify)
			p.listeners[spec.ID] = listener
			p.newListeners = append(p.newListeners, listener)
		}
	}
	m.mu.Lock()
	proxyActive := m.host != nil && m.host.proxy != nil
	m.mu.Unlock()
	if p.s.state.Host.SystemProxy.Enabled && !proxyActive {
		var endpoint string
		for _, i := range p.s.state.LocalInbounds {
			if i.ID == p.s.state.Host.SystemProxy.LocalInbound {
				endpoint = net.JoinHostPort(i.Listen.Host, strconv.Itoa(int(i.Listen.Port)))
			}
		}
		plan, err := m.host.manager.SystemProxyPlan(endpoint)
		if err != nil {
			return err
		}
		lease, err := m.host.manager.Prepare(ctx, plan, func() error {
			l := p.listeners[p.s.state.Host.SystemProxy.LocalInbound]
			if l == nil || l.socket == nil || l.spec.Kind != "http" && l.spec.Kind != "mixed" || l.socket.Addr().String() != endpoint {
				return identity.Err(identity.Unavailable, "system proxy listener unavailable")
			}
			return nil
		})
		p.proxy = lease
		return err
	}
	return nil
}

// An accept failure restores the owned proxy immediately. The specific listener
// pointer prevents a retired worker from restoring a replacement generation.
func (m *Manager) listenerFailed(l *localListener) {
	m.mu.Lock()
	if m.host == nil || m.host.proxy == nil || m.host.proxyListener != l {
		m.mu.Unlock()
		return
	}
	lease := m.host.proxy
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := lease.Restore(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.host.proxy != lease {
		return
	}
	if err == nil {
		m.host.proxy = nil
		m.host.proxyListener = nil
		m.host.lastError = "host_activation_degraded"
	} else {
		m.host.lastError = "host_restore_failed"
	}
}
func (m *Manager) closeListener(ctx context.Context, l *localListener) error {
	l.ready.Store(false)
	if l.tun != nil {
		l.tun.stop()
		err := errors.Join(l.tun.stopError(), l.tun.lease.Restore(ctx))
		if err == nil {
			m.underlay.SetHostVerifier(nil)
		}
		if err != nil && m.host != nil {
			m.mu.Lock()
			m.host.lastError = "host_restore_failed"
			m.mu.Unlock()
		}
		return err
	}
	err := l.socket.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
func (p *Prepared) abortHost() error {
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var err error
	for _, l := range p.newListeners {
		err = errors.Join(err, p.m.closeListener(cleanup, l))
	}
	if p.proxy != nil {
		err = errors.Join(err, p.proxy.Restore(cleanup))
	}
	return err
}
