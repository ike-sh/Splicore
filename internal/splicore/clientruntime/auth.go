package clientruntime

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks5"
	"time"
)

type proxyIdentity struct {
	account access.Account
	binding access.Binding
	pair    socks5.Credentials
	active  bool
}

func (m *Manager) proxyFailure(s *session, gen *snapshot) {
	for _, c := range []*counter{&s.stats, gen.inCounters[s.inbound], gen.outCounters[s.outbound], gen.nodeCounters[s.node], gen.accountCounters[s.account]} {
		if c != nil {
			c.errors.Add(1)
		}
	}
}

func (m *Manager) ConfigureAccounts(lookup func(context.Context, identity.ID) (access.Account, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accountLookup = lookup
}
func validateProxyAuth(state client.ProfileState, credentials map[identity.ID]access.Credential) error {
	seen := map[identity.ID]bool{}
	for _, i := range state.LocalInbounds {
		users := map[string]bool{}
		for _, b := range i.Bindings {
			c := credentials[b.CredentialID]
			if c.Validate() != nil || c.OwnerAccountID == nil || *c.OwnerAccountID != b.AccountID || seen[b.ID] {
				return proxy.Invalid()
			}
			seen[b.ID] = true
			pair, e := proxy.Pair(c)
			if e != nil || users[pair.Username] {
				return proxy.Invalid()
			}
			users[pair.Username] = true
		}
	}
	return nil
}
func (m *Manager) prepareProxyAuth(ctx context.Context, s *snapshot, credentials map[identity.ID]access.Credential) error {
	m.mu.Lock()
	lookup := m.accountLookup
	m.mu.Unlock()
	s.auth = map[identity.ID][]proxyIdentity{}
	s.accountCounters = map[identity.ID]*counter{}
	for _, i := range s.state.LocalInbounds {
		for _, b := range i.Bindings {
			if lookup == nil {
				return proxy.Invalid()
			}
			a, e := lookup(ctx, b.AccountID)
			if e != nil || a.Validate() != nil || a.ID != b.AccountID {
				return proxy.Invalid()
			}
			c := credentials[b.CredentialID]
			pair, _ := proxy.Pair(c)
			s.auth[i.ID] = append(s.auth[i.ID], proxyIdentity{a, b, *pair, c.State == "active"})
			m.mu.Lock()
			counters := m.accountStats[a.ID]
			m.mu.Unlock()
			if counters == nil {
				counters = &counter{}
			}
			s.accountCounters[a.ID] = counters
		}
	}
	return nil
}
func (m *Manager) proxyVerifier(s *session, gen *snapshot) func(string, string) bool {
	auth := false
	for _, i := range gen.state.LocalInbounds {
		if i.ID == s.inbound {
			auth = i.Auth
		}
	}
	if !auth {
		return nil
	}
	return func(user, pass string) bool {
		u, p := sha256.Sum256([]byte(user)), sha256.Sum256([]byte(pass))
		var account identity.ID
		for _, v := range gen.auth[s.inbound] {
			vu, vp := sha256.Sum256([]byte(v.pair.Username)), sha256.Sum256([]byte(v.pair.Password))
			match := subtle.ConstantTimeCompare(u[:], vu[:]) & subtle.ConstantTimeCompare(p[:], vp[:])
			if match == 1 && v.active && v.binding.Enabled && v.account.Enabled && v.account.Status == access.Active && (v.account.ExpiresAt == nil || time.Now().Before(*v.account.ExpiresAt)) {
				account = v.account.ID
			}
		}
		if account == "" {
			return false
		}
		m.mu.Lock()
		s.account = account
		m.mu.Unlock()
		return true
	}
}
