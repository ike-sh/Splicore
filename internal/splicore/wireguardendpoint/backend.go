package wireguardendpoint

import (
	"context"
	"errors"
	"net"
	"net/netip"

	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
)

// Availability is derived runtime state, never persisted backend selection.
type Availability string

const (
	Supported               Availability = "SUPPORTED"
	UnsupportedPlatform     Availability = "UNSUPPORTED_PLATFORM"
	KernelUnavailable       Availability = "WIREGUARD_KERNEL_UNAVAILABLE"
	KernelNotQualified      Availability = "KERNEL_NOT_QUALIFIED"
	InsufficientPrivilege   Availability = "INSUFFICIENT_PRIVILEGE"
	NetNSUnavailable        Availability = "NETNS_UNAVAILABLE"
	NetlinkUnavailable      Availability = "NETLINK_UNAVAILABLE"
	NetfilterUnavailable    Availability = "NETFILTER_UNAVAILABLE"
	NamespaceRestoreFailure Availability = "NAMESPACE_RESTORE_FAILURE"
	ConfigInvalid           Availability = "CONFIG_INVALID"
	RuntimeFailure          Availability = "RUNTIME_FAILURE"
	InterfaceCollision      Availability = "INTERFACE_COLLISION"
	CleanupFailure          Availability = "CLEANUP_FAILURE"
)

// BackendError preserves errno without formatting configuration or netlink data.
type BackendError struct {
	Class     Availability
	Operation string
	Cause     error
}

func (e *BackendError) Error() string {
	return "WireGuard " + string(e.Class) + " (" + e.Operation + ")"
}
func (e *BackendError) Unwrap() error { return e.Cause }

func fallbackEligible(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	found, eligible := false, true
	walkBackendErrors(err, func(e *BackendError) {
		found = true
		switch e.Class {
		case UnsupportedPlatform, KernelUnavailable, KernelNotQualified, InsufficientPrivilege, NetNSUnavailable, NetlinkUnavailable, NetfilterUnavailable:
		default:
			eligible = false
		}
	})
	return found && eligible && availabilityBranch(err)
}

// A raw sibling error in a Join (for example a DNS/invariant error) is not
// authorized by the availability classification of another branch.
func availabilityBranch(err error) bool {
	if _, ok := err.(*BackendError); ok {
		return true
	}
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		for _, cause := range e.Unwrap() {
			if !availabilityBranch(cause) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return availabilityBranch(e.Unwrap())
	}
	return false
}

// Joined operation/rollback errors must not hide a fatal namespace failure.
func backendAvailability(err error) Availability {
	class := RuntimeFailure
	found := false
	walkBackendErrors(err, func(e *BackendError) {
		if !found || e.Class == NamespaceRestoreFailure || (e.Class == CleanupFailure && class != NamespaceRestoreFailure) {
			class, found = e.Class, true
		}
	})
	return class
}

func walkBackendErrors(err error, visit func(*BackendError)) {
	if e, ok := err.(*BackendError); ok {
		visit(e)
	}
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		for _, cause := range e.Unwrap() {
			walkBackendErrors(cause, visit)
		}
	case interface{ Unwrap() error }:
		walkBackendErrors(e.Unwrap(), visit)
	}
}

type BackendStatus struct {
	Requested      E.WireGuardBackend `json:"requested_backend"`
	Selected       E.WireGuardBackend `json:"selected_backend,omitempty"`
	Availability   Availability       `json:"kernel_availability,omitempty"`
	InterfaceName  string             `json:"interface_name,omitempty"`
	InterfaceIndex int                `json:"interface_index,omitempty"`
	Namespace      uint64             `json:"namespace_inode,omitempty"`
	BirthNamespace uint64             `json:"birth_namespace_inode,omitempty"`
	PeerCount      int                `json:"peer_count"`
	FWMark         int                `json:"fwmark,omitempty"`
}

// WireGuardBackend varies only OS/data-plane ownership. Validation, DNS,
// AllowedIPs identity, application routing and endpoint lifecycle stay shared.
type WireGuardBackend interface {
	Prepare(context.Context) error
	Start(context.Context) error
	DialTCP(context.Context, netip.Addr, netip.AddrPort) (net.Conn, error)
	ListenUDP(context.Context, netip.Addr) (net.PacketConn, error)
	Status(*Status)
	Close() error
}

type userspaceBackend struct {
	e      *Endpoint
	config E.WireGuard
}

func (*userspaceBackend) Prepare(context.Context) error     { return nil }
func (b *userspaceBackend) Start(ctx context.Context) error { return b.e.startUserspace(ctx, b.config) }

func (b *userspaceBackend) DialTCP(ctx context.Context, local netip.Addr, remote netip.AddrPort) (net.Conn, error) {
	return b.e.stack.DialTCP(ctx, local, remote)
}

func (b *userspaceBackend) ListenUDP(ctx context.Context, local netip.Addr) (net.PacketConn, error) {
	return b.e.stack.ListenUDP(ctx, local)
}
func (b *userspaceBackend) Status(s *Status) { b.e.userspaceStatus(s) }
func (b *userspaceBackend) Close() error     { return b.e.closeUserspace() }
