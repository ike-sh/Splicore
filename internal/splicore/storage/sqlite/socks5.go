package sqlite

import (
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
)

func (w *writer) socks5InboundStamp(in access.Inbound) (identity.Stamp, error) {
	if in.ID.Validate() != nil || in.Protocol != proxy.Key("socks5") {
		return identity.Stamp{}, identity.Err(identity.Invalid, "invalid SOCKS5 inbound")
	}
	var key access.ProtocolKey
	var revision identity.Revision
	var created, updated string
	if err := w.tx.QueryRowContext(w.ctx, "SELECT protocol,wire_version,feature_profile,revision,created_at,updated_at FROM inbounds WHERE id=?", in.ID).
		Scan(&key.Protocol, &key.WireVersion, &key.FeatureProfile, &revision, &created, &updated); err != nil {
		return identity.Stamp{}, storageError(err)
	}
	if key != in.Protocol {
		return identity.Stamp{}, identity.Err(identity.Invalid, "invalid SOCKS5 inbound")
	}
	if in.Revision != revision {
		return identity.Stamp{}, identity.RevisionConflict(revision)
	}
	return storedStamp(revision, created, updated, "inbound")
}

func (w *writer) SetSOCKS5InboundEnabled(in access.Inbound, enabled bool) error {
	stamp, err := w.socks5InboundStamp(in)
	if err != nil {
		return err
	}
	next, err := stamp.Revision.Next()
	if err != nil {
		return err
	}
	return w.exec("UPDATE inbounds SET enabled=?,revision=?,updated_at=? WHERE id=?", enabled, next, utc(updateTime(time.Now(), stamp)), in.ID)
}

func (w *writer) DeleteSOCKS5Inbound(in access.Inbound, bindings []access.Binding) error {
	if _, err := w.socks5InboundStamp(in); err != nil {
		return err
	}
	for _, b := range bindings {
		if b.InboundID != in.ID {
			return identity.Err(identity.Invalid, "invalid SOCKS5 binding owner")
		}
		if err := w.DeleteBindingUser(b, b.Revision); err != nil {
			return err
		}
	}
	if err := w.exec("DELETE FROM listeners WHERE inbound_id=?", in.ID); err != nil {
		return err
	}
	if err := w.exec("DELETE FROM display_endpoints WHERE inbound_id=?", in.ID); err != nil {
		return err
	}
	return w.exec("DELETE FROM inbounds WHERE id=?", in.ID)
}
