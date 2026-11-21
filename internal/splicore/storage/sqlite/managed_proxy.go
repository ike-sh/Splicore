package sqlite

import (
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
)

func (w *writer) managedProxyInboundStamp(in access.Inbound) (identity.Stamp, error) {
	if in.ID.Validate() != nil || !proxy.IsManagedInbound(in.Protocol) {
		return identity.Stamp{}, identity.Err(identity.Invalid, "invalid managed proxy inbound")
	}
	var key access.ProtocolKey
	var revision identity.Revision
	var created, updated string
	if err := w.tx.QueryRowContext(w.ctx, "SELECT protocol,wire_version,feature_profile,revision,created_at,updated_at FROM inbounds WHERE id=?", in.ID).
		Scan(&key.Protocol, &key.WireVersion, &key.FeatureProfile, &revision, &created, &updated); err != nil {
		return identity.Stamp{}, storageError(err)
	}
	if key != in.Protocol {
		return identity.Stamp{}, identity.Err(identity.Invalid, "invalid managed proxy inbound")
	}
	if in.Revision != revision {
		return identity.Stamp{}, identity.RevisionConflict(revision)
	}
	return storedStamp(revision, created, updated, "inbound")
}

func (w *writer) SetManagedProxyInboundEnabled(in access.Inbound, enabled bool) error {
	stamp, err := w.managedProxyInboundStamp(in)
	if err != nil {
		return err
	}
	next, err := stamp.Revision.Next()
	if err != nil {
		return err
	}
	return w.exec("UPDATE inbounds SET enabled=?,revision=?,updated_at=? WHERE id=?", enabled, next, utc(updateTime(time.Now(), stamp)), in.ID)
}

func (w *writer) DeleteManagedProxyInbound(in access.Inbound, bindings []access.Binding) error {
	if _, err := w.managedProxyInboundStamp(in); err != nil {
		return err
	}
	for _, b := range bindings {
		if b.InboundID != in.ID {
			return identity.Err(identity.Invalid, "invalid managed proxy binding owner")
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

// RevokeManagedProxyCredential changes the encrypted credential's admission
// state and its sole binding in the same revision-guarded transaction.
func (w *writer) RevokeManagedProxyCredential(b access.Binding, expected identity.Revision) error {
	if err := w.bindingUser(b, expected); err != nil {
		return err
	}
	var inbound access.ProtocolKey
	if err := w.tx.QueryRowContext(w.ctx, "SELECT protocol,wire_version,feature_profile FROM inbounds WHERE id=?", b.InboundID).
		Scan(&inbound.Protocol, &inbound.WireVersion, &inbound.FeatureProfile); err != nil {
		return storageError(err)
	}
	if inbound != proxy.Key("http") {
		return identity.Err(identity.Invalid, "invalid HTTP proxy credential owner")
	}
	var revision identity.Revision
	var created, updated string
	if err := w.tx.QueryRowContext(w.ctx, "SELECT revision,created_at,updated_at FROM credentials WHERE id=? AND account_id=? AND kind=? AND state='active'",
		b.CredentialID, b.AccountID, access.UsernamePassword).Scan(&revision, &created, &updated); err != nil {
		return storageError(err)
	}
	var refs int
	if err := w.tx.QueryRowContext(w.ctx, "SELECT count(*) FROM bindings WHERE credential_id=?", b.CredentialID).Scan(&refs); err != nil {
		return storageError(err)
	}
	if refs != 1 {
		return identity.Err(identity.Conflict, "credential has other references")
	}
	credentialStamp, err := storedStamp(revision, created, updated, "credential")
	if err != nil {
		return err
	}
	bindingStamp, err := w.bindingUpdateStamp(b.ID, expected)
	if err != nil {
		return err
	}
	next, err := revision.Next()
	if err != nil {
		return err
	}
	now := updateTime(time.Now(), credentialStamp, bindingStamp)
	if err = w.exec("UPDATE credentials SET state='revoked',revision=?,updated_at=? WHERE id=?", next, utc(now), b.CredentialID); err != nil {
		return err
	}
	return w.setBindingEnabled(b.ID, false, bindingStamp, now)
}
