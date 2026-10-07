package sqlite

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"time"
)

func (w *writer) bindingUser(b access.Binding, expected identity.Revision) error {
	var account, inbound, credential identity.ID
	var revision identity.Revision
	if err := w.tx.QueryRowContext(w.ctx, "SELECT account_id,inbound_id,credential_id,revision FROM bindings WHERE id=?", b.ID).Scan(&account, &inbound, &credential, &revision); err != nil {
		return storageError(err)
	}
	if revision != expected {
		return identity.RevisionConflict(revision)
	}
	if account != b.AccountID || inbound != b.InboundID || credential != b.CredentialID {
		return identity.Err(identity.Invalid, "binding owner mismatch")
	}
	return nil
}

func (w *writer) RotateBindingCredential(b access.Binding, c access.Credential, expected identity.Revision) error {
	if err := w.bindingUser(b, expected); err != nil {
		return err
	}
	if c.Validate() != nil || c.ID != b.CredentialID || c.OwnerAccountID == nil || *c.OwnerAccountID != b.AccountID || c.OwnerInboundID != nil || c.OwnerNodeID != nil || c.State != "active" {
		return identity.Err(identity.Invalid, "credential owner mismatch")
	}
	var owner identity.ID
	var kind access.CredentialKind
	var revision identity.Revision
	var refs int
	if err := w.tx.QueryRowContext(w.ctx, "SELECT account_id,kind,revision FROM credentials WHERE id=?", c.ID).Scan(&owner, &kind, &revision); err != nil {
		return storageError(err)
	}
	if owner != b.AccountID || kind != c.Kind || revision != c.Revision {
		return identity.Err(identity.Conflict, "credential changed")
	}
	if err := w.tx.QueryRowContext(w.ctx, "SELECT count(*) FROM bindings WHERE credential_id=?", c.ID).Scan(&refs); err != nil {
		return storageError(err)
	}
	if refs != 1 {
		return identity.Err(identity.Conflict, "credential has other references")
	}
	if w.options.Cipher == nil {
		return identity.Err(identity.Unavailable, "credential key unavailable")
	}
	plain, err := encodePayload(c.Payload)
	if err != nil {
		return err
	}
	defer clear(plain)
	data, err := w.options.Cipher.Seal(plain, credentialAAD(c))
	if err != nil {
		return err
	}
	next, err := revision.Next()
	if err != nil {
		return err
	}
	if err = w.exec("UPDATE credentials SET ciphertext=?,key_id=?,revision=?,updated_at=? WHERE id=?", data, w.options.Cipher.KeyID(), next, utc(time.Now()), c.ID); err != nil {
		return err
	}
	return w.SetBindingEnabled(b.ID, b.Enabled, expected)
}

func (w *writer) DeleteBindingUser(b access.Binding, expected identity.Revision) error {
	if err := w.bindingUser(b, expected); err != nil {
		return err
	}
	var bindings, credentials int
	if err := w.tx.QueryRowContext(w.ctx, "SELECT count(*) FROM bindings WHERE account_id=? OR credential_id=?", b.AccountID, b.CredentialID).Scan(&bindings); err != nil {
		return storageError(err)
	}
	if err := w.tx.QueryRowContext(w.ctx, "SELECT count(*) FROM credentials WHERE account_id=?", b.AccountID).Scan(&credentials); err != nil {
		return storageError(err)
	}
	if bindings != 1 || credentials != 1 {
		return identity.Err(identity.Conflict, "user has other references")
	}
	if err := w.exec("DELETE FROM bindings WHERE id=?", b.ID); err != nil {
		return err
	}
	if err := w.exec("DELETE FROM credentials WHERE id=? AND account_id=?", b.CredentialID, b.AccountID); err != nil {
		return err
	}
	return w.exec("DELETE FROM accounts WHERE id=?", b.AccountID)
}
