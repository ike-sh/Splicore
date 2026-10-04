package sqlite

import (
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/provider"
	"github.com/sagernet/sing-box/internal/splicore/jsonstrict"
)

func providerAAD(id identity.ID) []byte { return []byte("Splicore/provider-source/1/" + string(id)) }
func (s *Store) RevealProviderSource(ctx context.Context, id identity.ID) (provider.Source, error) {
	var result provider.Source
	if id.Validate() != nil {
		return result, identity.Err(identity.Invalid, "invalid provider identity")
	}
	if s.options.Cipher == nil {
		return result, identity.Err(identity.Unavailable, "provider key required")
	}
	var b []byte
	var key string
	if e := s.db.QueryRowContext(ctx, "SELECT ciphertext,key_id FROM provider_sources WHERE id=?", id).Scan(&b, &key); e != nil {
		return result, storageError(e)
	}
	if key != s.options.Cipher.KeyID() {
		return result, identity.Err(identity.Unavailable, "provider key unavailable")
	}
	plain, e := s.options.Cipher.Open(b, providerAAD(id))
	if e != nil {
		return result, e
	}
	defer clear(plain)
	if jsonstrict.DecodeLimit(plain, &result, 16384) != nil || result.Validate() != nil {
		return provider.Source{}, identity.Err(identity.Corrupt, "invalid encrypted provider source")
	}
	return result, nil
}
func (w *writer) ReplaceProviderSources(sources map[identity.ID]provider.Source) error {
	if len(sources) == 0 {
		return nil
	}
	if w.options.Cipher == nil {
		return identity.Err(identity.Unavailable, "provider key required")
	}
	for id, s := range sources {
		if id.Validate() != nil || s.Validate() != nil {
			return identity.Err(identity.Invalid, "invalid provider source")
		}
		b, e := json.Marshal(s)
		if e != nil {
			return identity.Err(identity.Invalid, "invalid provider source")
		}
		sealed, e := w.options.Cipher.Seal(b, providerAAD(id))
		clear(b)
		if e != nil {
			return e
		}
		if e = w.exec("INSERT INTO provider_sources VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET ciphertext=excluded.ciphertext,key_id=excluded.key_id", id, sealed, w.options.Cipher.KeyID()); e != nil {
			return e
		}
	}
	return nil
}
