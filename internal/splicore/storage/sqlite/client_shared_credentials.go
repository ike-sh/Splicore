package sqlite

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
)

func (s *Store) RevealClientSharedCredentials(ctx context.Context, id identity.ID) ([]access.Credential, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	// Filter before decryption. Server-only keys cannot cross this port.
	rows, err := s.db.QueryContext(ctx, "SELECT id FROM credentials WHERE inbound_id=? AND kind='password' AND state='active' ORDER BY id LIMIT 17", id)
	if err != nil {
		return nil, storageError(err)
	}
	ids := []identity.ID{}
	for rows.Next() {
		var cid identity.ID
		if err = rows.Scan(&cid); err != nil {
			rows.Close()
			return nil, storageError(err)
		}
		ids = append(ids, cid)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, storageError(err)
	}
	if len(ids) > 16 {
		return nil, identity.Err(identity.Corrupt, "too many shared credentials")
	}
	result := []access.Credential{}
	for _, cid := range ids {
		c, err := s.RevealCredential(ctx, cid)
		if err != nil {
			return nil, err
		}
		if c.Kind != access.Password || c.State != "active" || c.OwnerInboundID == nil || *c.OwnerInboundID != id {
			return nil, identity.Err(identity.Corrupt, "invalid shared credential ownership")
		}
		result = append(result, c)
	}
	return result, nil
}
