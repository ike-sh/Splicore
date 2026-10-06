package sqlite

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

func (s *Store) RevealInboundCredentials(ctx context.Context, id identity.ID) ([]access.Credential, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id FROM credentials WHERE inbound_id=? ORDER BY id LIMIT 17", id)
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
		return nil, identity.Err(identity.Corrupt, "too many server credentials")
	}
	out := []access.Credential{}
	for _, cid := range ids {
		c, err := s.RevealCredential(ctx, cid)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}
