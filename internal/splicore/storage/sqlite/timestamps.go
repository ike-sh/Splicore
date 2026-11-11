package sqlite

import (
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

// storedStamp rejects corrupt committed state before an update can overwrite it.
func storedStamp(revision identity.Revision, created, updated, resource string) (identity.Stamp, error) {
	stamp := identity.Stamp{Revision: revision}
	var err error
	stamp.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return identity.Stamp{}, identity.Err(identity.Corrupt, "invalid "+resource+" timestamp")
	}
	stamp.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	if err != nil || stamp.Validate() != nil {
		return identity.Stamp{}, identity.Err(identity.Corrupt, "invalid "+resource)
	}
	return stamp, nil
}

// updateTime preserves committed timestamp order when wall time moves backward.
func updateTime(now time.Time, stamps ...identity.Stamp) time.Time {
	now = now.UTC()
	for _, stamp := range stamps {
		if now.Before(stamp.UpdatedAt) {
			now = stamp.UpdatedAt
		}
	}
	return now
}
