package ports

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/provider"
)

type ProviderRepository interface {
	RevealProviderSource(context.Context, identity.ID) (provider.Source, error)
}
type ProviderWriter interface {
	ReplaceProviderSources(map[identity.ID]provider.Source) error
}
