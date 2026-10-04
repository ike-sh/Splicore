package ports

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/provider"
)

type ProviderRepository interface {
	RevealProviderSource(context.Context, identity.ID) (provider.Source, error)
}
type ProviderWriter interface {
	ReplaceProviderSources(map[identity.ID]provider.Source) error
}
