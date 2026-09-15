package litellm

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// operationPrefixLiteLLM is the prefix for OpenAPI operation ids.
	operationPrefixLiteLLM = "litellm"
)

// version is overridden at build time with -ldflags "-X ...litellm.version=".
var version = "0.1.0-dev"

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *backend {
	b := &backend{}
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				configPath,
			},
		},
		Paths: []*framework.Path{
			b.pathConfig(),
			b.pathRoles(),
			b.pathRolesList(),
			b.pathCreds(),
		},
		Secrets: []*framework.Secret{
			keySecret(b),
		},
		BackendType:    logical.TypeLogical,
		RunningVersion: "v" + version,
	}
	return b
}

type backend struct {
	*framework.Backend
}

const backendHelp = `
The LiteLLM secrets engine issues LiteLLM virtual API keys.

Configure it with the LiteLLM URL and an admin key at "config", define
roles at "roles/<name>" carrying the key specification, and read
"creds/<name>" to generate a key whose lifetime is tied to the Vault lease.
`
