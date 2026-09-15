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
				staticRolePath + "*",
			},
		},
		Paths: []*framework.Path{
			b.pathConfig(),
			b.pathRoles(),
			b.pathRolesList(),
			b.pathCreds(),
			b.pathStaticRoles(),
			b.pathStaticRolesList(),
			b.pathStaticCreds(),
			b.pathRotateRole(),
			b.pathRotateRoot(),
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

"rotate-root" replaces the admin key with a new one under the same LiteLLM
user.

Static roles at "static-roles/<name>" bind an existing key by alias. Vault
regenerates the key to take ownership and serves it from "static-creds/<name>"
until "rotate-role/<name>" regenerates it again.
`
