package litellm

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const rotateRolePath = "rotate-role/"

func (b *backend) pathRotateRole() *framework.Path {
	return &framework.Path{
		Pattern: rotateRolePath + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixLiteLLM,
			OperationVerb:   "rotate",
			OperationSuffix: "static-role",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the static role.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRotateRoleWrite},
		},
		HelpSynopsis:    "Regenerate the key held for a static role.",
		HelpDescription: "The previous key stops working immediately. The key is looked up by alias, so this also recovers a role whose key was regenerated outside Vault.",
	}
}

func (b *backend) pathRotateRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	role, err := getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("static role %q not found", name), nil
	}
	c, err := getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	tokenID, err := c.findKeyByAlias(ctx, role.KeyAlias)
	if err != nil {
		return nil, err
	}
	if tokenID == "" {
		return logical.ErrorResponse("no LiteLLM key has alias %q; the key was deleted outside Vault", role.KeyAlias), nil
	}
	return regenerateStaticRole(ctx, req.Storage, c, name, role.KeyAlias, tokenID)
}
