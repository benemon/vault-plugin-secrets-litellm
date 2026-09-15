package litellm

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const staticCredsPath = "static-creds/"

func (b *backend) pathStaticCreds() *framework.Path {
	return &framework.Path{
		Pattern: staticCredsPath + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixLiteLLM,
			OperationVerb:   "read",
			OperationSuffix: "static-key",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the static role.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.pathStaticCredsRead},
		},
		HelpSynopsis:    "Read the key held for a static role.",
		HelpDescription: "Returns the key Vault stored at bind or last rotation. Fails if the key was regenerated or deleted outside Vault.",
	}
}

func (b *backend) pathStaticCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
	err = c.checkKey(ctx, role.TokenID)
	var ae *apiError
	if errors.As(err, &ae) && ae.Status == 404 {
		return logical.ErrorResponse("LiteLLM key %q was regenerated or deleted outside Vault; write rotate-role/%s to take ownership again", role.KeyAlias, name), nil
	}
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]any{
			"key":       role.Key,
			"key_alias": role.KeyAlias,
			"token_id":  role.TokenID,
		},
	}, nil
}
