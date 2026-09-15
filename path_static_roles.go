package litellm

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const staticRolePath = "static-roles/"

// staticRoleEntry holds the only copy of the key's plaintext; LiteLLM keeps
// just the hash and returns the plaintext once, from regenerate.
type staticRoleEntry struct {
	KeyAlias string `json:"key_alias"`
	TokenID  string `json:"token_id"`
	Key      string `json:"key"`
}

func (b *backend) pathStaticRoles() *framework.Path {
	return &framework.Path{
		Pattern: staticRolePath + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixLiteLLM,
			OperationSuffix: "static-role",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the static role.",
				Required:    true,
			},
			"key_alias": {
				Type:        framework.TypeString,
				Description: "Alias of the existing LiteLLM key to bind. Vault regenerates the key on bind and becomes its only holder.",
				Required:    true,
			},
		},
		ExistenceCheck: b.staticRoleExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathStaticRoleWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathStaticRoleWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathStaticRoleRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathStaticRoleDelete},
		},
		HelpSynopsis:    "Bind an existing LiteLLM key to a static role.",
		HelpDescription: "Binding regenerates the key, which invalidates the previous plaintext for every current consumer. Deleting the role leaves the key in LiteLLM.",
	}
}

func (b *backend) pathStaticRolesList() *framework.Path {
	return &framework.Path{
		Pattern: staticRolePath + "?$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixLiteLLM,
			OperationSuffix: "static-roles",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathStaticRoleList},
		},
		HelpSynopsis: "List the static roles.",
	}
}

func (b *backend) staticRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	role, err := getStaticRole(ctx, req.Storage, d.Get("name").(string))
	return role != nil, err
}

func (b *backend) pathStaticRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	alias := d.Get("key_alias").(string)
	if alias == "" {
		return logical.ErrorResponse("key_alias is required"), nil
	}
	existing, err := getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return logical.ErrorResponse("static role %q is already bound to %q; delete it to rebind", name, existing.KeyAlias), nil
	}
	bound, err := staticRoleForAlias(ctx, req.Storage, alias)
	if err != nil {
		return nil, err
	}
	if bound != "" {
		return logical.ErrorResponse("key alias %q is already bound to static role %q", alias, bound), nil
	}
	c, err := getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	tokenID, err := c.findKeyByAlias(ctx, alias)
	if err != nil {
		return nil, err
	}
	if tokenID == "" {
		return logical.ErrorResponse("no LiteLLM key has alias %q", alias), nil
	}
	return regenerateStaticRole(ctx, req.Storage, c, name, alias, tokenID)
}

func regenerateStaticRole(ctx context.Context, s logical.Storage, c *client, name, alias, tokenID string) (*logical.Response, error) {
	key, err := c.regenerateKey(ctx, tokenID)
	if err != nil {
		return nil, err
	}
	entry, err := logical.StorageEntryJSON(staticRolePath+name, &staticRoleEntry{
		KeyAlias: alias,
		TokenID:  key.TokenID,
		Key:      key.Key,
	})
	if err != nil {
		return nil, err
	}
	if err := s.Put(ctx, entry); err != nil {
		return nil, err
	}
	resp := &logical.Response{}
	resp.AddWarning(fmt.Sprintf("LiteLLM key %q was regenerated; its previous value no longer works. Read static-creds/%s for the current key.", alias, name))
	return resp, nil
}

func (b *backend) pathStaticRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	role, err := getStaticRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil || role == nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]any{
			"key_alias": role.KeyAlias,
			"token_id":  role.TokenID,
		},
	}, nil
}

func (b *backend) pathStaticRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, staticRolePath+d.Get("name").(string))
}

func (b *backend) pathStaticRoleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, staticRolePath)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

func getStaticRole(ctx context.Context, s logical.Storage, name string) (*staticRoleEntry, error) {
	entry, err := s.Get(ctx, staticRolePath+name)
	if err != nil || entry == nil {
		return nil, err
	}
	role := &staticRoleEntry{}
	if err := entry.DecodeJSON(role); err != nil {
		return nil, fmt.Errorf("decoding static role %q: %w", name, err)
	}
	return role, nil
}

// staticRoleForAlias returns the name of the static role bound to alias, or "".
func staticRoleForAlias(ctx context.Context, s logical.Storage, alias string) (string, error) {
	names, err := s.List(ctx, staticRolePath)
	if err != nil {
		return "", err
	}
	for _, name := range names {
		role, err := getStaticRole(ctx, s, name)
		if err != nil {
			return "", err
		}
		if role != nil && role.KeyAlias == alias {
			return name, nil
		}
	}
	return "", nil
}
