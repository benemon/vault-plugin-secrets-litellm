package litellm

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const rolePath = "roles/"

// reservedKeyRequestFields are owned by the backend at generate time.
var reservedKeyRequestFields = []string{"key", "key_alias", "duration"}

type roleEntry struct {
	TTL            time.Duration  `json:"ttl"`
	MaxTTL         time.Duration  `json:"max_ttl"`
	KeyRequest     map[string]any `json:"key_request"`
	UserIDTemplate string         `json:"user_id_template"`
	TeamIDTemplate string         `json:"team_id_template"`
}

func (b *backend) pathRoles() *framework.Path {
	return &framework.Path{
		Pattern: rolePath + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixLiteLLM,
			OperationSuffix: "role",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role.",
				Required:    true,
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default lease duration for generated keys. Defaults to the mount's default lease TTL.",
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Maximum lease duration for generated keys. Defaults to the mount's maximum lease TTL.",
			},
			"key_request": {
				Type:        framework.TypeString,
				Description: "JSON object sent as the body of LiteLLM's POST /key/generate. The key, key_alias and duration fields are set by Vault and may not be given here.",
			},
			"user_id_template": {
				Type:        framework.TypeString,
				Description: "Identity template resolved against the caller and sent as the key's user_id, e.g. {{identity.entity.aliases.<mount accessor>.name}}. A key is refused when it cannot resolve.",
			},
			"team_id_template": {
				Type:        framework.TypeString,
				Description: "Identity template resolved against the caller and sent as the key's team_id, e.g. {{identity.groups.names.<group>.metadata.litellm_team_id}}. A key is refused when it cannot resolve.",
			},
		},
		ExistenceCheck: b.roleExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRoleRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRoleDelete},
		},
		HelpSynopsis:    "Manage roles that describe the LiteLLM keys to generate.",
		HelpDescription: "A role holds the LiteLLM key specification and the lease bounds applied to keys read from creds/<name>.",
	}
}

func (b *backend) pathRolesList() *framework.Path {
	return &framework.Path{
		Pattern: rolePath + "?$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixLiteLLM,
			OperationSuffix: "roles",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathRoleList},
		},
		HelpSynopsis: "List the configured roles.",
	}
}

func (b *backend) roleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	role, err := getRole(ctx, req.Storage, d.Get("name").(string))
	return role != nil, err
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &roleEntry{}
	}
	if v, ok := d.GetOk("ttl"); ok {
		role.TTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(v.(int)) * time.Second
	}
	for _, f := range []string{"user_id_template", "team_id_template"} {
		v, ok := d.GetOk(f)
		if !ok {
			continue
		}
		tpl := v.(string)
		if tpl != "" {
			if _, err := framework.ValidateIdentityTemplate(tpl); err != nil {
				return logical.ErrorResponse("%s: %s", f, err), nil
			}
		}
		if f == "user_id_template" {
			role.UserIDTemplate = tpl
		} else {
			role.TeamIDTemplate = tpl
		}
	}
	if v, ok := d.GetOk("key_request"); ok {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(v.(string)), &parsed); err != nil {
			return logical.ErrorResponse("key_request must be a JSON object: %s", err), nil
		}
		role.KeyRequest = parsed
	}

	if role.MaxTTL > 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl cannot exceed max_ttl"), nil
	}
	for _, f := range reservedKeyRequestFields {
		if _, set := role.KeyRequest[f]; set {
			return logical.ErrorResponse("key_request.%s is set by Vault and may not be given", f), nil
		}
	}
	if md, set := role.KeyRequest["metadata"]; set {
		if _, ok := md.(map[string]any); !ok {
			return logical.ErrorResponse("key_request.metadata must be an object"), nil
		}
	}

	entry, err := logical.StorageEntryJSON(rolePath+name, role)
	if err != nil {
		return nil, err
	}
	return nil, req.Storage.Put(ctx, entry)
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	role, err := getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil || role == nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]any{
			"ttl":              int64(role.TTL.Seconds()),
			"max_ttl":          int64(role.MaxTTL.Seconds()),
			"key_request":      role.KeyRequest,
			"user_id_template": role.UserIDTemplate,
			"team_id_template": role.TeamIDTemplate,
		},
	}, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, rolePath+d.Get("name").(string))
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, rolePath)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

func getRole(ctx context.Context, s logical.Storage, name string) (*roleEntry, error) {
	entry, err := s.Get(ctx, rolePath+name)
	if err != nil || entry == nil {
		return nil, err
	}
	role := &roleEntry{}
	if err := entry.DecodeJSON(role); err != nil {
		return nil, fmt.Errorf("decoding role %q: %w", name, err)
	}
	return role, nil
}
