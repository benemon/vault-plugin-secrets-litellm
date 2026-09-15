package litellm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	credsPath     = "creds/"
	secretTypeKey = "litellm_key"
)

func (b *backend) pathCreds() *framework.Path {
	return &framework.Path{
		Pattern: credsPath + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixLiteLLM,
			OperationVerb:   "generate",
			OperationSuffix: "key",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.pathCredsRead},
		},
		HelpSynopsis:    "Generate a LiteLLM virtual key for a role.",
		HelpDescription: "The key expires in LiteLLM at the same time as the Vault lease and is deleted when the lease is revoked.",
	}
}

func keySecret(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretTypeKey,
		Fields: map[string]*framework.FieldSchema{
			"key": {
				Type:        framework.TypeString,
				Description: "The LiteLLM virtual key.",
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
		},
		Renew:  b.keyRenew,
		Revoke: b.keyRevoke,
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", name), nil
	}
	c, err := getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Core recomputes and caps the lease from the same inputs (and warns on
	// a cap), so this only has to land LiteLLM's expiry on the same instant.
	ttl, _, err := framework.CalculateTTL(b.System(), 0, role.TTL, 0, role.MaxTTL, 0, time.Time{})
	if err != nil {
		return nil, err
	}
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return nil, err
	}
	alias := fmt.Sprintf("vault-%s-%s", name, hex.EncodeToString(suffix))

	body := make(map[string]any, len(role.KeyRequest)+3)
	for k, v := range role.KeyRequest {
		body[k] = v
	}
	metadata := map[string]any{}
	if md, ok := body["metadata"].(map[string]any); ok {
		for k, v := range md {
			metadata[k] = v
		}
	}
	metadata["vault_role"] = name
	metadata["vault_request_id"] = req.ID
	metadata["vault_mount_path"] = req.MountPoint
	body["metadata"] = metadata
	body["key_alias"] = alias
	body["duration"] = litellmDuration(ttl)

	key, err := c.generateKey(ctx, body)
	if err != nil {
		return nil, err
	}

	resp := b.Secret(secretTypeKey).Response(
		map[string]any{
			"key":       key.Key,
			"token_id":  key.TokenID,
			"key_alias": key.KeyAlias,
			"expires":   key.Expires,
		},
		// Revoke and renew use key_alias and token_id; the plaintext is never stored.
		map[string]any{
			"role":      name,
			"key_alias": key.KeyAlias,
			"token_id":  key.TokenID,
		},
	)
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = role.MaxTTL
	return resp, nil
}

func (b *backend) keyRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	name, _ := req.Secret.InternalData["role"].(string)
	tokenID, _ := req.Secret.InternalData["token_id"].(string)
	if name == "" || tokenID == "" {
		return nil, errors.New("secret is missing role or token_id in internal data")
	}
	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("role %q not found during renewal", name)
	}
	c, err := getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	ttl, _, err := framework.CalculateTTL(b.System(), req.Secret.Increment, role.TTL, 0, role.MaxTTL, 0, req.Secret.IssueTime)
	if err != nil {
		return nil, err
	}
	if err := c.extendKey(ctx, tokenID, ttl); err != nil {
		return nil, err
	}
	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = role.MaxTTL
	return resp, nil
}

func (b *backend) keyRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	alias, _ := req.Secret.InternalData["key_alias"].(string)
	if alias == "" {
		return nil, errors.New("secret is missing key_alias in internal data")
	}
	c, err := getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	err = c.deleteKeyByAlias(ctx, alias)
	var ae *apiError
	if errors.As(err, &ae) && ae.Status == 404 {
		// Already gone: LiteLLM expired it or an operator deleted it.
		return nil, nil
	}
	return nil, err
}
