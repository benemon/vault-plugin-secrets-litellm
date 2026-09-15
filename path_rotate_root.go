package litellm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathRotateRoot() *framework.Path {
	return &framework.Path{
		Pattern: "rotate-root",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixLiteLLM,
			OperationVerb:   "rotate",
			OperationSuffix: "root-credentials",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRotateRootWrite},
		},
		HelpSynopsis:    "Replace the admin key with a new key under the same LiteLLM user.",
		HelpDescription: "Regenerates the admin key where LiteLLM allows it, otherwise generates a successor under the same user and deletes the old key once the successor is verified. The master key cannot be rotated.",
	}
}

func (b *backend) pathRotateRootWrite(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errors.New("LiteLLM connection not configured: write config first")
	}
	c, err := cfg.client()
	if err != nil {
		return nil, err
	}
	info, err := c.keyInfo(ctx, cfg.AdminKey)
	var ae *apiError
	if errors.As(err, &ae) && ae.Status == 404 {
		return logical.ErrorResponse("admin_key is not a virtual key; the master key cannot be rotated. Configure a key under a proxy_admin user first."), nil
	}
	if err != nil {
		return nil, err
	}
	// LiteLLM's hash is sha256 of the plaintext (pinned by the integration
	// suite) and /key/info by plaintext does not return it.
	sum := sha256.Sum256([]byte(cfg.AdminKey))
	oldHash := hex.EncodeToString(sum[:])

	fallback := false
	newKey, err := c.regenerateKey(ctx, oldHash)
	// The licence gate is a 500 whose only distinguishing mark is the message.
	if errors.As(err, &ae) && strings.Contains(ae.Message, "Enterprise") {
		fallback = true
		if info.UserID == "" {
			return logical.ErrorResponse("admin_key belongs to no LiteLLM user, so a successor cannot be generated"), nil
		}
		newKey, err = c.generateKey(ctx, map[string]any{
			"user_id":   info.UserID,
			"key_alias": fmt.Sprintf("%s-%d", info.KeyAlias, time.Now().Unix()),
		})
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	successor := newClient(cfg.URL, newKey.Key, c.http)
	if err := successor.checkAdminKey(ctx); err != nil {
		return nil, fmt.Errorf("new admin key was issued but failed verification, config unchanged: %w", err)
	}
	cfg.AdminKey = newKey.Key
	entry, err := logical.StorageEntryJSON(configPath, cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	if !fallback {
		return nil, nil
	}
	resp := &logical.Response{}
	err = successor.deleteKeyByHash(ctx, oldHash)
	if errors.As(err, &ae) && ae.Status == 404 {
		err = nil
	}
	if err != nil {
		resp.AddWarning(fmt.Sprintf("successor admin key stored, but the previous key could not be deleted and is still valid: %s", err))
	} else {
		resp.AddWarning("LiteLLM refused regenerate; a successor admin key was generated and the previous key deleted.")
	}
	return resp, nil
}
