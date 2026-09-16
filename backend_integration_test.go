//go:build integration

package litellm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// TestIntegration_BackendLifecycle drives the backend in-process against the real instance.
func TestIntegration_BackendLifecycle(t *testing.T) {
	c := integrationClient(t)
	ctx := context.Background()
	b, s := getBackend(t)

	if resp := writeConfig(t, b, s, map[string]any{"url": c.baseURL, "admin_key": c.adminKey}); resp.IsError() {
		t.Fatal(resp.Error())
	}
	if resp := writeConfig(t, b, s, map[string]any{"url": c.baseURL, "admin_key": "sk-wrong"}); !resp.IsError() {
		t.Fatal("wrong admin key accepted")
	}

	role := "it-" + time.Now().UTC().Format("150405")
	spec := `{"models":["qwen-a3b"],"max_budget":0.01,"rpm_limit":5,"metadata":{"suite":"integration"}}`
	if resp := writeRole(t, b, s, role, map[string]any{"ttl": "2m", "max_ttl": "10m", "key_request": spec}); resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	resp, err := readCreds(t, b, s, role, "")
	if err != nil {
		t.Fatal(err)
	}
	alias := resp.Data["key_alias"].(string)
	tokenID := resp.Data["token_id"].(string)
	t.Cleanup(func() { c.deleteKeyByAlias(ctx, alias) })
	if sum := sha256.Sum256([]byte(resp.Data["key"].(string))); hex.EncodeToString(sum[:]) != tokenID {
		t.Fatal("token_id is not the SHA-256 of the key")
	}
	if !strings.HasPrefix(alias, "vault-"+role+"-") || resp.Secret.TTL != 2*time.Minute {
		t.Fatalf("alias %q ttl %v", alias, resp.Secret.TTL)
	}

	info := liveKeyInfo(t, c, tokenID)
	md := info["metadata"].(map[string]any)
	if md["suite"] != "integration" || md["vault_role"] != role || md["vault_request_id"] != "req-123" || md["vault_mount_path"] != "litellm/" {
		t.Fatalf("metadata = %v", md)
	}
	if info["max_budget"] != 0.01 || info["rpm_limit"] != float64(5) || info["models"].([]any)[0] != "qwen-a3b" {
		t.Fatalf("key_request not applied: %v", info)
	}
	issued, _ := time.Parse(time.RFC3339Nano, info["expires"].(string))
	if d := time.Until(issued); d < 100*time.Second || d > 125*time.Second {
		t.Fatalf("LiteLLM expiry %v from now, want about 2m", d)
	}

	secret := resp.Secret
	secret.IssueTime = time.Now()
	secret.Increment = 5 * time.Minute
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RenewOperation, Path: credsPath + role, Storage: s, Secret: secret,
	}); err != nil {
		t.Fatal(err)
	}
	renewed, _ := time.Parse(time.RFC3339Nano, liveKeyInfo(t, c, tokenID)["expires"].(string))
	if d := time.Until(renewed); d < 4*time.Minute || d > 5*time.Minute+5*time.Second {
		t.Fatalf("LiteLLM expiry after renew %v from now, want about 5m", d)
	}

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation, Path: credsPath + role, Storage: s, Secret: secret,
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.do(ctx, http.MethodGet, "/key/info?key="+tokenID, nil, nil); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("key still present after revoke: %v", err)
	}
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation, Path: credsPath + role, Storage: s, Secret: secret,
	}); err != nil {
		t.Fatalf("second revoke must succeed: %v", err)
	}
}

func liveKeyInfo(t *testing.T, c *client, tokenID string) map[string]any {
	t.Helper()
	var out struct {
		Info map[string]any `json:"info"`
	}
	if err := c.do(context.Background(), http.MethodGet, "/key/info?key="+tokenID, nil, &out); err != nil {
		t.Fatal(err)
	}
	return out.Info
}

func TestIntegration_StaticRoleLifecycle(t *testing.T) {
	c := integrationClient(t)
	ctx := context.Background()
	b, s := getBackend(t)
	writeConfig(t, b, s, map[string]any{"url": c.baseURL, "admin_key": c.adminKey})

	alias := "vault-it-static-" + time.Now().UTC().Format("150405")
	orig, err := c.generateKey(ctx, map[string]any{"key_alias": alias, "duration": "10m", "models": []string{"qwen-a3b"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.deleteKeyByAlias(ctx, alias) })

	resp, err := handle(t, b, s, logical.UpdateOperation, staticRolePath+"svc", map[string]any{"key_alias": alias})
	if err != nil && strings.Contains(err.Error(), "Enterprise") {
		t.Skip("static roles need a licensed LiteLLM instance")
	}
	if err != nil || resp.IsError() || len(resp.Warnings) != 1 {
		t.Fatalf("bind: resp %v err %v", resp, err)
	}
	if authStatus(t, c, orig.Key) != 401 {
		t.Fatal("original key still authenticates after bind")
	}
	resp, _ = handle(t, b, s, logical.ReadOperation, staticCredsPath+"svc", nil)
	key, tokenID := resp.Data["key"].(string), resp.Data["token_id"].(string)
	if sum := sha256.Sum256([]byte(key)); hex.EncodeToString(sum[:]) != tokenID || tokenID == orig.TokenID {
		t.Fatalf("static-creds token_id %s does not match the served key", tokenID)
	}
	if authStatus(t, c, key) != 200 {
		t.Fatal("served key does not authenticate")
	}
	if info := liveKeyInfo(t, c, tokenID); info["key_alias"] != alias || info["models"].([]any)[0] != "qwen-a3b" {
		t.Fatalf("regenerate lost alias or settings: %v", info)
	}

	if resp, _ := handle(t, b, s, logical.UpdateOperation, rotateRolePath+"svc", nil); resp.IsError() {
		t.Fatal(resp.Error())
	}
	resp, _ = handle(t, b, s, logical.ReadOperation, staticCredsPath+"svc", nil)
	if authStatus(t, c, key) != 401 || authStatus(t, c, resp.Data["key"].(string)) != 200 {
		t.Fatal("rotate did not swap which key authenticates")
	}

	handle(t, b, s, logical.DeleteOperation, staticRolePath+"svc", nil)
	if err := c.checkKey(ctx, resp.Data["token_id"].(string)); err != nil {
		t.Fatalf("deleting the role removed the key: %v", err)
	}
}

// authStatus returns LiteLLM's status for key at /v1/models: 200 live, 401
// dead, no inference involved.
func authStatus(t *testing.T, c *client, key string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, c.baseURL+"/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestIntegration_RotateRoot(t *testing.T) {
	c := integrationClient(t)
	ctx := context.Background()
	user := "vault-it-admin-" + time.Now().UTC().Format("150405")
	if err := c.do(ctx, http.MethodPost, "/user/new", map[string]any{"user_id": user, "user_role": "proxy_admin"}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.do(ctx, http.MethodPost, "/user/delete", map[string]any{"user_ids": []string{user}}, nil) })
	admin, err := c.generateKey(ctx, map[string]any{"user_id": user, "key_alias": user + "-key"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var out struct {
			Keys []struct {
				Token string `json:"token"`
			} `json:"keys"`
		}
		c.do(ctx, http.MethodGet, "/key/list?return_full_object=true&user_id="+user, nil, &out)
		for _, k := range out.Keys {
			c.deleteKeyByHash(ctx, k.Token)
		}
	})

	b, s := getBackend(t)
	if resp := writeConfig(t, b, s, map[string]any{"url": c.baseURL, "admin_key": admin.Key}); resp.IsError() {
		t.Fatal(resp.Error())
	}
	resp, err := handle(t, b, s, logical.UpdateOperation, "rotate-root", nil)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotate-root: resp %v err %v", resp, err)
	}
	cfg, _ := getConfig(ctx, s)
	if cfg.AdminKey == admin.Key {
		t.Fatal("admin key unchanged")
	}
	if authStatus(t, c, admin.Key) != 401 || authStatus(t, c, cfg.AdminKey) != 200 {
		t.Fatal("rotation did not swap which admin key authenticates")
	}
	rotated := newClient(c.baseURL, cfg.AdminKey, c.http)
	if info, err := rotated.keyInfo(ctx, cfg.AdminKey); err != nil || info.UserID != user {
		t.Fatalf("rotated key not under the same user: %v %v", info, err)
	}
	if _, err := rotated.generateKey(ctx, map[string]any{"key_alias": user + "-probe", "duration": "1m", "user_id": user}); err != nil {
		t.Fatalf("rotated key cannot generate: %v", err)
	}
	if resp != nil {
		t.Logf("successor path taken: %d warnings", len(resp.Warnings))
	}
}

func TestIntegration_IdentityStamping(t *testing.T) {
	c := integrationClient(t)
	ctx := context.Background()
	b, s := getBackend(t)
	if resp := writeConfig(t, b, s, map[string]any{"url": c.baseURL, "admin_key": c.adminKey}); resp.IsError() {
		t.Fatal(resp.Error())
	}
	stamp := "vault-it-" + time.Now().UTC().Format("150405")
	entity := withCaller(t, b, stamp+"@example.com", stamp+"-team")
	if resp := writeRole(t, b, s, "stamped", map[string]any{
		"key_request":      `{"models":["qwen-a3b"]}`,
		"user_id_template": "{{identity.entity.aliases." + oidcAccessor + ".name}}",
		"team_id_template": "{{identity.groups.names.project-x.metadata.litellm_team_id}}",
	}); resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
	resp, err := readCreds(t, b, s, "stamped", entity)
	if err != nil || resp.IsError() {
		t.Fatalf("resp %v err %v", resp, err)
	}
	alias := resp.Data["key_alias"].(string)
	t.Cleanup(func() { c.deleteKeyByAlias(ctx, alias) })
	info := liveKeyInfo(t, c, resp.Data["token_id"].(string))
	if info["user_id"] != stamp+"@example.com" || info["team_id"] != stamp+"-team" {
		t.Fatalf("LiteLLM key carries user_id=%v team_id=%v", info["user_id"], info["team_id"])
	}
}
