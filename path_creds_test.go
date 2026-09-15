package litellm

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func setupCreds(t *testing.T, roleData map[string]any) (*fakeLiteLLM, *backend, logical.Storage) {
	t.Helper()
	f := newFakeLiteLLM(t)
	b, s := getBackend(t)
	if resp := writeConfig(t, b, s, map[string]any{"url": f.URL, "admin_key": f.adminKey}); resp.IsError() {
		t.Fatal(resp.Error())
	}
	if resp := writeRole(t, b, s, "app", roleData); resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
	return f, b, s
}

func readCreds(t *testing.T, b *backend, s logical.Storage, name, entityID string) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation:  logical.ReadOperation,
		Path:       credsPath + name,
		Storage:    s,
		ID:         "req-123",
		MountPoint: "litellm/",
		EntityID:   entityID,
	})
}

func TestCreds_Generate(t *testing.T) {
	spec := `{"models": ["qwen-a3b"], "metadata": {"team": "blue"}}`
	f, b, s := setupCreds(t, map[string]any{"ttl": "5m", "max_ttl": "1h", "key_request": spec})

	resp, err := readCreds(t, b, s, "app", "")
	if err != nil {
		t.Fatal(err)
	}
	alias := resp.Data["key_alias"].(string)
	if !strings.HasPrefix(alias, "vault-app-") {
		t.Fatalf("alias = %q", alias)
	}
	k := f.byAlias(alias)
	if k == nil {
		t.Fatal("key not generated in LiteLLM")
	}
	if resp.Data["key"] != k.Key || resp.Data["token_id"] != k.Token || resp.Data["expires"] == "" {
		t.Fatalf("response data %v does not match generated key", resp.Data)
	}
	if k.Duration != "300s" || resp.Secret.TTL != 5*time.Minute || resp.Secret.MaxTTL != time.Hour {
		t.Fatalf("duration %q, lease ttl %v max %v", k.Duration, resp.Secret.TTL, resp.Secret.MaxTTL)
	}
	if k.Request["models"].([]any)[0] != "qwen-a3b" {
		t.Fatalf("key_request not forwarded: %v", k.Request)
	}
	md := k.Request["metadata"].(map[string]any)
	if md["team"] != "blue" || md["vault_role"] != "app" || md["vault_request_id"] != "req-123" || md["vault_mount_path"] != "litellm/" {
		t.Fatalf("metadata = %v", md)
	}
	role, _ := getRole(context.Background(), s, "app")
	if role.KeyRequest["metadata"].(map[string]any)["vault_role"] != nil {
		t.Fatal("role's stored metadata was mutated")
	}

	if _, has := resp.Secret.InternalData["key"]; has {
		t.Fatal("plaintext key stored in lease internal data")
	}
	keys, err := logical.CollectKeys(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range keys {
		entry, _ := s.Get(context.Background(), path)
		if strings.Contains(string(entry.Value), k.Key) {
			t.Fatalf("plaintext key found in storage at %s", path)
		}
	}
}

func TestCreds_TTLDefaultsAndCap(t *testing.T) {
	f, b, s := setupCreds(t, map[string]any{})
	resp, err := readCreds(t, b, s, "app", "")
	if err != nil {
		t.Fatal(err)
	}
	want := b.System().DefaultLeaseTTL()
	if k := f.byAlias(resp.Data["key_alias"].(string)); k.Duration != litellmDuration(want) || resp.Secret.TTL != want {
		t.Fatalf("default ttl: duration %q lease %v want %v", k.Duration, resp.Secret.TTL, want)
	}

	writeRole(t, b, s, "app", map[string]any{"ttl": (b.System().MaxLeaseTTL() + time.Hour).String()})
	resp, err = readCreds(t, b, s, "app", "")
	if err != nil {
		t.Fatal(err)
	}
	max := b.System().MaxLeaseTTL()
	if k := f.byAlias(resp.Data["key_alias"].(string)); k.Duration != litellmDuration(max) || resp.Secret.TTL != max {
		t.Fatalf("capped ttl: duration %q lease %v want %v", k.Duration, resp.Secret.TTL, max)
	}
}

func TestCreds_RenewAndRevoke(t *testing.T) {
	f, b, s := setupCreds(t, map[string]any{"ttl": "5m", "max_ttl": "1h"})
	resp, err := readCreds(t, b, s, "app", "")
	if err != nil {
		t.Fatal(err)
	}
	alias := resp.Data["key_alias"].(string)
	before := f.byAlias(alias).Expires

	secret := resp.Secret
	secret.IssueTime = time.Now()
	secret.Increment = 10 * time.Minute
	renewed, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation, Path: credsPath + "app", Storage: s, Secret: secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Secret.TTL != 10*time.Minute || renewed.Secret.MaxTTL != time.Hour {
		t.Fatalf("renewed lease ttl %v max %v, want 10m / 1h", renewed.Secret.TTL, renewed.Secret.MaxTTL)
	}
	if k := f.byAlias(alias); k.Duration != "600s" || !k.Expires.After(before.Add(4*time.Minute)) {
		t.Fatalf("LiteLLM expiry not extended: duration %q before %v after %v", k.Duration, before, k.Expires)
	}

	// A renewal near max_ttl may only extend to the lease's hard end.
	secret.IssueTime = time.Now().Add(-55 * time.Minute)
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation, Path: credsPath + "app", Storage: s, Secret: secret,
	}); err != nil {
		t.Fatal(err)
	}
	d := f.byAlias(alias).Duration
	var secs int
	fmt.Sscanf(d, "%ds", &secs)
	if secs < 295 || secs > 300 {
		t.Fatalf("renewal past max_ttl sent duration %q, want about 300s", d)
	}

	revoke := &logical.Request{Operation: logical.RevokeOperation, Path: credsPath + "app", Storage: s, Secret: secret}
	if _, err := b.HandleRequest(context.Background(), revoke); err != nil {
		t.Fatal(err)
	}
	if f.byAlias(alias) != nil {
		t.Fatal("key still exists in LiteLLM after revoke")
	}
	if _, err := b.HandleRequest(context.Background(), revoke); err != nil {
		t.Fatalf("revoking an already-deleted key must succeed, got %v", err)
	}
}

func TestCreds_Errors(t *testing.T) {
	f, b, s := setupCreds(t, map[string]any{"key_request": `{"tags": ["x"]}`})

	resp, err := readCreds(t, b, s, "missing", "")
	if err != nil || resp == nil || !resp.IsError() || !strings.Contains(resp.Error().Error(), "not found") {
		t.Fatalf("unknown role: resp %v err %v", resp, err)
	}

	_, err = readCreds(t, b, s, "app", "")
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "Enterprise") {
		t.Fatalf("LiteLLM rejection not surfaced: %v", err)
	}
	if f.count() != 0 {
		t.Fatal("key created despite rejection")
	}

	resp, _ = readCreds(t, b, s, "app", "")
	secret := &logical.Secret{LeaseOptions: logical.LeaseOptions{IssueTime: time.Now()}, InternalData: map[string]any{"role": "gone", "token_id": "t", "key_alias": "a"}}
	secret.InternalData["secret_type"] = secretTypeKey
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation, Path: credsPath + "app", Storage: s, Secret: secret,
	}); err == nil || !strings.Contains(err.Error(), "not found during renewal") {
		t.Fatalf("renew with deleted role: %v", err)
	}

	b2, s2 := getBackend(t)
	writeRole(t, b2, s2, "app", map[string]any{})
	if _, err := readCreds(t, b2, s2, "app", ""); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("unconfigured backend: %v", err)
	}
}
