package litellm

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// setupAdminKey configures the backend with a virtual key under the
// proxy_admin user "vault-admin" rather than the fake's master key.
func setupAdminKey(t *testing.T) (*fakeLiteLLM, *backend, logical.Storage, string) {
	t.Helper()
	f := newFakeLiteLLM(t)
	f.adminUsers["vault-admin"] = true
	k, err := f.client().generateKey(context.Background(), map[string]any{"key_alias": "vault-admin-key", "user_id": "vault-admin"})
	if err != nil {
		t.Fatal(err)
	}
	b, s := getBackend(t)
	if resp := writeConfig(t, b, s, map[string]any{"url": f.URL, "admin_key": k.Key}); resp.IsError() {
		t.Fatal(resp.Error())
	}
	return f, b, s, k.Key
}

func TestRotateRoot_Regenerate(t *testing.T) {
	f, b, s, old := setupAdminKey(t)
	f.licensed = true
	resp, err := handle(t, b, s, logical.UpdateOperation, "rotate-root", nil)
	if err != nil || (resp != nil && (resp.IsError() || len(resp.Warnings) != 0)) {
		t.Fatalf("resp %v err %v", resp, err)
	}
	cfg, _ := getConfig(context.Background(), s)
	if cfg.AdminKey == old || cfg.AdminKey != f.byAlias("vault-admin-key").Key {
		t.Fatal("config does not hold the regenerated key")
	}
	if err := newClient(f.URL, old, f.Client()).checkAdminKey(context.Background()); err == nil {
		t.Fatal("old admin key still accepted")
	}
	if c, _ := getClient(context.Background(), s); c.checkAdminKey(context.Background()) != nil {
		t.Fatal("rotated key does not work")
	}
}

func TestRotateRoot_SuccessorOnCommunity(t *testing.T) {
	f, b, s, old := setupAdminKey(t)
	resp, err := handle(t, b, s, logical.UpdateOperation, "rotate-root", nil)
	if err != nil || resp == nil || resp.IsError() || len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "successor") {
		t.Fatalf("resp %v err %v", resp, err)
	}
	if f.byAlias("vault-admin-key") != nil {
		t.Fatal("previous admin key not deleted")
	}
	cfg, _ := getConfig(context.Background(), s)
	var successor *fakeKey
	for alias, k := range f.keys {
		if strings.HasPrefix(alias, "vault-admin-key-") {
			successor = k
		}
	}
	if successor == nil || cfg.AdminKey != successor.Key || successor.Request["user_id"] != "vault-admin" || cfg.AdminKey == old {
		t.Fatalf("successor not stored: cfg key %q", cfg.AdminKey)
	}
	if c, _ := getClient(context.Background(), s); c.checkAdminKey(context.Background()) != nil {
		t.Fatal("successor does not work")
	}
	if resp, _ := handle(t, b, s, logical.UpdateOperation, "rotate-root", nil); resp.IsError() {
		t.Fatalf("second rotation: %v", resp.Error())
	}
	if f.count() != 1 {
		t.Fatalf("expected exactly one admin key after two rotations, got %d", f.count())
	}
}

func TestRotateRoot_Refusals(t *testing.T) {
	f := newFakeLiteLLM(t)
	b, s := getBackend(t)
	writeConfig(t, b, s, map[string]any{"url": f.URL, "admin_key": f.adminKey})
	resp, err := handle(t, b, s, logical.UpdateOperation, "rotate-root", nil)
	if err != nil || !resp.IsError() || !strings.Contains(resp.Error().Error(), "master key") {
		t.Fatalf("master key: resp %v err %v", resp, err)
	}

	b2, s2 := getBackend(t)
	if _, err := handle(t, b2, s2, logical.UpdateOperation, "rotate-root", nil); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("unconfigured: %v", err)
	}
}

func TestRotateRoot_FailsClosedWhenSuccessorUnusable(t *testing.T) {
	f, b, s, old := setupAdminKey(t)
	f.demoteNewKeys = true
	_, err := handle(t, b, s, logical.UpdateOperation, "rotate-root", nil)
	if err == nil || !strings.Contains(err.Error(), "config unchanged") {
		t.Fatalf("want fail-closed error, got %v", err)
	}
	cfg, _ := getConfig(context.Background(), s)
	if cfg.AdminKey != old {
		t.Fatal("config was rewritten despite verification failure")
	}
	if f.byAlias("vault-admin-key") == nil {
		t.Fatal("previous admin key deleted although the successor failed")
	}
}
