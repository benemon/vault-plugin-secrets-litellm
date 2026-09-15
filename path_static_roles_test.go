package litellm

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// setupStatic returns a licensed fake holding a pre-existing key "team" and a
// configured backend.
func setupStatic(t *testing.T) (*fakeLiteLLM, *backend, logical.Storage) {
	t.Helper()
	f := newFakeLiteLLM(t)
	f.licensed = true
	if _, err := f.client().generateKey(context.Background(), map[string]any{"key_alias": "team", "duration": "1h"}); err != nil {
		t.Fatal(err)
	}
	b, s := getBackend(t)
	if resp := writeConfig(t, b, s, map[string]any{"url": f.URL, "admin_key": f.adminKey}); resp.IsError() {
		t.Fatal(resp.Error())
	}
	return f, b, s
}

func handle(t *testing.T, b *backend, s logical.Storage, op logical.Operation, path string, data map[string]any) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{Operation: op, Path: path, Storage: s, Data: data})
}

func TestStaticRoles_BindReadRotateDelete(t *testing.T) {
	f, b, s := setupStatic(t)
	before := f.byAlias("team").Key

	resp, err := handle(t, b, s, logical.UpdateOperation, staticRolePath+"svc", map[string]any{"key_alias": "team"})
	if err != nil || resp == nil || resp.IsError() || len(resp.Warnings) != 1 {
		t.Fatalf("bind: resp %v err %v", resp, err)
	}
	k := f.byAlias("team")
	if k.Key == before {
		t.Fatal("bind did not regenerate the key")
	}
	resp, _ = handle(t, b, s, logical.ReadOperation, staticRolePath+"svc", nil)
	if resp.Data["key_alias"] != "team" || resp.Data["token_id"] != k.Token {
		t.Fatalf("role read: %v", resp.Data)
	}
	if _, leaked := resp.Data["key"]; leaked {
		t.Fatal("role read returned the key")
	}

	resp, err = handle(t, b, s, logical.ReadOperation, staticCredsPath+"svc", nil)
	if err != nil || resp.IsError() || resp.Data["key"] != k.Key || resp.Data["token_id"] != k.Token || resp.Secret != nil {
		t.Fatalf("static-creds: resp %v err %v", resp, err)
	}
	again, _ := handle(t, b, s, logical.ReadOperation, staticCredsPath+"svc", nil)
	if again.Data["key"] != k.Key {
		t.Fatal("a second read changed the key")
	}

	prevKey, prevToken := k.Key, k.Token
	resp, err = handle(t, b, s, logical.UpdateOperation, rotateRolePath+"svc", nil)
	if err != nil || resp == nil || resp.IsError() || len(resp.Warnings) != 1 {
		t.Fatalf("rotate: resp %v err %v", resp, err)
	}
	rotated := f.byAlias("team")
	if rotated.Key == prevKey || rotated.Token == prevToken {
		t.Fatal("rotate did not regenerate")
	}
	resp, _ = handle(t, b, s, logical.ReadOperation, staticCredsPath+"svc", nil)
	if resp.Data["key"] != rotated.Key {
		t.Fatal("static-creds did not serve the rotated key")
	}

	if _, err := handle(t, b, s, logical.DeleteOperation, staticRolePath+"svc", nil); err != nil {
		t.Fatal(err)
	}
	resp, _ = handle(t, b, s, logical.ReadOperation, staticCredsPath+"svc", nil)
	if !resp.IsError() || !strings.Contains(resp.Error().Error(), "not found") {
		t.Fatalf("static-creds after delete: %v", resp)
	}
	if f.byAlias("team") == nil {
		t.Fatal("deleting the role removed the LiteLLM key")
	}
}

func TestStaticRoles_BindRefusals(t *testing.T) {
	f, b, s := setupStatic(t)
	if resp, _ := handle(t, b, s, logical.UpdateOperation, staticRolePath+"a", map[string]any{"key_alias": "team"}); resp.IsError() {
		t.Fatal(resp.Error())
	}
	cases := map[string]map[string]any{
		"already bound to static role \"a\"": {"key_alias": "team"},
		"no LiteLLM key has alias":           {"key_alias": "missing"},
		"key_alias is required":              {},
	}
	for want, data := range cases {
		resp, err := handle(t, b, s, logical.UpdateOperation, staticRolePath+"b", data)
		if err != nil || !resp.IsError() || !strings.Contains(resp.Error().Error(), want) {
			t.Errorf("%v: want %q, got resp %v err %v", data, want, resp, err)
		}
	}
	resp, _ := handle(t, b, s, logical.UpdateOperation, staticRolePath+"a", map[string]any{"key_alias": "other"})
	if !resp.IsError() || !strings.Contains(resp.Error().Error(), "delete it to rebind") {
		t.Fatalf("rebind: %v", resp)
	}
	if names, _ := handle(t, b, s, logical.ListOperation, staticRolePath, nil); len(names.Data["keys"].([]string)) != 1 {
		t.Fatalf("list: %v", names.Data)
	}

	f.licensed = false
	f.client().generateKey(context.Background(), map[string]any{"key_alias": "unlicensed"})
	_, err := handle(t, b, s, logical.UpdateOperation, staticRolePath+"c", map[string]any{"key_alias": "unlicensed"})
	if err == nil || !strings.Contains(err.Error(), "Enterprise") {
		t.Fatalf("community instance: %v", err)
	}
	if role, _ := getStaticRole(context.Background(), s, "c"); role != nil {
		t.Fatal("role stored despite failed regenerate")
	}
}

func TestStaticRoles_OutsideChanges(t *testing.T) {
	f, b, s := setupStatic(t)
	handle(t, b, s, logical.UpdateOperation, staticRolePath+"svc", map[string]any{"key_alias": "team"})

	f.mu.Lock()
	f.keys["team"].Key, f.keys["team"].Token = newKeyMaterial()
	f.mu.Unlock()
	resp, _ := handle(t, b, s, logical.ReadOperation, staticCredsPath+"svc", nil)
	if !resp.IsError() || !strings.Contains(resp.Error().Error(), "outside Vault") {
		t.Fatalf("stale key served: %v", resp)
	}
	if resp, _ := handle(t, b, s, logical.UpdateOperation, rotateRolePath+"svc", nil); resp.IsError() {
		t.Fatal(resp.Error())
	}
	resp, _ = handle(t, b, s, logical.ReadOperation, staticCredsPath+"svc", nil)
	if resp.IsError() || resp.Data["key"] != f.byAlias("team").Key {
		t.Fatalf("rotate did not recover: %v", resp)
	}

	f.client().deleteKeyByAlias(context.Background(), "team")
	resp, _ = handle(t, b, s, logical.ReadOperation, staticCredsPath+"svc", nil)
	if !resp.IsError() || !strings.Contains(resp.Error().Error(), "outside Vault") {
		t.Fatalf("deleted key served: %v", resp)
	}
	resp, _ = handle(t, b, s, logical.UpdateOperation, rotateRolePath+"svc", nil)
	if !resp.IsError() || !strings.Contains(resp.Error().Error(), "deleted outside Vault") {
		t.Fatalf("rotate of deleted key: %v", resp)
	}
}

func TestStaticRoles_PlaintextOnlyUnderStaticRoles(t *testing.T) {
	f, b, s := setupStatic(t)
	handle(t, b, s, logical.UpdateOperation, staticRolePath+"svc", map[string]any{"key_alias": "team"})
	key := f.byAlias("team").Key
	paths, _ := logical.CollectKeys(context.Background(), s)
	for _, p := range paths {
		entry, _ := s.Get(context.Background(), p)
		if strings.Contains(string(entry.Value), key) && !strings.HasPrefix(p, staticRolePath) {
			t.Fatalf("plaintext found outside the seal-wrapped prefix at %s", p)
		}
	}
}
