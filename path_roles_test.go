package litellm

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func writeRole(t *testing.T, b *backend, s logical.Storage, name string, data map[string]any) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      rolePath + name,
		Storage:   s,
		Data:      data,
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readRole(t *testing.T, b *backend, s logical.Storage, name string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      rolePath + name,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func listRoles(t *testing.T, b *backend, s logical.Storage) []string {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      rolePath,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.Data["keys"] == nil {
		return nil
	}
	return resp.Data["keys"].([]string)
}

func TestRoles_CRUDAndList(t *testing.T) {
	b, s := getBackend(t)
	spec := `{"models": ["qwen-a3b"], "max_budget": 1.5}`
	if resp := writeRole(t, b, s, "app", map[string]any{"ttl": "5m", "max_ttl": "1h", "key_request": spec}); resp.IsError() {
		t.Fatal(resp.Error())
	}
	resp := readRole(t, b, s, "app")
	if resp.Data["ttl"] != int64(300) || resp.Data["max_ttl"] != int64(3600) {
		t.Fatalf("ttl fields: %v", resp.Data)
	}
	if got := resp.Data["key_request"].(map[string]any); fmt.Sprint(got["max_budget"]) != "1.5" || got["models"].([]any)[0] != "qwen-a3b" {
		t.Fatalf("key_request: %v", got)
	}
	if got := listRoles(t, b, s); len(got) != 1 || got[0] != "app" {
		t.Fatalf("list = %v", got)
	}

	if resp := writeRole(t, b, s, "app", map[string]any{"ttl": "10m"}); resp.IsError() {
		t.Fatal(resp.Error())
	}
	resp = readRole(t, b, s, "app")
	if resp.Data["ttl"] != int64(600) || fmt.Sprint(resp.Data["key_request"].(map[string]any)["max_budget"]) != "1.5" {
		t.Fatalf("partial update lost fields: %v", resp.Data)
	}

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation, Path: rolePath + "app", Storage: s,
	}); err != nil {
		t.Fatal(err)
	}
	if readRole(t, b, s, "app") != nil || len(listRoles(t, b, s)) != 0 {
		t.Fatal("role survived delete")
	}
}

func TestRoles_Validation(t *testing.T) {
	b, s := getBackend(t)
	cases := map[string]map[string]any{
		"key_request.key is set by Vault":       {"key_request": `{"key": "sk-mine"}`},
		"key_request.key_alias is set by Vault": {"key_request": `{"key_alias": "x"}`},
		"key_request.duration is set by Vault":  {"key_request": `{"duration": "1h"}`},
		"ttl cannot exceed max_ttl":             {"ttl": "2h", "max_ttl": "1h"},
		"metadata must be an object":            {"key_request": `{"metadata": "nope"}`},
		"must be a JSON object":                 {"key_request": `["not", "an", "object"]`},
	}
	for want, data := range cases {
		resp := writeRole(t, b, s, "bad", data)
		if !resp.IsError() || !strings.Contains(resp.Error().Error(), want) {
			t.Errorf("%v: want error containing %q, got %v", data, want, resp)
		}
		if readRole(t, b, s, "bad") != nil {
			t.Errorf("%v: rejected role was stored", data)
		}
	}
}
