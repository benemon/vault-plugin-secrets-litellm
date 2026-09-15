package litellm

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func writeConfig(t *testing.T, b *backend, s logical.Storage, data map[string]any) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   s,
		Data:      data,
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readConfig(t *testing.T, b *backend, s logical.Storage) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      configPath,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestConfig_WriteReadDelete(t *testing.T) {
	f := newFakeLiteLLM(t)
	b, s := getBackend(t)

	if resp := writeConfig(t, b, s, map[string]any{"url": f.URL + "/", "admin_key": f.adminKey}); resp.IsError() {
		t.Fatal(resp.Error())
	}
	resp := readConfig(t, b, s)
	if resp.Data["url"] != f.URL+"/" || resp.Data["insecure_tls"] != false || resp.Data["ca_cert"] != "" {
		t.Fatalf("unexpected read data: %v", resp.Data)
	}
	if _, leaked := resp.Data["admin_key"]; leaked {
		t.Fatal("config read returned admin_key")
	}
	c, err := getClient(context.Background(), s)
	if err != nil || c.adminKey != f.adminKey || c.baseURL != f.URL {
		t.Fatalf("getClient = %+v, %v", c, err)
	}

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation, Path: configPath, Storage: s,
	}); err != nil {
		t.Fatal(err)
	}
	if resp := readConfig(t, b, s); resp != nil {
		t.Fatalf("config still readable after delete: %v", resp.Data)
	}
	if _, err := getClient(context.Background(), s); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("getClient after delete: %v", err)
	}
}

func TestConfig_RejectsBadAdminKey(t *testing.T) {
	f := newFakeLiteLLM(t)
	b, s := getBackend(t)
	resp := writeConfig(t, b, s, map[string]any{"url": f.URL, "admin_key": "sk-wrong"})
	if !resp.IsError() || !strings.Contains(resp.Error().Error(), "401") {
		t.Fatalf("want 401 error response, got %v", resp)
	}
	if entry, _ := s.Get(context.Background(), configPath); entry != nil {
		t.Fatal("rejected config was stored")
	}
}

func TestConfig_Validation(t *testing.T) {
	f := newFakeLiteLLM(t)
	b, s := getBackend(t)
	cases := map[string]map[string]any{
		"url is required":       {"admin_key": f.adminKey},
		"admin_key is required": {"url": f.URL},
		"http or https":         {"url": "ftp://x", "admin_key": f.adminKey},
		"no PEM":                {"url": f.URL, "admin_key": f.adminKey, "ca_cert": "not a cert"},
	}
	for want, data := range cases {
		resp := writeConfig(t, b, s, data)
		if !resp.IsError() || !strings.Contains(resp.Error().Error(), want) {
			t.Errorf("%v: want error containing %q, got %v", data, want, resp)
		}
	}
}

func TestConfig_UpdateKeepsAdminKey(t *testing.T) {
	f := newFakeLiteLLM(t)
	b, s := getBackend(t)
	writeConfig(t, b, s, map[string]any{"url": f.URL, "admin_key": f.adminKey})
	if resp := writeConfig(t, b, s, map[string]any{"insecure_tls": true}); resp.IsError() {
		t.Fatal(resp.Error())
	}
	if resp := readConfig(t, b, s); resp.Data["insecure_tls"] != true || resp.Data["url"] != f.URL {
		t.Fatalf("partial update lost fields: %v", resp.Data)
	}
	c, _ := getClient(context.Background(), s)
	if c.adminKey != f.adminKey {
		t.Fatal("partial update lost admin_key")
	}
}

func TestConfig_TLS(t *testing.T) {
	f := newFakeLiteLLMTLS(t)
	b, s := getBackend(t)

	resp := writeConfig(t, b, s, map[string]any{"url": f.URL, "admin_key": f.adminKey})
	if !resp.IsError() || !strings.Contains(resp.Error().Error(), "certificate") {
		t.Fatalf("untrusted cert accepted: %v", resp)
	}
	if resp := writeConfig(t, b, s, map[string]any{"url": f.URL, "admin_key": f.adminKey, "ca_cert": f.certPEM()}); resp.IsError() {
		t.Fatal(resp.Error())
	}
	if resp := readConfig(t, b, s); resp.Data["ca_cert"] != f.certPEM() {
		t.Fatal("ca_cert not returned on read")
	}
	b2, s2 := getBackend(t)
	if resp := writeConfig(t, b2, s2, map[string]any{"url": f.URL, "admin_key": f.adminKey, "insecure_tls": true}); resp.IsError() {
		t.Fatal(resp.Error())
	}
}
