//go:build integration

package litellm

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"
)

// integrationClient targets the instance named by LITELLM_URL and
// LITELLM_MASTER_KEY, skipping when either is unset.
func integrationClient(t *testing.T) *client {
	t.Helper()
	url, key := os.Getenv("LITELLM_URL"), os.Getenv("LITELLM_MASTER_KEY")
	if url == "" || key == "" {
		t.Skip("LITELLM_URL and LITELLM_MASTER_KEY not set")
	}
	return newClient(url, key, &http.Client{Timeout: 30 * time.Second})
}

func TestIntegration_ClientKeyLifecycle(t *testing.T) {
	c := integrationClient(t)
	ctx := context.Background()
	alias := "vault-it-" + time.Now().UTC().Format("20060102t150405.000")
	t.Cleanup(func() { c.deleteKeyByAlias(ctx, alias) })

	got, err := c.generateKey(ctx, map[string]any{"key_alias": alias, "duration": "60s", "max_budget": 0.01})
	if err != nil {
		t.Fatal(err)
	}
	if got.Key == "" || got.TokenID == "" || got.KeyAlias != alias || got.Expires == "" {
		t.Fatalf("incomplete generate response: %+v", got)
	}

	_, err = c.generateKey(ctx, map[string]any{"key_alias": alias})
	var ae *apiError
	if !errors.As(err, &ae) || ae.Status != 400 {
		t.Fatalf("duplicate alias: want 400, got %v", err)
	}

	if err := c.extendKey(ctx, got.TokenID, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := c.deleteKeyByAlias(ctx, alias); err != nil {
		t.Fatal(err)
	}
	err = c.deleteKeyByAlias(ctx, alias)
	if !errors.As(err, &ae) || ae.Status != 404 {
		t.Fatalf("delete after delete: want 404, got %v", err)
	}
	err = c.extendKey(ctx, got.TokenID, time.Minute)
	if !errors.As(err, &ae) || ae.Status != 404 {
		t.Fatalf("extend after delete: want 404, got %v", err)
	}
}

func TestIntegration_ClientCheckAdminKey(t *testing.T) {
	c := integrationClient(t)
	if err := c.checkAdminKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	err := newClient(c.baseURL, "sk-wrong", c.http).checkAdminKey(context.Background())
	var ae *apiError
	if !errors.As(err, &ae) || ae.Status != 401 {
		t.Fatalf("wrong key: want 401, got %v", err)
	}
}
