package litellm

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestClient_GenerateKey(t *testing.T) {
	f := newFakeLiteLLM(t)
	c := f.client()
	body := map[string]any{"key_alias": "a1", "duration": "60s", "max_budget": 0.5, "metadata": map[string]any{"x": "y"}}
	got, err := c.generateKey(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	k := f.byAlias("a1")
	if k == nil || got.Key != k.Key || got.TokenID != k.Token || got.KeyAlias != "a1" || got.Expires == "" {
		t.Fatalf("response %+v does not match stored key %+v", got, k)
	}
	if k.Request["max_budget"] != 0.5 || k.Request["metadata"].(map[string]any)["x"] != "y" {
		t.Fatalf("generate body not forwarded verbatim: %v", k.Request)
	}

	_, err = c.generateKey(context.Background(), body)
	var ae *apiError
	if !errors.As(err, &ae) || ae.Status != 400 {
		t.Fatalf("duplicate alias: want apiError 400, got %v", err)
	}
}

func TestClient_ExtendKey(t *testing.T) {
	f := newFakeLiteLLM(t)
	c := f.client()
	got, err := c.generateKey(context.Background(), map[string]any{"key_alias": "a1", "duration": "10s"})
	if err != nil {
		t.Fatal(err)
	}
	before := f.byAlias("a1").Expires
	if err := c.extendKey(context.Background(), got.TokenID, 90*time.Second); err != nil {
		t.Fatal(err)
	}
	k := f.byAlias("a1")
	if k.Duration != "90s" {
		t.Fatalf("duration sent = %q, want 90s", k.Duration)
	}
	if !k.Expires.After(before.Add(60 * time.Second)) {
		t.Fatalf("expiry not re-based: before %v after %v", before, k.Expires)
	}

	err = c.extendKey(context.Background(), "missing", time.Minute)
	var ae *apiError
	if !errors.As(err, &ae) || ae.Status != 404 {
		t.Fatalf("missing key: want apiError 404, got %v", err)
	}
}

func TestClient_DeleteKeyByAlias(t *testing.T) {
	f := newFakeLiteLLM(t)
	c := f.client()
	if _, err := c.generateKey(context.Background(), map[string]any{"key_alias": "a1"}); err != nil {
		t.Fatal(err)
	}
	if err := c.deleteKeyByAlias(context.Background(), "a1"); err != nil {
		t.Fatal(err)
	}
	if f.byAlias("a1") != nil {
		t.Fatal("key still present after delete")
	}
	err := c.deleteKeyByAlias(context.Background(), "a1")
	var ae *apiError
	if !errors.As(err, &ae) || ae.Status != 404 {
		t.Fatalf("second delete: want apiError 404, got %v", err)
	}
}

func TestClient_CheckAdminKey(t *testing.T) {
	f := newFakeLiteLLM(t)
	if err := f.client().checkAdminKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	err := newClient(f.URL, "sk-wrong", f.Client()).checkAdminKey(context.Background())
	var ae *apiError
	if !errors.As(err, &ae) || ae.Status != 401 {
		t.Fatalf("wrong key: want apiError 401, got %v", err)
	}
	if err := newClient(f.URL+"/", f.adminKey, f.Client()).checkAdminKey(context.Background()); err != nil {
		t.Fatalf("trailing slash on base URL: %v", err)
	}
}

func TestClient_TransportError(t *testing.T) {
	f := newFakeLiteLLM(t)
	c := f.client()
	f.Close()
	err := c.checkAdminKey(context.Background())
	var ae *apiError
	if err == nil || errors.As(err, &ae) {
		t.Fatalf("closed server: want transport error, got %v", err)
	}
}

func TestErrorMessage(t *testing.T) {
	cases := map[string]string{
		`{"error":{"message":"Key not found.","type":"not_found_error","code":"404"}}`: "Key not found.",
		`{"detail":[{"type":"int_parsing","loc":["body","rpm_limit"],"msg":"bad"}]}`:   `[{"type":"int_parsing","loc":["body","rpm_limit"],"msg":"bad"}]`,
		"<html>gateway timeout</html>": "<html>gateway timeout</html>",
	}
	for raw, want := range cases {
		if got := errorMessage([]byte(raw)); got != want {
			t.Errorf("errorMessage(%s) = %q, want %q", raw, got, want)
		}
	}
}

func TestLitellmDuration(t *testing.T) {
	if got := litellmDuration(90 * time.Second); got != "90s" {
		t.Fatalf("got %q", got)
	}
	if got := litellmDuration(2*time.Hour + 500*time.Millisecond); got != "7200s" {
		t.Fatalf("got %q", got)
	}
}
