package litellm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// client drives the LiteLLM proxy's /key/* endpoints with a single admin key.
type client struct {
	baseURL  string
	adminKey string
	http     *http.Client
}

func newClient(baseURL, adminKey string, hc *http.Client) *client {
	return &client{baseURL: strings.TrimRight(baseURL, "/"), adminKey: adminKey, http: hc}
}

// apiError is a non-2xx answer from LiteLLM. Callers distinguish revoke-after-
// expiry (404) from real failures by Status.
type apiError struct {
	Op      string
	Status  int
	Message string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("litellm: %s: %d: %s", e.Op, e.Status, e.Message)
}

// generatedKey is the part of a /key/generate answer the backend keeps. The
// plaintext Key is only ever available from this response.
type generatedKey struct {
	Key      string `json:"key"`
	TokenID  string `json:"token_id"`
	KeyAlias string `json:"key_alias"`
	Expires  string `json:"expires"`
}

func (c *client) generateKey(ctx context.Context, body map[string]any) (*generatedKey, error) {
	var out generatedKey
	if err := c.do(ctx, http.MethodPost, "/key/generate", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// extendKey re-bases the key's expiry to now plus d.
func (c *client) extendKey(ctx context.Context, tokenID string, d time.Duration) error {
	body := map[string]any{"key": tokenID, "duration": litellmDuration(d)}
	return c.do(ctx, http.MethodPost, "/key/update", body, nil)
}

func (c *client) deleteKeyByAlias(ctx context.Context, alias string) error {
	body := map[string]any{"key_aliases": []string{alias}}
	return c.do(ctx, http.MethodPost, "/key/delete", body, nil)
}

// findKeyByAlias returns the hashed token of the key with this alias, or ""
// when no key carries it.
func (c *client) findKeyByAlias(ctx context.Context, alias string) (string, error) {
	var out struct {
		Keys []struct {
			Token string `json:"token"`
		} `json:"keys"`
	}
	path := "/key/list?return_full_object=true&key_alias=" + url.QueryEscape(alias)
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return "", err
	}
	if len(out.Keys) == 0 {
		return "", nil
	}
	return out.Keys[0].Token, nil
}

// regenerateKey replaces the key's plaintext and hash, keeping its alias and
// settings; the previous plaintext stops working at once. Enterprise only.
func (c *client) regenerateKey(ctx context.Context, tokenID string) (*generatedKey, error) {
	var out generatedKey
	// LiteLLM rejects a regenerate call with no body, so an empty object is sent.
	if err := c.do(ctx, http.MethodPost, "/key/"+tokenID+"/regenerate", map[string]any{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// checkKey returns a 404 apiError when the hash no longer names a key, which
// is what regeneration or deletion outside Vault looks like.
func (c *client) checkKey(ctx context.Context, tokenID string) error {
	return c.do(ctx, http.MethodGet, "/key/info?key="+url.QueryEscape(tokenID), nil, nil)
}

// checkAdminKey lets LiteLLM's own auth gate decide whether the admin key works.
func (c *client) checkAdminKey(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/key/list?size=1", nil, nil)
}

// litellmDuration renders d in the unit-suffixed form LiteLLM requires; a bare
// integer is rejected with "Unsupported duration unit".
func litellmDuration(d time.Duration) string {
	return fmt.Sprintf("%ds", int64(d.Seconds()))
}

func (c *client) do(ctx context.Context, method, path string, body, out any) error {
	op := method + " " + path
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("litellm: %s: %w", op, err)
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return fmt.Errorf("litellm: %s: %w", op, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.adminKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("litellm: %s: %w", op, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("litellm: %s: %w", op, err)
	}
	if resp.StatusCode/100 != 2 {
		return &apiError{Op: op, Status: resp.StatusCode, Message: errorMessage(raw)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("litellm: %s: %w", op, err)
	}
	return nil
}

// errorMessage pulls the human text out of LiteLLM's {"error":{"message"}}
// envelope or FastAPI's {"detail":[...]} validation envelope.
func errorMessage(raw []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
		Detail json.RawMessage `json:"detail"`
	}
	if json.Unmarshal(raw, &e) == nil {
		if e.Error.Message != "" {
			return e.Error.Message
		}
		if len(e.Detail) > 0 {
			return string(e.Detail)
		}
	}
	s := strings.TrimSpace(string(raw))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
