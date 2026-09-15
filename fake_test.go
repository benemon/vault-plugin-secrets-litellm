package litellm

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeLiteLLM reproduces the /key/* behaviour and error envelopes observed on
// litellm 1.93.0: plaintext only at generate and regenerate, unique aliases,
// unit-suffixed durations, Enterprise gating of tags and regenerate.
type fakeLiteLLM struct {
	*httptest.Server
	adminKey string
	// licensed lifts the Enterprise gate on regenerate.
	licensed bool
	// adminUsers are LiteLLM users whose keys pass the admin gate like the
	// master key does (proxy_admin role).
	adminUsers map[string]bool
	// demoteNewKeys makes keys generated from now on fail the admin gate,
	// whatever user they belong to.
	demoteNewKeys bool

	mu   sync.Mutex
	keys map[string]*fakeKey // by alias
}

type fakeKey struct {
	Key     string
	Token   string
	Alias   string
	Expires time.Time
	// Request is the generate body exactly as received.
	Request map[string]any
	// Duration is the last duration string applied by generate or update.
	Duration string
	Demoted  bool
}

func newFakeLiteLLM(t *testing.T) *fakeLiteLLM {
	t.Helper()
	f := newUnstartedFake()
	f.Start()
	t.Cleanup(f.Close)
	return f
}

// newFakeLiteLLMTLS serves over TLS with a self-signed certificate; certPEM
// hands tests the CA to trust.
func newFakeLiteLLMTLS(t *testing.T) *fakeLiteLLM {
	t.Helper()
	f := newUnstartedFake()
	f.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.StartTLS()
	t.Cleanup(f.Close)
	return f
}

func (f *fakeLiteLLM) certPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Certificate().Raw}))
}

func newUnstartedFake() *fakeLiteLLM {
	f := &fakeLiteLLM{adminKey: "sk-admin", keys: map[string]*fakeKey{}, adminUsers: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /key/generate", f.generate)
	mux.HandleFunc("POST /key/update", f.update)
	mux.HandleFunc("POST /key/delete", f.delete)
	mux.HandleFunc("GET /key/list", f.list)
	mux.HandleFunc("GET /key/info", f.info)
	mux.HandleFunc("POST /key/{key}/regenerate", f.regenerate)
	f.Server = httptest.NewUnstartedServer(f.auth(mux))
	return f
}

func (f *fakeLiteLLM) client() *client {
	return newClient(f.URL, f.adminKey, f.Client())
}

func (f *fakeLiteLLM) byAlias(alias string) *fakeKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keys[alias]
}

func (f *fakeLiteLLM) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.keys)
}

func (f *fakeLiteLLM) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		switch {
		case got == "":
			f.fail(w, 401, "Authentication Error, No api key passed in.")
		case got != "Bearer "+f.adminKey && !f.isAdminVirtualKey(strings.TrimPrefix(got, "Bearer ")):
			f.fail(w, 401, "Authentication Error, Invalid proxy server token passed. Unable to find token in cache or `LiteLLM_VerificationTokenTable`")
		default:
			next.ServeHTTP(w, r)
		}
	})
}

func (f *fakeLiteLLM) isAdminVirtualKey(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.find(key)
	if k == nil {
		return false
	}
	user, _ := k.Request["user_id"].(string)
	return f.adminUsers[user] && !k.Demoted
}

func (f *fakeLiteLLM) fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
		"message": msg, "type": "error", "param": "None", "code": strconv.Itoa(status),
	}})
}

func (f *fakeLiteLLM) ok(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

var durationRe = regexp.MustCompile(`^(\d+)([smhd])$`)

func parseDuration(s string) (time.Duration, string) {
	if _, err := strconv.Atoi(s); err == nil {
		return 0, "Unsupported duration unit, passed duration: " + s
	}
	m := durationRe.FindStringSubmatch(s)
	if m == nil {
		return 0, "Invalid duration format"
	}
	n, _ := strconv.Atoi(m[1])
	unit := map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[m[2]]
	return time.Duration(n) * unit, ""
}

func (f *fakeLiteLLM) generate(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	if _, ok := body["tags"]; ok {
		f.fail(w, 403, "Setting tags is an Enterprise feature")
		return
	}
	alias, _ := body["key_alias"].(string)
	f.mu.Lock()
	defer f.mu.Unlock()
	if alias != "" {
		if _, dup := f.keys[alias]; dup {
			f.fail(w, 400, fmt.Sprintf("Key with alias '%s' already exists. Unique key aliases across all keys are required.", alias))
			return
		}
	}
	k := &fakeKey{Alias: alias, Request: body, Demoted: f.demoteNewKeys}
	if d, ok := body["duration"].(string); ok {
		dur, msg := parseDuration(d)
		if msg != "" {
			f.fail(w, 500, msg)
			return
		}
		k.Duration = d
		k.Expires = time.Now().Add(dur)
	}
	k.Key, k.Token = newKeyMaterial()
	if alias == "" {
		alias = k.Token
	}
	f.keys[alias] = k
	f.ok(w, map[string]any{
		"key": k.Key, "token_id": k.Token, "token": k.Token, "key_alias": k.Alias,
		"expires": expiresJSON(k.Expires), "metadata": body["metadata"],
	})
}

func expiresJSON(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format("2006-01-02T15:04:05.000000Z")
}

func (f *fakeLiteLLM) update(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	key, _ := body["key"].(string)
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.find(key)
	if k == nil {
		f.fail(w, 404, "Key not found.")
		return
	}
	if d, ok := body["duration"].(string); ok {
		dur, msg := parseDuration(d)
		if msg != "" {
			f.fail(w, 500, msg)
			return
		}
		k.Duration = d
		k.Expires = time.Now().Add(dur)
	}
	f.ok(w, map[string]any{"key": k.Token, "token": k.Token, "key_alias": k.Alias, "expires": expiresJSON(k.Expires)})
}

func (f *fakeLiteLLM) delete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Keys       []string `json:"keys"`
		KeyAliases []string `json:"key_aliases"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	defer f.mu.Unlock()
	var deleted []string
	for _, a := range body.KeyAliases {
		if _, ok := f.keys[a]; ok {
			delete(f.keys, a)
			deleted = append(deleted, a)
		}
	}
	for _, key := range body.Keys {
		for alias, k := range f.keys {
			if k.Key == key || k.Token == key {
				delete(f.keys, alias)
				deleted = append(deleted, key)
			}
		}
	}
	if len(deleted) == 0 {
		f.fail(w, 404, "{'error': 'No keys found'}")
		return
	}
	f.ok(w, map[string]any{"deleted_keys": deleted})
}

func (f *fakeLiteLLM) list(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	filter := r.URL.Query().Get("key_alias")
	keys := []map[string]any{}
	for _, k := range f.keys {
		if filter == "" || k.Alias == filter {
			keys = append(keys, map[string]any{"token": k.Token, "key_alias": k.Alias})
		}
	}
	f.ok(w, map[string]any{"keys": keys, "total_count": len(keys)})
}

func (f *fakeLiteLLM) find(keyOrToken string) *fakeKey {
	for _, k := range f.keys {
		if k.Key == keyOrToken || k.Token == keyOrToken {
			return k
		}
	}
	return nil
}

func (f *fakeLiteLLM) info(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.find(r.URL.Query().Get("key"))
	if k == nil {
		f.fail(w, 404, "Key not found in database")
		return
	}
	f.ok(w, map[string]any{"key": k.Token, "info": map[string]any{"key_alias": k.Alias, "expires": expiresJSON(k.Expires), "user_id": k.Request["user_id"]}})
}

func (f *fakeLiteLLM) regenerate(w http.ResponseWriter, r *http.Request) {
	if !f.licensed {
		f.fail(w, 500, "Regenerating Virtual Keys is an Enterprise feature, You must be a LiteLLM Enterprise user to use this feature.")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.find(r.PathValue("key"))
	if k == nil {
		f.fail(w, 404, "Key not found.")
		return
	}
	k.Key, k.Token = newKeyMaterial()
	f.ok(w, map[string]any{"key": k.Key, "token_id": k.Token, "token": k.Token, "key_alias": k.Alias, "expires": expiresJSON(k.Expires)})
}

func newKeyMaterial() (key, token string) {
	raw := make([]byte, 16)
	rand.Read(raw)
	key = "sk-" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(key))
	return key, hex.EncodeToString(sum[:])
}
