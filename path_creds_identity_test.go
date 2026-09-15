package litellm

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

const oidcAccessor = "auth_oidc_1234"

// withCaller gives the test system view an entity with an OIDC alias and a
// group carrying a LiteLLM team id, as an IdP-backed login would produce.
func withCaller(t *testing.T, b *backend) string {
	t.Helper()
	sys := b.System().(*logical.StaticSystemView)
	sys.EntityVal = &logical.Entity{
		ID:   "entity-1",
		Name: "entity_abc",
		Aliases: []*logical.Alias{{
			MountAccessor: oidcAccessor,
			MountType:     "oidc",
			Name:          "ben@example.com",
		}},
	}
	sys.GroupsVal = []*logical.Group{{
		ID:       "group-1",
		Name:     "project-x",
		Metadata: map[string]string{"litellm_team_id": "team-42"},
	}}
	return "entity-1"
}

func readCredsAs(t *testing.T, b *backend, s logical.Storage, name, entityID string) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: credsPath + name, Storage: s, EntityID: entityID, ID: "req-1",
	})
}

func TestCreds_IdentityTemplates(t *testing.T) {
	f, b, s := setupCreds(t, map[string]any{
		"key_request":      `{"models":["qwen-a3b"]}`,
		"user_id_template": "{{identity.entity.aliases." + oidcAccessor + ".name}}",
		"team_id_template": "{{identity.groups.names.project-x.metadata.litellm_team_id}}",
	})
	entity := withCaller(t, b)
	resp, err := readCredsAs(t, b, s, "app", entity)
	if err != nil || resp.IsError() {
		t.Fatalf("resp %v err %v", resp, err)
	}
	k := f.byAlias(resp.Data["key_alias"].(string))
	if k.Request["user_id"] != "ben@example.com" || k.Request["team_id"] != "team-42" {
		t.Fatalf("stamped user_id=%v team_id=%v", k.Request["user_id"], k.Request["team_id"])
	}
	resp = readRole(t, b, s, "app")
	if !strings.Contains(resp.Data["user_id_template"].(string), oidcAccessor) || resp.Data["team_id_template"] == "" {
		t.Fatalf("role read: %v", resp.Data)
	}
}

func TestCreds_IdentityTemplatesStrict(t *testing.T) {
	f, b, s := setupCreds(t, map[string]any{"user_id_template": "{{identity.entity.aliases." + oidcAccessor + ".name}}"})
	resp, err := readCredsAs(t, b, s, "app", "")
	if err != nil || !resp.IsError() || !strings.Contains(resp.Error().Error(), "no entity") {
		t.Fatalf("no entity: resp %v err %v", resp, err)
	}

	sys := b.System().(*logical.StaticSystemView)
	sys.EntityVal = &logical.Entity{ID: "entity-2", Name: "no-oidc-alias"}
	resp, err = readCredsAs(t, b, s, "app", "entity-2")
	if err != nil || !resp.IsError() || !strings.Contains(resp.Error().Error(), "did not resolve") {
		t.Fatalf("missing alias: resp %v err %v", resp, err)
	}
	if f.count() != 0 {
		t.Fatal("a key was issued despite the template failing")
	}

	writeRole(t, b, s, "app", map[string]any{"team_id_template": "{{identity.groups.names.other.metadata.litellm_team_id}}", "user_id_template": ""})
	withCaller(t, b)
	resp, _ = readCredsAs(t, b, s, "app", "entity-1")
	if !resp.IsError() || !strings.Contains(resp.Error().Error(), "team_id_template") {
		t.Fatalf("missing group: %v", resp)
	}
}

func TestCreds_ExplicitBeatsTemplate(t *testing.T) {
	f, b, s := setupCreds(t, map[string]any{
		"key_request":      `{"user_id":"svc-account","team_id":"team-fixed"}`,
		"user_id_template": "{{identity.entity.id}}",
		"team_id_template": "{{identity.entity.name}}",
	})
	resp, err := readCredsAs(t, b, s, "app", "")
	if err != nil || resp.IsError() {
		t.Fatalf("explicit values should not need an entity: resp %v err %v", resp, err)
	}
	k := f.byAlias(resp.Data["key_alias"].(string))
	if k.Request["user_id"] != "svc-account" || k.Request["team_id"] != "team-fixed" {
		t.Fatalf("explicit values overridden: %v", k.Request)
	}
}

func TestRoles_TemplateValidation(t *testing.T) {
	b, s := getBackend(t)
	resp := writeRole(t, b, s, "bad", map[string]any{"user_id_template": "{{identity.entity.aliases"})
	if !resp.IsError() || !strings.Contains(resp.Error().Error(), "user_id_template") {
		t.Fatalf("malformed template accepted: %v", resp)
	}
	if resp := writeRole(t, b, s, "ok", map[string]any{"user_id_template": "{{identity.entity.id}}"}); resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
}
