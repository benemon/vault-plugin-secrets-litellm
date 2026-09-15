package litellm

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func getBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	return b.(*backend), config.StorageView
}

func TestBackend_Factory(t *testing.T) {
	b, _ := getBackend(t)
	if got := b.PluginVersion().Version; got != "v"+version {
		t.Fatalf("PluginVersion = %q, want %q", got, "v"+version)
	}
	if b.Type() != logical.TypeLogical {
		t.Fatalf("Type = %v, want %v", b.Type(), logical.TypeLogical)
	}
}
