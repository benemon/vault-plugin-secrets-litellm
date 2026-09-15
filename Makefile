PLUGIN_NAME := vault-plugin-secrets-litellm
VERSION ?= 0.1.0-dev
LDFLAGS := -X github.com/benemon/vault-plugin-secrets-litellm.version=$(VERSION)

.PHONY: default
default: dev

.PHONY: dev
dev:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)

.PHONY: run
run:
	@CGO_ENABLED=0 sh -c "'$(CURDIR)/scripts/run.sh'"

.PHONY: test
test: fmtcheck
	CGO_ENABLED=0 go test ./... $(TESTARGS) -timeout=20m

# Exercises the real LiteLLM instance named by LITELLM_URL / LITELLM_MASTER_KEY.
.PHONY: integration
integration: fmtcheck
	CGO_ENABLED=0 go test -tags integration ./... -run Integration $(TESTARGS) -timeout=20m

.PHONY: fmtcheck
fmtcheck:
	@files=$$(gofmt -l .); if [ -n "$$files" ]; then echo "gofmt needed on:"; echo "$$files"; exit 1; fi

.PHONY: fmt
fmt:
	gofmt -l -w .

# Full lifecycle through a Vault dev server against the LiteLLM named by
# LITELLM_URL / LITELLM_MASTER_KEY.
.PHONY: e2e
e2e:
	@sh -c "'$(CURDIR)/scripts/e2e.sh'"
