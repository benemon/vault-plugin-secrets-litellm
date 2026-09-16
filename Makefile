PLUGIN_NAME := vault-plugin-secrets-litellm

.PHONY: default
default: dev

.PHONY: dev
dev:
	CGO_ENABLED=0 go build -o bin/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)

.PHONY: run
run:
	@CGO_ENABLED=0 sh -c "'$(CURDIR)/scripts/run.sh'"

.PHONY: test
test: fmtcheck
	go vet ./...
	CGO_ENABLED=0 go test ./... $(TESTARGS) -timeout=20m

# Exercises the real LiteLLM instance named by LITELLM_URL / LITELLM_MASTER_KEY.
.PHONY: integration
integration: fmtcheck
	CGO_ENABLED=0 go test -count=1 -tags integration ./... -run Integration $(TESTARGS) -timeout=20m

.PHONY: fmtcheck
fmtcheck:
	@files=$$(gofmt -l .); if [ -n "$$files" ]; then echo "gofmt needed on:"; echo "$$files"; exit 1; fi

.PHONY: fmt
fmt:
	gofmt -l -w .

# Needs LITELLM_URL and LITELLM_MASTER_KEY.
.PHONY: e2e
e2e:
	@sh -c "'$(CURDIR)/scripts/e2e.sh'"

.PHONY: snapshot
snapshot:
	go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=sign,sbom
