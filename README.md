# vault-plugin-secrets-litellm

A [HashiCorp Vault](https://www.vaultproject.io) secrets engine that issues
[LiteLLM](https://docs.litellm.ai) virtual keys. Reading `creds/<role>`
generates a key through LiteLLM's `/key/generate`, ties it to a Vault lease,
extends it on renewal and deletes it on revocation. The plugin composes
LiteLLM's own `/key/*` endpoints and adds no workflow of its own.

## Status

Dynamic keys only, targeting LiteLLM community edition. Static roles (handing
back an existing key) depend on `/key/regenerate`, which LiteLLM gates behind
an Enterprise licence, and are not implemented. See [Limits](#limits).

## Requirements

- Vault 1.12 or later (the plugin is served with plugin multiplexing).
- LiteLLM proxy with a database, reachable from the Vault servers.
- A LiteLLM key with proxy admin rights: the master key or a `proxy_admin`
  virtual key.

## Installation

Build the binary and place it in Vault's configured `plugin_directory`, then
register it under the short name `litellm` so the engine type and mount
accessor read `litellm` rather than the binary name:

```sh
make dev
vault plugin register -sha256="$(shasum -a 256 bin/vault-plugin-secrets-litellm | cut -d' ' -f1)" \
  -command=vault-plugin-secrets-litellm secret litellm
vault secrets enable -path=litellm litellm
```

## Configuration

```sh
vault write litellm/config \
  url=https://litellm.example.com \
  admin_key=sk-...
```

| Parameter | Description |
|---|---|
| `url` (required) | Base URL of the LiteLLM proxy. |
| `admin_key` (required) | LiteLLM key with proxy admin rights. Verified against LiteLLM on every write. Never returned. |
| `ca_cert` | PEM bundle used to verify the LiteLLM server certificate. Defaults to the system trust store. |
| `insecure_tls` | Skip server certificate verification. Default `false`. |

The write is refused unless LiteLLM accepts the key on `GET /key/list`.
Writing again with a subset of parameters keeps the others. Reading returns
`url`, `ca_cert` and `insecure_tls`.

There is no `rotate-root`: LiteLLM exposes no API for rotating the master key.

## Roles

```sh
vault write litellm/roles/app \
  ttl=1h max_ttl=24h \
  key_request=@app.json
```

where `app.json` is the body LiteLLM should receive on `POST /key/generate`:

```json
{
  "models": ["qwen-a3b"],
  "max_budget": 5,
  "rpm_limit": 60,
  "metadata": {"team": "blue"}
}
```

| Parameter | Description |
|---|---|
| `ttl` | Default lease duration for generated keys. Defaults to the mount's default lease TTL. |
| `max_ttl` | Maximum lease duration. Defaults to the mount's maximum lease TTL. |
| `key_request` | JSON object forwarded to `/key/generate`. Any field LiteLLM accepts is allowed except `key`, `key_alias` and `duration`, which Vault sets. |

LiteLLM validates `key_request`; the plugin does not. Fields that need an
Enterprise licence, such as `tags` and `guardrails`, are forwarded as given and
LiteLLM's `403` is returned to the caller on a community instance.

Roles are listed with `vault list litellm/roles`.

## Generating keys

```sh
vault read litellm/creds/app
```

```
Key                Value
---                -----
lease_id           litellm/creds/app/...
lease_duration     1h
lease_renewable    true
expires            2026-09-15T14:37:04.928000Z
key                sk-...
key_alias          vault-app-1852cc6ac3a5
token_id           6de8743f...
```

Each read calls `/key/generate` with the role's `key_request` plus:

- `key_alias` of the form `vault-<role>-<random>`; LiteLLM requires aliases to
  be unique and the alias is the handle used to delete the key.
- `duration` equal to the lease TTL Vault will grant, so LiteLLM expires the
  key at the lease end even if Vault never revokes it.
- `metadata` merged with `vault_role`, `vault_request_id` and
  `vault_mount_path`, so a key or spend-log row in LiteLLM can be traced to
  the Vault audit entry that issued it.

Renewing the lease calls `/key/update` with a new `duration`, computed from
the same inputs Vault core uses, so LiteLLM's expiry tracks the lease end and
never exceeds `max_ttl` from issue time. Revoking the lease calls
`/key/delete` by alias; a key LiteLLM has already expired counts as revoked.

## Audit

- All operations go through Vault's audit devices. `admin_key` and `key` are
  marked sensitive in the path schema.
- `token_id` is LiteLLM's SHA-256 of the key, the identifier LiteLLM itself
  uses in its key list and spend logs.
- Vault storage never holds a plaintext key. Lease internal data records the
  role, alias and `token_id` only; the plaintext exists in the `creds`
  response and nowhere else.
- LiteLLM error bodies are surfaced verbatim with their HTTP status. The
  plugin never logs request bodies or keys.

## Limits

- **Static roles** are deferred. LiteLLM stores only the hash of a key and
  returns the plaintext once, from `/key/generate`; the only way for Vault to
  take ownership of an existing key is `/key/regenerate`, an Enterprise-only
  endpoint. The design (alias-only role, regenerate on bind) is ready to
  implement against a licensed instance.
- **No key rotation** for the same reason.
- **Vault UI.** The UI has no screens for external secrets engines. The mount
  appears in the engine list with Configure (mount tuning) and Delete; config,
  roles and creds are CLI and API only. The API explorer lists the plugin's
  operations, though Vault's merged OpenAPI document omits external mounts'
  request-body schemas; `vault path-help litellm/config` shows them in full.
- `duration` values sent to LiteLLM are whole seconds; sub-second lease
  fractions are dropped.

## Development

```sh
make test          # unit tests against an in-process fake LiteLLM
make integration   # tagged tests against LITELLM_URL / LITELLM_MASTER_KEY
make e2e           # full lifecycle through a Vault dev server
make run           # dev server with the plugin registered and mounted at litellm/
```

`make run` and `make e2e` start `vault server -dev`; set `VAULT_BIN` to point
at a community build if the `vault` on your path is an unlicensed Enterprise
binary. On macOS keep the plugin directory outside `/tmp`, which Vault
rejects because `/tmp` resolves to `/private/tmp`.

The fake in `fake_test.go` reproduces the responses observed on LiteLLM
1.93.0: plaintext only at generate, unique aliases, unit-suffixed durations,
`404` on missing keys, and the Enterprise gate on `tags`, `guardrails` and
`/key/regenerate`.
