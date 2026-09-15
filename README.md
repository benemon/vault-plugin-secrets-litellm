# vault-plugin-secrets-litellm

LiteLLM virtual keys are created by hand in the proxy, live until someone
deletes them, and leave no record of who holds them. This Vault secrets
engine issues them on demand instead. Each key is generated through LiteLLM's
own key API, bound to a Vault lease, extended when the lease is renewed and
deleted when the lease ends or is revoked.

## Setup

Prerequisites:

- Vault 1.12 or later with a configured `plugin_directory`.
- `VAULT_ADDR` and a token able to register plugins and enable secrets
  engines.
- A LiteLLM proxy backed by a database.
- A LiteLLM key with proxy admin rights. The master key works, as does a
  `proxy_admin` virtual key.

Register and enable the engine:

1. Build the plugin and copy `bin/vault-plugin-secrets-litellm` into the
   plugin directory.

   ```sh
   make dev
   ```

2. Register it under the catalog name `litellm`. The catalog name becomes the
   engine type and the prefix of the mount accessor.

   ```sh
   vault plugin register \
     -sha256="$(shasum -a 256 bin/vault-plugin-secrets-litellm | cut -d' ' -f1)" \
     -command=vault-plugin-secrets-litellm secret litellm
   ```

3. Enable it.

   ```sh
   vault secrets enable -path=litellm litellm
   ```

The Vault documentation on
[plugin management](https://developer.hashicorp.com/vault/docs/plugins/plugin-management)
covers directories, checksums and upgrades.

## Usage

### Configure the connection

```sh
vault write litellm/config \
  url=https://litellm.example.com \
  admin_key=sk-...
```

The write calls LiteLLM's `GET /key/list` with the supplied key and is
refused if LiteLLM rejects it. Writing again with a subset of parameters
keeps the others. `vault read litellm/config` returns `url`, `ca_cert` and
`insecure_tls`. `vault delete litellm/config` removes the configuration, after
which role and key operations fail until it is written again.

### Define a role

```sh
vault write litellm/roles/app ttl=1h max_ttl=24h key_request=@app.json
```

`app.json` is the body LiteLLM receives on `POST /key/generate`:

```json
{
  "models": ["qwen-a3b"],
  "max_budget": 5,
  "rpm_limit": 60,
  "metadata": {"team": "blue"}
}
```

The plugin rejects a `key_request` that is not a JSON object, one whose
`metadata` is not an object, and one that sets `key`, `key_alias` or
`duration`, which Vault fills in itself. It also rejects a `ttl` above
`max_ttl`. Everything else is passed to LiteLLM as given and validated there.
On a community instance LiteLLM answers `403` for fields that need an
Enterprise licence, such as `tags` and `guardrails`, and that error is returned
to the caller.

Roles are read with `vault read litellm/roles/app`, listed with
`vault list litellm/roles` and removed with `vault delete litellm/roles/app`.

### Generate a key

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

## Lease behaviour

Each read of `creds/<role>` sends the role's `key_request` to
`POST /key/generate` with three additions:

- `key_alias` of the form `vault-<role>-<random>`. LiteLLM requires aliases
  to be unique, and the alias is what the plugin later deletes by.
- `duration` equal to the lease TTL Vault grants. LiteLLM expires the key at
  the lease end on its own, so an unreachable Vault cannot leave a working key
  behind.
- `metadata` from the role merged with `vault_role`, `vault_request_id` and
  `vault_mount_path`. A key or spend-log row in LiteLLM can be traced to the
  Vault audit entry that issued it.

Renewing the lease calls `POST /key/update` with a new `duration`. The plugin
computes it from the same inputs Vault core uses, so LiteLLM's expiry lands on
the new lease end and never passes `max_ttl` counted from issue time. Renewal
fails if the role has been deleted.

Revoking the lease, or letting it expire, calls `POST /key/delete` with the
alias. A `404` from LiteLLM is treated as success, so a key LiteLLM already
expired, or an operator already removed, does not block revocation.

`token_id` is the SHA-256 of the key and is the identifier LiteLLM shows in
its key list and spend logs. Vault storage holds the alias and `token_id` in
the lease and never the key itself. The key appears in the `creds` response
and nowhere in Vault after that.

The [LiteLLM virtual keys documentation](https://docs.litellm.ai/docs/proxy/virtual_keys)
describes the key API, alias rules and the Enterprise-only endpoints.

## API

| Path | Operations | Description |
|---|---|---|
| `config` | write, read, delete | LiteLLM connection. |
| `roles/<name>` | write, read, delete | Key specification and lease bounds. |
| `roles` | list | Role names. |
| `creds/<name>` | read | Generate a key under a lease. |

### config

| Parameter | Description |
|---|---|
| `url` (required) | Base URL of the LiteLLM proxy. |
| `admin_key` (required) | Key with proxy admin rights. Verified on write. Never returned. |
| `ca_cert` | PEM bundle used to verify the LiteLLM server certificate. Defaults to the system trust store. |
| `insecure_tls` | Skip server certificate verification. Default `false`. |

### roles/<name>

| Parameter | Description |
|---|---|
| `ttl` | Default lease duration. Defaults to the mount's default lease TTL. |
| `max_ttl` | Maximum lease duration. Defaults to the mount's maximum lease TTL. |
| `key_request` | JSON object sent to `POST /key/generate`. `key`, `key_alias` and `duration` are reserved. |

`admin_key` and the returned `key` are marked sensitive in the path schemas.
Errors from LiteLLM are returned with their HTTP status and the message from
LiteLLM's error envelope, truncated to 200 bytes.

## Limits

- Static roles, which would hand back an existing key, are not implemented.
  LiteLLM returns a key's plaintext only from `/key/generate`. Taking over an
  existing key needs `/key/regenerate`, which requires an Enterprise licence.
  Key rotation is absent for the same reason.
- There is no `rotate-root`. LiteLLM has no API for rotating the master key.
- The Vault UI has no screens for external secrets engines. The mount is
  listed with Configure, which is mount tuning, and Delete. The browser CLI
  and the Leases view work with the engine. The API explorer lists the
  plugin's operations without request-body schemas, which
  `vault path-help litellm/config` shows in full.
- `duration` values sent to LiteLLM are whole seconds.

## Development

```sh
make test          # unit tests against an in-process fake LiteLLM
make integration   # tagged tests against a live instance
make e2e           # full lifecycle through a Vault dev server and a live instance
make run           # dev server with the plugin registered and mounted at litellm/
```

`make integration` and `make e2e` need `LITELLM_URL` and
`LITELLM_MASTER_KEY`. `make run` and `make e2e` start `vault server -dev` from
`VAULT_BIN`, defaulting to the `vault` on your path. On macOS keep the plugin
directory outside `/tmp`. Vault rejects it because `/tmp` resolves to
`/private/tmp`.
