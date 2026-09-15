# vault-plugin-secrets-litellm

LiteLLM virtual keys are created by hand in the proxy, live until someone
deletes them, and leave no record of who holds them. This Vault secrets
engine issues them on demand instead. Each key is generated through LiteLLM's
own key API, bound to a Vault lease, extended when the lease is renewed and
deleted when the lease ends or is revoked. A static role binds one existing
key by alias and serves the same key to every reader until an operator
rotates it through Vault.

## Setup

Prerequisites:

- Vault 1.12 or later with a configured `plugin_directory`.
- `VAULT_ADDR` and a token able to register plugins and enable secrets
  engines.
- A LiteLLM proxy backed by a database.
- A LiteLLM key with proxy admin rights. The master key works, as does a
  `proxy_admin` virtual key.

Register and enable the engine:

1. Download the archive for the Vault server's platform from the
   [releases page](https://github.com/benemon/vault-plugin-secrets-litellm/releases)
   and copy `vault-plugin-secrets-litellm` into the plugin directory. To
   build from source instead, run `make dev` and use `bin/vault-plugin-secrets-litellm`.

   Each release ships a `SHA256SUMS` file signed with Sigstore Cosign, a
   CycloneDX SBOM per archive, and a GitHub build-provenance attestation:

   ```sh
   cosign verify-blob \
     --certificate vault-plugin-secrets-litellm_<version>_SHA256SUMS.pem \
     --signature vault-plugin-secrets-litellm_<version>_SHA256SUMS.sig \
     --certificate-identity-regexp 'https://github.com/benemon/vault-plugin-secrets-litellm/' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     vault-plugin-secrets-litellm_<version>_SHA256SUMS
   gh attestation verify vault-plugin-secrets-litellm_<version>_linux_amd64.tar.gz \
     --repo benemon/vault-plugin-secrets-litellm
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

### Bind a static role

> [!IMPORTANT]
> Static roles require a LiteLLM Enterprise licence. Bind and rotation call
> `/key/{token_id}/regenerate`, which a community instance refuses with a
> licence error. Dynamic roles need no licence.

```sh
vault write litellm/static-roles/svc key_alias=team-blue
```

```
WARNING! The following warnings were returned from Vault:

  * LiteLLM key "team-blue" was regenerated; its previous value no longer
  works. Read static-creds/svc for the current key.
```

The alias must name an existing LiteLLM key that no other static role binds.
The write regenerates the key, so any consumer holding the previous value
loses access at that moment. `vault read litellm/static-roles/svc` returns
`key_alias` and `token_id`. `vault list litellm/static-roles` lists the
roles. `vault delete litellm/static-roles/svc` removes Vault's copy and
leaves the key in LiteLLM.

### Read a static key

```sh
vault read litellm/static-creds/svc
```

```
Key          Value
---          -----
key          sk-...
key_alias    team-blue
token_id     4c1f0e2a...
```

There is no lease. Every read returns the same key until the role is rotated.

### Rotate a static key

```sh
vault write -f litellm/rotate-role/svc
```

The key is regenerated and the previous value stops working. The same
warning as on bind is returned.

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
its key list and spend logs. For dynamic keys, Vault storage holds the alias
and `token_id` in the lease and never the key itself. The key appears in the
`creds` response only.

The [LiteLLM virtual keys documentation](https://docs.litellm.ai/docs/proxy/virtual_keys)
describes the key API, alias rules and the Enterprise-only endpoints.

## Static key custody

> [!IMPORTANT]
> Everything in this section depends on `/key/regenerate`, a LiteLLM
> Enterprise endpoint.

LiteLLM returns a key's plaintext once, from `/key/generate` or
`/key/{token_id}/regenerate`, and stores only the hash. A static role
therefore takes ownership of its key by calling regenerate at bind, and Vault
keeps the returned plaintext in the role's storage entry. That entry sits
under the `static-roles/` prefix, which the plugin registers for seal
wrapping. Reads serve the stored copy without regenerating.

The plugin verifies the alias exists and refuses a bind when `key_alias` is
missing, when the alias names no LiteLLM key, when another static role
already binds the alias, or when the role already exists. A bound role cannot
be rewritten. Delete it and bind again.

LiteLLM stays the authority on the key's existence and settings. Before
serving a read, the plugin checks that the stored hash still names a key. If
the key was regenerated or deleted outside Vault, the read fails and names
`rotate-role/<name>` as the recovery. Rotation looks the key up by alias and
regenerates, so it recovers from an outside regeneration. It refuses when
the role does not exist or when no key carries the alias any more.

Regenerate keeps the alias, limits, budget, spend and expiry and changes the
hash. There is no overlap window. The previous value stops working when the
regenerate call returns.

## API

| Path | Operations | Description |
|---|---|---|
| `config` | write, read, delete | LiteLLM connection. |
| `roles/<name>` | write, read, delete | Key specification and lease bounds. |
| `roles` | list | Role names. |
| `creds/<name>` | read | Generate a key under a lease. |
| `static-roles/<name>` | write, read, delete | Bind an existing key by alias. |
| `static-roles` | list | Static role names. |
| `static-creds/<name>` | read | The key held for a static role. |
| `rotate-role/<name>` | write | Regenerate a static role's key. |

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

### static-roles/<name>

| Parameter | Description |
|---|---|
| `key_alias` (required) | Alias of the existing LiteLLM key. Must be unbound. |

`admin_key` and the returned `key` are marked sensitive in the path schemas.
Errors from LiteLLM are returned with their HTTP status and the message from
LiteLLM's error envelope, truncated to 200 bytes.

## Limits

- Static roles need a LiteLLM Enterprise licence. See
  [Bind a static role](#bind-a-static-role).
- Rotation of static keys is on demand only. There is no `rotation_period`.
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
make snapshot      # cross-build every release target into dist/
```

Releases are cut by pushing a `v*` tag that points at a commit on `main`.
The release workflow refuses any other tag.

`make integration` and `make e2e` need `LITELLM_URL` and
`LITELLM_MASTER_KEY`. The static-role steps need a licensed instance. The
integration test skips them on a community instance and `make e2e` fails. `make run` and `make e2e` start `vault server -dev` from
`VAULT_BIN`, defaulting to the `vault` on your path. On macOS keep the plugin
directory outside `/tmp`. Vault rejects it because `/tmp` resolves to
`/private/tmp`.
