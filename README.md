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
- A LiteLLM proxy backed by a database, with its URL in `LITELLM_URL` and
  its master key in `LITELLM_MASTER_KEY` for the preparation step.

Prepare LiteLLM:

1. Create the plugin's admin identity: a user with the `proxy_admin` role
   and a virtual key under it. The key is the plugin's `admin_key`.

   ```sh
   curl -H "Authorization: Bearer $LITELLM_MASTER_KEY" -H "Content-Type: application/json" \
     -X POST "$LITELLM_URL/user/new" \
     -d '{"user_id":"vault-plugin","user_role":"proxy_admin"}'
   curl -H "Authorization: Bearer $LITELLM_MASTER_KEY" -H "Content-Type: application/json" \
     -X POST "$LITELLM_URL/key/generate" \
     -d '{"user_id":"vault-plugin","key_alias":"vault-plugin-admin"}'
   ```

   LiteLLM's documentation covers
   [virtual keys](https://docs.litellm.ai/docs/proxy/virtual_keys) and
   [user roles](https://docs.litellm.ai/docs/proxy/access_control).

Register and enable the engine:

2. Download the archive for the Vault server's platform from the
   [releases page](https://github.com/benemon/vault-plugin-secrets-litellm/releases),
   extract `vault-plugin-secrets-litellm`, and place it in the plugin
   directory owned by the user Vault runs as and executable by it:

   ```sh
   install -o vault -g vault -m 0755 vault-plugin-secrets-litellm /etc/vault.d/plugins/
   ```

   To build from source instead, run `make dev` and install
   `bin/vault-plugin-secrets-litellm` the same way.

   Each release ships a `SHA256SUMS` file with a Sigstore Cosign bundle, a
   SPDX SBOM per archive, and a GitHub build-provenance attestation:

   ```sh
   cosign verify-blob \
     --bundle vault-plugin-secrets-litellm_<version>_SHA256SUMS.sigstore.json \
     --certificate-identity-regexp 'https://github.com/benemon/vault-plugin-secrets-litellm/' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     vault-plugin-secrets-litellm_<version>_SHA256SUMS
   gh attestation verify vault-plugin-secrets-litellm_<version>_linux_amd64.zip \
     --repo benemon/vault-plugin-secrets-litellm
   ```

3. Register it under the catalog name `litellm`, passing the checksum of the
   installed binary and the release version. The released `SHA256SUMS` file
   verifies the downloaded archive; Vault needs the checksum of the extracted
   binary it will execute, which is not in that file, so compute it on the
   installed file. The catalog name becomes the engine type and the prefix of
   the mount accessor. On Vault Enterprise the plugin catalog belongs to the
   root namespace, so run this with a root-namespace token even when the
   engine will be mounted in a child namespace.

   ```sh
   vault plugin register \
     -sha256="$(sha256sum /etc/vault.d/plugins/vault-plugin-secrets-litellm | cut -d' ' -f1)" \
     -version=v0.1.0 \
     -command=vault-plugin-secrets-litellm secret litellm
   ```

4. Enable it, in whichever namespace the engine should live.

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

### Rotate the admin key

```sh
vault write -f litellm/rotate-root
```

On a LiteLLM Enterprise instance the admin key is regenerated in place and
the previous value stops working at once. On a community instance the plugin
generates a successor key under the same LiteLLM user, verifies it, stores
it, and then deletes the previous key, returning a warning that says so. If
that deletion fails the warning says the previous key is still valid. The
configuration is rewritten only after the new key has been verified.

Rotation is refused when the configured key is the master key, which LiteLLM
cannot rotate, and when the key belongs to no LiteLLM user, since a successor
needs an owner.

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
`max_ttl` and a malformed `user_id_template` or `team_id_template`.
Everything else in `key_request` is passed to LiteLLM as given and validated
there.

To attribute each key to the caller, set identity templates on the role:

```sh
vault write litellm/roles/app key_request=@app.json \
  user_id_template='{{identity.entity.aliases.auth_oidc_5b7c1e2a.name}}' \
  team_id_template='{{identity.groups.names.project-x.metadata.litellm_team_id}}'
```

A role with a template refuses reads from tokens without an entity, such as
the root token. See [Attribution](#attribution).
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
`POST /key/generate` with these additions:

- `key_alias` of the form `vault-<role>-<random>`. LiteLLM requires aliases
  to be unique, and the alias is what the plugin later deletes by.
- `duration` equal to the lease TTL Vault grants. LiteLLM expires the key at
  the lease end on its own, so an unreachable Vault cannot leave a working key
  behind.
- `metadata` from the role merged with `vault_role`, `vault_request_id` and
  `vault_mount_path`. A key or spend-log row in LiteLLM can be traced to the
  Vault audit entry that issued it.
- `user_id` and `team_id` when the role sets a template for them. See
  [Attribution](#attribution).

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

## Attribution

LiteLLM records a key's `user_id` and `team_id` on every request row and in
its daily aggregates, and keeps them after the key is deleted. Its
[cost tracking documentation](https://docs.litellm.ai/docs/proxy/cost_tracking)
covers those endpoints. A role can set both from the Vault caller's identity
with [identity templates](https://developer.hashicorp.com/vault/docs/concepts/policies#templated-policies),
the syntax Vault policies use.

`{{identity.entity.aliases.<accessor>.name}}` resolves to the caller's alias
name on that auth mount, the subject or email the IdP supplied, which is
also what LiteLLM's [SSO login](https://docs.litellm.ai/docs/proxy/ui)
assigns as `user_id`. `{{identity.groups.names.<group>.metadata.<key>}}`
reads a LiteLLM team id from the metadata of a Vault group. A key may carry
both.

Resolution is strict. When a template is set, the read fails and no key is
issued if the caller's token has no entity, if the entity lacks the alias,
group or metadata the template names, or if the template resolves to an
empty string. The errors read `user_id_template is set but the caller's
token has no entity`, `user_id_template "…" did not resolve for this caller:
…` and `user_id_template "…" resolved to an empty value for this caller`,
with `team_id_template` in the same forms. A non-empty `user_id` or
`team_id` in `key_request` is used as-is and skips the template, which is
how a service role keeps a fixed identity. Templates are validated when the
role is written.

The plugin never creates LiteLLM users or teams. A stamped `user_id` needs
no user record for LiteLLM's analytics endpoints, and a record created later
with `POST /user/new` attaches everything logged under that id. The LiteLLM
UI lists only users with a record. Whatever a template resolves to is
visible to LiteLLM administrators on every key and log row.

## Static key custody

> [!IMPORTANT]
> Everything in this section depends on `/key/regenerate`, a LiteLLM
> Enterprise endpoint.

LiteLLM returns a key's plaintext once, from `/key/generate` or
`/key/{token_id}/regenerate`, and stores only the hash. A static role
therefore takes ownership of its key by calling regenerate at bind, and Vault
keeps the returned plaintext in the role's storage entry. That entry sits
under the `static-roles/` prefix, which the plugin registers for seal
wrapping along with the `config` entry that holds the admin key. Reads serve the stored copy without regenerating.

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
| `rotate-root` | write | Replace the admin key with a new one under the same user. |
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
| `admin_key` (required) | A virtual key under a `proxy_admin` user. The master key is accepted but cannot be rotated. Verified on write, never returned, replaced by `rotate-root`. |
| `ca_cert` | PEM bundle used to verify the LiteLLM server certificate. Defaults to the system trust store. |
| `insecure_tls` | Skip server certificate verification. Default `false`. |

### roles/<name>

| Parameter | Description |
|---|---|
| `ttl` | Default lease duration. Defaults to the mount's default lease TTL. |
| `max_ttl` | Maximum lease duration. Defaults to the mount's maximum lease TTL. |
| `key_request` | JSON object sent to `POST /key/generate`. `key`, `key_alias` and `duration` are reserved. |
| `user_id_template` | Identity template resolved against the caller and sent as `user_id`. |
| `team_id_template` | Identity template resolved against the caller and sent as `team_id`. |

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
- Rotation of static keys and of the admin key is on demand only. There is
  no `rotation_period`.
- A role with an identity template cannot issue keys to tokens without an
  entity, such as the root token. Automation without an entity uses a role
  that sets `user_id` or `team_id` in `key_request` instead.
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
`LITELLM_MASTER_KEY`. Both create a `proxy_admin` user and key with the
master key, configure the plugin with that key, and rotate it. `make e2e` detects whether the instance is licensed and asserts the
matching behaviour. On Enterprise that is static binds and in-place admin
key regeneration. On community it is the licence refusal for binds and the
successor path for `rotate-root`. The integration test skips the static-role test on a
community instance. `make run` and `make e2e` start `vault server -dev` from
`VAULT_BIN`, defaulting to the `vault` on your path. On macOS keep the plugin
directory outside `/tmp`. Vault rejects it because `/tmp` resolves to
`/private/tmp`.
