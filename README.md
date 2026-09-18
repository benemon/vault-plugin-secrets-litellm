[![ci](https://github.com/benemon/vault-plugin-secrets-litellm/actions/workflows/ci.yml/badge.svg)](https://github.com/benemon/vault-plugin-secrets-litellm/actions/workflows/ci.yml) [![Dependabot Updates](https://github.com/benemon/vault-plugin-secrets-litellm/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/benemon/vault-plugin-secrets-litellm/actions/workflows/dependabot/dependabot-updates) [![release](https://github.com/benemon/vault-plugin-secrets-litellm/actions/workflows/release.yml/badge.svg)](https://github.com/benemon/vault-plugin-secrets-litellm/actions/workflows/release.yml) [![codeql](https://github.com/benemon/vault-plugin-secrets-litellm/actions/workflows/codeql.yml/badge.svg)](https://github.com/benemon/vault-plugin-secrets-litellm/actions/workflows/codeql.yml) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/benemon/vault-plugin-secrets-litellm/badge)](https://scorecard.dev/viewer/?uri=github.com/benemon/vault-plugin-secrets-litellm)

# vault-plugin-secrets-litellm

A Vault secrets engine for LiteLLM virtual keys. Dynamic roles generate a
key through LiteLLM's key API, bind it to a Vault lease, extend it when the
lease is renewed and delete it when the lease ends or is revoked. Static
roles bind one existing key by alias and serve the same key to every reader
until an operator rotates it through Vault.

## Setup

Prerequisites:

- Vault with plugin multiplexing, which every supported release has, and a
  configured `plugin_directory`. Releases are built for the platforms Vault
  2.0 ships for: linux 386, amd64 and arm64, darwin amd64 and arm64, freebsd
  386 and amd64, windows 386 and amd64.
- `VAULT_ADDR` and a token able to register plugins and enable secrets
  engines.
- A LiteLLM proxy backed by a database, with its URL in `LITELLM_URL` and
  its master key in `LITELLM_MASTER_KEY` for step 1.

1. Create the plugin's admin identity in LiteLLM: a user with the
   `proxy_admin` role and a virtual key under it. The key is the plugin's
   `admin_key`. `auto_create_key` must be false, because LiteLLM otherwise
   mints a second, unnamed key for the new user.

   ```sh
   curl -H "Authorization: Bearer $LITELLM_MASTER_KEY" -H "Content-Type: application/json" \
     -X POST "$LITELLM_URL/user/new" \
     -d '{"user_id":"vault-plugin","user_role":"proxy_admin","auto_create_key":false}'
   curl -H "Authorization: Bearer $LITELLM_MASTER_KEY" -H "Content-Type: application/json" \
     -X POST "$LITELLM_URL/key/generate" \
     -d '{"user_id":"vault-plugin","key_alias":"vault-plugin-admin"}'
   ```

   LiteLLM's documentation covers
   [virtual keys](https://docs.litellm.ai/docs/proxy/virtual_keys) and
   [user roles](https://docs.litellm.ai/docs/proxy/access_control).

2. Download the zip for the Vault server's platform from the
   [releases page](https://github.com/benemon/vault-plugin-secrets-litellm/releases),
   verify it as described under [Verifying a release](#verifying-a-release),
   extract `vault-plugin-secrets-litellm`, and copy it into the
   [plugin directory](https://developer.hashicorp.com/vault/docs/configuration#plugin_directory)
   on every Vault node:

   ```sh
   cp vault-plugin-secrets-litellm /etc/vault.d/plugins/
   ```

   Vault must be able to read and execute the file. If the server runs
   with `VAULT_ENABLE_FILE_PERMISSIONS_CHECK`, see
   [plugin_file_permissions](https://developer.hashicorp.com/vault/docs/configuration#plugin_file_permissions).

   To build from source instead, run `make dev` and copy
   `bin/vault-plugin-secrets-litellm` the same way.

3. Register it under the catalog name `litellm`. The catalog name becomes
   the engine type and the prefix of the mount accessor. Vault needs the
   checksum of the binary it will execute, so compute it on the installed
   file rather than taking a value from the release's checksum file, which
   covers the zips. `-version` is optional and lets several releases coexist
   in the catalog. On Vault Enterprise the plugin catalog belongs to the root
   namespace, so run this with a root-namespace token even when the engine
   will be mounted in a child namespace.

   ```sh
   vault plugin register \
     -sha256="$(sha256sum /etc/vault.d/plugins/vault-plugin-secrets-litellm | cut -d' ' -f1)" \
     -version=<version> \
     -command=vault-plugin-secrets-litellm secret litellm
   ```

4. Enable it, in whichever namespace the engine should live.

   ```sh
   vault secrets enable -path=litellm litellm
   ```

The Vault documentation on
[plugin management](https://developer.hashicorp.com/vault/docs/plugins/plugin-management)
covers directories, checksums, multiplexing and upgrades.

### Verifying a release

Each release ships a `SHA256SUMS` file over the zips with a Sigstore Cosign
bundle, an SPDX SBOM per zip, and a GitHub build-provenance attestation over
the zips and the checksum file.

```sh
cosign verify-blob \
  --bundle vault-plugin-secrets-litellm_<version>_SHA256SUMS.sigstore.json \
  --certificate-identity-regexp 'https://github.com/benemon/vault-plugin-secrets-litellm/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vault-plugin-secrets-litellm_<version>_SHA256SUMS
gh attestation verify vault-plugin-secrets-litellm_<version>_linux_amd64.zip \
  --repo benemon/vault-plugin-secrets-litellm
```

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
`insecure_tls`. `vault delete litellm/config` removes the configuration,
after which role and key operations fail until it is written again.

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
there. Fields that need a LiteLLM Enterprise licence, such as `tags` and
`guardrails`, are refused by a community instance with its licence error,
which is returned to the caller.

`user_id` and `team_id` are set on the role, either as fixed values in
`key_request` or from the caller's identity through `user_id_template` and
`team_id_template`. Nothing is set per request. [Attribution](#attribution)
shows the options and the precedence between them.

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
`vault read litellm/static-roles/svc` returns `key_alias` and `token_id`.
Deleting the role removes Vault's copy and leaves the key in LiteLLM.

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

There is no lease. Reads return the stored key while it still exists in
LiteLLM. [Key custody](#key-custody) covers what happens when it does not.

### Rotate a static key

```sh
vault write -f litellm/rotate-role/svc
```

The same warning as on bind is returned.

### Rotate the admin key

```sh
vault write -f litellm/rotate-root
```

On a LiteLLM Enterprise instance the admin key is regenerated in place. On a
community instance a successor key is generated under the same LiteLLM user
and the previous key is deleted, with a warning that says so.
[Key custody](#key-custody) covers the guarantees and refusals.

### Consume keys from Kubernetes

[Vault Secrets Operator](https://developer.hashicorp.com/vault/docs/platform/k8s/vso)
syncs both kinds of role into Kubernetes Secrets. The custom resource has to
match the kind of role, because the operator restarts workloads on different
triggers for each.

Dynamic roles use a
[VaultDynamicSecret](https://developer.hashicorp.com/vault/docs/platform/k8s/vso/api-reference#vaultdynamicsecret).
The operator renews the lease at `renewalPercent` of its TTL, reads a new key
when a renewal is capped by `max_ttl`, revokes the lease when the resource is
deleted, and restarts the listed workloads whenever it syncs a new key.

```yaml
apiVersion: secrets.hashicorp.com/v1beta1
kind: VaultDynamicSecret
metadata:
  name: app-litellm
spec:
  vaultAuthRef: vault-auth
  mount: litellm
  path: creds/app
  renewalPercent: 67
  revoke: true
  destination:
    create: true
    name: litellm-key
  rolloutRestartTargets:
    - kind: Deployment
      name: app
```

Static roles use a
[VaultStaticSecret](https://developer.hashicorp.com/vault/docs/platform/k8s/vso/api-reference#vaultstaticsecret)
with `type: kv-v1`. The `type` field accepts only `kv-v1` and `kv-v2`, and
`kv-v1` is a plain read of `<mount>/<path>` whose data becomes the Secret,
which is what `static-creds/<role>` returns. The operator re-reads the path
every `refreshAfter`, compares the data with what it last wrote, and restarts
the listed workloads only when the key has changed, which happens when
`rotate-role/<role>` is written.

```yaml
apiVersion: secrets.hashicorp.com/v1beta1
kind: VaultStaticSecret
metadata:
  name: svc-litellm
spec:
  vaultAuthRef: vault-auth
  mount: litellm
  type: kv-v1
  path: static-creds/svc
  refreshAfter: 60s
  destination:
    create: true
    name: litellm-static-key
  rolloutRestartTargets:
    - kind: Deployment
      name: svc
```

Do not point a `VaultDynamicSecret` at `static-creds/<role>`. It syncs,
because the path answers a read, but the operator treats every refresh of a
response without a lease as a new secret and restarts the workloads each
time. After `rotate-role` the previous key is refused until the next refresh,
so `refreshAfter` bounds the outage.

The Vault policy for the operator's auth role needs `read` on the
`creds/<role>` or `static-creds/<role>` path, and for dynamic roles `update`
on `sys/leases/renew` and `sys/leases/revoke`.

## Lease behaviour

Each read of `creds/<role>` sends the role's `key_request` to
`POST /key/generate` with these additions:

- `key_alias` of the form `vault-<role>-<random>`. LiteLLM requires aliases
  to be unique, and the alias is what the plugin later deletes by.
- `duration` equal to the lease TTL Vault grants. LiteLLM expires the key at
  the lease end on its own, so an unreachable Vault cannot leave a working key
  behind.
- `metadata` from the role merged with `vault_role`, `vault_request_id` and
  `vault_mount_path`.
- `user_id` and `team_id` when the role sets a template for them.

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
covers those endpoints, and its
[team documentation](https://docs.litellm.ai/docs/proxy/team_budgets) covers
what a team's models and budget do to a key that carries its `team_id`.

### Where the values come from

Both fields are set on the role and only there. A read of `creds/<role>`
takes no parameters, so the caller cannot supply or override either value.
The role is the policy boundary: whoever can write it decides how its keys
are attributed, and a caller who could choose their own `user_id` would
defeat that.

A role sets each field in one of two ways, and the two can be combined.

**Fixed.** A value in `key_request` is sent as given on every read. This
suits a service whose keys should all be accounted together.

```json
{
  "models": ["qwen-a3b"],
  "user_id": "billing-service",
  "team_id": "9c1d2e3f-team-blue"
}
```

**From the caller.** `user_id_template` and `team_id_template` resolve
against the identity of the Vault token that reads the role, using the
[identity template syntax](https://developer.hashicorp.com/vault/docs/concepts/policies#templated-policies)
of Vault policies. This suits a role shared by people or workloads that
should be accounted separately.

```sh
vault write litellm/roles/people key_request=@people.json \
  user_id_template='{{identity.entity.aliases.auth_oidc_5b7c1e2a.name}}' \
  team_id_template='{{identity.groups.names.project-x.metadata.litellm_team_id}}'
```

**Mixed.** A fixed value wins over the template for the same field, so a
role can pin the team and still stamp each caller as the user.

```sh
vault write litellm/roles/team-blue \
  key_request='{"models":["qwen-a3b"],"team_id":"9c1d2e3f-team-blue"}' \
  user_id_template='{{identity.entity.aliases.auth_kubernetes_130e0f36.name}}'
```

A role with neither sends no `user_id` or `team_id`, and LiteLLM records
the key without an owner.

### How templates resolve

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
with `team_id_template` in the same forms. Templates are validated when the
role is written.

### Records in LiteLLM

The plugin never creates LiteLLM users or teams, and LiteLLM accepts either
id on a key without a record behind it. Create the team first so its
settings apply. A stamped `user_id` needs no user record for LiteLLM's
analytics endpoints, and a record created later with `POST /user/new`
attaches everything logged under that id. The LiteLLM UI lists only users
with a record. Whatever a template resolves to is visible to LiteLLM
administrators on every key and log row.

## Key custody

> [!IMPORTANT]
> Static roles depend on `/key/regenerate`, a LiteLLM Enterprise endpoint.
> Admin key rotation uses it where available and has a community path.

LiteLLM returns a key's plaintext once, from `/key/generate` or
`/key/{token_id}/regenerate`, and stores only the hash. A static role
therefore takes ownership of its key by calling regenerate at bind, and Vault
keeps the returned plaintext in the role's storage entry. The `static-roles/`
prefix and the `config` entry that holds the admin key are registered for
seal wrapping. Reads serve the stored copy without regenerating.

A bind is refused when `key_alias` is missing, when the alias names no
LiteLLM key, when another static role already binds the alias, or when the
role already exists. A bound role cannot be rewritten. Delete it and bind
again.

Before serving a read, the plugin checks that the stored hash still names a
key. If the key was regenerated or deleted outside Vault, the read fails and
names `rotate-role/<name>` as the recovery. Rotation looks the key up by
alias and regenerates, so it recovers from an outside regeneration. It
refuses when the role does not exist or when no key carries the alias any
more. Regenerate changes the hash and keeps the alias and the key's settings,
as the [virtual keys documentation](https://docs.litellm.ai/docs/proxy/virtual_keys)
describes. The previous value stops working when the call returns.

`rotate-root` regenerates the admin key in place when LiteLLM allows it. When
LiteLLM answers with its licence error, the plugin generates a successor key
under the admin key's LiteLLM user, verifies it with `GET /key/list`, stores
it, and then deletes the previous key by hash. The configuration is rewritten
only after the successor has been verified. If the deletion fails, the
warning says the previous key is still valid. Rotation is refused when the
configured key is the master key, which LiteLLM cannot rotate. On the
successor path it is also refused when the admin key belongs to no LiteLLM
user.

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
LiteLLM's error envelope in full. A body that is not LiteLLM's envelope is
returned as text cut at 200 bytes.

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

Go 1.27 or later.

```sh
make dev           # build bin/vault-plugin-secrets-litellm
make test          # gofmt check, go vet, unit tests against an in-process fake LiteLLM
make integration   # tagged tests against a live instance
make e2e           # full lifecycle through a Vault dev server and a live instance
make run           # dev server with the plugin registered and mounted at litellm/
make snapshot      # cross-build every release target into dist/, unsigned, no SBOMs
make fmt           # gofmt in place
```

`make test` and `make integration` fail on unformatted files. `make snapshot`
downloads GoReleaser on first use.

`make integration` and `make e2e` need `LITELLM_URL` and
`LITELLM_MASTER_KEY`. The integration tests configure the plugin with the
master key, except the rotation test, which creates a `proxy_admin` user and
key for itself. `make e2e` creates a `proxy_admin` user and key with the
master key, configures the plugin with that key, rotates it, and detects
whether the instance is licensed to assert the matching behaviour. On
Enterprise that is static binds and in-place admin key regeneration. On
community it is the licence refusal for binds and the successor path for
`rotate-root`. The integration test skips the static-role test on a
community instance.

`make run` and `make e2e` start `vault server -dev` from `VAULT_BIN`,
defaulting to the `vault` on your path. On macOS keep the plugin directory
outside `/tmp`. Vault rejects it because `/tmp` resolves to `/private/tmp`.

## Contributing

Changes go through pull requests against `main`, which requires the `test`,
`vulncheck`, `snapshot` and `analyze` checks: gofmt, vet and unit tests;
govulncheck; a GoReleaser snapshot build of every release target; and
CodeQL. CodeQL runs on pull requests, on pushes to `main` and weekly.
OpenSSF Scorecard scores `main` on every push and weekly. Both report to
the Security tab. Releases are cut by pushing a `v*` tag that points at a
commit on `main`. The release workflow runs only for `v*` tags and refuses
one whose commit is not on `main`. Release notes are generated from commit
subjects, excluding those prefixed `chore`.
