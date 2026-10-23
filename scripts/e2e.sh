#!/usr/bin/env bash
# End-to-end check through a real Vault dev server and a real LiteLLM.
# Needs LITELLM_URL and LITELLM_MASTER_KEY; VAULT_BIN selects the server binary.
set -euo pipefail

: "${LITELLM_URL:?set LITELLM_URL}"
: "${LITELLM_MASTER_KEY:?set LITELLM_MASTER_KEY}"
PLUGIN_NAME="vault-plugin-secrets-litellm"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="$DIR/scripts/tmp-e2e"
V="${VAULT_BIN:-vault}"
export VAULT_ADDR="http://127.0.0.1:8210"
export VAULT_TOKEN=root
MH="Authorization: Bearer $LITELLM_MASTER_KEY"
ADMIN_USER="vault-e2e-admin"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }
# /key/info takes its key in the query string, and LiteLLM's access log records
# query strings, so keys are looked up by their hash, which it also accepts.
key_hash() { printf %s "$1" | python3 -c 'import hashlib,sys;print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'; }
key_status() { curl -sS -o /dev/null -w '%{http_code}' -H "$MH" "$LITELLM_URL/key/info?key=$(key_hash "$1")"; }
key_info() { curl -sS -H "$MH" "$LITELLM_URL/key/info?key=$(key_hash "$1")"; }
# json a.b.c reads one field of the JSON on stdin; lists and objects come back
# as compact JSON, a missing field as an empty string.
json() { python3 -c 'import json,sys
v=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    v=v.get(k) if isinstance(v,dict) else None
print("" if v is None else json.dumps(v,separators=(",",":")) if isinstance(v,(dict,list)) else v)' "$1"; }
key_expires() { key_info "$1" | json info.expires; }
auth_status() { curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $1" "$LITELLM_URL/v1/models"; }
to_epoch() { python3 -c 'import sys,datetime;print(int(datetime.datetime.fromisoformat(sys.argv[1].replace("Z","+00:00")).timestamp()))' "$1"; }

mkdir -p "$SCRATCH/plugins"
go build -o "$SCRATCH/plugins/$PLUGIN_NAME" "$DIR/cmd/$PLUGIN_NAME"
"$V" server -dev -dev-root-token-id=root -dev-listen-address="${VAULT_ADDR#http://}" \
  -dev-plugin-dir="$SCRATCH/plugins" -log-level=warn >"$SCRATCH/vault.log" 2>&1 &
VAULT_PID=$!
cleanup() {
  kill -INT "$VAULT_PID" 2>/dev/null || true; wait "$VAULT_PID" 2>/dev/null || true
  remove_admin_identity
  curl -sS -o /dev/null -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/user/delete" -d '{"user_ids":["e2e-person"]}'
  rm -rf "$SCRATCH"
}
remove_admin_identity() {
  curl -sS -H "$MH" "$LITELLM_URL/key/list?return_full_object=true&user_id=$ADMIN_USER" \
    | python3 -c 'import json,sys;print(" ".join(k["token"] for k in json.load(sys.stdin).get("keys",[])))' \
    | xargs -n1 -I% curl -sS -o /dev/null -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/key/delete" -d '{"keys":["%"]}'
  curl -sS -o /dev/null -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/user/delete" -d "{\"user_ids\":[\"$ADMIN_USER\"]}"
}
trap cleanup EXIT
for _ in $(seq 1 40); do "$V" status >/dev/null 2>&1 && break; sleep 0.5; done

SHASUM=$(shasum -a 256 "$SCRATCH/plugins/$PLUGIN_NAME" | cut -d' ' -f1)
"$V" plugin register -sha256="$SHASUM" -command="$PLUGIN_NAME" secret litellm >/dev/null
"$V" secrets enable -path=litellm litellm >/dev/null

# Mirrors the README install path: the plugin holds a proxy_admin virtual key.
curl -sS -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/user/new" \
  -d "{\"user_id\":\"$ADMIN_USER\",\"user_role\":\"proxy_admin\",\"auto_create_key\":false}" >/dev/null
ADMIN_KEY=$(curl -sS -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/key/generate" \
  -d "{\"user_id\":\"$ADMIN_USER\",\"key_alias\":\"$ADMIN_USER-key\"}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["key"])')
"$V" write litellm/config url="$LITELLM_URL" admin_key="$ADMIN_KEY" >/dev/null
pass "configured with a proxy_admin virtual key"

# Regenerate is the Enterprise-gated call.
PROBE=$(curl -sS -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/key/generate" -d '{"key_alias":"vault-e2e-edition-probe","duration":"2m"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["token_id"])')
REGEN=$(curl -sS -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/key/$PROBE/regenerate" -d '{}')
if [ -n "$(json key <<<"$REGEN")" ]; then EDITION=enterprise; else EDITION=community; fi
curl -sS -o /dev/null -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/key/delete" -d '{"key_aliases":["vault-e2e-edition-probe"]}'
pass "LiteLLM edition detected: $EDITION"

"$V" write -f litellm/rotate-root >"$SCRATCH/rotate.txt" 2>&1 || fail "rotate-root failed: $(cat "$SCRATCH/rotate.txt")"
[ "$(auth_status "$ADMIN_KEY")" = 401 ] || fail "previous admin key still authenticates after rotate-root"
"$V" read litellm/config >/dev/null || fail "plugin unusable after rotate-root"
if [ "$EDITION" = enterprise ]; then
  grep -q successor "$SCRATCH/rotate.txt" && fail "rotate-root took the successor path on an Enterprise instance"
else
  grep -q successor "$SCRATCH/rotate.txt" || fail "rotate-root did not take the successor path on a community instance"
fi
pass "rotate-root replaced the admin key by the $EDITION path"

# The master key is not a virtual key: /key/info answers 404 for it, on every
# release, and rotate-root refuses rather than minting a successor.
"$V" secrets enable -path=litellm-master litellm >/dev/null
"$V" write litellm-master/config url="$LITELLM_URL" admin_key="$LITELLM_MASTER_KEY" >/dev/null
"$V" write -f litellm-master/rotate-root >"$SCRATCH/rotate-master.txt" 2>&1 && fail "rotate-root accepted the master key"
grep -q 'not a virtual key' "$SCRATCH/rotate-master.txt" || fail "rotate-root refused the master key for another reason: $(cat "$SCRATCH/rotate-master.txt")"
[ "$(auth_status "$LITELLM_MASTER_KEY")" = 200 ] || fail "master key stopped authenticating after a refused rotate-root"
"$V" secrets disable litellm-master >/dev/null
pass "rotate-root refused the master key"

"$V" write litellm/roles/e2e ttl=10m max_ttl=15m \
  key_request='{"models":["qwen-a3b"],"max_budget":0.05,"rpm_limit":10,"metadata":{"suite":"e2e"}}' >/dev/null
"$V" read -format=json litellm/creds/e2e >"$SCRATCH/creds.json"
read -r KEY LEASE < <(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["data"]["key"],d["lease_id"])' "$SCRATCH/creds.json")
[ "$(key_status "$KEY")" = 200 ] || fail "generated key unknown to LiteLLM"
pass "generated key from role (lease $LEASE)"

# The plugin's half of scoping: the key LiteLLM holds carries the role's
# key_request, field for field.
INFO=$(key_info "$KEY")
[ "$(json info.models <<<"$INFO")" = '["qwen-a3b"]' ] || fail "key models: want [\"qwen-a3b\"], got $(json info.models <<<"$INFO")"
[ "$(json info.max_budget <<<"$INFO")" = 0.05 ] || fail "key max_budget: want 0.05, got $(json info.max_budget <<<"$INFO")"
[ "$(json info.rpm_limit <<<"$INFO")" = 10 ] || fail "key rpm_limit: want 10, got $(json info.rpm_limit <<<"$INFO")"
[ "$(json info.metadata.suite <<<"$INFO")" = e2e ] || fail "key metadata.suite: want e2e, got $(json info.metadata.suite <<<"$INFO")"
# LiteLLM's half. The auth layer answers both requests without inference, so
# they hold while the lab's model backends are asleep. The first shows the key
# is valid, so the refusal can only be about the model. The refusal is judged
# by its status and error type, which LiteLLM keeps stable; its message is not
# (https://github.com/BerriAI/litellm/pull/41310), and no longer tells a
# refused model from a misspelled one.
[ "$(auth_status "$KEY")" = 200 ] || fail "issued key does not authenticate: /v1/models answered $(auth_status "$KEY")"
CODE=$(curl -sS --max-time 30 -o "$SCRATCH/refusal.json" -w '%{http_code}' -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -X POST "$LITELLM_URL/v1/chat/completions" -d '{"model":"granite","max_tokens":4,"messages":[{"role":"user","content":"hi"}]}')
TYPE=$(json error.type <"$SCRATCH/refusal.json")
[ "$CODE" = 403 ] && [ "$TYPE" = key_model_access_denied ] || fail "model outside the role: want 403 key_model_access_denied, got $CODE ${TYPE:-no error type}"
pass "key carries the role's request and is refused models outside it"
if curl -sS --max-time 60 -o "$SCRATCH/chat.json" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -X POST "$LITELLM_URL/v1/chat/completions" -d '{"model":"qwen-a3b","max_tokens":4,"messages":[{"role":"user","content":"Say OK"}]}' \
  && grep -q '"choices"' "$SCRATCH/chat.json"; then
  pass "chat completion with the issued key"
else
  echo "warn: chat completion did not answer within 60s (lab inference backend); auth-layer check above stands"
fi

E0=$(to_epoch "$(key_expires "$KEY")")
"$V" lease renew -increment=12m "$LEASE" >/dev/null
E1=$(to_epoch "$(key_expires "$KEY")")
NOW=$(date +%s)
[ $((E1 - NOW)) -ge 700 ] && [ $((E1 - NOW)) -le 725 ] || fail "renew: LiteLLM expiry $((E1 - NOW))s from now, want ~720s (was $((E0 - NOW))s)"
pass "renew moved LiteLLM expiry to the new lease end"

"$V" lease renew -increment=60m "$LEASE" >/dev/null 2>&1
E2=$(to_epoch "$(key_expires "$KEY")")
[ $((E2 - NOW)) -le 905 ] || fail "renew past max_ttl: LiteLLM expiry $((E2 - NOW))s from now, must not exceed 900s"
pass "renew beyond max_ttl capped at the lease's hard end"

"$V" lease revoke "$LEASE" >/dev/null
sleep 1
# A deleted key answers 404 from /key/info, or, from LiteLLM v1.103.0, a record
# whose info.status is "deleted"
# (https://github.com/BerriAI/litellm/pull/41311). Either way it must also stop
# authenticating: a record that says deleted proves nothing about whether the
# credential still works.
key_gone() {
  local code
  code=$(curl -sS -o "$SCRATCH/info.json" -w '%{http_code}' -H "$MH" "$LITELLM_URL/key/info?key=$(key_hash "$1")")
  [ "$code" = 404 ] && return 0
  [ "$code" = 200 ] && [ "$(json info.status <"$SCRATCH/info.json")" = deleted ]
}
key_gone "$KEY" || fail "key still present after lease revoke: /key/info answered $(key_status "$KEY")"
[ "$(auth_status "$KEY")" = 401 ] || fail "revoked key still authenticates: /v1/models answered $(auth_status "$KEY")"
pass "revoke deleted the key"

"$V" write litellm/roles/short ttl=20s key_request='{"models":["qwen-a3b"]}' >/dev/null
K2=$("$V" read -field=key litellm/creds/short)
[ "$(key_status "$K2")" = 200 ] || fail "short-lived key unknown to LiteLLM"
sleep 35
key_gone "$K2" || fail "key survived its lease expiring"
[ "$(auth_status "$K2")" = 401 ] || fail "expired key still authenticates"
pass "expired lease deleted the key"

# Revoking a lease whose key was already deleted outside Vault is a no-op: the
# engine reads LiteLLM's 404 from /key/delete as "already gone".
read -r K3 L3 < <("$V" read -format=json litellm/creds/e2e | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["data"]["key"],d["lease_id"])')
curl -sS -o /dev/null -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/key/delete" -d "{\"keys\":[\"$(key_hash "$K3")\"]}"
key_gone "$K3" || fail "setup: the key deleted outside Vault is still there"
"$V" lease revoke -sync "$L3" >"$SCRATCH/revoke-gone.txt" 2>&1 || fail "revoking a lease whose key was already deleted failed: $(cat "$SCRATCH/revoke-gone.txt")"
"$V" lease lookup "$L3" >/dev/null 2>&1 && fail "lease survived its revoke"
pass "revoke of a key already deleted outside Vault succeeded"

# The root token has no entity.
"$V" auth enable userpass >/dev/null
ACCESSOR=$("$V" auth list -format=json | python3 -c 'import json,sys;print(json.load(sys.stdin)["userpass/"]["accessor"])')
"$V" write litellm/roles/e2e-stamped ttl=5m key_request='{"models":["qwen-a3b"]}' \
  user_id_template="{{identity.entity.aliases.$ACCESSOR.name}}" >/dev/null
"$V" read litellm/creds/e2e-stamped >"$SCRATCH/root-read.txt" 2>&1 && fail "templated role issued a key to the root token"
grep -q 'no entity' "$SCRATCH/root-read.txt" || fail "unexpected refusal: $(cat "$SCRATCH/root-read.txt")"
printf 'path "litellm/creds/e2e-stamped" { capabilities = ["read"] }\n' | "$V" policy write e2e-person - >/dev/null
"$V" write auth/userpass/users/e2e-person password=e2e-password policies=e2e-person >/dev/null
PERSON_TOKEN=$("$V" login -method=userpass -token-only username=e2e-person password=e2e-password)
VAULT_TOKEN="$PERSON_TOKEN" "$V" read -format=json litellm/creds/e2e-stamped >"$SCRATCH/stamped.json"
read -r SKEYP SLEASE STOKEN < <(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["data"]["key"],d["lease_id"],d["data"]["token_id"])' "$SCRATCH/stamped.json")
[ "$(curl -sS -H "$MH" "$LITELLM_URL/key/info?key=$STOKEN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["info"]["user_id"])')" = e2e-person ] \
  || fail "stamped user_id did not reach LiteLLM"
pass "identity template refused the root token and stamped the userpass alias as user_id"

# Attribution outlives the key and needs no LiteLLM user record; a record
# created afterwards picks the history up.
curl -sS --max-time 90 -o /dev/null -H "Authorization: Bearer $SKEYP" -H 'Content-Type: application/json' \
  -X POST "$LITELLM_URL/v1/chat/completions" -d '{"model":"qwen-a3b","max_tokens":4,"messages":[{"role":"user","content":"hi"}]}'
"$V" lease revoke "$SLEASE" >/dev/null
DAY_FROM=$(date -u -v-1d +%Y-%m-%d 2>/dev/null || date -u -d yesterday +%Y-%m-%d); DAY_TO=$(date -u -v+1d +%Y-%m-%d 2>/dev/null || date -u -d tomorrow +%Y-%m-%d)
ROWS=0; for _ in $(seq 1 12); do
  ROWS=$(curl -sS -H "$MH" "$LITELLM_URL/spend/logs/v2?user_id=e2e-person&start_date=$DAY_FROM&end_date=$DAY_TO" | python3 -c 'import json,sys;print(len(json.load(sys.stdin).get("data",[])))')
  [ "$ROWS" -ge 1 ] && break; sleep 5
done
[ "$ROWS" -ge 1 ] || fail "no spend log rows for the stamped user after the key was revoked"
curl -sS -o /dev/null -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/user/new" -d '{"user_id":"e2e-person","user_role":"internal_user","auto_create_key":false}'
REQS=0; for _ in $(seq 1 24); do
  REQS=$(curl -sS -H "$MH" "$LITELLM_URL/user/daily/activity?user_id=e2e-person&start_date=$DAY_FROM&end_date=$DAY_TO" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("metadata",{}).get("total_api_requests") or 0)')
  [ "$REQS" -ge 1 ] && break; sleep 5
done
[ "$REQS" -ge 1 ] || fail "daily activity did not attach to the user record created after the fact"
curl -sS -o /dev/null -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/user/delete" -d '{"user_ids":["e2e-person"]}'
pass "attribution survived revocation and attached to a user record created afterwards"

SALIAS="vault-e2e-static"
ORIG=$(curl -sS -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/key/generate" \
  -d "{\"key_alias\":\"$SALIAS\",\"duration\":\"10m\"}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["key"])')
if [ "$EDITION" = community ]; then
  "$V" write litellm/static-roles/svc key_alias="$SALIAS" >"$SCRATCH/bind.txt" 2>&1 && fail "static bind succeeded on a community instance"
  grep -q Enterprise "$SCRATCH/bind.txt" || fail "static bind refused for the wrong reason: $(cat "$SCRATCH/bind.txt")"
  "$V" read litellm/static-roles/svc >/dev/null 2>&1 && fail "static role stored despite the refused bind"
  [ "$(auth_status "$ORIG")" = 200 ] || fail "pre-existing key harmed by the refused bind"
  curl -sS -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/key/delete" -d "{\"key_aliases\":[\"$SALIAS\"]}" >/dev/null
  pass "community: static bind refused with LiteLLM's licence error, nothing stored, key untouched"
else
  "$V" write litellm/static-roles/svc key_alias="$SALIAS" 2>&1 | grep -q 'regenerated' || fail "bind gave no regeneration warning"
  [ "$(auth_status "$ORIG")" = 401 ] || fail "original key still authenticates after bind"
  SKEY=$("$V" read -field=key litellm/static-creds/svc)
  [ "$(auth_status "$SKEY")" = 200 ] || fail "static-creds key does not authenticate"
  [ "$("$V" read -field=key litellm/static-creds/svc)" = "$SKEY" ] || fail "second static-creds read changed the key"
  pass "static role bound: Vault holds the regenerated key, the original is dead"
  "$V" write -f litellm/rotate-role/svc >/dev/null
  SKEY2=$("$V" read -field=key litellm/static-creds/svc)
  [ "$(auth_status "$SKEY")" = 401 ] && [ "$(auth_status "$SKEY2")" = 200 ] || fail "rotate-role did not swap the live key"
  pass "rotate-role regenerated the static key"
  "$V" delete litellm/static-roles/svc >/dev/null
  [ "$(key_status "$SKEY2")" = 200 ] || fail "deleting the static role removed the key from LiteLLM"
  curl -sS -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/key/delete" -d "{\"key_aliases\":[\"$SALIAS\"]}" >/dev/null
  pass "static role deleted, key left in LiteLLM until removed by hand"
fi

remove_admin_identity
LEFT=$(curl -sS -H "$MH" "$LITELLM_URL/key/list?key_alias=vault-e2e-&substring_matching=true" | python3 -c 'import json,sys;print(json.load(sys.stdin)["total_count"])')
[ "$LEFT" = 0 ] || fail "$LEFT vault-e2e-* keys left in LiteLLM"
! grep -qE '\[ERROR\]|panic' "$SCRATCH/vault.log" || fail "vault logged errors: $(grep -E '\[ERROR\]|panic' "$SCRATCH/vault.log" | head -3)"
echo "E2E PASSED"
