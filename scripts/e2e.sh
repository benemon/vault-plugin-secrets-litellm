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

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }
key_status() { curl -sS -o /dev/null -w '%{http_code}' -H "$MH" "$LITELLM_URL/key/info?key=$1"; }
key_expires() { curl -sS -H "$MH" "$LITELLM_URL/key/info?key=$1" | python3 -c 'import json,sys;print(json.load(sys.stdin)["info"]["expires"])'; }
auth_status() { curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $1" "$LITELLM_URL/v1/models"; }
to_epoch() { python3 -c 'import sys,datetime;print(int(datetime.datetime.fromisoformat(sys.argv[1].replace("Z","+00:00")).timestamp()))' "$1"; }

mkdir -p "$SCRATCH/plugins"
go build -o "$SCRATCH/plugins/$PLUGIN_NAME" "$DIR/cmd/$PLUGIN_NAME"
"$V" server -dev -dev-root-token-id=root -dev-listen-address="${VAULT_ADDR#http://}" \
  -dev-plugin-dir="$SCRATCH/plugins" -log-level=warn >"$SCRATCH/vault.log" 2>&1 &
VAULT_PID=$!
cleanup() {
  kill -INT "$VAULT_PID" 2>/dev/null; wait "$VAULT_PID" 2>/dev/null || true
  curl -sS -H "$MH" "$LITELLM_URL/key/list?return_full_object=true&user_id=vault-e2e-admin" \
    | python3 -c 'import json,sys;print(" ".join(k["token"] for k in json.load(sys.stdin).get("keys",[])))' 2>/dev/null \
    | xargs -n1 -I{} curl -sS -o /dev/null -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/key/delete" -d '{"keys":["{}"]}'
  curl -sS -o /dev/null -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/user/delete" -d '{"user_ids":["vault-e2e-admin"]}'
  rm -rf "$SCRATCH"
}
trap cleanup EXIT
for _ in $(seq 1 40); do "$V" status >/dev/null 2>&1 && break; sleep 0.5; done

SHASUM=$(shasum -a 256 "$SCRATCH/plugins/$PLUGIN_NAME" | cut -d' ' -f1)
"$V" plugin register -sha256="$SHASUM" -command="$PLUGIN_NAME" secret litellm >/dev/null
"$V" secrets enable -path=litellm litellm >/dev/null

# The documented setup: a proxy_admin user and a virtual key under it, minted
# once with the master key, are what the plugin holds.
ADMIN_USER="vault-e2e-admin"
curl -sS -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/user/new" \
  -d "{\"user_id\":\"$ADMIN_USER\",\"user_role\":\"proxy_admin\"}" >/dev/null
ADMIN_KEY=$(curl -sS -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/key/generate" \
  -d "{\"user_id\":\"$ADMIN_USER\",\"key_alias\":\"e2e-plugin-admin\"}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["key"])')
"$V" write litellm/config url="$LITELLM_URL" admin_key="$ADMIN_KEY" >/dev/null
pass "configured with a proxy_admin virtual key"

"$V" write -f litellm/rotate-root >"$SCRATCH/rotate.txt" 2>&1 || fail "rotate-root failed: $(cat "$SCRATCH/rotate.txt")"
[ "$(auth_status "$ADMIN_KEY")" = 401 ] || fail "previous admin key still authenticates after rotate-root"
"$V" read litellm/config >/dev/null || fail "plugin unusable after rotate-root"
pass "rotate-root replaced the admin key ($(grep -q successor "$SCRATCH/rotate.txt" && echo successor path || echo regenerate path))"

"$V" write litellm/roles/e2e ttl=10m max_ttl=15m \
  key_request='{"models":["qwen-a3b"],"max_budget":0.05,"rpm_limit":10,"metadata":{"suite":"e2e"}}' >/dev/null
"$V" read -format=json litellm/creds/e2e >"$SCRATCH/creds.json"
read -r KEY LEASE < <(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["data"]["key"],d["lease_id"])' "$SCRATCH/creds.json")
[ "$(key_status "$KEY")" = 200 ] || fail "generated key unknown to LiteLLM"
pass "generated key from role (lease $LEASE)"

# The auth layer answers this without inference, so it proves the key works
# even when the lab's model backends are asleep.
OUT=$(curl -sS --max-time 30 -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -X POST "$LITELLM_URL/v1/chat/completions" -d '{"model":"granite","max_tokens":4,"messages":[{"role":"user","content":"hi"}]}')
grep -q 'key not allowed to access model' <<<"$OUT" || fail "model outside role was not rejected: $OUT"
pass "key authenticates and is scoped to the role's models"
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
[ "$(key_status "$KEY")" = 404 ] || fail "key still present after lease revoke"
pass "revoke deleted the key"

"$V" write litellm/roles/short ttl=20s key_request='{"models":["qwen-a3b"]}' >/dev/null
K2=$("$V" read -field=key litellm/creds/short)
[ "$(key_status "$K2")" = 200 ] || fail "short-lived key unknown to LiteLLM"
sleep 35
[ "$(key_status "$K2")" = 404 ] || fail "key survived its lease expiring"
pass "expired lease deleted the key"

SALIAS="vault-e2e-static"
ORIG=$(curl -sS -H "$MH" -H 'Content-Type: application/json' -X POST "$LITELLM_URL/key/generate" \
  -d "{\"key_alias\":\"$SALIAS\",\"duration\":\"10m\"}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["key"])')
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

LEFT=$(curl -sS -H "$MH" "$LITELLM_URL/key/list?key_alias=vault-e2e-&substring_matching=true" | python3 -c 'import json,sys;print(json.load(sys.stdin)["total_count"])')
[ "$LEFT" = 0 ] || fail "$LEFT vault-e2e-* keys left in LiteLLM"
! grep -qE '\[ERROR\]|panic' "$SCRATCH/vault.log" || fail "vault logged errors: $(grep -E '\[ERROR\]|panic' "$SCRATCH/vault.log" | head -3)"
echo "E2E PASSED"
