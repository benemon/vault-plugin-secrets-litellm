#!/usr/bin/env bash
# Builds the plugin, starts a Vault dev server with it registered and mounted
# at litellm/, and keeps the server in the foreground until interrupted.
# VAULT_BIN selects the server binary (the community build lives in bin/vault
# when the PATH vault is Enterprise and unlicensed).
set -e

PLUGIN_NAME="vault-plugin-secrets-litellm"
PLUGIN_CATALOG_NAME="litellm"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="$DIR/scripts/tmp"
mkdir -p "$SCRATCH/plugins"

export VAULT_DEV_ROOT_TOKEN_ID="root"
export VAULT_ADDR="http://127.0.0.1:8200"

echo "--> Building"
go build -o "$SCRATCH/plugins/$PLUGIN_NAME" "$DIR/cmd/$PLUGIN_NAME"
SHASUM=$(shasum -a 256 "$SCRATCH/plugins/$PLUGIN_NAME" | cut -d " " -f1)

echo "--> Starting Vault"
"${VAULT_BIN:-vault}" server \
  -dev \
  -dev-root-token-id=root \
  -dev-plugin-dir="$SCRATCH/plugins" \
  -log-level="${VAULT_LOG_LEVEL:-info}" \
  &
VAULT_PID=$!

cleanup() {
  echo "==> Cleaning up"
  kill -INT "$VAULT_PID"
  wait "$VAULT_PID"
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

for _ in $(seq 1 20); do vault status >/dev/null 2>&1 && break; sleep 0.5; done
vault login root >/dev/null

echo "--> Registering plugin"
vault plugin register -sha256="$SHASUM" -command="$PLUGIN_NAME" secret "$PLUGIN_CATALOG_NAME"

echo "--> Mounting at $PLUGIN_CATALOG_NAME/"
vault secrets enable -path="$PLUGIN_CATALOG_NAME" "$PLUGIN_CATALOG_NAME"

echo "==> Ready: VAULT_ADDR=$VAULT_ADDR VAULT_TOKEN=root"
wait "$VAULT_PID"
