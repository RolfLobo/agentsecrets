#!/bin/bash
# scripts/sign.sh
set -e

# If the private key is not set, print a warning and skip signing (e.g. for snapshots / local builds)
if [ -z "$DEV_PRIVATE_KEY" ]; then
  echo "Warning: DEV_PRIVATE_KEY environment variable is empty. Skipping binary signing."
  exit 0
fi

BINARY_PATH="$1"
if [ -z "$BINARY_PATH" ]; then
  echo "Error: No binary path specified for signing."
  exit 1
fi

echo "Signing binary: ${BINARY_PATH}"

# Write private key to a temporary file, preserving newlines
TMP_KEY=$(mktemp)
echo "$DEV_PRIVATE_KEY" > "$TMP_KEY"

# Generate signature (64 bytes)
TMP_SIG=$(mktemp)
openssl pkeyutl -sign -inkey "$TMP_KEY" -rawin -in "$BINARY_PATH" -out "$TMP_SIG"

# Append signature and KCAS magic bytes
cat "$BINARY_PATH" "$TMP_SIG" <(echo -n "KCAS") > "${BINARY_PATH}.signed"
mv "${BINARY_PATH}.signed" "$BINARY_PATH"

# Cleanup
rm -f "$TMP_KEY" "$TMP_SIG"

echo "✓ Successfully signed ${BINARY_PATH} with Ed25519 key."
