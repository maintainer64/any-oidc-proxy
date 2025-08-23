#!/bin/sh
set -e

# Display version information
VERSION=$(/app/any-oidc-proxy -version 2>/dev/null || echo "unknown")
echo "Starting any-oidc-proxy ${VERSION}"

# Wait for dependencies if needed (optional)
if [ -n "${PROXY_URL}" ]; then
  echo "Waiting for upstream: ${PROXY_URL}"
  # You can add wait-for-it.sh or similar script here
  # ./wait-for-it.sh ${PROXY_URL} --timeout=30
fi

# Run the application
exec /app/any-oidc-proxy
