#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# STUB: Helper to generate compile_commands.json for clangd via a dynamic module build.

WORKSPACE="${WORKSPACE:-/home/william/myNginxWorkspace}"
NGINX_SRC_ROOT="${NGINX_SRC_ROOT:-$WORKSPACE/nginx-src}"
NGINX_INSTALL_ROOT="${NGINX_INSTALL_ROOT:-$WORKSPACE/nginx-install}"
MODULE_DIR="$WORKSPACE/nginx-http-waf-module-v2"

command -v bear >/dev/null 2>&1 || {
  echo "[setup-clangd] ERROR: bear not found. Please install 'bear' first." >&2
  exit 1
}

cd "$NGINX_SRC_ROOT"
if [ ! -f configure ]; then
  echo "[setup-clangd] ERROR: '$NGINX_SRC_ROOT' does not look like an nginx source tree (missing 'configure')." >&2
  exit 1
fi

echo "[setup-clangd] Configuring nginx with dynamic module from $MODULE_DIR ..."
./configure \
  --prefix="$NGINX_INSTALL_ROOT" \
  --with-debug \
  --with-compat \
  --add-dynamic-module="$MODULE_DIR"

echo "[setup-clangd] Building modules and generating compile_commands.json ..."
bear -- make modules -j"$(nproc)"

ln -sf "$NGINX_SRC_ROOT/compile_commands.json" "$MODULE_DIR/"
echo "[setup-clangd] Done. Linked: $MODULE_DIR/compile_commands.json"


