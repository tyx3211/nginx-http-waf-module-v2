#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# STUB: Helper to generate compile_commands.json for clangd via a dynamic module build.

WORKSPACE="${WORKSPACE:-/home/william/myNginxWorkspace}"
NGINX_VERSION="${NGINX_VERSION:-1.24.0}"
NGINX_SRC_ROOT="$WORKSPACE/nginx-src"
NGINX_DIR="$NGINX_SRC_ROOT/nginx-$NGINX_VERSION"
MODULE_DIR="$WORKSPACE/nginx-http-waf-module-v2"

command -v bear >/dev/null 2>&1 || {
  echo "[setup-clangd] ERROR: bear not found. Please install 'bear' first." >&2
  exit 1
}

if command -v curl >/dev/null 2>&1; then
  DOWNLOADER="curl -fL -o"
elif command -v wget >/dev/null 2>&1; then
  DOWNLOADER="wget -O"
else
  echo "[setup-clangd] ERROR: neither curl nor wget is available for downloading nginx." >&2
  exit 1
fi

mkdir -p "$NGINX_SRC_ROOT"
cd "$NGINX_SRC_ROOT"

if [ ! -d "$NGINX_DIR" ]; then
  TARBALL="nginx-$NGINX_VERSION.tar.gz"
  if [ ! -f "$TARBALL" ]; then
    echo "[setup-clangd] Downloading nginx-$NGINX_VERSION ..."
    sh -c "$DOWNLOADER $TARBALL http://nginx.org/download/nginx-$NGINX_VERSION.tar.gz"
  fi
  tar -zxf "$TARBALL"
fi

cd "$NGINX_DIR"
echo "[setup-clangd] Configuring nginx with dynamic module from $MODULE_DIR ..."
./configure \
  --prefix=/usr/local/nginx \
  --with-debug \
  --with-compat \
  --add-dynamic-module="$MODULE_DIR"

echo "[setup-clangd] Building modules and generating compile_commands.json ..."
bear -- make modules -j"$(nproc)"

ln -sf "$NGINX_DIR/compile_commands.json" "$MODULE_DIR/"
echo "[setup-clangd] Done. Linked: $MODULE_DIR/compile_commands.json"


