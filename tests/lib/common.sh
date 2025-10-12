#!/usr/bin/env bash
set -euo pipefail

# 颜色与日志
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_error "缺少依赖命令: $cmd"
    return 1
  fi
}

ensure_dir() {
  mkdir -p "$@"
}

wait_for_port() {
  local host="$1" port="$2" timeout_sec="${3:-10}"
  local start_ts now
  start_ts=$(date +%s)
  while true; do
    if (echo > /dev/tcp/"$host"/"$port") >/dev/null 2>&1; then
      return 0
    fi
    now=$(date +%s)
    if (( now - start_ts >= timeout_sec )); then
      return 1
    fi
    sleep 0.1
  done
}

nginx_start() {
  local nginx_bin="$1" conf_path="$2" pid_file="$3"
  "$nginx_bin" -c "$conf_path" -g "daemon on; master_process on;" >/dev/null 2>&1 || return 1
  for _ in {1..50}; do
    if [[ -f "$pid_file" ]]; then return 0; fi
    sleep 0.1
  done
  return 1
}

nginx_stop() {
  local pid_file="$1"
  if [[ -f "$pid_file" ]]; then
    local pid
    pid=$(cat "$pid_file" 2>/dev/null || echo "")
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      for _ in {1..50}; do
        if ! kill -0 "$pid" 2>/dev/null; then return 0; fi
        sleep 0.1
      done
      return 1
    fi
  fi
  return 0
}

http_get() {
  local url="$1"; shift
  curl -sS -m 5 "$url" "$@"
}

jsonl_last() {
  local file="$1"
  tail -n 1 -- "$file"
}

assert_jq() {
  local jsonl_line="$1" jq_filter="$2" expect="$3"
  local got
  got=$(printf '%s' "$jsonl_line" | jq -r "$jq_filter" 2>/dev/null || echo "__JQ_ERR__")
  if [[ "$got" == "__JQ_ERR__" ]]; then
    echo "JQ_PARSE_ERROR"
    return 1
  fi
  if [[ "$got" != "$expect" ]]; then
    echo "EXPECT_FAIL got=$got expect=$expect"
    return 1
  fi
  echo "OK"
}


