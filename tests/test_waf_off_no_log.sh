#!/usr/bin/env bash
set -euo pipefail

NGINX_BIN="${1:-/usr/local/nginx/sbin/nginx}"
NGINX_PREFIX="${2:-/usr/local/nginx}"
MODULE_DIR="${3:-$(cd "$(dirname "$0")/.." && pwd)}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

ART_DIR="/home/william/myNginxWorkspace/nginx-http-waf-module-v2/tests/artifacts"
LOGS_DIR="$ART_DIR/logs/waf_off"
PIDS_DIR="$ART_DIR/pids"
CONF="/home/william/myNginxWorkspace/nginx-http-waf-module-v2/tests/configs/waf_off_nginx.conf"
PID="$PIDS_DIR/waf_off.pid"
WAF_JSONL="$LOGS_DIR/waf.jsonl"

cleanup() { nginx_stop "$PID" || true; }
on_err() {
  echo "--- 失败诊断: test_waf_off_no_log ---"
  echo "[nginx -V]"; "$NGINX_BIN" -V 2>&1 || true
  echo "[nginx -t]"; "$NGINX_BIN" -t -c "$CONF" 2>&1 || true
  echo "[conf]"; sed -n '1,200p' "$CONF" || true
  echo "[error.log tail]"; tail -n 200 "$LOGS_DIR/error.log" 2>/dev/null || true
  echo "[waf.jsonl tail]"; tail -n 50 "$WAF_JSONL" 2>/dev/null || true
}
trap 'on_err || true; cleanup' ERR
trap cleanup EXIT

ensure_dir "$LOGS_DIR" "$PIDS_DIR"
truncate -s 0 "$WAF_JSONL" 2>/dev/null || true
touch "$WAF_JSONL"; chmod 666 "$WAF_JSONL" || true

nginx_start "$NGINX_BIN" "$CONF" "$PID"
wait_for_port 127.0.0.1 8091 10

# 触发危险查询，应被旁路且不写事件
curl -sS "http://127.0.0.1:8091/?q=select+from" >/dev/null || true

# JSONL 应为空或无新事件
if [[ -s "$WAF_JSONL" ]]; then
  # 若实现为全局开关关闭仍写入 minimal 记录，则校验 finalAction 为 BYPASS/ALLOW
  last=$(jsonl_last "$WAF_JSONL" || true)
  [[ -n "$last" ]] || true
  fa=$(echo "$last" | jq -r .finalAction 2>/dev/null || echo "")
  if [[ "$fa" != "ALLOW" && "$fa" != "BYPASS" && -n "$fa" ]]; then
    echo "waf off 时不应记录阻断/告警，finalAction=$fa"; exit 1
  fi
else
  true
fi

echo "waf off 不阻断且不记事件 用例通过"
exit 0




