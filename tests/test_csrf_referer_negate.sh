#!/usr/bin/env bash
set -euo pipefail

NGINX_BIN="${1:-/usr/local/nginx/sbin/nginx}"
NGINX_PREFIX="${2:-/usr/local/nginx}"
MODULE_DIR="${3:-$(cd "$(dirname "$0")/.." && pwd)}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

ART_DIR="/home/william/myNginxWorkspace/nginx-http-waf-module-v2/tests/artifacts"

CONF_BLOCK="/home/william/myNginxWorkspace/nginx-http-waf-module-v2/tests/configs/referer_csrf_block_nginx.conf"
CONF_LOG="/home/william/myNginxWorkspace/nginx-http-waf-module-v2/tests/configs/referer_csrf_log_nginx.conf"
LOGS_BLOCK_DIR="$ART_DIR/logs/referer_csrf_block"
LOGS_LOG_DIR="$ART_DIR/logs/referer_csrf_log"
PIDS_DIR="$ART_DIR/pids"
PID_BLOCK="$PIDS_DIR/referer_csrf_block.pid"
PID_LOG="$PIDS_DIR/referer_csrf_log.pid"
WAF_JSONL_BLOCK="$LOGS_BLOCK_DIR/waf.jsonl"
WAF_JSONL_LOG="$LOGS_LOG_DIR/waf.jsonl"

cleanup() {
  nginx_stop "$PID_BLOCK" || true
  nginx_stop "$PID_LOG" || true
}

on_err() {
  echo "--- 失败诊断: test_csrf_referer_negate ---"
  echo "[nginx -V]"; "$NGINX_BIN" -V 2>&1 || true
  echo "[nginx -t block]"; "$NGINX_BIN" -t -c "$CONF_BLOCK" 2>&1 || true
  echo "[nginx -t log]"; "$NGINX_BIN" -t -c "$CONF_LOG" 2>&1 || true
  echo "[conf block]"; sed -n '1,220p' "$CONF_BLOCK" || true
  echo "[conf log]"; sed -n '1,220p' "$CONF_LOG" || true
  echo "[error.log block tail]"; tail -n 200 "$LOGS_BLOCK_DIR/error.log" 2>/dev/null || true
  echo "[error.log log tail]"; tail -n 200 "$LOGS_LOG_DIR/error.log" 2>/dev/null || true
  echo "[waf.jsonl block tail]"; tail -n 50 "$WAF_JSONL_BLOCK" 2>/dev/null || true
  echo "[waf.jsonl log tail]"; tail -n 50 "$WAF_JSONL_LOG" 2>/dev/null || true
}
trap 'on_err || true; cleanup' ERR
trap cleanup EXIT

ensure_dir "$LOGS_BLOCK_DIR" "$LOGS_LOG_DIR" "$PIDS_DIR"
truncate -s 0 "$WAF_JSONL_BLOCK" 2>/dev/null || true
truncate -s 0 "$WAF_JSONL_LOG" 2>/dev/null || true
touch "$WAF_JSONL_BLOCK" "$WAF_JSONL_LOG"; chmod 666 "$WAF_JSONL_BLOCK" "$WAF_JSONL_LOG" || true

# 启动 BLOCK 实例
nginx_start "$NGINX_BIN" "$CONF_BLOCK" "$PID_BLOCK"
wait_for_port 127.0.0.1 8096 10

# 启动 LOG 实例
nginx_start "$NGINX_BIN" "$CONF_LOG" "$PID_LOG"
wait_for_port 127.0.0.1 8097 10

# 1) 无 Referer：允许（命中 ^$，再被 negate 取反，不拦截）
code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8096/")
if [[ "$code" == "403" ]]; then echo "无 Referer 在 BLOCK 模式不应拦截"; exit 1; fi

# 2) 白名单域：允许
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Referer: https://sub.test.my.com/path" "http://127.0.0.1:8096/")
if [[ "$code" == "403" ]]; then echo "白名单 Referer 在 BLOCK 模式不应拦截"; exit 1; fi

# 3) 非白名单域：应 403（BLOCK 模式）
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Referer: https://evil.example/" "http://127.0.0.1:8096/")
if [[ "$code" != "403" ]]; then echo "非白名单 Referer 在 BLOCK 模式应被拦截"; exit 1; fi

# 4) LOG 模式：非白名单域返回 200/2xx 且应有 JSONL 事件，finalAction=ALLOW
curl -sS -H "Referer: https://evil.example/" "http://127.0.0.1:8097/" >/dev/null || true
last=""
for _ in {1..40}; do
  last=$(jsonl_last "$WAF_JSONL_LOG" || true)
  [[ -n "$last" ]] && break
  sleep 0.1
done
[[ -n "$last" ]] || { echo "LOG 模式未生成 JSONL"; exit 1; }
fa=$(echo "$last" | jq -r .finalAction 2>/dev/null || echo "")
if [[ "$fa" != "ALLOW" && "$fa" != "BYPASS" ]]; then
  echo "LOG 模式期望 finalAction=ALLOW/BYPASS 实际 $fa"; exit 1
fi

echo "CSRF Referer negate 用例通过"
exit 0




