#!/usr/bin/env bash
set -euo pipefail

NGINX_BIN="${1:-/usr/local/nginx/sbin/nginx}"
NGINX_PREFIX="${2:-/usr/local/nginx}"
MODULE_DIR="${3:-$(cd "$(dirname "$0")/.." && pwd)}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

ART_DIR="/home/william/myNginxWorkspace/nginx-http-waf-module-v2/tests/artifacts"
LOGS_DIR="$ART_DIR/logs/default_log"
PIDS_DIR="$ART_DIR/pids"
CONF="/home/william/myNginxWorkspace/nginx-http-waf-module-v2/tests/configs/default_log_nginx.conf"
PID="$PIDS_DIR/default_log.pid"
WAF_JSONL="$LOGS_DIR/waf.jsonl"

cleanup() { nginx_stop "$PID" || true; }
on_err() {
  echo "--- 失败诊断: test_default_action_log ---"
  echo "[nginx -V]"; "$NGINX_BIN" -V 2>&1 || true
  echo "[nginx -t]"; "$NGINX_BIN" -t -c "$CONF" 2>&1 || true
  echo "[conf]"; sed -n '1,220p' "$CONF" || true
  echo "[error.log tail]"; tail -n 200 "$LOGS_DIR/error.log" 2>/dev/null || true
  echo "[waf.jsonl tail]"; tail -n 50 "$WAF_JSONL" 2>/dev/null || true
}
trap 'on_err || true; cleanup' ERR
trap cleanup EXIT

ensure_dir "$LOGS_DIR" "$PIDS_DIR"
truncate -s 0 "$WAF_JSONL" 2>/dev/null || true
touch "$WAF_JSONL"; chmod 666 "$WAF_JSONL" || true

nginx_start "$NGINX_BIN" "$CONF" "$PID"
wait_for_port 127.0.0.1 8092 10

# 触发规则但由于 default_action=log，不应 403；同时应写 JSONL 事件且 finalAction=ALLOW/BYPASS
# comprehensive_rules.json 中 sqli 规则匹配 "union.*select"，使用该 payload 确保命中
code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8092/?x=union+select+1,2")
if [[ "$code" == "403" ]]; then echo "default_action=log 时不应阻断"; exit 1; fi

last=""
for _ in {1..20}; do
  last=$(jsonl_last "$WAF_JSONL" || true)
  [[ -n "$last" ]] && break
  sleep 0.1
done
[[ -n "$last" ]] || { echo "未生成 JSONL"; exit 1; }
fa=$(echo "$last" | jq -r .finalAction 2>/dev/null || echo "")
if [[ "$fa" != "ALLOW" && "$fa" != "BYPASS" ]]; then
  echo "default_action=log 期望 ALLOW/BYPASS 实际 $fa"; exit 1
fi

echo "default_action log 用例通过"
exit 0



