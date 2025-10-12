#!/usr/bin/env bash
set -euo pipefail

NGINX_BIN="${1:-/usr/local/nginx/sbin/nginx}"
NGINX_PREFIX="${2:-/usr/local/nginx}"
MODULE_DIR="${3:-$(cd "$(dirname "$0")/.." && pwd)}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

ART_DIR="/home/william/myNginxWorkspace/nginx-http-waf-module-v2/tests/artifacts"
LOGS_DIR="$ART_DIR/logs/smoke"
PIDS_DIR="$ART_DIR/pids"
CONF="/home/william/myNginxWorkspace/nginx-http-waf-module-v2/tests/configs/smoke_nginx.conf"
PID="$PIDS_DIR/smoke.pid"
WAF_JSONL="$LOGS_DIR/waf.jsonl"

# 选择动态模块路径：优先使用已安装模块
MODULE_SO="$NGINX_PREFIX/modules/ngx_http_waf_module.so"
if [[ ! -f "$MODULE_SO" ]]; then
  MODULE_SO="$MODULE_DIR/objs/ngx_http_waf_module.so"
fi

cleanup() { nginx_stop "$PID" || true; }
on_err() {
  echo "--- 失败诊断: test_smoke_basic ---"
  echo "[nginx -V]"; "$NGINX_BIN" -V 2>&1 || true
  echo "[nginx -t]"; "$NGINX_BIN" -t -c "$CONF" 2>&1 || true
  echo "[conf]"; sed -n '1,200p' "$CONF" || true
  echo "[error.log tail]"; tail -n 200 "$LOGS_DIR/error.log" 2>/dev/null || true
  echo "[waf.jsonl tail]"; tail -n 50 "$WAF_JSONL" 2>/dev/null || true
}
trap 'on_err || true; cleanup' ERR
trap cleanup EXIT

ensure_dir "$LOGS_DIR" "$PIDS_DIR"
touch "$WAF_JSONL"
chmod 666 "$WAF_JSONL" || true

nginx_start "$NGINX_BIN" "$CONF" "$PID"
wait_for_port 127.0.0.1 8085 10

# 1) 健康检查旁路
resp=$(http_get "http://127.0.0.1:8085/health") || true

# 2) 规则触发：RCE 正则
set +e
code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8085/api?x=eval(")
set -e
if [[ "$code" != "403" ]]; then
  echo "期望 403，实际 $code"; exit 1
fi

# 校验 JSONL 基本字段
last=$(jsonl_last "$WAF_JSONL" || true)
[[ -n "$last" ]] || { echo "未生成 JSONL"; exit 1; }

echo "$last" | jq . >/dev/null 2>&1 || { echo "JSONL 非法"; exit 1; }

echo "smoke 基础校验通过"
exit 0


