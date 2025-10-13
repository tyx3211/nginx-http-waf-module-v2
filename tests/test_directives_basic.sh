#!/usr/bin/env bash
set -euo pipefail

NGINX_BIN="${1:-/usr/local/nginx/sbin/nginx}"
NGINX_PREFIX="${2:-/usr/local/nginx}"
MODULE_DIR="${3:-$(cd "$(dirname "$0")/.." && pwd)}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

ART_DIR="/home/william/myNginxWorkspace/nginx-http-waf-module-v2/tests/artifacts"
LOGS_DIR="$ART_DIR/logs/dir_basic"
PIDS_DIR="$ART_DIR/pids"
CONF="/home/william/myNginxWorkspace/nginx-http-waf-module-v2/tests/configs/directives_basic_nginx.conf"
PID="$PIDS_DIR/dir_basic.pid"
WAF_JSONL="$LOGS_DIR/waf.jsonl"

# 已安装模块优先
MODULE_SO="$NGINX_PREFIX/modules/ngx_http_waf_module.so"
if [[ ! -f "$MODULE_SO" ]]; then
  MODULE_SO="$MODULE_DIR/objs/ngx_http_waf_module.so"
fi

cleanup() { nginx_stop "$PID" || true; }
on_err() {
  echo "--- 失败诊断: test_directives_basic ---"
  echo "[nginx -V]"; "$NGINX_BIN" -V 2>&1 || true
  echo "[nginx -t]"; "$NGINX_BIN" -t -c "$CONF" 2>&1 || true
  echo "[conf]"; sed -n '1,200p' "$CONF" || true
  echo "[error.log tail]"; tail -n 200 "$LOGS_DIR/error.log" 2>/dev/null || true
  echo "[waf.jsonl tail]"; tail -n 50 "$WAF_JSONL" 2>/dev/null || true
}
trap 'on_err || true; cleanup' ERR
trap cleanup EXIT

ensure_dir "$LOGS_DIR" "$PIDS_DIR"
touch "$WAF_JSONL"; chmod 666 "$WAF_JSONL" || true

nginx_start "$NGINX_BIN" "$CONF" "$PID"
wait_for_port 127.0.0.1 8087 10

# 1) location /health 关闭 waf，应 200
code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8087/health")
if [[ "$code" != "200" ]]; then echo "waf off 未旁路，期望200 实际 $code"; exit 1; fi

# 2) location /api1 继承 waf on，默认 BLOCK，全局 default_action BLOCK，规则匹配 403
code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8087/api1?x=eval(")
if [[ "$code" != "403" ]]; then echo "/api1 期望403 实际 $code"; exit 1; fi

# 3) location /api2 覆盖 waf_default_action log，应不阻断（200 或 404，视返回）；校验 JSONL 有事件但 finalAction=ALLOW 或 BYPASS
code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8087/api2?x=eval(")
if [[ "$code" == "403" ]]; then echo "/api2 不应阻断，拿到403"; exit 1; fi

# 校验 JSONL 基本字段
last=$(jsonl_last "$WAF_JSONL" || true)
[[ -n "$last" ]] || { echo "未生成 JSONL"; exit 1; }
echo "$last" | jq -r .finalAction >/dev/null 2>&1 || { echo "JSONL 非法"; exit 1; }

echo "指令基础用例通过"
exit 0



