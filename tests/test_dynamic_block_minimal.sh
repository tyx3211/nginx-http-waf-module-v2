#!/usr/bin/env bash
set -euo pipefail

NGINX_BIN="${1:-/usr/local/nginx/sbin/nginx}"
NGINX_PREFIX="${2:-/usr/local/nginx}"
MODULE_DIR="${3:-$(cd "$(dirname "$0")/.." && pwd)}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

ART_DIR="/home/william/myNginxWorkspace/nginx-http-waf-module-v2/tests/artifacts"
LOGS_DIR="$ART_DIR/logs/dyn_minimal"
PIDS_DIR="$ART_DIR/pids"
CONF="/home/william/myNginxWorkspace/nginx-http-waf-module-v2/tests/configs/dyn_minimal_nginx.conf"
PID="$PIDS_DIR/dyn_minimal.pid"
WAF_JSONL="$LOGS_DIR/waf.jsonl"

# 选择动态模块路径：优先使用已安装模块
MODULE_SO="$NGINX_PREFIX/modules/ngx_http_waf_module.so"
if [[ ! -f "$MODULE_SO" ]]; then
  MODULE_SO="$MODULE_DIR/objs/ngx_http_waf_module.so"
fi

cleanup() { nginx_stop "$PID" || true; }
on_err() {
  echo "--- 失败诊断: test_dynamic_block_minimal ---"
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
wait_for_port 127.0.0.1 8086 10

# 连续触发高分规则，累计计分应进入封禁
for i in {1..3}; do
  curl -sS "http://127.0.0.1:8086/?q=select+from" >/dev/null || true
  sleep 0.2
done

# 再次访问，应被 403（若已达到阈值）。阈值当前实现默认 100，规则 70 + base 2*多次应跨阈值
set +e
code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8086/?q=ping")
set -e

if [[ "$code" != "403" ]]; then
  echo "动态封禁未生效，期望403 实际 $code"; exit 1
fi

last=$(jsonl_last "$WAF_JSONL" || true)
[[ -n "$last" ]] || { echo "未生成 JSONL"; exit 1; }
echo "$last" | jq -r .finalActionType | grep -E '^BLOCK_BY_(RULE|REPUTATION|DYNAMIC_BLOCK)$' >/dev/null || {
  echo "finalActionType 不符合预期：$last"; exit 1;
}

echo "动态封禁最小用例通过"
exit 0


