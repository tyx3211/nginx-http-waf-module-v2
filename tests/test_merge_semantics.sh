#!/usr/bin/env bash
set -euo pipefail

NGINX_BIN="${1:-/usr/local/nginx/sbin/nginx}"
NGINX_PREFIX="${2:-/usr/local/nginx}"
MODULE_DIR="${3:-$(cd "$(dirname "$0")/.." && pwd)}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

ART_DIR="/home/william/myNginxWorkspace/nginx-http-waf-module-v2/tests/artifacts"
LOGS_DIR="$ART_DIR/logs/merge_semantics"
PIDS_DIR="$ART_DIR/pids"
CONF="/home/william/myNginxWorkspace/nginx-http-waf-module-v2/tests/configs/merge_semantics_nginx.conf"
PID="$PIDS_DIR/merge_semantics.pid"
WAF_JSONL="$LOGS_DIR/waf.jsonl"

# 优先已安装模块
MODULE_SO="$NGINX_PREFIX/modules/ngx_http_waf_module.so"
if [[ ! -f "$MODULE_SO" ]]; then
  MODULE_SO="$MODULE_DIR/objs/ngx_http_waf_module.so"
fi

cleanup() { nginx_stop "$PID" || true; }
on_err() {
  echo "--- 失败诊断: test_merge_semantics ---"
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
wait_for_port 127.0.0.1 8090 10

# 触发父集规则 id=800001（groupA，父为 ALL_PARAMS，经重写应为 URI），请求参数包含 "evil" 但 URI 不含，重写到 URI 后不应命中 -> 不应被 403 阻断
code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8090/?x=evil")
if [[ "$code" == "403" ]]; then echo "URI 重写后不应阻断，仍得到403"; exit 1; fi

# 命中本地规则 800004：/local 精确匹配，应 403
code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8090/local")
if [[ "$code" != "403" ]]; then echo "/local 期望403 实际 $code"; exit 1; fi

# 800002（header 标记）应被 disableByTag 移除，带头也不应403
code=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Test: forbidden" "http://127.0.0.1:8090/")
if [[ "$code" == "403" ]]; then echo "disableByTag 未生效，出现403"; exit 1; fi

# 重复规则 800003：父为 DENY，本地 LOG；duplicatePolicy=warn_keep_last -> 以最后为准，访问 /old 不应403
code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8090/old")
if [[ "$code" == "403" ]]; then echo "keep_last 预期覆盖为 LOG，但仍403"; exit 1; fi

# 基本 JSONL 校验
last=$(jsonl_last "$WAF_JSONL" || true)
[[ -n "$last" ]] || { echo "未生成 JSONL"; exit 1; }
echo "$last" | jq -r .finalAction >/dev/null 2>&1 || { echo "JSONL 非法"; exit 1; }

echo "合并/继承/禁用/去重 语义用例通过"
exit 0


