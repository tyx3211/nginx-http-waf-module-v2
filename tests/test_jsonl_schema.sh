#!/usr/bin/env bash
set -euo pipefail

NGINX_BIN="${1:-/usr/local/nginx/sbin/nginx}"
NGINX_PREFIX="${2:-/usr/local/nginx}"
MODULE_DIR="${3:-$(cd "$(dirname "$0")/.." && pwd)}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

ART_DIR="/home/william/myNginxWorkspace/nginx-http-waf-module-v2/tests/artifacts"
LOGS_DIR="$ART_DIR/logs/jsonl_schema"
PIDS_DIR="$ART_DIR/pids"
CONF="/home/william/myNginxWorkspace/nginx-http-waf-module-v2/tests/configs/jsonl_schema_nginx.conf"
PID="$PIDS_DIR/jsonl_schema.pid"
WAF_JSONL="$LOGS_DIR/waf.jsonl"

MODULE_SO="$NGINX_PREFIX/modules/ngx_http_waf_module.so"
if [[ ! -f "$MODULE_SO" ]]; then
  MODULE_SO="$MODULE_DIR/objs/ngx_http_waf_module.so"
fi

cleanup() { nginx_stop "$PID" || true; }
on_err() {
  echo "--- 失败诊断: test_jsonl_schema ---"
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
wait_for_port 127.0.0.1 8088 10

# 触发 BLOCK_BY_RULE
curl -sS "http://127.0.0.1:8088/api?x=eval(" >/dev/null || true

last=$(jsonl_last "$WAF_JSONL" || true)
[[ -n "$last" ]] || { echo "未生成 JSONL"; exit 1; }

# 必备字段与取值校验
echo "$last" | jq -e '.time and .clientIp and .method and .uri and .events and .finalAction and .finalActionType and .currentGlobalAction and .level' >/dev/null

fa=$(echo "$last" | jq -r .finalAction)
fat=$(echo "$last" | jq -r .finalActionType)
lvl=$(echo "$last" | jq -r .level)

if [[ "$fa" != "BLOCK" ]]; then echo "finalAction 期望 BLOCK 实际 $fa"; exit 1; fi
echo "$fat" | grep -E '^BLOCK_BY_(RULE|REPUTATION|DYNAMIC_BLOCK)$' >/dev/null || { echo "finalActionType 不符合 $fat"; exit 1; }
echo "$lvl" | grep -E '^(ALERT|ERROR|INFO|DEBUG)$' >/dev/null || { echo "level 非法 $lvl"; exit 1; }

# 事件数组至少含有 reputation 或 rule
ev_types=$(echo "$last" | jq -r '.events[].type' | sort | uniq | tr '\n' ' ')
echo "$ev_types" | grep -E '(rule|reputation)' >/dev/null || { echo "events 未包含 rule/reputation: $ev_types"; exit 1; }

# 若为 RULE 阻断则应含 blockRuleId
if [[ "$fat" == "BLOCK_BY_RULE" ]]; then
  echo "$last" | jq -e '.blockRuleId' >/dev/null || { echo "缺少 blockRuleId"; exit 1; }
fi

echo "JSONL schema 校验通过"
exit 0



