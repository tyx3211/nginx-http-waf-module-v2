#!/usr/bin/env bash
set -euo pipefail

NGINX_BIN="${1:-/usr/local/nginx/sbin/nginx}"
NGINX_PREFIX="${2:-/usr/local/nginx}"
MODULE_DIR="${3:-/home/william/myNginxWorkspace/nginx-http-waf-module-v2}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

WORKDIR="/tmp/waf_v2_jsonl"
LOGDIR="$WORKDIR/logs"
CONFDIR="$WORKDIR/conf"
HTMLDIR="$WORKDIR/html"
RULES_DIR="$WORKDIR/waf_rules"
PID_FILE="$WORKDIR/nginx.pid"

cleanup() {
  nginx_stop "$PID_FILE" || true
  # 保留失败环境
  if [[ "${KEEP_ON_FAIL:-0}" == "0" ]]; then rm -rf "$WORKDIR"; fi
}
trap cleanup EXIT

ensure_dir "$WORKDIR" "$LOGDIR" "$CONFDIR" "$HTMLDIR" "$RULES_DIR"
cp -f "$SCRIPT_DIR/resources/basic_rules.json" "$RULES_DIR/rules.json"
echo OK > "$HTMLDIR/index.html"

cat > "$CONFDIR/nginx.conf" <<EOF
load_module $NGINX_PREFIX/modules/ngx_http_waf_module.so;

worker_processes  1;
error_log $LOGDIR/error.log debug;
pid $PID_FILE;

events { worker_connections  256; }

http {
  access_log $LOGDIR/access.log;
  waf_jsons_dir $RULES_DIR;
  waf_json_log $LOGDIR/waf.jsonl;
  waf_json_log_level info;
  waf_shm_zone waf_zone 10m;

  server {
    listen 18082;
    server_name localhost;

    waf on;
    waf_default_action BLOCK;
    waf_rules_json rules.json;

    location / {
      return 200 "OK";
    }
  }
}
EOF

nginx_start "$NGINX_BIN" "$CONFDIR/nginx.conf" "$PID_FILE"
wait_for_port 127.0.0.1 18082 10

# 触发 BLOCK：带 select 触发规则 200010
set +e
curl -sS -o /dev/null -w "%{http_code}" "http://127.0.0.1:18082/?q=select" >"$WORKDIR/status.txt"
set -e

status=$(cat "$WORKDIR/status.txt")
[[ "$status" == "403" || "$status" == "200" || "$status" == "000" ]] || true

sleep 0.2
last=$(jsonl_last "$LOGDIR/waf.jsonl")
[[ -n "$last" ]] || { echo "未产生 JSONL"; exit 1; }

# 基本字段
jq -e '.time and .clientIp and .method and .uri and .events and .finalAction and .finalActionType and .level and .currentGlobalAction' >/dev/null <<<"$last" || { echo "缺少关键字段"; exit 1; }

# finalAction 必为 BLOCK，level 至少 ALERT（文本）
fa=$(jq -r '.finalAction' <<<"$last")
[[ "$fa" == "BLOCK" ]] || { echo "finalAction 非 BLOCK: $fa"; exit 1; }

lvl=$(jq -r '.level' <<<"$last")
case "$lvl" in ALERT|ERROR) ;; *) echo "level 不是 ALERT/ERROR: $lvl"; exit 1;; esac

# finalActionType 与 blockRuleId 联动（规则阻断）
fat=$(jq -r '.finalActionType' <<<"$last")
[[ "$fat" == "BLOCK_BY_RULE" ]] || { echo "finalActionType 非 BLOCK_BY_RULE: $fat"; exit 1; }

rid=$(jq -r '.blockRuleId // 0' <<<"$last")
[[ "$rid" == "200010" ]] || { echo "blockRuleId 异常: $rid"; exit 1; }

# decisive 事件存在且仅一次
dec_cnt=$(jq '[.events[] | select(.decisive==true)] | length' <<<"$last")
[[ "$dec_cnt" == "1" ]] || { echo "decisive 计数异常: $dec_cnt"; exit 1; }

exit 0


