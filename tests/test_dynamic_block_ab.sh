#!/usr/bin/env bash
set -euo pipefail

NGINX_BIN="${1:-/usr/local/nginx/sbin/nginx}"
NGINX_PREFIX="${2:-/usr/local/nginx}"
MODULE_DIR="${3:-/home/william/myNginxWorkspace/nginx-http-waf-module-v2}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

WORKDIR="/tmp/waf_v2_dyn"
LOGDIR="$WORKDIR/logs"
CONFDIR="$WORKDIR/conf"
PID_FILE="$WORKDIR/nginx.pid"
RULES_DIR="$WORKDIR/waf_rules"

cleanup() {
  nginx_stop "$PID_FILE" || true
  if [[ "${KEEP_ON_FAIL:-0}" == "0" ]]; then rm -rf "$WORKDIR"; fi
}
trap cleanup EXIT

ensure_dir "$WORKDIR" "$LOGDIR" "$CONFDIR" "$RULES_DIR"

cat > "$RULES_DIR/rules.json" <<'EOF'
{
  "version": 1,
  "meta": {"name": "dyn", "tags": ["functional-tests"]},
  "rules": [
    {"id": 900001, "target": "URI", "match": "EXACT", "pattern": "/hit", "action": "DENY", "score": 25}
  ]
}
EOF

cat > "$CONFDIR/nginx.conf" <<EOF
load_module $NGINX_PREFIX/modules/ngx_http_waf_module.so;

worker_processes  1;
error_log $LOGDIR/error.log info;
pid $PID_FILE;

events { worker_connections  256; }

http {
  access_log $LOGDIR/access.log;
  waf_jsons_dir $RULES_DIR;
  waf_json_log $LOGDIR/waf.jsonl;
  waf_json_log_level debug;
  waf_shm_zone waf_zone 10m;
  waf_trust_xff off;

  # 动态封禁参数（低阈值便于测试）
  waf_dynamic_block_score_threshold 50;
  waf_dynamic_block_duration 1m;
  waf_dynamic_block_window_size 1m;

  server {
    listen 18083;
    server_name localhost;

    waf on;
    waf_default_action BLOCK;
    waf_rules_json rules.json;
    waf_dynamic_block_enable on;

    location /hit { return 200 "hit"; }
    location / { return 200 "ok"; }
  }
}
EOF

nginx_start "$NGINX_BIN" "$CONFDIR/nginx.conf" "$PID_FILE"
wait_for_port 127.0.0.1 18083 10

# 发送多次 /hit 以累计分数 vượt 阈值（25 * 3 = 75 > 50）
for _ in {1..3}; do
  curl -sS -o /dev/null -w "%{http_code}" "http://127.0.0.1:18083/hit" || true
done

# 再次访问应被动态封禁阻断（BLOCK_BY_DYNAMIC_BLOCK）
sleep 0.3
curl -sS -o /dev/null -w "%{http_code}" "http://127.0.0.1:18083/" >"$WORKDIR/status.txt" || true
status=$(cat "$WORKDIR/status.txt")

last=$(jsonl_last "$LOGDIR/waf.jsonl")
[[ -n "$last" ]] || { echo "未产生 JSONL"; exit 1; }
fat=$(jq -r '.finalActionType' <<<"$last")
[[ "$fat" == "BLOCK_BY_DYNAMIC_BLOCK" ]] || { echo "finalActionType 非 BLOCK_BY_DYNAMIC_BLOCK: $fat"; exit 1; }

# 存在 ban 事件且 decisive 落在 ban 事件
ban_cnt=$(jq '[.events[] | select(.type=="ban")] | length' <<<"$last")
[[ "$ban_cnt" -ge 1 ]] || { echo "缺少 ban 事件"; exit 1; }
dec_ban=$(jq '[.events[] | select(.type=="ban" and .decisive==true)] | length' <<<"$last")
[[ "$dec_ban" -ge 1 ]] || { echo "decisive 未标记在 ban 事件"; exit 1; }

exit 0


