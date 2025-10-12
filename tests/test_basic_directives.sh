#!/usr/bin/env bash
set -euo pipefail

NGINX_BIN="${1:-/usr/local/nginx/sbin/nginx}"
NGINX_PREFIX="${2:-/usr/local/nginx}"
MODULE_DIR="${3:-/home/william/myNginxWorkspace/nginx-http-waf-module-v2}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

WORKDIR="/tmp/waf_v2_basic"
LOGDIR="$WORKDIR/logs"
CONFDIR="$WORKDIR/conf"
HTMLDIR="$WORKDIR/html"
RULES_DIR="$WORKDIR/waf_rules"
PID_FILE="$WORKDIR/nginx.pid"

cleanup() {
  nginx_stop "$PID_FILE" || true
  if [[ "${KEEP_ON_FAIL:-0}" == "0" ]]; then rm -rf "$WORKDIR"; fi
}
trap cleanup EXIT

ensure_dir "$WORKDIR" "$LOGDIR" "$CONFDIR" "$HTMLDIR" "$RULES_DIR"
cp -f "$SCRIPT_DIR/resources/basic_rules.json" "$RULES_DIR/rules.json"
echo "OK" > "$HTMLDIR/index.html"

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
  waf_trust_xff off;
  waf_shm_zone waf_zone 10m;

  server {
    listen 18081;
    server_name localhost;

    waf on;
    waf_default_action BLOCK;
    waf_rules_json rules.json;

    location / {
      root $HTMLDIR;
      index index.html;
    }

    location /off/ {
      waf off;
      root $HTMLDIR;
    }

    location /log-only/ {
      waf_default_action log;
      return 200 "LOG ONLY";
    }
  }
}
EOF

# 启动并验证
nginx_start "$NGINX_BIN" "$CONFDIR/nginx.conf" "$PID_FILE"
wait_for_port 127.0.0.1 18081 10

# 1) 基础可访问
resp=$(http_get "http://127.0.0.1:18081/")
[[ "$resp" == "OK" ]] || { echo "首页访问失败"; exit 1; }

# 2) waf off 区域完全旁路（不写 JSONL）
before_lines=$(wc -l < "$LOGDIR/waf.jsonl" 2>/dev/null || echo 0)
http_get "http://127.0.0.1:18081/off/?q=select" >/dev/null || true
after_lines=$(wc -l < "$LOGDIR/waf.jsonl" 2>/dev/null || echo 0)
if (( after_lines > before_lines )); then
  echo "waf off 区域不应产生日志"
  exit 1
fi

# 3) LOG 策略路径不阻断但可写 JSONL（level 由 info 控制）
http_get "http://127.0.0.1:18081/log-only/" >/dev/null
if [[ -f "$LOGDIR/waf.jsonl" ]]; then
  last=$(jsonl_last "$LOGDIR/waf.jsonl")
  [[ -n "$last" ]] || { echo "JSONL 空"; exit 1; }
  # 仅验证能写入且 finalAction 存在（ALLOW 或 BYPASS 均可能）
  jq -e '.finalAction' >/dev/null <<<"$last" || { echo "缺少 finalAction"; exit 1; }
fi

exit 0


