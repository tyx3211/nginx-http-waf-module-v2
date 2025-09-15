#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="/home/william/myNginxWorkspace/nginx-http-waf-module-v2"
JSON_DIR="$ROOT_DIR/WAF_RULES_JSON"

NGINX_PREFIX="/usr/local/nginx"
NGINX_SBIN="$NGINX_PREFIX/sbin/nginx"

CONF_DIR="$ROOT_DIR/dev/nginx"
CONF_FILE="$CONF_DIR/nginx_m1.conf"
LOG_DIR="$ROOT_DIR/dev/logs"
mkdir -p "$CONF_DIR" "$CONF_DIR/logs" "$LOG_DIR"

function write_conf() {
  local entry_json="$1"
  cat > "$CONF_FILE" <<EOF
load_module $NGINX_PREFIX/modules/ngx_http_waf_module.so;

worker_processes  1;
error_log  $LOG_DIR/error.log info;
pid        $LOG_DIR/nginx.pid;

events { worker_connections  64; }

http {
    # v2 module directives
    waf_jsons_dir $JSON_DIR;
    waf_json_extends_max_depth 5;

    server {
        listen 127.0.0.1:8089;
        location / {
            waf_rules_json $entry_json;
            return 200 "ok";
        }
    }
}
EOF
}

function nginx_test() {
  "$NGINX_SBIN" -t -c "$CONF_FILE" -p "$CONF_DIR" | cat || true
}

function grep_rules_count() {
  local expect="$1"; shift
  local name="$1"; shift
  local got
  local combined_tmp
  combined_tmp=$(mktemp)
  cat "$CONF_DIR/logs/error.log" "$LOG_DIR/error.log" 2>/dev/null | tee -a /dev/null > "$combined_tmp" || true
  got=$(grep -E "waf: merged rules [0-9]+ from" -o "$combined_tmp" | tail -n1 | awk '{print $4}') || got="0"
  rm -f "$combined_tmp"
  if [[ "$got" == "$expect" ]]; then
    echo "[PASS] $name rules=$got"
  else
    echo "[FAIL] $name got=$got expect=$expect"; return 1
  fi
}

> "$LOG_DIR/error.log" || true

echo "== Case1: include/exclude/disable + dup keep last =="
write_conf "entry.json"
nginx_test
grep_rules_count "5" "entry.json"

echo "== Case2: extends loop detection =="
> "$LOG_DIR/error.log"; > "$CONF_DIR/logs/error.log"
write_conf "loop_a.json"
"$NGINX_SBIN" -t -c "$CONF_FILE" -p "$CONF_DIR" 2>>"$LOG_DIR/error.log" || true
(grep -q "extends cycle" "$LOG_DIR/error.log" || grep -q "extends cycle" "$CONF_DIR/logs/error.log") && echo "[PASS] loop detected" || { echo "[FAIL] loop not detected"; exit 1; }

echo "== Case3: depth limit =="
> "$LOG_DIR/error.log"; > "$CONF_DIR/logs/error.log"
write_conf "depth_root.json"
sed -i 's/waf_json_extends_max_depth 5;/waf_json_extends_max_depth 2;/' "$CONF_FILE"
"$NGINX_SBIN" -t -c "$CONF_FILE" -p "$CONF_DIR" 2>>"$LOG_DIR/error.log" || true
(grep -q "深度超出上限" "$LOG_DIR/error.log" || grep -q "深度超出上限" "$CONF_DIR/logs/error.log") && echo "[PASS] depth limit" || { echo "[FAIL] depth limit not triggered"; exit 1; }

echo "== Case4: duplicate policy error =="
> "$LOG_DIR/error.log"; > "$CONF_DIR/logs/error.log"
write_conf "dup_error.json"
"$NGINX_SBIN" -t -c "$CONF_FILE" -p "$CONF_DIR" 2>>"$LOG_DIR/error.log" || true
(grep -q "duplicate rule" "$LOG_DIR/error.log" || grep -q "duplicate rule" "$CONF_DIR/logs/error.log" || grep -q "重复规则" "$LOG_DIR/error.log" || grep -q "重复规则" "$CONF_DIR/logs/error.log") && echo "[PASS] dup error" || { echo "[FAIL] dup error not triggered"; exit 1; }

echo "== Case5: duplicate policy skip =="
> "$LOG_DIR/error.log"; > "$CONF_DIR/logs/error.log"
write_conf "dup_skip.json"
nginx_test
grep_rules_count "1" "dup_skip.json"

echo "== Case6: duplicate policy keep last =="
> "$LOG_DIR/error.log"; > "$CONF_DIR/logs/error.log"
write_conf "dup_keep_last.json"
nginx_test
grep_rules_count "1" "dup_keep_last.json"

echo "All M1 cases passed."


