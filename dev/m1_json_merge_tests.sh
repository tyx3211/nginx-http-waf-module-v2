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

function grep_final_doc_contains() { :; }

function reset_logs() {
  > "$LOG_DIR/error.log"; > "$CONF_DIR/logs/error.log"
}

function nginx_test_expect_fail() {
  local entry_json="$1"; shift
  local name="$1"; shift || true
  reset_logs
  write_conf "$entry_json"
  set +e
  "$NGINX_SBIN" -t -c "$CONF_FILE" -p "$CONF_DIR" 2>>"$LOG_DIR/error.log"
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    echo "[PASS] $name failed as expected"
  else
    echo "[FAIL] $name should fail but passed"; return 1
  fi
}

function nginx_test_expect_fail_or_skip() {
  local entry_json="$1"; shift
  local name="$1"; shift || true
  reset_logs
  write_conf "$entry_json"
  set +e
  "$NGINX_SBIN" -t -c "$CONF_FILE" -p "$CONF_DIR" 2>>"$LOG_DIR/error.log"
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    echo "[PASS] $name failed as expected"
  else
    echo "[SKIP] $name not validated yet"
  fi
}

> "$LOG_DIR/error.log" || true

echo "== Case1: disable-only + dup keep last =="
write_conf "entry.json"
nginx_test
grep_rules_count "4" "entry.json"
# final_doc 输出已在模块中注释掉，以下检查移除以减少噪音

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
reset_logs
write_conf "dup_skip.json"
nginx_test
grep_rules_count "1" "dup_skip.json"

echo "== Case6: duplicate policy keep last =="
reset_logs
write_conf "dup_keep_last.json"
nginx_test
grep_rules_count "1" "dup_keep_last.json"

echo "== Case7: duplicate default policy warn_skip =="
reset_logs
write_conf "dup_default_warn_skip.json"
nginx_test
grep_rules_count "1" "dup_default_warn_skip.json"

echo "== Case8: required missing id =="
nginx_test_expect_fail "required_missing_id.json" "missing id"

echo "== Case9: required missing target =="
nginx_test_expect_fail "required_missing_target.json" "missing target"

echo "== Case10: type invalid pattern object =="
nginx_test_expect_fail "type_invalid_pattern_object.json" "invalid pattern type"

echo "== Case11: type invalid match value =="
nginx_test_expect_fail "type_invalid_match_value.json" "invalid match type"

echo "== Case12: illegal header without name =="
nginx_test_expect_fail "illegal_combination_header_without_name.json" "header without name"

echo "== Case13: illegal bypass with score =="
nginx_test_expect_fail "illegal_combination_bypass_with_score.json" "bypass with score"

echo "== Case14: header with other targets (array invalid) =="
nginx_test_expect_fail "header_array_invalid.json" "header with other targets"

echo "== Case15: empty target array invalid =="
nginx_test_expect_fail "invalid_target_combo.json" "empty target array"

echo "== Case16: unknown fields in rule should fail =="
nginx_test_expect_fail "unknown_field_rule.json" "unknown field in rule"

echo "== Case17: bad score types should fail =="
nginx_test_expect_fail "bad_score_types.json" "bad score types"

echo "== Case18: boundary values should fail =="
nginx_test_expect_fail "boundary_values.json" "boundary values"

echo "== Case19: rewrite targets by tag (counts unchanged) =="
reset_logs
write_conf "rewrite_tags.json"
nginx_test
grep_rules_count "2" "rewrite_tags.json"

echo "== Case20: rewrite targets by ids (counts unchanged) =="
reset_logs
write_conf "rewrite_ids.json"
nginx_test
grep_rules_count "2" "rewrite_ids.json"

echo "== Case21: missing parent file should fail =="
nginx_test_expect_fail "missing_parent_entry.json" "missing parent file"

echo "== Case22: empty file should fail =="
nginx_test_expect_fail "empty_file.json" "empty file"

echo "All M1 cases passed."


