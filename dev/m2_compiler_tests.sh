#!/usr/bin/env bash
set -euo pipefail

NGINX_SRC_DIR="/home/william/myNginxWorkspace/nginx-src"
MODULE_DIR="/home/william/myNginxWorkspace/nginx-http-waf-module-v2"
PREFIX_DIR="/home/william/myNginxWorkspace/nginx-install"
CONF_DIR="$MODULE_DIR/dev/m2/nginx"
RULES_DIR="$MODULE_DIR/WAF_RULES_JSON/m2"

mkdir -p "$PREFIX_DIR/modules" "$PREFIX_DIR/logs"

echo "[M2] 构建 nginx 动态模块与本地 nginx 二进制..."
cd "$NGINX_SRC_DIR"
if [ ! -x ./configure ]; then
  echo "ERROR: 未找到 $NGINX_SRC_DIR/configure，请确保 nginx 源码已就绪" >&2
  exit 1
fi

# 可选清理：设置 CLEAN=1 时执行 make clean
if [ "${CLEAN:-0}" = "1" ]; then
  make clean | cat || true
fi

# 统一使用 with-compat，便于动态模块装载
./configure --with-compat --add-dynamic-module="$MODULE_DIR" | cat
make -j"$(nproc)" | cat
make -j"$(nproc)" modules | cat

if [ ! -f "$NGINX_SRC_DIR/objs/ngx_http_waf_module.so" ]; then
  echo "ERROR: 未生成 ngx_http_waf_module.so" >&2
  exit 1
fi
cp -f "$NGINX_SRC_DIR/objs/ngx_http_waf_module.so" "$PREFIX_DIR/modules/"

NGINX_BIN="$NGINX_SRC_DIR/objs/nginx"
if [ ! -x "$NGINX_BIN" ]; then
  echo "ERROR: 未找到 nginx 可执行文件：$NGINX_BIN" >&2
  exit 1
fi

pass_cnt=0
fail_cnt=0

run_case() {
  local name="$1"; shift
  local conf="$1"; shift
  local expect_rc="$1"; shift
  printf '\n[M2][CASE] %s -> %s (expect rc=%s)\n' "$name" "$conf" "$expect_rc" | cat
  if "$NGINX_BIN" -t -p "$PREFIX_DIR" -c "$conf" 2>&1 | cat; then
    rc=0
  else
    rc=$?
  fi
  if [ "$rc" = "$expect_rc" ]; then
    echo "[OK] $name" | cat
    pass_cnt=$((pass_cnt+1))
  else
    echo "[FAIL] $name: rc=$rc, expect=$expect_rc" | cat
    fail_cnt=$((fail_cnt+1))
  fi
}

# 用例列表
run_case "valid_bucket_sort"      "$CONF_DIR/test_valid.conf"           0
run_case "explicit_phase_ok"       "$CONF_DIR/test_phase_ok.conf"        0
run_case "invalid_phase_combo"     "$CONF_DIR/test_phase_invalid.conf"   1
run_case "invalid_regex_compile"   "$CONF_DIR/test_regex_invalid.conf"    1
run_case "invalid_cidr_parse"      "$CONF_DIR/test_cidr_invalid.conf"     1
run_case "empty_rules"             "$CONF_DIR/test_empty.conf"            0
run_case "header_ok"               "$CONF_DIR/test_header_ok.conf"        0
run_case "header_missing_name"     "$CONF_DIR/test_header_invalid_no_header_name.conf" 1
run_case "header_mixed_targets"    "$CONF_DIR/test_header_invalid_mixed_targets.conf"   1
run_case "all_params_expand"       "$CONF_DIR/test_all_params_expand.conf" 0
run_case "policies_passthrough"    "$CONF_DIR/test_policies_passthrough.conf" 0

printf '\n[M2] 测试完成：PASS=%s FAIL=%s\n' "$pass_cnt" "$fail_cnt" | cat
if [ "$fail_cnt" -ne 0 ]; then
  exit 1
fi




