#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
NGINX_SRC_DIR="/home/william/myNginxWorkspace/nginx-src"
NGINX_PREFIX="/usr/local/nginx"
NGINX_BIN="$NGINX_PREFIX/sbin/nginx"

source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat <<EOF
用法：$(basename "$0") [选项]

选项：
  --build             先构建并安装 Nginx 与模块（使用 nginx-src/build_v2.sh --preset debug3）
  --jobs N            构建并行度（与 --build 配合）
  --list              仅列出将要运行的测试
  -h, --help          显示帮助

测试脚本目录：$SCRIPT_DIR
EOF
}

DO_BUILD=0
JOBS=""
LIST_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build) DO_BUILD=1; shift;;
    --jobs) JOBS="$2"; shift 2;;
    --list) LIST_ONLY=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "未知参数: $1"; usage; exit 1;;
  esac
done

# 依赖检查
require_cmd bash
require_cmd curl
require_cmd jq || { log_warn "未安装 jq，JSONL 校验将失败"; }

if (( DO_BUILD )); then
  log_info "开始构建 Nginx 与模块..."
  CMD=("./build_v2.sh" --preset debug3 --module-dir "$MODULE_DIR")
  if [[ -n "$JOBS" ]]; then CMD+=(--jobs "$JOBS"); fi
  (
    cd "$NGINX_SRC_DIR"
    bash "${CMD[@]}"
  )
  log_info "构建完成。"
fi

if [[ ! -x "$NGINX_BIN" ]]; then
  log_error "未找到 Nginx 可执行文件：$NGINX_BIN。可使用 --build 构建。"
  exit 1
fi

TEST_SCRIPTS=(
  "$SCRIPT_DIR/test_smoke_basic.sh"
  "$SCRIPT_DIR/test_dynamic_block_minimal.sh"
)

for t in "${TEST_SCRIPTS[@]}"; do
  if [[ ! -f "$t" ]]; then
    log_warn "缺少测试脚本：$t（将跳过）"
  fi
done

if (( LIST_ONLY )); then
  echo "将运行以下测试："
  printf ' - %s\n' "${TEST_SCRIPTS[@]}"
  exit 0
fi

TOTAL=0; PASS=0; FAIL=0
FAILED=()
ARTIFACT_DIR="/home/william/myNginxWorkspace/nginx-http-waf-module-v2/tests/artifacts/test_runs"
ensure_dir "$ARTIFACT_DIR"

for t in "${TEST_SCRIPTS[@]}"; do
  [[ -f "$t" ]] || continue
  TOTAL=$((TOTAL+1))
  log_info "运行测试：$t"
  log_file="$ARTIFACT_DIR/$(basename "$t").log"
  if bash "$t" "$NGINX_BIN" "$NGINX_PREFIX" "$MODULE_DIR" >"$log_file" 2>&1; then
    echo -e "${GREEN}✅ PASS${NC} $t"
    PASS=$((PASS+1))
  else
    echo -e "${RED}❌ FAIL${NC} $t"
    FAIL=$((FAIL+1))
    FAILED+=("$t")
    echo "——— 失败日志开始 ($log_file) ———"
    cat "$log_file"
    echo "——— 失败日志结束 ———"
  fi
done

echo ""
echo "======== 测试统计 ========"
echo "总计: $TOTAL"
echo -e "通过: ${GREEN}$PASS${NC}"
echo -e "失败: ${RED}$FAIL${NC}"
if (( FAIL )); then
  echo "失败用例："; printf ' - %s\n' "${FAILED[@]}"
  exit 1
fi
exit 0


