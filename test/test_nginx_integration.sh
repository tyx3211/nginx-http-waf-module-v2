#!/bin/bash
# Nginx HTTP WAF v2 集成测试脚本
# 
# 测试目标：
# 1. 验证模块能否正常编译
# 2. 验证Nginx能否正常加载模块
# 3. 验证配置指令能否正常解析
# 4. 验证基本的拦截功能

# 注意：不使用 set -e，以便继续运行后续测试

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 测试计数器
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=()  # 记录失败的测试名称和原因
FATAL_ERROR=0  # 是否发生致命错误

# 工作目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
NGINX_BIN="$(which nginx)"  # 使用环境变量中的nginx
NGINX_MODULE_PATH="/usr/local/nginx/modules/ngx_http_waf_module.so"  # 已安装的模块路径
TEST_NGINX_DIR="/tmp/waf_v2_test_nginx"
TEST_LOG_DIR="/tmp/waf_v2_test_logs"

# 清理函数
cleanup() {
  if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${YELLOW}清理测试环境...${NC}"
    if [ -f "$TEST_NGINX_DIR/nginx.pid" ]; then
      kill $(cat "$TEST_NGINX_DIR/nginx.pid") 2>/dev/null || true
    fi
    rm -rf "$TEST_NGINX_DIR"
    rm -rf "$TEST_LOG_DIR"
  else
    echo -e "${YELLOW}保留测试环境供调试：${NC}"
    echo -e "  配置目录: $TEST_NGINX_DIR"
    echo -e "  日志目录: $TEST_LOG_DIR"
  fi
}

# 注册清理函数
trap cleanup EXIT

# 辅助函数
print_header() {
  echo ""
  echo -e "${BLUE}========================================${NC}"
  echo -e "${BLUE}  $1${NC}"
  echo -e "${BLUE}========================================${NC}"
  echo ""
}

CURRENT_TEST_NAME=""

test_start() {
  TESTS_RUN=$((TESTS_RUN + 1))
  CURRENT_TEST_NAME="$1"
  echo -n "  测试 $TESTS_RUN: $1 ... "
}

test_pass() {
  TESTS_PASSED=$((TESTS_PASSED + 1))
  echo -e "${GREEN}✅ 通过${NC}"
  CURRENT_TEST_NAME=""
}

test_fail() {
  TESTS_FAILED=$((TESTS_FAILED + 1))
  echo -e "${RED}❌ 失败${NC}"
  echo -e "${RED}    原因: $1${NC}"
  FAILED_TESTS+=("$CURRENT_TEST_NAME|$1")
  CURRENT_TEST_NAME=""
}

print_header "WAF v2 Nginx集成测试"

echo "模块目录: $MODULE_DIR"
echo "Nginx可执行文件: $NGINX_BIN"
echo "WAF模块路径: $NGINX_MODULE_PATH"
echo ""

# =================================================================
# 测试1：检查源代码文件是否存在
# =================================================================

test_start "检查源代码文件完整性"

REQUIRED_FILES=(
  "src/module/ngx_http_waf_module.c"
  "src/module/ngx_http_waf_config.c"
  "src/core/ngx_http_waf_compiler.c"
  "src/core/ngx_http_waf_action.c"
  "src/core/ngx_http_waf_log.c"
  "src/core/ngx_http_waf_dynamic_block.c"
  "src/json/ngx_http_waf_json.c"
  "config"
)

ALL_FILES_EXIST=true
for file in "${REQUIRED_FILES[@]}"; do
  if [ ! -f "$MODULE_DIR/$file" ]; then
    test_fail "缺失文件: $file"
    ALL_FILES_EXIST=false
    break
  fi
done

if [ "$ALL_FILES_EXIST" = true ]; then
  test_pass
fi

# =================================================================
# 测试2：检查Nginx可执行文件是否存在
# =================================================================

test_start "检查Nginx可执行文件"

if [ ! -f "$NGINX_BIN" ]; then
  test_fail "Nginx可执行文件不存在: $NGINX_BIN (请先安装Nginx或检查PATH)"
  FATAL_ERROR=1
else
  test_pass
fi

# =================================================================
# 测试3：检查WAF模块是否已安装
# =================================================================

test_start "检查WAF模块文件"

if [ ! -f "$NGINX_MODULE_PATH" ]; then
  test_fail "WAF模块文件不存在: $NGINX_MODULE_PATH (提示: cd nginx-src && bash build_v2.sh --preset debug3)"
  FATAL_ERROR=1
else
  test_pass
fi

# =================================================================
# 测试4：创建测试环境
# =================================================================

test_start "创建测试环境"

mkdir -p "$TEST_NGINX_DIR"/{conf,logs,client_body_temp,proxy_temp,fastcgi_temp,uwsgi_temp,scgi_temp}
mkdir -p "$TEST_LOG_DIR"
mkdir -p "$TEST_NGINX_DIR/html"

echo "Test OK" > "$TEST_NGINX_DIR/html/index.html"

test_pass

# =================================================================
# 测试5：创建测试用规则JSON
# =================================================================

test_start "创建测试规则JSON"

mkdir -p "$TEST_NGINX_DIR/waf_rules"

cat > "$TEST_NGINX_DIR/waf_rules/test_rules.json" <<'EOF'
{
  "version": 1,
  "meta": {"name": "test_rules", "tags": ["integration-test"]},
  "rules": [
    {
      "id": 200010,
      "tags": ["sqli"],
      "target": "ARGS_COMBINED",
      "match": "CONTAINS",
      "pattern": "select",
      "action": "DENY",
      "score": 20
    },
    {
      "id": 200020,
      "tags": ["xss"],
      "target": "ARGS_COMBINED",
      "match": "CONTAINS",
      "pattern": "<script",
      "action": "DENY",
      "score": 20
    },
    {
      "id": 100001,
      "tags": ["whitelist"],
      "target": "CLIENT_IP",
      "match": "EXACT",
      "pattern": ["127.0.0.1", "::1"],
      "action": "BYPASS"
    }
  ]
}
EOF

test_pass

# =================================================================
# 测试6：创建Nginx配置文件
# =================================================================

test_start "创建Nginx配置文件"

cat > "$TEST_NGINX_DIR/conf/nginx.conf" <<EOF
# 加载WAF动态模块
load_module $NGINX_MODULE_PATH;

worker_processes 1;
daemon off;
master_process off;

error_log $TEST_LOG_DIR/error.log debug;
pid $TEST_NGINX_DIR/nginx.pid;

events {
    worker_connections 1024;
}

http {
    access_log $TEST_LOG_DIR/access.log;
    
    # WAF v2 配置
    waf_jsons_dir $TEST_NGINX_DIR/waf_rules;
    waf_shm_zone waf_zone 10m;
    waf_json_log $TEST_LOG_DIR/waf.jsonl;
    waf_json_log_level debug;
    waf_trust_xff off;
    
    waf_dynamic_block_score_threshold 100;
    waf_dynamic_block_duration 30m;
    waf_dynamic_block_window_size 1m;
    
    server {
        listen 18080;
        server_name localhost;
        
        # 启用WAF
        waf on;
        waf_rules_json test_rules.json;
        waf_dynamic_block_enable on;
        
        location / {
            root $TEST_NGINX_DIR/html;
            index index.html;
        }
        
        location /test {
            return 200 "Test endpoint\n";
        }
    }
}
EOF

test_pass

# =================================================================
# 测试7：测试Nginx配置文件语法
# =================================================================

test_start "测试Nginx配置语法"

# 如果已有致命错误，跳过此测试
if [ $FATAL_ERROR -eq 1 ]; then
  test_fail "跳过测试（因前置条件失败）"
else
  # 保存测试输出
  TEST_OUTPUT=$($NGINX_BIN -t -c "$TEST_NGINX_DIR/conf/nginx.conf" 2>&1)
  TEST_EXIT_CODE=$?

  echo "$TEST_OUTPUT" > "$TEST_LOG_DIR/nginx_test_output.log"

  if echo "$TEST_OUTPUT" | grep -q "syntax is ok"; then
    test_pass
  else
    test_fail "配置文件语法错误"
    echo ""
    echo "Nginx测试输出："
    echo "$TEST_OUTPUT"
    echo ""
  fi
fi

# =================================================================
# 输出测试统计
# =================================================================

echo ""
print_header "测试结果统计"

echo "  总计: $TESTS_RUN"
echo -e "  通过: ${GREEN}$TESTS_PASSED ✅${NC}"
echo -e "  失败: ${RED}$TESTS_FAILED ❌${NC}"

# 显示详细的失败信息
if [ $TESTS_FAILED -gt 0 ]; then
  echo ""
  echo -e "${RED}失败的测试详情：${NC}"
  echo -e "${RED}────────────────────────────────────────${NC}"
  
  for i in "${!FAILED_TESTS[@]}"; do
    IFS='|' read -r test_name test_reason <<< "${FAILED_TESTS[$i]}"
    echo -e "${RED}  $((i+1)). ${YELLOW}$test_name${NC}"
    echo -e "${RED}     原因: $test_reason${NC}"
  done
  
  echo -e "${RED}────────────────────────────────────────${NC}"
fi

echo ""

if [ $TESTS_FAILED -eq 0 ]; then
  echo -e "${GREEN}🎉 所有测试通过！${NC}"
  echo ""
  exit 0
else
  echo -e "${RED}⚠️  有 $TESTS_FAILED 个测试失败${NC}"
  echo ""
  
  # 给出建议
  if [ $FATAL_ERROR -eq 1 ]; then
    echo -e "${YELLOW}提示: 请先解决前置条件问题（Nginx或模块文件缺失）${NC}"
  fi
  
  echo -e "${YELLOW}调试信息保留在:${NC}"
  echo -e "  配置目录: $TEST_NGINX_DIR"
  echo -e "  日志目录: $TEST_LOG_DIR"
  echo ""
  exit 1
fi

