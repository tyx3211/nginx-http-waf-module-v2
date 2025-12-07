#!/usr/bin/env bash
set -euo pipefail

# 交互式 Nginx WAF 编译部署脚本
# 功能：自动下载 Nginx 源码、配置编译参数、编译安装、部署规则

# 默认值
PREFIX_DEFAULT="/usr/local/nginx"
NGINX_VERSION_DEFAULT="1.24.0"
V2_MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../nginx-http-waf-module-v2" && pwd)"
RULES_SRC_DIR="$V2_MODULE_DIR/WAF_RULES_JSON"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR=$(pwd)

# 颜色
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_err() { echo -e "${RED}[ERROR] $1${NC}"; }

# 1. 检查环境
check_env() {
    if ! command -v wget &> /dev/null && ! command -v curl &> /dev/null; then
        log_err "需安装 wget 或 curl"
        exit 1
    fi
    if ! command -v tar &> /dev/null; then
        log_err "需安装 tar"
        exit 1
    fi
    if ! command -v make &> /dev/null; then
        log_err "需安装 make"
        exit 1
    fi
    # 检查 PCRE2
    if ! pkg-config --exists libpcre2-8; then
        log_warn "未检测到 libpcre2-8，编译可能失败。请确保安装了 libpcre2-dev"
    fi
}

# 2. 交互式配置
interactive_config() {
    echo "------------------------------------------------"
    echo "   Nginx WAF v2 交互式编译脚本"
    echo "------------------------------------------------"

    # 选择 Nginx 源码来源
    echo "请选择 Nginx 源码来源:"
    echo "  1) 自动下载官方源码 (默认)"
    echo "  2) 使用本地已有源码目录"
    read -p "请输入选项 [1]: " SRC_SOURCE
    SRC_SOURCE=${SRC_SOURCE:-1}

    if [[ "$SRC_SOURCE" == "2" ]]; then
        read -p "请输入本地 Nginx 源码目录路径: " INPUT_SRC_DIR
        # 处理相对路径
        if [[ ! "$INPUT_SRC_DIR" = /* ]]; then
            INPUT_SRC_DIR="$WORK_DIR/$INPUT_SRC_DIR"
        fi
        
        if [[ ! -d "$INPUT_SRC_DIR" || ! -f "$INPUT_SRC_DIR/configure" ]]; then
            log_err "无效的 Nginx 源码目录 (未找到 configure): $INPUT_SRC_DIR"
            exit 1
        fi
        NGINX_SRC_DIR="$INPUT_SRC_DIR"
        NGINX_VERSION="local"
    else
        # 选择 Nginx 版本
        read -p "请输入 Nginx 版本 [默认 $NGINX_VERSION_DEFAULT]: " INPUT_VER
        NGINX_VERSION=${INPUT_VER:-$NGINX_VERSION_DEFAULT}
        NGINX_SRC_DIR="$WORK_DIR/nginx-$NGINX_VERSION"
    fi

    # 选择安装路径
    read -p "请输入 Nginx 安装路径 (Prefix) [默认 $PREFIX_DEFAULT]: " INPUT_PREFIX
    PREFIX=${INPUT_PREFIX:-$PREFIX_DEFAULT}

    # 选择模块路径
    read -p "请输入 v2 模块源码路径 [默认 $V2_MODULE_DIR]: " INPUT_MOD_DIR
    MODULE_DIR=${INPUT_MOD_DIR:-$V2_MODULE_DIR}
    
    if [[ ! -d "$MODULE_DIR" ]]; then
        log_err "模块路径不存在: $MODULE_DIR"
        exit 1
    fi

    # 确认
    echo "------------------------------------------------"
    echo "配置摘要:"
    echo "  Nginx 源码: $NGINX_SRC_DIR"
    echo "  安装路径:   $PREFIX"
    echo "  模块路径:   $MODULE_DIR"
    echo "------------------------------------------------"
    read -p "确认开始编译? [Y/n] " CONFIRM
    if [[ "$CONFIRM" =~ ^[Nn]$ ]]; then
        exit 0
    fi
}

# 3. 下载与解压 (仅当选择自动下载时)
prepare_source() {
    if [[ "$SRC_SOURCE" == "2" ]]; then
        log_info "使用本地源码: $NGINX_SRC_DIR"
        cd "$NGINX_SRC_DIR"
        return
    fi

    if [[ -d "$NGINX_SRC_DIR" ]]; then
        log_warn "目录 $NGINX_SRC_DIR 已存在，跳过下载"
        cd "$NGINX_SRC_DIR"
        return
    fi

    URL="http://nginx.org/download/nginx-$NGINX_VERSION.tar.gz"
    log_info "下载 Nginx: $URL"
    
    if command -v wget &> /dev/null; then
        wget "$URL"
    else
        curl -O "$URL"
    fi

    tar -zxf "nginx-$NGINX_VERSION.tar.gz"
    cd "$NGINX_SRC_DIR"
}

# 4. 编译安装
build_nginx() {
    log_info "清理环境..."
    make clean || true

    log_info "配置 Configure..."
    # 默认参数：--with-compat, --add-dynamic-module
    # 生产环境通常不需要 --with-debug，但为了排查问题可选保留，此处默认去掉
    ./configure \
        --prefix="$PREFIX" \
        --with-compat \
        --add-dynamic-module="$MODULE_DIR" # \
        # --with-http_ssl_module \
        # --with-http_v2_module

    log_info "编译 Make..."
    make -j$(nproc)

    log_info "安装 Install..."
    sudo make install
}

# 5. 部署规则与配置
deploy_rules() {
    log_info "部署 WAF 规则集..."
    
    TARGET_RULES_DIR="$PREFIX/WAF_RULES_JSON"
    
    if [[ -d "$TARGET_RULES_DIR" ]]; then
        log_warn "目标规则目录已存在: $TARGET_RULES_DIR，备份为 .bak"
        sudo mv "$TARGET_RULES_DIR" "$TARGET_RULES_DIR.bak.$(date +%s)"
    fi

    if [[ -d "$MODULE_DIR/WAF_RULES_JSON" ]]; then
        sudo cp -r "$MODULE_DIR/WAF_RULES_JSON" "$PREFIX/"
        log_info "规则集已复制到 $TARGET_RULES_DIR"
    else
        log_err "未找到源规则目录: $MODULE_DIR/WAF_RULES_JSON"
    fi
}

# 6. 提示后续步骤
post_install_tips() {
    echo ""
    echo "========================================================"
    log_info "安装完成！"
    echo "========================================================"
    echo "1. 请将以下配置添加到 $PREFIX/conf/nginx.conf 的 http {} 块中:"
    echo ""
    echo "    waf on;"
    echo "    waf_shm_zone waf_block_zone 10m;"
    echo "    waf_jsons_dir WAF_RULES_JSON;"
    echo "    waf_rules_json user/gotestwaf_user_rules.json;"
    echo "    waf_json_log logs/waf.jsonl;"
    echo "    waf_json_log_level info;"
    echo "    waf_default_action block;"
    echo "    waf_dynamic_block_enable on; # 按需开启"
    echo ""
    echo "2. 或者直接使用提供的模板:"
    echo "   sudo cp $MODULE_DIR/doc/gotestwaf.nginx.conf $PREFIX/conf/nginx.conf"
    echo ""
    echo "3. 启动 Nginx:"
    echo "   sudo $PREFIX/sbin/nginx"
    echo ""
    echo "4. 验证安装:"
    echo "   curl -I http://localhost:8080/"
    echo "========================================================"
}

# 主流程
main() {
    check_env
    interactive_config
    prepare_source
    build_nginx
    deploy_rules
    post_install_tips
}

main
