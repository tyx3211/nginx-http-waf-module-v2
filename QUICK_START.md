# Nginx HTTP WAF 模块 v2 - 快速部署指南

> 本指南帮助您在 5 分钟内完成 WAF 模块的编译、部署和验证。

## 📋 目录

- [1. 环境准备](#1-环境准备)
- [2. 获取源码](#2-获取源码)
- [3. 编译安装](#3-编译安装)
- [4. 配置 WAF](#4-配置-waf)
- [5. 规则配置](#5-规则配置)
- [6. 日志配置](#6-日志配置)
- [7. 启动测试](#7-启动测试)
- [8. 常见问题](#8-常见问题)

---

## 1. 环境准备

### 1.1 系统要求

- **操作系统**：Linux（推荐 Ubuntu 20.04+）
- **依赖库**：
  - GCC/G++ 编译器
  - PCRE2 开发库（**必需**，用于正则表达式）
  - OpenSSL 开发库（可选，HTTPS 支持）
  - Zlib 开发库（可选，gzip 支持）

### 1.2 安装依赖

**Ubuntu/Debian：**
```bash
sudo apt-get update
sudo apt-get install -y build-essential libpcre2-dev libssl-dev zlib1g-dev
```

**CentOS/RHEL：**
```bash
sudo yum install -y gcc gcc-c++ pcre2-devel openssl-devel zlib-devel
```

---

## 2. 获取源码

### 2.1 下载 Nginx 源码

推荐使用 **Nginx 1.24.0** 版本：

```bash
cd /home/yourname/workspace  # 替换为你的工作目录
wget http://nginx.org/download/nginx-1.24.0.tar.gz
tar -zxvf nginx-1.24.0.tar.gz
mv nginx-1.24.0 nginx-src
cd nginx-src
```

### 2.2 获取 WAF 模块

```bash
# 假设你已经拉取了 WAF 模块到同级目录
# 目录结构应该是：
# workspace/
# ├── nginx-src/           (Nginx 源码)
# └── nginx-http-waf-module-v2/  (WAF 模块)
```

---

## 3. 编译安装

### 3.1 使用构建脚本（推荐）

WAF 模块提供了便捷的构建脚本 `build_v2.sh`：

```bash
cd nginx-src

# 方式一：快速编译（推荐用于开发调试）
./build_v2.sh --preset debug1 --jobs 8

# 方式二：完整编译并安装
./build_v2.sh --preset debug3 --jobs 8

# 说明：
# --preset debug1: 清理 → 配置 → 编译动态模块 → 复制 .so
# --preset debug3: 清理 → 配置 → 完整编译 → 安装 → 复制 .so
# --jobs 8: 使用 8 个线程加速编译
```

### 3.2 手动编译（可选）

如果需要自定义配置：

```bash
cd nginx-src

# 配置
./configure \
  --prefix=/usr/local/nginx \
  --with-debug \
  --with-compat \
  --add-dynamic-module=../nginx-http-waf-module-v2

# 编译动态模块
make modules -j8

# 或完整编译并安装
make -j8
sudo make install

# 复制动态模块
sudo mkdir -p /usr/local/nginx/modules
sudo cp objs/ngx_http_waf_module.so /usr/local/nginx/modules/
```

### 3.3 创建软链接（推荐）

为了方便管理，建议创建软链接：

```bash
sudo ln -sf /usr/local/nginx /usr/local/nginx-install
# 或者根据你的实际安装路径调整
```

---

## 4. 配置 WAF

### 4.1 部署配置文件

WAF 模块提供了两个核心配置文件，需要复制到 Nginx 配置目录：

```bash
# 创建 WAF 配置目录
sudo mkdir -p /usr/local/nginx/conf/waf

# 复制配置文件
sudo cp nginx-http-waf-module-v2/conf/waf/waf_core.conf /usr/local/nginx/conf/waf/
sudo cp nginx-http-waf-module-v2/conf/waf/waf_access_log.conf /usr/local/nginx/conf/waf/

# 创建日志目录
sudo mkdir -p /var/log/nginx
sudo chmod 755 /var/log/nginx
```

### 4.2 编辑 nginx.conf

编辑 `/usr/local/nginx/conf/nginx.conf`，在文件开头添加模块加载：

```nginx
# 在 events 块之前添加
load_module modules/ngx_http_waf_module.so;

worker_processes  auto;
error_log  logs/error.log notice;
pid        logs/nginx.pid;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;
    
    # 引入 WAF 核心配置
    include waf/waf_core.conf;
    include waf/waf_access_log.conf;
    
    sendfile        on;
    keepalive_timeout  65;

    server {
        listen       8080;
        server_name  localhost;

        location / {
            root   html;
            index  index.html index.htm;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }
    }
}
```

### 4.3 调整 waf_core.conf（重要）

编辑 `/usr/local/nginx/conf/waf/waf_core.conf`，修改规则文件路径：

```nginx
# 原配置（示例路径）
# waf_jsons_dir /usr/local/nginx/conf/waf/releases/current;
# waf_rules_json /usr/local/nginx/conf/waf/releases/current/main.json;

# 快速开始配置（使用测试规则）
waf_jsons_dir /usr/local/nginx/conf/waf/rules;
waf_rules_json /usr/local/nginx/conf/waf/rules/main.json;
```

---

## 5. 规则配置

### 5.1 创建规则目录

```bash
sudo mkdir -p /usr/local/nginx/conf/waf/rules
```

### 5.2 创建基础规则文件

**创建 `/usr/local/nginx/conf/waf/rules/base.json`：**

```bash
sudo tee /usr/local/nginx/conf/waf/rules/base.json > /dev/null <<'EOF'
{
  "version": 1,
  "meta": {
    "name": "基础防护规则",
    "tags": ["baseline"]
  },
  "rules": [
    {
      "id": 1001,
      "tags": ["sqli"],
      "target": "ALL_PARAMS",
      "match": "CONTAINS",
      "pattern": "attack",
      "caseless": true,
      "action": "DENY",
      "score": 50,
      "priority": 10
    },
    {
      "id": 1002,
      "tags": ["xss"],
      "target": "ALL_PARAMS",
      "match": "REGEX",
      "pattern": "(?i)<script",
      "caseless": true,
      "action": "DENY",
      "score": 50,
      "priority": 10
    },
    {
      "id": 2001,
      "tags": ["whitelist"],
      "target": "URI",
      "match": "EXACT",
      "pattern": "/health",
      "action": "BYPASS",
      "priority": 1
    }
  ]
}
EOF
```

**创建 `/usr/local/nginx/conf/waf/rules/main.json`（入口文件）：**

```bash
sudo tee /usr/local/nginx/conf/waf/rules/main.json > /dev/null <<'EOF'
{
  "version": 1,
  "meta": {
    "name": "WAF 主规则集",
    "extends": ["./base.json"],
    "duplicatePolicy": "warn_skip"
  },
  "rules": [
    {
      "id": 3001,
      "tags": ["custom"],
      "target": "HEADER",
      "headerName": "User-Agent",
      "match": "CONTAINS",
      "pattern": "BadBot",
      "action": "DENY",
      "score": 30,
      "priority": 5
    }
  ]
}
EOF
```

### 5.3 规则文件说明

- **main.json**：入口规则文件，通过 `extends` 继承 `base.json`
- **base.json**：基础规则库，包含常见攻击防护规则
- **ALL_PARAMS**：自动展开为 `URI`、`ARGS_COMBINED`、`BODY` 三个目标
- **action 类型**：
  - `DENY`：拦截请求（返回 403）
  - `LOG`：仅记录日志
  - `BYPASS`：跳过后续检测（白名单）

---

## 6. 日志配置

### 6.1 日志文件位置

WAF v2 生成两类日志：

1. **JSONL 审计日志**（详细事件记录）
   - 默认路径：`/var/log/nginx/waf.jsonl`
   - 配置项：`waf_json_log` (在 `waf_core.conf` 中)

2. **Access 日志**（带 WAF 变量的访问日志）
   - 默认路径：`/var/log/nginx/access_waf.json`
   - 配置项：`access_log` (在 `waf_access_log.conf` 中)

### 6.2 JSONL 日志格式

JSONL 日志每行一个完整的 JSON 对象，包含：

```json
{
  "time": "2025-10-20T12:00:00Z",
  "clientIp": "192.168.1.100",
  "method": "GET",
  "host": "localhost",
  "uri": "/test?id=attack",
  "events": [
    {
      "type": "rule",
      "ruleId": 1001,
      "intent": "BLOCK",
      "scoreDelta": 50,
      "totalScore": 50,
      "matchedPattern": "attack",
      "target": "ARGS_COMBINED",
      "decisive": true
    }
  ],
  "finalAction": "BLOCK",
  "finalActionType": "BLOCK_BY_RULE",
  "currentGlobalAction": "BLOCK",
  "blockRuleId": 1001,
  "status": 403,
  "level": "ALERT"
}
```

### 6.3 Access 日志格式

Access 日志以 JSON 格式记录，包含 WAF 变量：

```json
{
  "ts": "1729425600.123",
  "ip": "192.168.1.100",
  "method": "GET",
  "uri": "/test?id=attack",
  "status": 403,
  "bytes": 162,
  "rt": 0.001,
  "ua": "curl/7.68.0",
  "ref": "",
  "blocked": 1,
  "waf_action": "BLOCK",
  "waf_rule": "1001",
  "waf_type": "sqli"
}
```

### 6.4 查看日志

```bash
# 查看 JSONL 审计日志（实时）
sudo tail -f /var/log/nginx/waf.jsonl | jq '.'

# 查看 Access 日志（实时）
sudo tail -f /var/log/nginx/access_waf.json | jq '.'

# 查看被拦截的请求
sudo grep '"finalAction":"BLOCK"' /var/log/nginx/waf.jsonl | jq '.'

# 查看特定规则触发的请求
sudo grep '"ruleId":1001' /var/log/nginx/waf.jsonl | jq '.'
```

---

## 7. 启动测试

### 7.1 验证配置

```bash
# 测试配置文件语法
sudo /usr/local/nginx/sbin/nginx -t

# 应该看到：
# nginx: the configuration file /usr/local/nginx/conf/nginx.conf syntax is ok
# nginx: configuration file /usr/local/nginx/conf/nginx.conf test is successful
```

### 7.2 启动 Nginx

```bash
# 启动
sudo /usr/local/nginx/sbin/nginx

# 或重载配置（如果已启动）
sudo /usr/local/nginx/sbin/nginx -s reload
```

### 7.3 测试 WAF 功能

**测试 1：正常请求（应返回 200）**
```bash
curl -i http://localhost:8080/

# 应看到 200 响应
```

**测试 2：触发规则 1001（URI 包含 "attack"，应返回 403）**
```bash
curl -i http://localhost:8080/test?id=attack

# 应看到 403 Forbidden
```

**测试 3：触发规则 1002（XSS 攻击，应返回 403）**
```bash
curl -i "http://localhost:8080/test?q=<script>alert(1)</script>"

# 应看到 403 Forbidden
```

**测试 4：触发规则 3001（恶意 User-Agent，应返回 403）**
```bash
curl -i -H "User-Agent: BadBot/1.0" http://localhost:8080/

# 应看到 403 Forbidden
```

**测试 5：白名单路径（应返回 200）**
```bash
curl -i http://localhost:8080/health

# 应看到 200 或 404（取决于文件是否存在），但不会被 WAF 拦截
```

### 7.4 查看日志验证

```bash
# 查看最新的 JSONL 日志
sudo tail -5 /var/log/nginx/waf.jsonl | jq '.'

# 查看最新的 Access 日志
sudo tail -5 /var/log/nginx/access_waf.json | jq '.'
```

---

## 8. 常见问题

### 8.1 编译问题

**问题：找不到 PCRE2 库**
```
./configure: error: the HTTP rewrite module requires the PCRE library.
```

**解决：**
```bash
sudo apt-get install libpcre2-dev  # Ubuntu/Debian
sudo yum install pcre2-devel       # CentOS/RHEL
```

---

**问题：找不到动态模块文件**
```
nginx: [emerg] module "/usr/local/nginx/modules/ngx_http_waf_module.so" not found
```

**解决：**
```bash
# 检查文件是否存在
ls -l /usr/local/nginx/modules/ngx_http_waf_module.so

# 如果不存在，重新复制
sudo cp nginx-src/objs/ngx_http_waf_module.so /usr/local/nginx/modules/
```

### 8.2 配置问题

**问题：规则文件找不到**
```
[alert] WAF failed to parse JSON from file: /usr/local/nginx/conf/waf/rules/main.json
```

**解决：**
```bash
# 检查文件是否存在
ls -l /usr/local/nginx/conf/waf/rules/main.json

# 检查 JSON 格式是否正确
jq '.' /usr/local/nginx/conf/waf/rules/main.json

# 检查文件权限
sudo chmod 644 /usr/local/nginx/conf/waf/rules/*.json
```

---

**问题：WAF 没有生效（请求未被拦截）**

**排查步骤：**

1. 检查 WAF 是否启用：
```bash
grep "waf on" /usr/local/nginx/conf/waf/waf_core.conf
```

2. 检查规则是否加载：
```bash
# 查看 error.log 中是否有 WAF 相关日志
sudo tail -100 /usr/local/nginx/logs/error.log | grep -i waf
```

3. 检查默认动作：
```bash
grep "waf_default_action" /usr/local/nginx/conf/waf/waf_core.conf
# 确保是 "block" 而不是 "log"
```

4. 测试配置并重载：
```bash
sudo /usr/local/nginx/sbin/nginx -t
sudo /usr/local/nginx/sbin/nginx -s reload
```

### 8.3 日志问题

**问题：没有生成 JSONL 日志文件**

**解决：**

1. 检查日志路径配置：
```bash
grep "waf_json_log" /usr/local/nginx/conf/waf/waf_core.conf
```

2. 检查目录权限：
```bash
sudo mkdir -p /var/log/nginx
sudo chmod 755 /var/log/nginx
```

3. 检查日志级别：
```bash
grep "waf_json_log_level" /usr/local/nginx/conf/waf/waf_core.conf
# 确保不是 "off"
```

4. 发送测试请求后检查：
```bash
curl http://localhost:8080/test?id=attack
sudo ls -lh /var/log/nginx/waf.jsonl
```

---

**问题：Access 日志中 WAF 变量为空**

**检查：**
```bash
# 确保引入了 waf_access_log.conf
grep "include waf/waf_access_log.conf" /usr/local/nginx/conf/nginx.conf

# 检查日志格式定义
grep "log_format waf_json" /usr/local/nginx/conf/waf/waf_access_log.conf
```

### 8.4 性能问题

**问题：WAF 导致请求延迟增加**

**优化建议：**

1. 调整日志缓冲：
```nginx
# 在 waf_access_log.conf 中
access_log /var/log/nginx/access_waf.json waf_json buffer=64k flush=500ms;
```

2. 减少规则复杂度：
   - 避免过于复杂的正则表达式
   - 使用 `CONTAINS` 替代 `REGEX`（当可以时）
   - 将高优先级规则（如白名单）的 `priority` 设置更高

3. 禁用动态封禁（如果不需要）：
```nginx
waf_dynamic_block_enable off;
```

### 8.5 调试技巧

**启用详细日志：**
```nginx
# 在 waf_core.conf 中
waf_json_log_level debug;  # 记录所有请求，包括正常请求

# 在 nginx.conf 中
error_log  logs/error.log debug;
```

**查看模块加载状态：**
```bash
sudo /usr/local/nginx/sbin/nginx -V 2>&1 | grep waf
```

**实时监控所有日志：**
```bash
# 终端1：监控 error.log
sudo tail -f /usr/local/nginx/logs/error.log

# 终端2：监控 waf.jsonl
sudo tail -f /var/log/nginx/waf.jsonl | jq '.'

# 终端3：监控 access_waf.json
sudo tail -f /var/log/nginx/access_waf.json | jq '.'
```

---

## 9. 下一步

### 9.1 进阶配置

- 查看 [README.md](README.md) 了解完整的 JSON 规则格式
- 学习 `extends` 继承机制实现规则复用
- 配置动态封禁功能防止恶意扫描

### 9.2 生产部署建议

1. **规则版本管理：**
```bash
sudo mkdir -p /usr/local/nginx/conf/waf/releases/{v1.0,v1.1,current}
sudo ln -sf /usr/local/nginx/conf/waf/releases/v1.0 /usr/local/nginx/conf/waf/releases/current
```

2. **日志轮转配置：**
```bash
sudo tee /etc/logrotate.d/nginx-waf > /dev/null <<'EOF'
/var/log/nginx/waf.jsonl {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        [ -f /usr/local/nginx/logs/nginx.pid ] && kill -USR1 `cat /usr/local/nginx/logs/nginx.pid`
    endscript
}
EOF
```

3. **监控告警：**
   - 配合 ELK/Loki 收集 JSONL 日志
   - 基于 `finalAction=BLOCK` 设置告警规则
   - 监控 `blockRuleId` 分布，识别攻击模式

### 9.3 集成控制面板

本项目配套提供了 **Web 控制面板**（NestJS 后端 + Vue3 前端）：

- 可视化规则编辑与发布
- 实时攻击监控与统计
- 规则版本管理与回滚

详见控制面板项目的部署文档。

---

## 🎉 完成！

恭喜你成功部署了 Nginx HTTP WAF v2！

如有问题，请检查：
1. `/usr/local/nginx/logs/error.log` - Nginx 错误日志
2. `/var/log/nginx/waf.jsonl` - WAF 审计日志
3. `/var/log/nginx/access_waf.json` - WAF 访问日志

**技术支持：** 查看 [README.md](README.md) 获取详细的 API 文档和故障排查指南。

