# Nginx HTTP WAF Module (v2.0)

> 🛡️ **High-Performance, Native C, JSON-Based Web Application Firewall for Nginx**
>
> *Build for Modern DevOps & High Concurrency*

---

## 📖 简介

**Nginx HTTP WAF v2** 是一款专为高并发生产环境设计的 Nginx 原生安全模块（Dynamic Module）。

相比于传统的 WAF，v2 版本彻底重构了数据面架构，引入了 **"Configuration as Code"** 的设计理念。它利用 **JSON** 定义规则，支持复杂的继承与重写机制，使得安全策略的管理像代码一样灵活可控。同时，基于 **C 语言** 实现的“胖数据面”保证了在极低延迟下完成复杂的 SQLi/XSS 检测、动态信誉评分与自动封禁。

---

## 🌟 核心亮点 (Why v2?)

### 🧩 1. 控制面解耦 (Control Plane Ready)
**这是 v2 重构的根本契机。**
我们放弃了晦涩的专有配置文件，拥抱标准的 **JSON** 生态。
*   **API 友好**: 无论是 Web 控制台（如 NestJS 后端）、CI/CD 流水线还是 AI 运维 Agent，都可以轻松生成、解析和校验 WAF 规则。
*   **结构化表达**: 利用 JSON 的对象结构，实现了强大的 **继承 (`extends`)**、**重写 (`rewrite`)** 和 **去重 (`duplicatePolicy`)** 机制。这让管理成百上千条规则变得井井有条。
*   **审计友好**: 审计日志采用 **JSONL** 格式，每行一个 JSON 对象，天然适配 ELK/ClickHouse 等大数据分析平台。

### 🚀 2. 极致性能 (Performance First)
*   **原生 C 实现**: 零依赖，基于 Nginx 内存池构建，拒绝 GC 暂停。
*   **胖数据面 (Fat Data Plane)**: 复杂的规则继承、去重全部在 Nginx 启动阶段完成。运行时**零解析**，只有高效的查表与位运算。
*   **五段流水线**: 精心编排的 `IP -> Reputation -> URI -> Detect` 流水线，短路机制确保 99% 的请求在低开销阶段即可完成判定。
*   **零拷贝解码**: 智能的 Request-Level Cache，确保 URI/Args/Body 只解码一次，拒绝重复计算。

### 🤖 3. 现代防御体系 (Modern Security)
*   **动态信誉系统 (Dynamic Reputation)**: 每一个 IP 都有“信誉分”。攻击不是单点的，而是累积的。超过阈值自动封禁（Block），并支持跨 Worker 进程共享状态。
*   **Decisive Trace**: 智能标记“压死骆驼的最后根稻草”（Decisive Event），在成百上千条规则中瞬间定位拦截原因，告别盲猜。

---

## 📚 文档导航

我们为您准备了生产级的详细文档：

| 文档类型 | 链接 | 说明 |
| :--- | :--- | :--- |
| **架构指南** | 👉 **[docs/architecture-v2.md](docs/architecture-v2.md)** | **开发者必读**。深入理解“胖数据面”、“短路控制流”与“异步时序”。 |
| **Nginx 指令** | [friendly-waf-directives-spec-v2.0.md](docs/friendly-waf-directives-spec-v2.0.md) | `waf_rule_json`, `waf_mode` 等配置详解。 |
| **JSON 规则** | [friendly-waf-json-spec-v2.0.md](docs/friendly-waf-json-spec-v2.0.md) | 规则文件结构、继承机制与编写指南。 |
| **审计日志** | [friendly-waf-jsonl-spec-v2.0.md](docs/friendly-waf-jsonl-spec-v2.0.md) | JSONL 日志字段全解析。 |

---

## 🏗️ 架构流水线

```text
       [ Request ]
            ⬇
    +------------------+
    |   Nginx Worker   |
    +------------------+
            ⬇
+--------------------------+
|  WAF v2 Pipeline (C)     |
|                          |
|  1. [IP Allow]           | --> (Bypass)
|  2. [IP Deny]            | --> (Block)
|  3. [Dynamic Reputation] | <-> [Shared Memory] (Score/Ban)
|  4. [URI Check]          |
|  5. [Detect Bundle]      | --> (Rule Matching: SQLi/XSS/...)
|                          |      ⬆
+--------------------------+       | (Compiled Snapshot)
            ⬇                     |
    [ Upstream / Static ]    [ JSON Rules Engine ]
                                  ⬆
                             (extends/merge)
                                  ⬆
                          [ .json Config Files ]
```

---

## 🧠 深度架构解析 (TL;DR)

> 💡 想了解完整实现细节？请阅读 [docs/architecture-v2.md](docs/architecture-v2.md)。

### 1. 规则引擎设计：编译期平铺
v2 规则引擎的核心思想是 **“把复杂留给启动期，把简单留给运行期”**。
*   **继承与重写**: 在 Nginx 启动（或 Reload）时，解析器会递归加载所有 JSON 文件，处理 `extends` 继承关系，并将所有规则“平铺”到一个线性数组中。
*   **内存快照**: 编译器（Compiler）将这个线性数组转换为高效的内存快照 (`waf_compiled_snapshot_t`)，并按 Phase 和 Target 进行分桶。运行时无需任何 JSON 解析开销。

### 2. 五段流水线 (Pipeline)
WAF 的处理逻辑被严格划分为五个阶段，每一步都对应特定的防护目标：
1.  **IP Allow**: 白名单 IP 直接放行（Bypass）。
2.  **IP Deny**: 黑名单 IP 直接拦截（Block）。
3.  **Dynamic Reputation**: 检查 IP 动态信誉分与封禁状态。
4.  **URI Allow**: 静态资源或特定 API 白名单放行。
5.  **Detect Bundle**: 执行核心规则检测（SQLi, XSS, Body Check 等）。

### 3. 动态信誉与共享内存
*   我们不依赖外部数据库（如 Redis），而是直接使用 Nginx 的 **Shared Memory**。
*   这意味着所有 Worker 进程共享同一份 IP 信誉数据。一个 Worker 封禁了 IP，所有 Worker 立即生效。
*   使用红黑树（Rbtree）和 LRU 队列管理 IP 状态，实现了极高的读写性能。

---

## 🔧 配置与规则速览 (TL;DR)

> 💡 即使不读长篇文档，看这三段代码你也能明白 v2 怎么用。

### 1. Nginx 指令 (`nginx.conf`)
v2 的指令设计极简，主要负责“环境初始化”和“文件引用”。

```nginx
waf on;                                     # 总开关
waf_shm_zone waf_zone 10m;                  # 申请 10MB 共享内存用于 IP 信誉
waf_jsons_dir /etc/nginx/waf/rules;         # JSON 规则根目录

# 引用入口规则文件
waf_rules_json user_policy.json;

# 审计日志
waf_json_log /var/log/nginx/waf.jsonl;
waf_json_log_level info;

# 动态封禁策略
waf_dynamic_block_enable on;
waf_dynamic_block_score_threshold 100;      # 累计扣分超 100 即自动封禁
```
👉 *完整指令手册：[friendly-waf-directives-spec-v2.0.md](docs/friendly-waf-directives-spec-v2.0.md)*

### 2. 规则 JSON (`user_policy.json`)
支持继承 (`extends`)，这意味着你不需要重写成千上万条基础规则，只需“引用”它们，然后写你自己的业务规则。

```json
{
  "meta": {
    "name": "My App Policy",
    /* 继承核心规则集，站在巨人的肩膀上 */
    "extends": [ "../core/core_sqli_rules.json", "../core/core_xss_rules.json" ],
    /* 遇到 ID 冲突时，保留最后加载的（覆盖旧规则） */
    "duplicatePolicy": "warn_keep_last"
  },
  /* 批量禁用某些误报规则 */
  "disableById": [ 20001, 20005 ],
  "rules": [
    /* 你的自定义规则：拦截 Query 参数中的 'admin' */
    {
      "id": 90001,
      "target": "ARGS_COMBINED",
      "match": "CONTAINS",
      "pattern": "admin",
      "action": "DENY",
      "score": 10
    }
  ]
}
```
👉 *完整规则指南：[friendly-waf-json-spec-v2.0.md](docs/friendly-waf-json-spec-v2.0.md)*

### 3. 审计日志 (`waf.jsonl`)
一行 JSON 讲清楚所有故事。谁来的？干了什么？为什么被拦截？

```json
{
  "time": "2025-12-07T12:00:00Z",
  "clientIp": "1.2.3.4",
  "uri": "/login?user=admin",
  "finalAction": "BLOCK",            // 最终被拦截了
  "finalActionType": "BLOCK_BY_RULE",
  "blockRuleId": 90001,              // 罪魁祸首是 ID 90001
  "events": [
    {
      "type": "rule",
      "ruleId": 90001,
      "intent": "BLOCK",
      "scoreDelta": 10,              // 扣了 10 分
      "decisive": true               // ★ 致命一击：是这条规则导致了拦截
    }
  ]
}
```
👉 *完整日志字段：[friendly-waf-jsonl-spec-v2.0.md](docs/friendly-waf-jsonl-spec-v2.0.md)*

---

## ⚡ 快速上手与部署

### 1. 编译安装 (交互式脚本)

我们提供了一个方便的交互式脚本 `script/interactive_build.sh`，可自动下载 Nginx 源码并完成编译安装。

**步骤**:
1. **克隆仓库**:
   ```bash
   git clone https://github.com/tyx3211/nginx-http-waf-module-v2.git
   cd nginx-http-waf-module-v2
   ```

2. **运行交互式脚本**:
   ```bash
   chmod +x script/interactive_build.sh
   ./script/interactive_build.sh
   ```
   *脚本会提示输入 Nginx 版本（默认 1.24.0）、安装路径（默认 `/usr/local/nginx`）等信息，确认后自动开始下载、编译并安装。*

### 2. 手动编译 (高级用户)

如果您偏好手动控制或已有 Nginx 源码：

1. **下载 Nginx 源码**: [nginx.org](http://nginx.org/en/download.html)
2. **Configure**:
   ```bash
   ./configure --prefix=/usr/local/nginx \
               --with-compat \
               --add-dynamic-module=/path/to/nginx-http-waf-module-v2 \
               # 其他您需要的模块...
   ```
3. **Build & Install**:
   ```bash
   make && sudo make install
   ```
4. **部署规则**:
   将 `WAF_RULES_JSON` 目录复制到 `/usr/local/nginx/WAF_RULES_JSON`。

### 3. 配置 Nginx

**推荐配置**：直接使用我们提供的模板 `doc/gotestwaf.nginx.conf`（已包含最佳实践配置）。

```bash
sudo cp nginx-http-waf-module-v2/doc/gotestwaf.nginx.conf /usr/local/nginx/conf/nginx.conf
```

**或者手动修改 `nginx.conf`**:

在 `http {}` 块中添加：

```nginx
# 加载模块 (若编译为动态模块)
load_module modules/ngx_http_waf_module.so;

http {
    # ...
    
    # --- WAF 核心配置 ---
    waf on;
    waf_shm_zone waf_block_zone 10m;            # 动态信誉共享内存
    waf_jsons_dir WAF_RULES_JSON;               # 规则根目录(相对prefix)
    
    # 入口规则文件 (推荐继承核心集)
    waf_rules_json user/gotestwaf_user_rules.json;

    # 审计日志
    waf_json_log logs/waf.jsonl;
    waf_json_log_level info;

    # 执法策略
    waf_default_action block;
    waf_dynamic_block_enable on;                # 开启动态封禁
    waf_dynamic_block_score_threshold 100;      # 封禁阈值
    # -------------------
}
```

---

## ✅ 启动与验证

```bash
sudo /usr/local/nginx/sbin/nginx
# 或重载
sudo /usr/local/nginx/sbin/nginx -s reload
```

**验证方法**:
1. **简单测试**:
   访问 `http://localhost:8080/?id=1'%20or%20'1'='1`，应返回 `403 Forbidden`。
   查看日志：`tail -f /usr/local/nginx/logs/waf.jsonl`。

2. **GoTestWAF 完整测试**:
   (推荐) 使用 `gotestwaf` 配合本项目提供的测试用例集：
   ```bash
   # 安装 gotestwaf
   go install github.com/gotenberg/gotestwaf@latest
   
   # 运行测试，注意将路径替换为clone本项目的gotestwaf_testcases的绝对路径
   ~/go/bin/gotestwaf --url http://localhost:8080/ \
     --blockStatusCodes 403 \
     --testCasesPath /path/to/nginx-http-waf-module-v2/gotestwaf_testcases
   ```
   *预期结果：评分 A+ (90分以上)*

   预期测试图片：
   ![GoTestWaf测试结果](doc/gotestwaf.png)

   测试结果html见[doc/waf-evaluation-report-2025-December-07-23-35-30.html](doc/waf-evaluation-report-2025-December-07-23-35-30.html)

---

## 📂 目录结构说明

- `script/`: 包含交互式构建脚本 `interactive_build.sh`。
- `nginx-http-waf-module-v2/`: 模块 v2 核心源码。
  - `src/`: C 代码实现。
  - `WAF_RULES_JSON/`: 官方规则集仓库。
  - `docs/`: 详细设计文档与规范。
  - `doc/`: gotestwaf相关测试文档。
- `gotestwaf_testcases/`: 专用测试用例集。
