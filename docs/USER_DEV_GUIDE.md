## Nginx HTTP WAF v2 使用者 + 开发者说明书（通俗版）

本指南面向两类读者：
- 使用者（运维/后端工程师）：如何配置 Nginx 指令、如何编写规则 JSON、如何看日志、如何快速排错。
- 开发者（接手/扩展本项目的人）：指令与规则的边界、数据结构、合并与继承、运行期日志的决策逻辑。

与 v1 的“多指令+多规则文件”不同，v2 将“检测策略”结构化为 JSON 工件（rules.json），通过少量 Nginx 指令装配运行时设施与加载入口。你可以把指令理解为“开关与基础设施”，把规则 JSON 理解为“策略和匹配逻辑”。

---

### 1. 概览：两条主线

- 运维面（Nginx 指令，写在 nginx.conf）：
  - 负责启停、日志、共享内存、动态封禁总开关与全局参数、规则入口等。
- 数据面（规则 JSON，写在 rules.json）：
  - 负责“匹配什么、何时阻断/放行/只记日志”。支持继承（extends）、禁用父集（disableById/disableByTag）与去重策略（duplicatePolicy）。

一句话：指令决定“在哪儿、以什么模式跑”，规则 JSON 决定“拦截什么”。

---

### 2. 必要指令（先会用，再理解）

把下列片段加入 `http {}`，绝大多数场景就能跑通：

```nginx
# 日志与共享内存（MAIN 级，仅 http{}）
waf_json_log        /var/log/nginx/waf.jsonl;      # JSONL 审计日志（一次请求一行）
waf_json_log_level  info;                          # BYPASS/ALLOW 的落盘阈值；BLOCK 必落盘
waf_shm_zone        waf_dyn 32m;                   # 共享内存（动态封禁等）
waf_trust_xff       on;                            # 反向代理后取最左侧真实客户端 IP（可选）
waf_dynamic_block_score_threshold 100;             # 评分阈值（达到后封禁）
waf_dynamic_block_duration        30m;             # 封禁时长
waf_dynamic_block_window_size     1m;              # 计分窗口

# 规则入口与继承深度（LOC 级，可 http/server/location）
waf on;                                            # 模块开关（默认 on）
waf_default_action BLOCK;                          # 全局执法（BLOCK/LOG）
waf_dynamic_block_enable on;                       # 开启动态封禁（建议仅 http{} 设置一次）
waf_jsons_dir /usr/local/nginx/conf/waf/releases/current;  # 规则根目录
waf_rules_json /usr/local/nginx/conf/waf/releases/current/main.json; # 入口 JSON
waf_json_extends_max_depth 5;                      # 继承最大深度

# 建议：同时 include Access JSON 日志（含 $waf_* 变量）
include waf/waf_access_log.conf;                   # 默认输出 /var/log/nginx/access_waf.json
```

要点：
- MAIN 级（http{} 专属，不继承）：`waf_json_log*`、`waf_shm_zone`、`waf_trust_xff`、`waf_dynamic_block_*`、`waf_jsons_dir`。
- LOC 级（可继承/覆盖）：`waf`、`waf_default_action`、`waf_dynamic_block_enable`、`waf_rules_json`、`waf_json_extends_max_depth`。
- 最佳实践：`waf_dynamic_block_enable on;` 只在 http{} 设一次，让所有路径统一继承；静态目录或健康检查可在具体 location 关掉。

---

### 3. 规则 JSON（怎么写）

最小可用入口文件 `main.json`：

```json
{
  "version": 1,
  "meta": {
    "name": "main",
    "extends": ["./base.json"],
    "duplicatePolicy": "warn_skip"
  },
  "disableById": [200],
  "disableByTag": ["legacy"],
  "rules": [
    { "id": 400, "tags": ["ua"], "target": "HEADER", "headerName": "User-Agent", "match": "CONTAINS", "pattern": "BadBot", "action": "DENY", "score": 30, "priority": 5 }
  ]
}
```

常用字段速记：
- 顶层：
  - `meta.extends`: 继承父规则（可多层），字符串或对象（对象形态可对父集做“按标签/ID 批量重写 target”）。
  - `disableById` / `disableByTag`: 仅移除父集中不想要的规则；不影响本地 `rules`。
  - `meta.duplicatePolicy`: `error|warn_skip|warn_keep_last`，控制“本层可见集合”的 ID 去重策略。
- 规则项 Rule：
  - `id:number`（必填，正整数，集合内唯一）
  - `target:"CLIENT_IP|URI|ALL_PARAMS|ARGS_COMBINED|ARGS_NAME|ARGS_VALUE|BODY|HEADER"`（可为数组；`ALL_PARAMS` 会展开为 URI/ARGS_COMBINED/BODY）
  - `headerName:string`（当 `target=HEADER` 时必填，且不得与其他 target 混用）
  - `match:"CONTAINS|EXACT|REGEX|CIDR"`
  - `pattern:string|string[]`（数组为 OR；元素必须非空）
  - `caseless?:boolean`、`negate?:boolean`
  - `action:"DENY|LOG|BYPASS"`（BYPASS 用于白名单）
  - `score?:number`（默认 10；BYPASS 禁止出现）
  - `priority?:number`（默认 0；用于稳定排序）

三条常见示例：

```json
{ "id": 1001, "target": "ALL_PARAMS", "match": "CONTAINS", "pattern": "eval(", "action": "DENY", "score": 20 }
```

```json
{ "id": 2001, "target": "URI", "match": "EXACT", "pattern": "/health", "action": "BYPASS" }
```

```json
{ "id": 3001, "target": "HEADER", "headerName": "User-Agent", "match": "CONTAINS", "pattern": "BadBot", "action": "LOG", "score": 1 }
```

继承 + 重写 + 禁用（对象形态 extends）：

```json
{
  "meta": {
    "extends": [
      "./base.json",
      { "file": "./child.json", "rewriteTargetsForTag": { "apply:multi-surface": ["ALL_PARAMS"] } }
    ],
    "duplicatePolicy": "warn_keep_last"
  },
  "disableById": [200],
  "rules": []
}
```

---

### 4. 指令与规则的关系（谁负责什么）

- 指令决定“运行期设施与边界”：
  - JSONL 输出位置与阈值（`waf_json_log*`）
  - 共享内存与动态封禁（`waf_shm_zone`、`waf_dynamic_block_*`、`waf_dynamic_block_enable`）
  - 真实客户端 IP 获取（`waf_trust_xff`）
  - 入口工件（`waf_jsons_dir` + `waf_rules_json`）
  - 默认执法策略（`waf_default_action`）

- 规则 JSON 决定“策略与匹配”：
  - 匹配目标/匹配方式/模式
  - 决策：DENY（阻断）、LOG（仅记）、BYPASS（白名单）
  - 分值：配合动态封禁的信誉计分
  - 组织方式：继承/禁用/去重

经验法则：
- “要不要拦”由 `waf_default_action + 规则 action` 一起决定；`BLOCK` 时命中 DENY 直接 403。
- “要不要记”由 `waf_json_log_level + finalAction` 决定：BLOCK 必记；BYPASS/ALLOW 达到阈值才记；空事件的 ALLOW 不落盘。
- “会不会被后续封禁”由动态封禁的阈值、时长、窗口与 score 累积决定。

---

### 5. 日志与观测（两类，别混淆）

1) JSONL 审计日志（结构化、一次请求一行）

配置：

```nginx
waf_json_log        /var/log/nginx/waf.jsonl;
waf_json_log_level  info;      # off|debug|info|alert|error；BLOCK 必落盘（至少 alert）
```

关键字段：`finalAction|finalActionType|currentGlobalAction|blockRuleId|events[]|status|level`。

2) Access JSON 日志（含 $waf_* 变量）

启用：

```nginx
include waf/waf_access_log.conf; # 默认 /var/log/nginx/access_waf.json
```

用途：用于和业务 access 观察对齐（是否被拦、命中哪个 ruleId、耗时等）。

---

### 6. 快速排错清单

- 没有 `waf.jsonl`：
  - 检查 `waf_json_log` 路径、目录权限、`waf_json_log_level` 是否为 `off`。
  - BLOCK 请求必然落盘；若没有 BLOCK，请调低阈值为 `info` 做观察。
- `access_waf.json` 无输出：确认已 `include waf/waf_access_log.conf`。
- 规则不生效：
  - `waf on;` 是否开启、`waf_rules_json` 路径是否正确、JSON 是否合法（可用 `jq` 检查）。
  - `waf_default_action` 是否为 `LOG`（仅记录不拦截）。
- 动态封禁不生效：
  - `waf_dynamic_block_enable on;` 是否在 http{} 设置。
  - 评分阈值/窗口/时长是否合适；是否存在高分规则。

---

### 7. 给开发者：实现要点速读

- 指令实现位置：`src/module/ngx_http_waf_config.c`（解析/存储作用域）；
- 规则解析与合并：`src/json/ngx_http_waf_json.c`（入口 JSON → 继承/重写/禁用/去重 → 只读快照）；
- 编译期校验与规则装配：`src/core/ngx_http_waf_compiler.c`（target 约束、HEADER 限制、ALL_PARAMS 展开、phase 推断等）；
- 运行期执法与日志：`src/core/ngx_http_waf_log.c`（events 聚合、decisive 选择、finalAction 计算、落盘策略）。

语义边界：
- MAIN（http{}）仅存放全局设施与参数（日志、共享内存、waf_jsons_dir、动态封禁全局参数、XFF）；
- LOC（http/server/location）可继承覆盖策略开关与入口工件；
- JSON 的 `policies` 在 v2.0 透传，不参与 M1 合并；动态封禁“基础访问分”等策略留给 JSON（如 `policies.dynamicBlock.baseAccessScore`）。

日志决策（实现对齐 `waf-jsonl-spec-v2.0.md`）：
- BLOCK：必落盘（至少 `alert`），带 `blockRuleId`/`finalActionType`。
- BYPASS：强制落盘；
- 其他 ALLOW：`effective_level >= waf_json_log_level` 才落盘；空事件 ALLOW 不落盘。

---

### 8. 最小可跑示例（整合）

`nginx.conf` 关键片段：

```nginx
load_module modules/ngx_http_waf_module.so;

events { worker_connections 1024; }

http {
    include       mime.types;
    default_type  application/octet-stream;

    # MAIN/LOC 指令
    waf_json_log        /var/log/nginx/waf.jsonl;
    waf_json_log_level  info;
    waf_shm_zone        waf_dyn 32m;
    waf_trust_xff       on;
    waf_dynamic_block_score_threshold 100;
    waf_dynamic_block_duration 30m;
    waf_dynamic_block_window_size 1m;

    waf on;
    waf_default_action BLOCK;
    waf_dynamic_block_enable on;
    waf_jsons_dir /usr/local/nginx/conf/waf/releases/current;
    waf_rules_json /usr/local/nginx/conf/waf/releases/current/main.json;

    include waf/waf_access_log.conf;

    server { listen 8080; server_name localhost; location / { root html; index index.html; } }
}
```

`/usr/local/nginx/conf/waf/releases/current/main.json`：

```json
{ "version":1, "meta":{ "name":"main", "extends":["./base.json"], "duplicatePolicy":"warn_skip" }, "rules": [] }
```

`/usr/local/nginx/conf/waf/releases/current/base.json`：

```json
{
  "version": 1,
  "meta": { "name": "base", "tags": ["baseline"] },
  "rules": [
    { "id": 1001, "target": "ALL_PARAMS", "match": "CONTAINS", "pattern": "attack", "caseless": true, "action": "DENY", "score": 50 },
    { "id": 2001, "target": "URI", "match": "EXACT", "pattern": "/health", "action": "BYPASS" }
  ]
}
```

验证：

```bash
nginx -t && nginx -s reload
curl -i "http://127.0.0.1:8080/?q=attack"        # 403
tail -n1 /var/log/nginx/waf.jsonl                 # 观察 BLOCK 事件
tail -n1 /var/log/nginx/access_waf.json           # 观察 access 带 $waf_*
```

---

如需“更系统”的字段与行为细节，请在理解本指南后再对照：
- `docs/waf-directives-spec-v2.0.md`（指令完整语义与作用域）
- `docs/waf-json-spec-v2.0-simplified.md`（规则 JSON 合并与字段校验）
- `docs/waf-jsonl-spec-v2.0.md`（JSONL 日志字段与落盘策略）

这三份是事实标准；本指南是“易读索引”。

---

### 9. 实战示例（可直接复制）

以下示例均可直接放入某个入口 JSON 的 `rules` 数组中使用；如需模块化，建议将示例拆成独立 `json` 文件并在入口通过 `meta.extends` 引入。

9.1 IP 白名单（BYPASS）

场景：公司办公网段、内网网段完全放行。

```json
{
  "id": 510001,
  "tags": ["ip", "whitelist"],
  "target": "CLIENT_IP",
  "match": "CIDR",
  "pattern": ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"],
  "action": "BYPASS"
}
```

说明：BYPASS 用于“强白名单”，命中即放行且在 JSONL 中 `finalAction=BYPASS`，不再执行后续 DENY 规则。

9.2 IP 黑名单（DENY）

场景：明确恶意 IP 或高风险来源直接阻断。

```json
{
  "id": 520001,
  "tags": ["ip", "blacklist"],
  "target": "CLIENT_IP",
  "match": "CIDR",
  "pattern": ["203.0.113.0/24", "198.51.100.23/32"],
  "action": "DENY",
  "score": 100
}
```

说明：配合较高 `score` 有助于触发动态封禁评分（若开启），但是否拦截取决于 `waf_default_action`（默认 BLOCK）。

9.3 URI 白名单（BYPASS）

场景：健康检查、静态资源或对内调试端点放行。

```json
{ "id": 530001, "tags": ["uri", "whitelist"], "target": "URI", "match": "EXACT", "pattern": "/health", "action": "BYPASS" }
```

```json
{ "id": 530002, "tags": ["uri", "whitelist"], "target": "URI", "match": "EXACT", "pattern": "/status", "action": "BYPASS" }
```

9.4 SQL 注入防范（基础基线）

场景：对常见 SQLi 关键词/模式进行检测；建议配合 `ALL_PARAMS`，涵盖 URI、查询串与表单 BODY。

```json
{
  "id": 540001,
  "tags": ["sqli", "baseline"],
  "target": "ALL_PARAMS",
  "match": "REGEX",
  "pattern": "(?i)(union\\s+select|select\\s+.*\\s+from|insert\\s+into|update\\s+.+\\s+set|delete\\s+from)",
  "action": "DENY",
  "score": 50,
  "priority": 10,
  "caseless": true
}
```

```json
{
  "id": 540002,
  "tags": ["sqli", "baseline"],
  "target": "ALL_PARAMS",
  "match": "CONTAINS",
  "pattern": ["' or '1'='1", "\" or \"1\"=\"1", "-- ", "/*"],
  "action": "DENY",
  "score": 40,
  "priority": 10,
  "caseless": true
}
```

```json
{
  "id": 540003,
  "tags": ["sqli", "baseline"],
  "target": "ALL_PARAMS",
  "match": "REGEX",
  "pattern": "(?i)information_schema|sleep\\s*\\(|benchmark\\s*\\(",
  "action": "DENY",
  "score": 50,
  "priority": 10,
  "caseless": true
}
```

实践建议：
- 先将 `waf_default_action LOG;` 运行一段时间观察 JSONL，确认低误报后再切回 `BLOCK`。
- 结合动态封禁：将多条低权重命中（score）累积到阈值后封禁噪声 IP；关键高危规则设置更高 score 实现快速封禁。
- 对业务白名单路径（如 `/health`、`/status`、部分静态资源）优先添加 BYPASS，减少不必要检测。


