### Nginx HTTP WAF v2 接入指南（供 NestJS 后端与 Vue3 前端使用）

本指南面向下游控制台（NestJS 后端 + Vue3 前端），提供“可发布、可回滚、可校验”的对接契约：
- 规则 JSON（数据面）字段与取值一览（严格以当前实现为准）
- Nginx 指令（运维面）完整清单与作用域
- JSONL 请求日志字段定义（一次请求最多一行）

注：下文内容以仓库 `src/` 真实实现为基准，已与以下核心源码交叉校对：
- 指令注册与配置：`src/module/ngx_http_waf_config.c`
- 规则 JSON 解析与合并：`src/json/ngx_http_waf_json.c`
- 编译期快照与字段校验：`src/core/ngx_http_waf_compiler.c`
- JSONL 日志实现：`src/core/ngx_http_waf_log.c`

---

## 1. 规则 JSON（数据面）

入口 JSON 顶层对象，支持注释与尾逗号（宽容解析）。最终合并后的产物由模块在加载时生成（不可变）。

### 1.1 顶层字段
- version: number（可选）。仅透传，不参与合并。
- meta: object（可选，分层生效项仅用于本层合并时读取，最终产物保留入口层 meta）
  - name: string（可选）
  - versionId: string（可选）
  - tags: string[]（可选；仅信息标识，不参与合并规则）
  - extends: Array<string | object>（可选；父规则文件列表，左→右递归合并）
    - 字符串：路径（绝对/相对），解析规则见“路径解析”。
    - 对象：{ file: string; rewriteTargetsForTag?: Record<string, Target[]>; rewriteTargetsForIds?: Array<{ ids: number[]; target: Target[] }>}。
      - rewriteTargetsForTag：对 imported_set 中包含指定标签的规则，批量重写其 target。
      - rewriteTargetsForIds：对 imported_set 中命中 id 的规则，批量重写其 target。
  - duplicatePolicy: "error" | "warn_skip" | "warn_keep_last"（默认：warn_skip；本层合并结束时执行去重策略）。
- disableById: number[]（可选；仅过滤 imported_set，不影响本地 rules）
- disableByTag: string[]（可选；仅过滤 imported_set，不影响本地 rules）
- rules: Rule[]（必填；本地规则集合，追加在 imported_set 之后，再统一去重）
- policies: object（可选；当前版本透传到内存快照，未参与 M1 合并与执法）

路径解析：
- 绝对路径原样；以 `./`、`../` 开头相对当前 JSON 所在目录；否则相对 `waf_jsons_dir`（若配置）或 Nginx prefix。解析后统一规范化。

循环与深度：
- 检测 extends 循环（报错信息包含“extends cycle detected”）；深度上限由指令 `waf_json_extends_max_depth` 控制（0 表示不限）。

### 1.2 Rule 项完整字段与取值
每条规则必须为对象，且仅允许以下字段（多余字段将报错）：
- id: number（必填，正整数；集合内作为去重键）
- tags: string[]（可选）
- phase: "ip_allow" | "ip_block" | "uri_allow" | "detect"（可选）
- target: Target | Target[]（必填；支持数组表示多目标独立评估）
- headerName: string（当 target=HEADER 时必填；其他 target 禁止出现）
- match: "CONTAINS" | "EXACT" | "REGEX" | "CIDR"（必填）
- pattern: string | string[]（必填；数组为 OR；字符串/数组元素不得为空）
- caseless: boolean（可选；默认 false）
- negate: boolean（可选；默认 false）
- action: "DENY" | "LOG" | "BYPASS"（必填）
- score: number（可选；默认 10；当 action=BYPASS 禁止出现）

Target 取值全集（严格与实现一致）：
- "CLIENT_IP" | "URI" | "ALL_PARAMS" | "ARGS_COMBINED" | "ARGS_NAME" | "ARGS_VALUE" | "BODY" | "HEADER"
- 语义与约束：
  - ALL_PARAMS：在解析期自动展开为 ["URI","ARGS_COMBINED","BODY"]，最终规则不保留字面 ALL_PARAMS。
  - HEADER：当 target 包含 HEADER 时：
    - 必须提供非空 `headerName`；
    - 严禁与其他目标混用（target 不得再包含其他项）。
  - CLIENT_IP：`match=CIDR` 时编译期预解析；`BYPASS`→`ip_allow`，`DENY`→`ip_block` 推断/校验。

组合与校验（编译期 `src/core/ngx_http_waf_compiler.c`）：
- phase 显式提供时将严格校验 `phase/target/action` 组合：
  - ip_allow: target 必须为 CLIENT_IP 且 action=BYPASS
  - ip_block: target 必须为 CLIENT_IP 且 action=DENY
  - uri_allow: target 必须为 URI 且 action=BYPASS
  - detect: 其他组合
- 未显式给出 phase 时按上述规则从 target+action 推断。

duplicatePolicy 去重（解析期按层执行，键=id）：
- error：发现重复 id 立即报错
- warn_skip（默认）：保留首次，忽略其后
- warn_keep_last：保留最后一次出现（位置覆盖首个位置，保持整体顺序语义）

禁用 imported_set（只作用父集）：
- disableById：移除命中的规则 id
- disableByTag：规则含任一本条禁用标签即移除

导入级重写（仅作用于本层 imported_set，不回写父文件）：
- rewriteTargetsForTag：按标签重写父集规则目标
- rewriteTargetsForIds：按 id 集合重写父集规则目标

示例（片段）：
```json
{
  "meta": {
    "extends": [
      "./base.json",
      { "file": "./child.json", "rewriteTargetsForTag": { "apply:multi-surface": ["URI","ARGS_COMBINED","BODY"] } }
    ],
    "duplicatePolicy": "warn_keep_last"
  },
  "disableById": [200],
  "disableByTag": ["legacy"],
  "rules": [
    { "id": 300001, "target": "HEADER", "headerName": "User-Agent", "match": "CONTAINS", "pattern": "BadBot", "action": "LOG", "score": 1 }
  ]
}
```

---

## 2. Nginx 指令（运维面）

指令以模块实现为准（`src/module/ngx_http_waf_config.c`）。括号内为作用域：MAIN 仅 http{}，LOC 为 http/server/location。

MAIN（全局，不继承）
- waf_jsons_dir <dir>：规则 JSON 根目录
- waf_json_log <path|off>：JSONL 日志文件路径；设为 `off` 关闭
- waf_json_log_level off|debug|info|alert|error：日志级别阈值（BLOCK 至少 alert 强制落盘）
- waf_shm_zone <name> <size>：共享内存区（动态封禁等）
- waf_trust_xff on|off：是否信任 X-Forwarded-For（取最左 IP）
- waf_dynamic_block_score_threshold <number>：封禁阈值（默认 100）
- waf_dynamic_block_duration <time>：封禁持续时长（默认 30m）
- waf_dynamic_block_window_size <time>：评分窗口（默认 1m）

LOC（可继承/覆盖）
- waf on|off：模块开关（默认 on）
- waf_default_action block|log：全局执法策略（默认 block）；与日志 `currentGlobalAction` 对应
- waf_dynamic_block_enable on|off：是否启用动态封禁（默认 off；建议仅 http{} 设置一次）
- waf_rules_json <path>：入口规则文件（解析合并后在本作用域生效）
- waf_json_extends_max_depth <uint>：extends 最大深度（默认 5；0 表示不限）

注意：
- `waf_json_log` 写入采用 Nginx open_files 句柄，支持 USR1 reopen；未配置路径则仅输出 error_log 摘要。
- `waf off` 时该作用域完全旁路（不检测、不加分、不封禁、不写 JSONL）。

### 快速 include 接入（access 日志 + WAF 核心）

在 `http {}` 中加入：

```
include waf/waf_core.conf;       # 模块指令集中定义
include waf/waf_access_log.conf; # 输出 access_waf.json（含 $waf_*）
```

更多“快速交付”说明见 `docs/quick-implementation.md`。

部署建议：将两份 conf 安装至 `/usr/local/nginx/conf/waf/` 目录（本仓库提供示例：`conf/waf/waf_core.conf` 与 `conf/waf/waf_access_log.conf`）。
示例（加入 http{}）：
```
include waf/waf_core.conf;
include waf/waf_access_log.conf;
```


---

## 3. JSONL 日志（一次请求最多一行）

顶层字段（`src/core/ngx_http_waf_log.c`）：
- time: string（UTC ISO8601）
- clientIp: string（文本 IP）
- method: string
- host?: string（可选）
- uri: string
- events: array<object>（见下）
- finalAction: string（BLOCK | BYPASS | ALLOW）
- finalActionType: string（ALLOW | BYPASS_BY_IP_WHITELIST | BYPASS_BY_URI_WHITELIST | BLOCK_BY_RULE | BLOCK_BY_REPUTATION | BLOCK_BY_IP_BLACKLIST | BLOCK_BY_DYNAMIC_BLOCK）
- currentGlobalAction: string（BLOCK | LOG；来自生效的 `waf_default_action`）
- blockRuleId?: uint（当 finalActionType=BLOCK_BY_RULE 时出现）
- status?: uint（最终 HTTP 状态；BLOCK/BYPASS 路径会被设置）
- level: string（DEBUG | INFO | ALERT | ERROR | NONE；最终日志级别文本）

events 类型与字段：
- type="rule"：规则事件
  - ruleId: uint
  - intent?: "BLOCK" | "LOG" | "BYPASS"
  - scoreDelta?: uint
  - totalScore: uint
  - matchedPattern?: string
  - patternIndex?: uint
  - target?: string（命中目标标签）
  - negate?: bool
  - decisive?: bool（仅在最终决策事件上会标记，最多 1 次）
- type="reputation"：信誉加分
  - scoreDelta?: uint
  - totalScore: uint
  - reason?: string
- type="ban"：进入动态封禁窗口
  - window: uint(ms)
- type="reputation_window_reset"：信誉窗口到期清零
  - prevScore: uint
  - windowStartMs: uint
  - windowEndMs: uint
  - reason: "window_expired"
  - category: "reputation/dyn_block"

落盘策略：
- finalAction=BLOCK：必落盘（至少 alert）
- finalAction=BYPASS：强制落盘
- 其他（ALLOW）：若 `effective_level >= waf_json_log_level` 才落盘；空事件且 ALLOW 不落盘

decisive 选择规则：
- BYPASS：最后一条 intent=BYPASS 的规则事件
- BLOCK_BY_DYNAMIC_BLOCK：最后一条 ban 事件；若无，则回退到规则事件策略
- BLOCK_BY_RULE：优先匹配 blockRuleId 的规则事件；若无，则回退到“最后一条 intent=BLOCK 的规则事件”

---

## 4. 对接建议（最小实现）

后端（NestJS）：
- POST /policies/validate：上传 JSON/JSONL（JSON 模式）做 schema/业务校验，返回诊断（可复用本仓库测试器或嵌入 yyjson + 轻量校验）。
- POST /policies/publish：原子落盘至版本目录（软链 current 切换）并执行 `nginx -s reload`。
- POST /policies/rollback：切回历史版本目录并 reload。
- GET /waf/status：读取运行中模块状态、最近发布版本与日志样例。

前端（Vue3）：
- 策略编辑/校验/发布/回滚；对 imported_set 的“重写/禁用”提供可视化辅助。

目录与原子发布建议：
- `/usr/local/nginx/conf/waf/releases/<semver-or-ts>/rules.json` + 软链 `current`；`waf_rules_json` 指向 `current`。

---

## 5. 附：字段/取值速查（权威源自实现）

Rule.match：CONTAINS | EXACT | REGEX | CIDR

Rule.action：DENY | LOG | BYPASS（BYPASS 禁止出现 score）

Rule.target：CLIENT_IP | URI | ALL_PARAMS(解析期展开) | ARGS_COMBINED | ARGS_NAME | ARGS_VALUE | BODY | HEADER（HEADER 需 headerName，且不能与其它目标并存）

phase：ip_allow | ip_block | uri_allow | detect（可省略，由 target+action 推断，显式指定当前未实现）

指令作用域：
- MAIN：waf_jsons_dir / waf_json_log / waf_json_log_level / waf_shm_zone / waf_trust_xff / waf_dynamic_block_score_threshold / waf_dynamic_block_duration / waf_dynamic_block_window_size
- LOC：waf / waf_default_action / waf_dynamic_block_enable / waf_rules_json / waf_json_extends_max_depth

JSONL 顶层：time, clientIp, method, host?, uri, events[], finalAction, finalActionType, currentGlobalAction, blockRuleId?, status?, level


## 6. 一套可跑通的完整示例（配置 + 规则 JSON + 日志样例 + 调试命令）

- 目标：用最小可用配置跑通“扩展继承 + 重写目标 + 禁用父集规则 + 头部阻断 + JSONL 落盘”全链路。
- 假设目录：
  - 规则根：`/usr/local/nginx/conf/waf/releases/current/`
  - 日志：`/var/log/nginx/waf.jsonl`

### 6.1 nginx.conf 关键片段（MAIN + LOC 指令）
```nginx
worker_processes  auto;

events { worker_connections  1024; }

http {
    # MAIN 级（不继承）
    waf_jsons_dir /usr/local/nginx/conf/waf/releases/current;
    waf_json_log /var/log/nginx/waf.jsonl;
    waf_json_log_level info;           # off|debug|info|alert|error
    waf_shm_zone waf_dyn 32m;
    waf_trust_xff on;

    waf_dynamic_block_score_threshold 100;
    waf_dynamic_block_duration 30m;
    waf_dynamic_block_window_size 1m;

    # LOC 可继承：直接在 http{} 设定，所有 server/location 生效
    waf on;
    waf_default_action block;          # block|log
    waf_dynamic_block_enable on;
    waf_json_extends_max_depth 5;      # 0 表示不限

    # 入口规则文件（可放 http/server/location，放 http{} 便于继承）
    waf_rules_json /usr/local/nginx/conf/waf/releases/current/main.json;

    server {
        listen 8080;
        server_name localhost;

        location / {
            proxy_pass http://127.0.0.1:9000;
        }
    }
}
```

### 6.2 规则 JSON（父子两层 + 重写 + 禁用）

- 文件：`/usr/local/nginx/conf/waf/releases/current/base.json`
```json
{
  "version": 1,
  "meta": {
    "name": "base",
    "tags": ["baseline"]
  },
  "rules": [
    {
      "id": 100,
      "tags": ["system"],
      "target": "URI",
      "match": "EXACT",
      "pattern": "/healthz",
      "action": "BYPASS",
      "priority": 0
    },
    {
      "id": 200,
      "tags": ["legacy", "csrf"],
      "target": "URI",
      "match": "CONTAINS",
      "pattern": "csrf",
      "action": "LOG",
      "score": 1,
      "priority": 10
    },
    {
      "id": 300,
      "tags": ["apply:multi-surface", "sqli"],
      "target": "URI",
      "match": "REGEX",
      "pattern": ".*(sql|select).*",
      "caseless": true,
      "action": "DENY",
      "priority": 5
    }
  ]
}
```

- 文件：`/usr/local/nginx/conf/waf/releases/current/child.json`
```json
{
  "version": 1,
  "meta": { "name": "child" },
  "rules": [
    {
      "id": 301,
      "tags": ["referer:csrf"],
      "target": "HEADER",
      "headerName": "Referer",
      "match": "EXACT",
      "pattern": "evil.com",
      "action": "DENY",
      "priority": 1
    }
  ]
}
```

- 文件：`/usr/local/nginx/conf/waf/releases/current/main.json`（入口：继承 + 重写 + 禁用 + 本地规则）
```json
{
  "version": 2,
  "meta": {
    "name": "main",
    "extends": [
      "./base.json",
      {
        "file": "./child.json",
        "rewriteTargetsForTag": {
          "apply:multi-surface": ["ALL_PARAMS"]
        }
      }
    ],
    "duplicatePolicy": "warn_keep_last"
  },

  "disableById": [200],
  "disableByTag": ["legacy"],

  "rules": [
    {
      "id": 400,
      "tags": ["referer:strict"],
      "target": "HEADER",
      "headerName": "Referer",
      "match": "EXACT",
      "pattern": "evil.com",
      "action": "DENY",
      "priority": 0
    }
  ]
}
```

说明要点：
- `apply:multi-surface` 标签在入口通过 `rewriteTargetsForTag` 被改写为 `ALL_PARAMS`，解析期会展开为 `URI`、`ARGS_COMBINED`、`BODY`。
- `disableById: [200]` 会把父集中 ID=200 的规则移除（只影响 imported_set）。
- `HEADER` 目标要求必须提供非空 `headerName`；若通过重写去掉了 `HEADER`，实现会自动移除多余的 `headerName`。

### 6.3 触发与观测

- 重载并压一条请求触发 SQLi 阻断（命中 id=300，经 ALL_PARAMS 展开，对 `ARGS_COMBINED` 也生效）：
```bash
nginx -s reload
curl -H "User-Agent: BadBot/1.0" "http://127.0.0.1:8080/?q=select" -I
tail -n 1 /var/log/nginx/waf.jsonl
```

- 参考 JSONL 样例（单行）：
```json
{
  "time": "2025-10-13T12:00:00Z",
  "clientIp": "203.0.113.1",
  "method": "GET",
  "host": "localhost",
  "uri": "/?q=select",
  "events": [
    {
      "type": "rule",
      "ruleId": 300,
      "intent": "BLOCK",
      "scoreDelta": 10,
      "totalScore": 10,
      "matchedPattern": ".*(sql|select).*",
      "patternIndex": 0,
      "target": "ARGS_COMBINED",
      "decisive": true
    }
  ],
  "finalAction": "BLOCK",
  "finalActionType": "BLOCK_BY_RULE",
  "currentGlobalAction": "BLOCK",
  "blockRuleId": 300,
  "status": 403,
  "level": "ALERT"
}
```

- 触发 Referer 阻断（命中 id=400 或 301，二选一即可）：
```bash
curl -H "Referer: evil.com" "http://127.0.0.1:8080/" -I
tail -n 1 /var/log/nginx/waf.jsonl
```

### 6.4 常见问题速记
- 没有 `waf.jsonl`：检查 `waf_json_log` 是否配置；`off` 时仅输出 error_log 摘要。
- BYPASS/ALLOW 不落盘：只有 `BLOCK/BYPASS` 强制落盘；ALLOW 需 `effective_level >= waf_json_log_level`。
- `extends` 报循环：检查继承链是否自引用；超深度则调整 `waf_json_extends_max_depth` 或精简链路。

