## 注意：内置工件优先哲学（置顶）

- 内置优先（优先 Nginx，其次系统）：对路径解析、文件操作、正则、内存池/字符串、日志等，默认复用内置 API。
- 不重复造轮子：除非存在明确缺口且经论证，否则不自研通用工具函数。
- 保守处理：字符串层仅做必要的“格式化”而非“安全归一”；安全边界采用基于目录句柄的系统调用（如 `openat`/`fstatat`）进行约束。
- 一致性与可维护：内存统一使用 `ngx_pool_t`/slab；`ngx_str_t`/`ngx_p[n]alloc` 字符串/内存族；API/行为与 Nginx 保持一致，随上游演进。
- 评审门槛：如未采用内置实现，PR 必须给出理由、对比与测试覆盖。
- 功能不失：在不改变既有语义的前提下引入内置替换，相关回归必须通过。

- 参考（优先选型）：
  - 路径：`ngx_get_full_name`、`ngx_conf_full_name`
  - 文件：`ngx_file_info`、`ngx_open_file`、`ngx_read_file`
  - 正则：`ngx_regex_compile`
  - 内存/字符串：`ngx_pool_t`、`ngx_palloc/ngx_pnalloc`、`ngx_str_t`、`ngx_cpystrn`
  - 日志：`ngx_log_error`

## 注意：编码偏好与装配脚本（置顶）

- 编码偏好（强制）
  - 头文件引入：禁止使用相对路径 include（如 `#include "third_party/yyjson/yyjson.h"`）；统一通过构建脚本配置头文件搜索路径，代码中使用 `<yyjson/yyjson.h>`、`<uthash/uthash.h>`、`"src/include/..."` 等标准形式。
  - 构建配置：在模块 `config`/`CFLAGS` 中追加 `-I$ngx_addon_dir/src/include -I$ngx_addon_dir/third_party/yyjson -I$ngx_addon_dir/third_party/uthash`，避免在源码里写相对路径 include。
  - 绝对路径优先：文档与脚本示例尽量给出绝对路径，命令行参数可覆盖默认路径。
  - 注释与沟通：统一中文注释与中文说明，函数/模块级注释强调“为什么”。

- 现有装配脚本（v1，参考）
  - `nginx-src/debug1.sh`：`make clean` → `./configure --with-compat --add-dynamic-module=...` → `make modules` → 将 `objs/ngx_http_waf_module.so` 拷贝到 `/usr/local/nginx/modules/`。
  - `nginx-src/debug2.sh`：删除 `objs/addon/src/*.o` 后 `make modules` → 拷贝 `.so`。
  - `nginx-src/debug3.sh`：`make clean` → `./configure` → `make` → `make install` → 拷贝 `.so`。

- v2 推荐装配脚本
  - 新增 `nginx-src/build_v2.sh`（封装上述流程，支持 preset 与细粒度步骤、`--bear`、`--jobs`、`--link-compile-db`）。
  - 常用示例：
    - `./build_v2.sh --preset debug1`
    - `./build_v2.sh --preset debug2`
    - `./build_v2.sh --preset debug3`
    - `./build_v2.sh --all --bear --link-compile-db --jobs 8`
  - 关键默认值：`prefix=/usr/local/nginx`，`module-dir=<repo>/nginx-http-waf-module-v2`，模块产物 `objs/ngx_http_waf_module.so` 拷贝到 `$prefix/modules/`。

## 注意：预置目录

- nginx源码目录：`/home/william/myNginxWorkspace/nginx-src`
- v2模块目录：`/home/william/myNginxWorkspace/nginx-http-waf-module-v2`
- v1模块目录：`/home/william/myNginxWorkspace/nginx-http-waf-module`
- nginx安装目录：`/usr/local/nginx`或者`/home/william/myNginxWorkspace/nginx-install`(软链接)

## Nginx HTTP WAF v2 重构设计与实施文档（破坏性变更版）

### 决策与范围

- 实施路径：采用“对照旧代码 + 在新目录重写”的方式，保证代码纯净度与准确性，同时复用原仓库中成熟的实现与经验点。
- 兼容性策略：破坏性变更；仅支持结构化 JSON 规则工件，完全移除行级 DSL 解析与相关配置路径。
- 目标优先级：可读性与可维护性 > 向后兼容。性能不退化为红线，必要处做优化。
- 分支策略：在 v2 仓库主干迭代，完成验收后再制定迁移指南用于老仓库升级。

### 必须保留与复用的“经验点”（来自 v1 源码）

1) Nginx 1.24.0 动态模块的 `config` 写法与构建链路。
2) `ngx_array_create` 的预留容量不得为 0（至少为 1），避免段错误。
3) 异步请求体回调处理完后，显式推进阶段（`r->phase_handler++; ngx_http_core_run_phases(r);`）。
4) 请求体处理三段式：异步回调函数 + 请求体收集函数 + 具体执行函数（返回 rc）。
5) rc 语义：通过时继续检查，仅在拦截（或错误）时返回；最终 rc 由统一的“动作执行”函数产出。
6) 允许直接迁移 v1 中优秀的函数/片段（如请求体收集、XFF/IPv4 解析等），在 v2 中统一命名与注释风格。

---

## 一、第三方库引入（vendored）

- yyjson（`third_party/yyjson/*`）
  - 目的：高性能 JSON 解析/生成；`mut_doc` 便于 `extends` 合并与日志事件聚合。
  - 用途：规则工件加载与合并；请求期 JSONL 日志构建。
  - 引入方式：vendored，直接纳入源码树；通过模块 `config` 增加包含目录与源文件编译。
  - 约束：不在 JSON 节点中存放本地指针（避免生命周期/对齐/ASLR 风险）。

- uthash（`third_party/uthash/uthash.h`）
  - 目的：配置期规则 ID 唯一性校验与 O(1) 定位；构建 `id → compiled_rule*` 映射。
  - 用途：规则去重、冲突处理、诊断与导出。
  - 引入方式：vendored，单头文件；仅在配置解析/编译期相关 `.c` 中使用。
  - 约束：运行期共享内存路径禁止使用第三方可写哈希（沿用 Nginx 原生结构）。

---

## 二、模块大改动目标与最终形态

- 规则解析模块
  - 从行级 DSL 彻底迁移至结构化 JSON（唯一来源）。
  - 支持 `extends/includeTags/excludeTags/disableById/disableByTag/extraRules/duplicatePolicy`。
  - `pattern` 支持 `string|string[]`；白名单规则化（`action=BYPASS`）。

- 执行与阶段模型
  - 固定 5 段流水线：IP 允许 → IP 拒绝 → 信誉评分/封禁 → URI 允许 → 检测段。
  - 检测段内部支持 `priority` 排序；其它段不交错执行。
  - 运行期基于“编译后的只读结构”，预编译 REGEX/CIDR，并按 `phase/target` 分桶索引。

- 日志模块
  - 一请求一行 JSONL；事件模型（评分/规则/封禁/放行）；可控详略级别。

- 动态封禁模块
  - API 拆分：`waf_apply_reputation`（纯评分）与 `waf_enforce`（执法/日志），共享内存采用 rbtree + queue + slab。

- 指令系统
  - 保留最小集：`waf`、`waf_rules_json`、`waf_jsons_dir`、`waf_json_log`、`waf_json_log_level`、`waf_trust_xff`、动态封禁指令组、`waf_shm_zone`。
  - 移除旧有“类别开关/路径/targets/策略类”指令。

- 最终形态
  - 开发者只管理 JSON 规则工件（可多文件，支持 `extends`）。
  - Nginx 通过 `waf_rules_json` 引用；多级继承继续使用 http/srv/loc 的 Nginx 原生机制。
  - 控制台与 CI 可对 JSON 做 schema 校验，发布时强制 `nginx -t` 验证。

---

## 三、总体架构与阶段模型（5 段流水线）

1) IP 允许（硬放行）：`target=CLIENT_IP & action=BYPASS`；命中短路返回。
2) IP 拒绝（硬拒绝）：`target=CLIENT_IP & action=DENY`；命中直接拒绝。
3) 信誉系统：为基础访问加分；检查是否处于封禁窗口，命中拒绝。
4) URI 允许（软放行）：`target=URI & action=BYPASS`；命中后跳过“检测段”（第 5 段）。
5) 检测段：SQLi/XSS/UA/非法方法/Cookie/CSRF 等统一规则化执行；根据 `action/score` 叠加信誉并可能执法。

分桶策略：默认由 `target + action` 隐式推断 `phase`；允许规则级 `phase` 可选覆盖；无效组合在编译期报错。

---

## 四、JSON 规则 Schema（概要）

- 顶层
  - `version?: number`（默认 1）
  - `meta?: { name?: string; versionId?: string; tags?: string[]; extends?: string[]; includeTags?: string[]; excludeTags?: string[]; duplicatePolicy?: "error"|"warn_skip"|"warn_keep_last" }`
  - `disableById?: number[]`, `disableByTag?: string[]`, `extraRules?: Rule[]`
  - `policies?: { dynamicBlock?: { baseAccessScore?: number } }`

- 规则项 `Rule`
  - `id: number`
  - `tags?: string[]`
  - `phase?: "ip_allow"|"ip_block"|"uri_allow"|"detect"`
  - `target: "CLIENT_IP"|"URI"|"ALL_PARAMS"|"ARGS_COMBINED"|"ARGS_NAME"|"ARGS_VALUE"|"BODY"|"HEADER"`
  - `headerName?: string`（当 `target=HEADER` 必填）
  - `match: "CONTAINS"|"REGEX"|"CIDR"`
  - `pattern: string|string[]`（数组为 OR 语义）
  - `caseless?: boolean`（默认 false）
  - `action: "DENY"|"LOG"|"BYPASS"`
  - `score?: number`（默认 10；BYPASS 忽略）
  - `priority?: number`（检测段内部排序，默认 0）

示例（片段）：

```json
{
  "version": 1,
  "meta": {
    "name": "prod_api",
    "extends": ["./crs_core.json", "./crs_xss.json"],
    "includeTags": ["core", "xss"],
    "duplicatePolicy": "warn_keep_last"
  },
  "disableById": [200123],
  "disableByTag": ["legacy"],
  "policies": { "dynamicBlock": { "baseAccessScore": 1 } },
  "rules": [
    { "id": 1001, "tags": ["whitelist:ip"],  "target": "CLIENT_IP", "match": "CIDR",  "pattern": ["10.0.0.0/8","192.168.0.0/16"], "action": "BYPASS" },
    { "id": 1101, "tags": ["blacklist:ip"],  "target": "CLIENT_IP", "match": "CIDR",  "pattern": ["1.2.3.4/32"],                             "action": "DENY"   },
    { "id": 1201, "tags": ["whitelist:uri"], "target": "URI",       "match": "PREFIX", "pattern": ["/health","/metrics"],                 "action": "BYPASS" },
    { "id": 200010, "tags": ["core","sqli"], "target": "ALL_PARAMS", "match": "REGEX",  "pattern": ["(?i)union\\s+select","(?i)or\\s+1=1"], "action": "DENY", "score": 20 }
  ]
}
```

---

## 五、指令最小集与路径解析

- 新/保留指令
  - `waf on|off;`
  - `waf_rules_json <path>;`（http/server/location；子块设置即替换父块）
  - `waf_jsons_dir <abs-path>;`（仅 http；作为 JSON 根目录）
  - `waf_json_log <path>|off;`（仅 http；JSON 行日志输出）
  - `waf_json_extends_max_depth <number>;`（http/server/location；设置 `meta.extends` 最大深度，0 表示不限）
  - `waf_json_log_level off|error|info|debug;`（仅 http）
  - 动态封禁：`waf_shm_zone`、`waf_dynamic_block_enable`、`waf_dynamic_block_score_threshold`、`waf_dynamic_block_duration`、`waf_dynamic_block_window_size`
  - `waf_trust_xff on|off;`

- 移除指令
  - `waf_rules_file` 及“类别开关/规则路径/targets/策略类”相关全部旧指令。

- 路径解析
  - 绝对路径 `/...`：按绝对路径解析。
  - `./` 或 `../`：相对“当前 JSON 文件所在目录”。
  - 其他裸路径：若设置 `waf_jsons_dir` 则相对该目录；否则相对 Nginx prefix。

---

## 六、解析与合并（yyjson_mut_doc）

流程：
1) 解析当前 JSON（允许注释与尾逗号）。
2) 递归处理 `extends`（左→右），检测循环与深度上限（默认 5，可通过指令配置；0 表示不限深度但仍进行环检测）。
3) 对“被引入规则集合”应用 `includeTags/excludeTags` 过滤。
4) 追加当前文件的 `rules`。
5) 应用 `disableById/disableByTag`。
6) 追加 `extraRules`。
7) 依据 `duplicatePolicy` 处理冲突 id（error|warn_skip|warn_keep_last）。

默认值：若未在入口 JSON 指定 `duplicatePolicy`，默认采用 `warn_skip`（跳过后出现的重复规则，并输出 warn 日志）。

校验：
- 必填字段与类型；HEADER→`headerName` 必填；BYPASS 不允许 `score`；`phase/target/action` 组合合法。
- 错误信息指向 JSON 路径（如 `rules[3].target`）。

产出：`final_mut_doc`（扁平结果，便于诊断/导出），随后进入编译期。

---

## 七、运行期编译（分桶索引；uthash 仅编译期）

编译产物（挂 loc_conf，只读）：
- `compiled_rule_t`（核心字段）
  - `rule_id:uint32`, `tags:ngx_array_t(ngx_str_t)`, `phase`, `target`, `header_name`, `match`,
    `pattern_list:ngx_array_t(ngx_str_t)`, `compiled_matchers`, `action`, `score:uint32`, `caseless:bool`, `priority:int`。
- 不持久化第三方哈希结构（遵循“内置工件优先”与“运行期零分配”）：
  - 编译期使用临时 uthash（`id → compiled_rule_t*`）做唯一性校验与诊断（仅在编译过程中存在）；
  - 运行期 loc_conf 中仅保留分桶的 `ngx_array_t(compiled_rule_t*)`；
  - 可选（调试构建或显式开关）：生成只读 `id_index`（`ngx_array_t` of `{id:uint32, ptr:compiled_rule_t*}`），便于二分检索与诊断；默认关闭。
- `buckets`：5 段 × target 的 `ngx_array_t(compiled_rule_t*)`。
- `policies_snapshot`：如 `baseAccessScore`。

实现要点：
- 预编译 REGEX（`ngx_regex_compile`）；CONTAINS 生成轻量匹配器；CIDR 解析为网络前缀结构。
- `ngx_array_create` 预留容量至少为 1（即使预计为空），避免段错误。
- detect 段内部按 `priority` 稳定排序；请求期零额外分配。

---

## 八、动态封禁与共享内存

API：
```c
void waf_apply_reputation(ngx_http_request_t* r,
                          ngx_http_waf_ctx_t* ctx,
                          int delta_score,
                          const char* reason_tag);

typedef enum { WAF_INTENT_BLOCK, WAF_INTENT_LOG, WAF_INTENT_BYPASS } waf_intent_e;

ngx_int_t waf_enforce(ngx_http_request_t* r,
                      ngx_http_waf_main_conf_t* mcf,
                      ngx_http_waf_loc_conf_t* lcf,
                      ngx_http_waf_ctx_t* ctx,
                      waf_intent_e intent,
                      int http_status,
                      uint32_t rule_id_or_0);
```

共享内存设计：
- 结构：`ngx_rbtree_t + ngx_queue_t`（LRU/TTL），内存来自 `ngx_slab_pool`；使用 `ngx_shmtx_t` 加锁。
- 评分窗口滑动与封禁过期；必要时多 `zone` 分片以降低竞争。
- 禁止第三方可写哈希表用于共享内存路径。

请求期调用：
- 基础访问加分：`waf_apply_reputation(..., baseAccessScore, "base_access")` → 达阈值则 `waf_enforce(..., WAF_INTENT_BLOCK, 403, 0)`。
- 规则命中：DENY→`waf_enforce(...BLOCK, 403, rule_id)`；LOG→`waf_enforce(...LOG, NGX_DECLINED, rule_id)`；有 `score` 时同步加分。

---

## 九、日志（一次请求一行 JSONL）

- ctx 中维护 `log_doc` 与 `events[]`；提供 `waf_log_append_event(...)` 与 `waf_log_flush(...)`。
- 事件字段：`type`（reputation|rule|ban|bypass）、`ruleId?`、`intent`、`scoreDelta?`、`totalScore`、`matchedPattern?`、`patternIndex?`、`target`、`ts`。
- 输出：O_APPEND 写入 `waf_json_log`；级别由 `waf_json_log_level` 控制。

示例：
```json
{"time":"2025-09-14T12:34:56.789Z","clientIp":"1.2.3.4","method":"POST","uri":"/login?x=1","events":[{"type":"reputation","scoreDelta":1,"totalScore":1,"ts":1699999999000},{"type":"rule","ruleId":200010,"intent":"BLOCK","scoreDelta":20,"totalScore":21,"matchedPattern":"(?i)union\\s+select","patternIndex":0,"target":"ALL_PARAMS","ts":1699999999050},{"type":"ban","ts":1699999999051}],"finalAction":"BLOCK","status":403}
```

---

## 十、目录结构与职责（v2）

```
nginx-http-waf-module-v2/
  src/
    core/        # 动作、日志、动态封禁、通用工具
    json/        # JSON 解析/合并/校验
    module/      # Nginx 模块入口、指令与挂载
    include/     # 统一头文件与公开结构/枚举
  third_party/
    yyjson/
    uthash/uthash.h
  docs/
  WAF_RULES_JSON/  # 示例规则
  config           # Nginx 动态模块构建脚本
```

核心文件：
- `src/json/ngx_http_waf_json.[ch]`：yyjson 解析/合并/错误定位。
- `src/core/ngx_http_waf_compiler.[ch]`：Rule → compiled_rule 编译与分桶。
- `src/core/ngx_http_waf_action.[ch]`：统一执法（最终 rc）。
- `src/core/ngx_http_waf_log.[ch]`：事件聚合与 JSONL 输出。
- `src/core/ngx_http_waf_dynamic_block.[ch]`：信誉与封禁（shm）。
- `src/core/ngx_http_waf_utils.[ch]`：工具函数（IPv4/XFF/regex 封装/CIDR/路径解析）。
- `src/module/ngx_http_waf_config.[ch]`：新指令与 merge 逻辑。
- `src/module/ngx_http_waf_module.c`：ACCESS 阶段 5 段流水线（瘦身）。

---

## 十一、构建与 Nginx 动态模块 `config`

关键点（对照 v1 并适配 v2 目录）：
- 声明 `ngx_addon_name=ngx_http_waf_module`，加入 `HTTP_MODULES`；
- 将 `src/module/*.c src/core/*.c src/json/*.c third_party/yyjson/*.c` 加入 `NGX_ADDON_SRCS`；
- 将 `src/include`、`third_party/yyjson`、`third_party/uthash` 加入包含路径；
- 根据编译器开启必要的警告与优化；保持与 Nginx 自身编译选项兼容。

参考片段：
```sh
ngx_addon_name=ngx_http_waf_module

HTTP_MODULES="$HTTP_MODULES ngx_http_waf_module"
NGX_ADDON_DEPS="$NGX_ADDON_DEPS \ \
  $ngx_addon_dir/src/include/*.h \ \
  $ngx_addon_dir/third_party/uthash/uthash.h"

NGX_ADDON_SRCS="$NGX_ADDON_SRCS \ \
  $ngx_addon_dir/src/module/ngx_http_waf_module.c \ \
  $ngx_addon_dir/src/module/ngx_http_waf_config.c \ \
  $ngx_addon_dir/src/core/ngx_http_waf_action.c \ \
  $ngx_addon_dir/src/core/ngx_http_waf_log.c \ \
  $ngx_addon_dir/src/core/ngx_http_waf_dynamic_block.c \ \
  $ngx_addon_dir/src/core/ngx_http_waf_utils.c \ \
  $ngx_addon_dir/src/json/ngx_http_waf_json.c \ \
  $ngx_addon_dir/src/core/ngx_http_waf_compiler.c \ \
  $ngx_addon_dir/third_party/yyjson/yyjson.c"

CFLAGS="$CFLAGS -I$ngx_addon_dir/src/include -I$ngx_addon_dir/third_party/yyjson -I$ngx_addon_dir/third_party/uthash"
```

---

## 十二、迁移指南（从 v1 到 v2）

1) 删除所有旧指令（类别开关/规则文件/targets 等）；保留 `waf`、`waf_trust_xff`、`waf_shm_zone`、动态封禁组与 JSON 相关指令。
2) 将原“核心规则”转换为 JSON 工件（可分模块并用 `extends` 组合）。
3) 在 http/server/location 级使用 `waf_rules_json` 指向目标 JSON；子块如需在父基础上小改，则在子 JSON 中用 `meta.extends` 指向父 JSON 并做增量。
4) 动态封禁：在 http 级配置 `waf_shm_zone` 与阈值/窗口，在 loc/http 配置 `waf_dynamic_block_enable`，在 JSON 设置 `policies.dynamicBlock.baseAccessScore`。
5) 日志：在 http 级配置 `waf_json_log` 与 `waf_json_log_level`；控制台 tail JSONL 即可。

示例 `nginx.conf` 片段：
```nginx
load_module modules/ngx_http_waf_module.so;

http {
    waf on;
    waf_trust_xff on;
    waf_shm_zone waf_zone 32m;

    waf_jsons_dir /etc/nginx/waf;
    waf_json_log  /var/log/nginx/waf.jsonl;
    waf_json_log_level info;

    waf_dynamic_block_score_threshold 120;
    waf_dynamic_block_duration 1800000;    # 30 min
    waf_dynamic_block_window_size 60000;   # 60 s

    server {
        listen 8080 reuseport;

        location /api {
            waf_dynamic_block_enable on;
            waf_rules_json api/base.json;
        }
    }
}
```

---

## 十三、阶段执行与请求体处理（对照重写要点）

- ACCESS 阶段入口：按 5 段流水线顺序执行；只在检测段内按 `priority` 排序。
- 请求体异步：`ngx_http_read_client_request_body` + 回调；回调结束显式推进阶段。
- 请求体收集：朴素合并（支持内存/文件缓冲区），必要时按 `content-type` 解码 `x-www-form-urlencoded`。
- rc 语义：默认继续（`NGX_DECLINED`/`NGX_OK`），只有在拦截或错误时返回 HTTP 特殊响应码；统一经 `waf_enforce` 产出最终 rc。

---

## 十四、测试与验收

- 单测：
  - JSON 解析：类型/缺字段/非法组合/REGEX 编译失败/循环 extends/深度上限。
  - 合并策略：`include/excludeTags`、`disableById/Tag`、`extraRules`、`duplicatePolicy` 三模式。
  - 编译器：`pattern[]`→`compiled_matchers[]`；phase 推断；分桶；ID 去重。
  - 动态封禁：窗口滑动/LRU/封禁过期；阈值命中路径。
  - 日志：事件聚合/flush/级别过滤。

- 集成：
  - 请求线完整：GET/HEAD/POST（含大体与分块）/表单解码。
  - 白名单/黑名单/BYPASS 短路；URI 白名单软放行。
  - SQLi/XSS/UA/非法方法/Cookie/CSRF（均规则化）命中路径。
  - `waf_jsons_dir` 路径解析；http/srv/loc 继承与替换符合预期。

- 性能：
  - 规则规模/REGEX 数量对延迟与吞吐的影响；与 v1 对比请确保不退化。

- 回归：
  - gotestwaf：TP/FP 不退化；重点场景全覆盖。

---

## 十五、里程碑（顺序与验收）

为降低集成风险并尽早获得“可执行最小集”，调整顺序如下（详见 `docs/milestones.md` 获取更细 DoD/依赖与排期）：

M0：骨架与工具链
- [ ] 最小模块骨架（config + module + include）可编译
- [ ] 引入 yyjson/uthash（vendored 目录就绪）
- [ ] clangd 工作（compile_commands.json 可生成与符号解析正常）

M1：JSON 解析与合并（数据面）
- [ ] 解析入口与错误定位（yyjson）
- [ ] `extends` 递归与循环检测、深度上限（支持指令配置：0=不限）
- [ ] 过滤/禁用/追加与冲突策略（`include/excludeTags`、`disableById/Tag`、`extraRules`、`duplicatePolicy`）
- [ ] 产出 `final_mut_doc`（用于诊断/导出）

M2：编译期快照
- [ ] 规则字段校验与逻辑约束
- [ ] phase 推断与覆盖校验
- [ ] REGEX/CONTAINS/CIDR 预编译
- [ ] uthash `id_map` 与分桶；`ngx_array_create` 最小容量保障
- [ ] 快照挂 loc_conf；请求期零分配校验

M3：指令与路径解析
- [ ] 新指令：`waf_rules_json`、`waf_jsons_dir`、`waf_json_log[_level]`
- [ ] 动态封禁指令组与 `waf_trust_xff`、`waf_shm_zone`
- [ ] 移除/拒绝旧指令；文档/样例更新

M4：执行管线（ACCESS）
- [ ] ACCESS 入口与 5 段流水线（IP 允许/拒绝、信誉、URI 允许、检测）
- [ ] 请求体三段式 + 回调推进
- [ ] 目标提取复用与优化（URI/ARGS/BODY/HEADER）

M5：动态封禁（并行推进，最小可用集）
- [ ] shm：rbtree+queue+slab；窗口/过期/LRU
- [ ] 评分/执法 API 打通；统一动作出口复检与日志

M6：日志 JSONL
- [ ] ctx 日志对象；事件追加与 flush；JSONL 输出
- [ ] 级别控制；error.log 摘要（可选）

M7：测试/回归/性能
- [ ] 单测/集成；gotestwaf；性能基线

M8：清理与交付
- [ ] 删除旧 DSL/旧指令路径；迁移指南；设计决策记录；发布

---

## 十六、风险与对策

- REGEX 差异：在解析与编译期同时校验；失败给出 JSON 路径与具体模式；提供替代建议。
- 配置迁移：以 JSON 工件 + `extends` 为主，最小化 Nginx 配置改动；发布前强制 `nginx -t`。
- 共享内存竞争：优先分片（多 zone）与合理锁粒度；避免引入复杂第三方索引。
- 性能回退：编译结构零分配；日志按级别输出；必要时延迟格式化日志字段。

---

## 十七、可直接迁移/复用的 v1 实现（建议清单）

- 请求体收集（合并内存/文件缓冲），表单解码（`x-www-form-urlencoded`）。
- 异步回调推进模板代码（`r->phase_handler++; ngx_http_core_run_phases(r);`）。
- IPv4 解析与 XFF 可信链首个 IP 提取逻辑（简化与重命名）。
- 若有现成 REGEX 封装/CIDR 解析工具，可迁移并与 v2 命名/注释规范对齐。

---

## 十八、代码风格与注释规范（强制）

- 命名：完整语义，函数用动词短语；变量避免缩写；结构体字段自解释。
- 控制流：早返回；错误优先；避免深层嵌套；不捕获后丢弃错误。
- 注释：模块/文件/关键函数提供中文注释（解释“为什么”）。
- JSON 指针：禁止把本地指针写入 JSON 节点；跨模块只传值或只读句柄。
- 共享内存：仅用 Nginx 原生结构；所有内存来自 slab；锁使用 `ngx_shmtx_t`。

---

## 十九、附录

### A. 最小 JSON Schema（用于前端/CI 提示，非正式草案）

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.com/nginx-waf/rules.schema.json",
  "type": "object",
  "properties": {
    "version": { "type": "number" },
    "meta": {
      "type": "object",
      "properties": {
        "name": { "type": "string" },
        "versionId": { "type": "string" },
        "tags": { "type": "array", "items": { "type": "string" } },
        "extends": { "type": "array", "items": { "type": "string" } },
        "includeTags": { "type": "array", "items": { "type": "string" } },
        "excludeTags": { "type": "array", "items": { "type": "string" } },
        "duplicatePolicy": { "enum": ["error", "warn_skip", "warn_keep_last"] }
      }
    },
    "disableById": { "type": "array", "items": { "type": "number" } },
    "disableByTag": { "type": "array", "items": { "type": "string" } },
    "extraRules": { "$ref": "#/definitions/rulesArray" },
    "policies": {
      "type": "object",
      "properties": {
        "dynamicBlock": {
          "type": "object",
          "properties": { "baseAccessScore": { "type": "number" } },
          "additionalProperties": false
        }
      },
      "additionalProperties": false
    },
    "rules": { "$ref": "#/definitions/rulesArray" }
  },
  "required": ["rules"],
  "additionalProperties": false,
  "definitions": {
    "rule": {
      "type": "object",
      "properties": {
        "id": { "type": "number" },
        "tags": { "type": "array", "items": { "type": "string" } },
        "phase": { "enum": ["ip_allow", "ip_block", "uri_allow", "detect"] },
        "target": { "enum": ["CLIENT_IP", "URI", "ALL_PARAMS", "ARGS_COMBINED", "ARGS_NAME", "ARGS_VALUE", "BODY", "HEADER"] },
        "headerName": { "type": "string" },
        "match": { "enum": ["CONTAINS", "REGEX", "CIDR"] },
        "pattern": {
          "oneOf": [
            { "type": "string" },
            { "type": "array", "items": { "type": "string" }, "minItems": 1 }
          ]
        },
        "caseless": { "type": "boolean" },
        "action": { "enum": ["DENY", "LOG", "BYPASS"] },
        "score": { "type": "number" },
        "priority": { "type": "number" }
      },
      "required": ["id", "target", "match", "pattern", "action"],
      "additionalProperties": false
    },
    "rulesArray": {
      "type": "array",
      "items": { "$ref": "#/definitions/rule" }
    }
  }
}
```

### B. 示例 JSON 规则与 `nginx.conf`
- 见前文示例。

### C. 典型伪代码（ACCESS 阶段骨架）

```c
// 省略: 获取 mcf/lcf/ctx, 过滤内部/子请求, 提取 client_ip

// 1) IP BYPASS
if (match_ip_bypass(ctx)) return NGX_DECLINED;

// 2) IP DENY
if (match_ip_deny(ctx)) return waf_enforce(..., WAF_INTENT_BLOCK, NGX_HTTP_FORBIDDEN, rule_id);

// 3) 信誉评分与封禁
waf_apply_reputation(r, ctx, baseAccessScore, "base_access");
if (is_banned(ctx)) return waf_enforce(..., WAF_INTENT_BLOCK, NGX_HTTP_FORBIDDEN, 0);

// 4) URI BYPASS（软放行）
if (match_uri_bypass(r)) return NGX_DECLINED;

// 5) 检测段（按 priority）
for (each rule in detect_bucket_sorted) {
  if (rule_match(r, rule)) {
    if (rule.score) waf_apply_reputation(r, ctx, rule.score, "rule");
    ngx_int_t rc = waf_enforce(..., map_intent(rule.action), status_for(rule), rule.id);
    if (rc != NGX_OK && rc != NGX_DECLINED) return rc;
  }
}
return NGX_DECLINED;
```

---

本文档即为 v2 的设计与实施“单一事实来源”。实现过程中若有偏差，应先更新本文档，再开展编码工作。

---

## 二十、实现顺序与动态封禁（重要）

- 动态封禁信誉系统是核心能力，不可后置到开发末期。
- 顺序调整：将原 M5（动态封禁）前移，与 M4（执行管线）并行推进，并预先完成最小可用集（共享内存结构 + 评分/封禁检查 + 统一动作出口对接）。
- 统一动作出口加分：无论事件来源（规则、非法方法、策略），都通过统一的动作执行函数聚合加分与执法，保持一致的 rc 语义与日志侧写。
- 依赖关系：
  - M1/M2（JSON→编译快照）完成后，即可用“最低限度的规则命中信息”驱动信誉系统；
  - 信誉系统自身仅依赖 `main_conf` 的阈值/窗口/时长与共享内存初始化，不依赖复杂规则结构。

结论：动态封禁不再是“后置优化”，而是执行路径的第二检查点（参见“阶段模型：第 3 段 信誉系统”）。

---

## 二十一、统一动作出口的职责（含加分）

- 统一动作函数负责：
  - 根据事件意图（BLOCK/LOG）与全局策略（BLOCK/LOG）决定是否拦截；
  - 若本次事件含加分（score > 0），则先调用信誉系统进行加分与倍率（若启用）运算；
  - 加分后立刻再次检查封禁状态（避免“先记录、后封禁”的时间窗）；
  - 统一记录事件日志（含 ruleId/intent/scoreDelta/totalScore）。
- 这样可确保“任何能触发日志的安全事件”都能触发信誉评分路径，避免遗漏。

---

## 二十二、柔性限流模式（v2 初版不纳入）

- 为降低用户心智负担与实现复杂度，v2 初版仅保留 BLOCK/LOG 两种全局策略；柔性限流（倍率累乘）留待 v2.1。
- 迁移策略：
  - 移除或隐藏相关指令；
  - 统一动作出口仍预留“可扩展参数位”，但默认关闭。

---

## 二十三、存根实现规范（必读）

- 存根标识：在文件与函数级中文档注释首行标注“STUB: 说明”，并在关键路径记录 `ngx_log_error(NGX_LOG_WARN, ...)`，运行期可见。
- 编译期提示：在存根文件顶部定义 `#define WAF_STUB 1`，并通过 `#if WAF_STUB` 包裹“临时代码块”。
- 行为边界：
  - 存根不得静默吞错；
  - 必须返回“安全缺省”（例如继续放行并强制日志），并在日志中提示“STUB 未实现”；
  - 存根不可写共享内存或对外可见持久状态（避免产生不可控副作用）。
- 清理要求：在里程碑合入前去除 `WAF_STUB` 并移除相应日志。

---

## 二十四、模块 config 校验清单（动态模块）

- 动态模块分支：检测 `ngx_module_link`，设置：
  - `ngx_module_type=HTTP`；
  - `ngx_module_name=ngx_http_waf_module`；
  - `ngx_module_srcs` 指向 v2 源文件集合；
  - `CFLAGS` 追加 `-I$ngx_addon_dir/src/include -I$ngx_addon_dir/third_party/yyjson -I$ngx_addon_dir/third_party/uthash`；
  - 点入 `. auto/module`。
- 静态模块分支：
  - 追加到 `HTTP_MODULES`；
  - 追加文件到 `NGX_ADDON_SRCS`；
  - 如需库，在静态分支追加到 `CORE_LIBS`（动态分支避免直接连库）。
- 其他注意：
  - 不要在动态分支强行追加 `CORE_LIBS`；
  - 目录更名或结构变动时，保持 `NGX_ADDON_DEPS` 与包含路径同步；
  - 与 v1 的 `config` 保持基本一致的探测与变量命名，以减少构建风险。

---

## 二十五、clangd/compile_commands.json 开发环境

- 目标：为 v2 目录提供可用的 `compile_commands.json`，使 clangd 正确解析 `#include "src/include/..."` 等路径。
- 方法（建议在仓库平级创建 Nginx 源码构建目录）：

步骤：
1) 安装工具（若未安装）：`bear`, `build-essential`, `libpcre2-dev`, `zlib1g-dev`, `libssl-dev`；
2) 在 `/home/william/myNginxWorkspace` 下创建 `nginx-src/` 目录，下载并解压 `nginx-1.24.0`；
3) 在 `nginx-1.24.0/` 目录内执行：
   - `./configure --prefix=/usr/local/nginx --with-debug --with-compat --add-dynamic-module=../nginx-http-waf-module-v2`；
   - `bear -- make modules -j$(nproc)`；
   - 生成的 `compile_commands.json` 链接到 v2 根目录：`ln -sf $(pwd)/compile_commands.json ../nginx-http-waf-module-v2/`。

提示：
- 在 v2 源码骨架尚未落地前，`make modules` 会失败，需先创建最小骨架（空的 `.c/.h` 也可）确保构建系统可运行。
- v2 的 `config` 必须已经包含 `src/include` 与第三方目录的 `-I` 路径，clangd 才能识别头文件位置。
- 如需完整命令与脚本，见新增 `docs/clangd-setup.md`。

---

## 二十六、v1 模块前提与依赖关系（对照清单）

- 阶段与回调
  - ACCESS 阶段入口；请求体采用异步读取；回调后必须显式推进相位（`r->phase_handler++; ngx_http_core_run_phases(r);`）。
  - 三段式体处理：回调函数 → 请求体收集 → 规则执行；此拆分在 v2 延续。
- 客户端 IP 提取
  - `waf_trust_xff on` 时从 XFF 第一段取真实 IP；否则取对端地址。
  - v1 仅用 IPv4（`ctx->client_ip_addr` 为 32 位），动态封禁以此为键；v2 初版沿用 IPv4，IPv6 作为后续增强。
- 共享内存与并发
  - 结构：`ngx_rbtree_t + ngx_queue_t(LRU)`，内存来自 `ngx_slab_pool`，使用 `ngx_shmtx_t` 加锁；所有修改在“已持锁”上下文中进行（`*_locked` 分配/释放）。
  - 驱逐策略：优先驱逐未被封禁节点；被封禁节点通常保留至过期。
  - 窗口：`waf_dynamic_block_window_size` 控制评分窗口；过期重置分数与起点。
- 统一动作与日志
  - `ngx_http_waf_perform_action` 聚合全局策略与事件意图；动态封禁加分与封禁检查应在此统一出口执行；
  - v1 记录到 error.log；v2 采用 JSONL 结构化日志（仍保留 error.log 摘要）。
- Regex 与依赖
  - v1 文档建议 PCRE2，但 v1 `config` 仅在静态编译分支链接 `-lpcre`；
  - v2 采用 `ngx_regex_compile`，与 Nginx 自身的 PCRE/PCRE2 绑定保持一致；动态模块分支不直接链接 PCRE 库（避免符号冲突）。
- 配置与继承
  - 旧有多指令体系在 http/server/location 级分别 merge；v2 以 `waf_rules_json` 为主，仍遵循 Nginx 原生继承/覆盖规则。


