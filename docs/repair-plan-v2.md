## 修复计划（v2）

### 目标
- 完成 v2 端到端一致性修复，使配置、执法、动态封禁和日志达到生产可用标准。
- 统一 IP 字节序（网络序），修正动态封禁计分路径与日志细节，补齐最终动作类型与事件字段。

### 总体原则
- 与 Nginx/内核/常用网络库保持一致：内部存储与比较统一使用网络序。
- 所有“边界转换”显式化：读取/写入套接字、解析/打印文本、与第三方库交互处，进行清晰的 `htonl/ntohl` 或 `inet_ntop/inet_pton` 转换。
- 改动可回滚：对外接口和配置项保持兼容；必要时增加内部适配层。

### 修复项清单与设计要点

#### 1) 统一 IP 字节序（网络序）
- 进度：已完成
- 影响范围：
  - `src/module/ngx_http_waf_module.c`（上下文 `ctx->client_ip` 获取与传递）
  - `src/module/ngx_http_waf_utils.c`（IP 解析/转换、CIDR 相关工具）
  - `src/core/*` 中涉及 IP 比较/封禁键值/日志的模块
  - 共享内存动态封禁键（IP 作为 key）
- 设计：
  - 存储：`ctx->client_ip`、CIDR 节点、动态封禁条目统一为网络序。
  - 比较：CIDR 掩码与 `(ip & mask) == net` 按网络序实现；IPv6 预留同样语义。
  - 打印：统一使用 `inet_ntop`（IPv4/IPv6）输出；如仅支持 IPv4，亦以 `inet_ntop(AF_INET, ...)` 为准。
  - 工具：提供 `waf_utils_ip_to_text(pool, addr, family)`，内部调用 `inet_ntop`；弃用手工移位打印。
- 验收标准：
  - IPv4 地址在日志和测试中与 `curl -4` 的源地址一致；CIDR 匹配用例通过。
  - 与 v1 兼容：配置中录入的 CIDR/白名单/黑名单不需要改变写法。

#### 2) 修复日志 IP 输出
- 进度：已完成
- 影响范围：`src/core/ngx_http_waf_log.c`、`src/module/ngx_http_waf_utils.c`。
- 设计：
  - 所有 IP 文本化统一改为 `inet_ntop`；不再使用位移拼接点分字符串。
  - 若内部存网络序，`inet_ntop` 可直接使用，不需 `htonl`。
- 验收标准：
  - 集成测试抓取 JSONL，`clientIp` 始终与 `ngx_access_log` 对齐。

#### 3) 动态封禁积分（按增量写入 + 补基础加分）
- 进度：已完成（含窗口重置与请求级时间语义）
- 影响范围：`src/core/ngx_http_waf_action.c`、`src/core/ngx_http_waf_dynamic_block.c`、可能涉及计分调用点。
- 设计：
  - 在每次规则命中/阶段评分时调用 `waf_dyn_score_add(r, score_delta)`，传入“本次增量”而非总分。
  - 在“基础访问”阶段增加统一的基础加分（可配置或常量），确保窗口内访问速率对封禁算法生效。
  - 阈值判断从“累计值≥阈值时设置封禁状态”，无需写入总分覆盖。
- 验收标准：
  - 在测试环境内，通过压测/脚本可观察到窗口累计积分触发封禁；解除时间等于 `duration`。

补充（未在最初版本中细述，现已实现）：
- 窗口过期重置事件：在“请求 JSONL”中记录 `reputation_window_reset`（debug 级），仅当 `prev_score>0`；字段含 `prevScore/windowStartMs/windowEndMs/reason/category`；不影响计分。
- 计时语义：动态封禁模块在单个请求内统一使用 `ctx->request_now_msec` 作为“当前时间”；避免同一请求多次读取 `ngx_current_msec` 造成的边界抖动。

#### 4) 最终动作类型映射（按来源区分）
- 进度：已完成（已区分 BYPASS_BY_IP_WHITELIST/BYPASS_BY_URI_WHITELIST/BLOCK_BY_RULE/BLOCK_BY_IP_BLACKLIST/BLOCK_BY_DYNAMIC_BLOCK）
- 影响范围：`src/core/ngx_http_waf_action.c`。
- 设计：
  - BYPASS：区分 `BYPASS_BY_IP_WHITELIST` 与 `BYPASS_BY_URI_WHITELIST`。
  - BLOCK：区分 `BLOCK_BY_IP_BLACKLIST` 与 `BLOCK_BY_RULE`；若动态封禁触发，标记 `BLOCK_BY_DYNAMIC_BLOCK`。
  - LOG：保持 `LOG` 并附带事件细节。
- 验收标准：
  - 在 JSONL 的 `finalActionType` 字段准确反映来源；对应用例全部通过。

#### 5) 事件细节补齐（target/matchedPattern/patternIndex/negate）
- 进度：待完成（动作层具备字段，检测阶段尚未透传）
- 影响范围：`src/core/ngx_http_waf_action.c` 与规则匹配回调路径。
- 设计：
  - 将编译产物（规则 ID、目标、是否大小写不敏感、是否取反、pattern 及其索引）在命中时带入日志事件构建器。
  - 统一使用一个 `waf_log_append_rule_event(...)` 的强类型接口，避免传 `NULL`。
- 验收标准：
  - 命中事件的每个字段在日志中可见且与规则定义一致；复杂规则数组命中索引正确。

#### 6) 参数解码使用请求级内存池
- 进度：已完成（主要路径统一使用 r->pool，未检出对 ngx_cycle->pool 的回退）
- 影响范围：`src/module/ngx_http_waf_utils.c` 参数遍历与解码路径。
- 设计：
  - 将 `ngx_cycle->pool` 替换为 `r->pool` 或由调用方传入 `ngx_pool_t*`。
  - 确保生命周期与请求一致，避免泄漏。
- 验收标准：
  - ASAN/valgrind（如启用）不再提示相关泄漏；请求结束后资源正确回收。

#### 7) 动态封禁默认持续时间改为 30m
- 进度：已完成
- 影响范围：`src/module/ngx_http_waf_config.c` 默认值初始化。
- 设计：
  - 将 `dyn_block_duration` 默认从 300000ms 调整为 1800000ms（30 分钟）。
- 验收标准：
  - 未显式配置时，`/status` 或调试日志显示 30m；相关集成测试通过。

#### 8) 集成测试补充
- 进度：待完成
- 新增：
  - IP 字节序一致性测试：比较 `clientIp` 与 `access_log` 一致性。
  - 动态封禁积分窗口测试：以固定请求速率触发封禁并在 `duration` 到期后解除。
  - `finalActionType` 来源区分测试。
  - 事件细节完整性测试（校验日志 JSON 字段）。

### 迁移与兼容性
- v1 到 v2：规则与配置不变；内部实现改为网络序，不影响用户写法。
- 如需短期兼容：保留 `waf_utils_ip_to_str_legacy(host_order)`（仅用于过渡/测试），后续移除。

### 实施步骤与里程碑
1. 统一网络序（含日志输出函数替换）
2. 动态封禁积分改造（增量与基础加分）
3. finalActionType 按来源映射
4. 事件细节补齐
5. 参数解码使用请求池
6. 默认 30m 生效
7. 新增集成测试并全量跑通

### 风险与回滚
- 风险：
  - 老代码路径遗漏转换导致间歇性错配；积分窗口边界条件误判。
- 缓解：
  - 搜索并移除所有点分字符串“手工位移”实现；集中切换到 `inet_ntop`。
  - 引入小步提交与回归测试；动态封禁支持开关与调试日志。
- 回滚：
  - 以提交粒度回滚到切换网络序前版本；或仅禁用动态封禁功能。

### 验收清单（Definition of Done）
- 全部集成测试通过，无新增 linter/编译告警。
- 日志 `clientIp` 与 `access_log` 一致；CIDR 命中结果与预期一致。
- JSONL 中 `finalAction`/`finalActionType`、规则事件细节完整且正确。
- 动态封禁在压测中可复现并按 `duration` 自动解除。
