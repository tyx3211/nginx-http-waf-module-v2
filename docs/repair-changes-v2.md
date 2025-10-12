## 修复变更记录（v2）

说明：本文件用于在修复完成后，记录每一次提交/合并的关键变更点，便于审计与回溯。

### 记录格式建议
- 日期/提交哈希/作者
- 变更摘要（1-3 行）
- 受影响模块与文件列表
- 行为变更（兼容性/默认值变化）
- 相关测试用例与结果（如新增/修改）

### 示例占位
- 2025-10-04 / <commit> / <author>
  - 摘要：统一 IP 存储/比较为网络序；日志输出改为 inet_ntop。
  - 影响：`src/module/ngx_http_waf_module.c`、`src/core/ngx_http_waf_log.c`、`src/module/ngx_http_waf_utils.c`、`src/core/*`
  - 默认值变更：无
  - 测试：新增 IP 字节序一致性测试，通过。

（修复进行中，内容持续补充）

---

- 2025-10-12 / <commit> / <author>
  - 摘要：补齐请求 JSONL 顶层 `level` 字段；统一规则/信誉事件的收集与等级；窗口重置事件保持门控；对齐最终落盘策略与五段流水。
  - 影响：
    - `src/core/ngx_http_waf_log.c`（`waf_log_flush_final` 顶层新增 `level`；写出门槛基于 `effective_level` 与 `waf_json_log_level`；`decisive` 与 `blockRuleId` 条件输出保持）
    - `src/core/ngx_http_waf_action.c`（规则事件一律 `COLLECT_ALWAYS`；`BLOCK→ALERT`、`LOG/BYPASS→INFO`；`base_access` reputation 事件改为 `COLLECT_ALWAYS+INFO`；BYPASS/BLOCK 内部立即 final 落盘；ALLOW 由尾部统一落盘）
    - `src/core/ngx_http_waf_dynamic_block.c`（窗口过期重置事件通过动作层包装按 `LEVEL_GATED+DEBUG` 记录；动态封禁窗口/阈值语义保持；默认封禁 30m 已生效）
    - `src/module/ngx_http_waf_module.c`（五段流水采用 `WAF_STAGE` 宏；跳过内部请求/子请求；尾部 `waf_action_finalize_allow`）
    - `src/module/ngx_http_waf_config.c`（`waf_trust_xff`/`waf_json_log_level`/动态封禁相关指令完备；默认值回填）
    - `src/include/ngx_http_waf_log.h`（等级与最终动作类型枚举；事件接口保持）
  - 行为变更：
    - JSONL 结构：新增顶层 `level`（文本：DEBUG/INFO/ALERT/ERROR/NONE），反映 `effective_level`；`BLOCK` 仍强制落盘，`BYPASS/ALLOW` 受 `waf_json_log_level` 阈值控制。
    - 规则事件：统一改为 `COLLECT_ALWAYS`；等级映射为 `BLOCK→ALERT`、`LOG/BYPASS→INFO`，便于按请求提升 `effective_level` 并决定是否落盘。
    - 信誉事件：`base_access` 改为 `COLLECT_ALWAYS+INFO`；窗口重置 `reputation_window_reset` 仅在 `prev_score>0` 且 `LEVEL_GATED+DEBUG` 下记录，避免噪声。
    - 最终动作：`finalActionType` 覆盖 `BLOCK_BY_RULE/BLOCK_BY_IP_BLACKLIST/BLOCK_BY_DYNAMIC_BLOCK/BYPASS_*`，并在规则导致阻断时联动 `blockRuleId`。
  - 测试：建议补充 JSONL 顶层 `level`、规则事件等级映射与窗口重置事件门控的用例（未新增自动化用例）。

- 2025-10-04 / <commit> / <author>
  - 摘要：动态封禁窗口过期时在“请求 JSONL”追加 debug 事件 `reputation_window_reset`；统一使用请求级时间快照避免单请求时间割裂；运维日志保留 INFO 级窗口重置信息。
  - 影响：`src/core/ngx_http_waf_dynamic_block.c`（窗口过期路径）、`src/core/ngx_http_waf_log.c`（新增 JSONL 事件构建）、`src/include/ngx_http_waf_log.h`（接口声明）。
  - 行为变更：
    - JSONL：当窗口过期且 `prev_score>0` 时，写入一条 debug 级事件，字段含 `prevScore/windowStartMs/windowEndMs/reason/category`，不参与计分、不携带 `rule_id`。
    - 计时：动态封禁使用 `ctx->request_now_msec` 作为本请求统一时间源。
    - 运维日志：窗口重置仍以 INFO 级输出一行摘要。
  - 默认值变更：无（不新增开关，事件级别为 debug，可由全局 `json_log_level` 控制是否落盘）。
  - 测试：建议新增“窗口过期重置”JSONL 事件校验用例（待补）。

- 2025-10-07 / <commit> / <author>
  - 摘要：调整日志模块 API 设计以支持两类语义：
    1) ALWAYS：一定写入 JSONL 并提升日志等级；2) CONDITIONAL：按配置等级决定是否写入与提升。为专用事件函数增加 `write_mode` 与 `level` 参数；新增动作层包装，避免业务直接调用日志模块。
  - 影响：
    - `src/include/ngx_http_waf_log.h`：新增 `waf_log_write_mode_e`；扩展 `waf_log_append_*` 函数签名以接收 `mcf/write_mode/level`。
    - `src/core/ngx_http_waf_log.c`：实现 `waf_log_should_write` 与在 append_* 内统一提升级别；去除隐式提升的分散逻辑。
    - `src/core/ngx_http_waf_action.c`：新增 `waf_action_log_window_reset`，并在规则/信誉/ban 路径按语义选择 ALWAYS 或 CONDITIONAL。
    - `src/core/ngx_http_waf_dynamic_block.c`：改为调用动作层包装，移除对日志模块的直接依赖。
  - 行为变更：
    - 所有专用事件函数均可通过 `write_mode` 精确控制是“强制写入”还是“按级别写入”；并且在函数内部根据 `level` 统一提升 `effective_level`。
    - 动态模块不再直接写日志，统一经由 action 层转发，利于未来策略治理与埋点一致性。
  - 默认值变更：无（保持现有 `json_log_level` 语义）。
  - 兼容性：需要同步调整所有调用点（已完成当前仓库内调用替换）。
  - 状态：已完成

- 2025-10-07 / <commit> / <author>
  - 摘要：引入 `BLOCK_BY_DYNAMIC_BLOCK` 最终动作类型；统一动态封禁路径的 `finalActionType` 与日志提示；移除参数解码对 `ngx_cycle->pool` 的回退。
  - 影响：
    - `src/include/ngx_http_waf_log.h`：新增 `WAF_FINAL_ACTION_TYPE_BLOCK_BY_DYNAMIC_BLOCK`。
    - `src/core/ngx_http_waf_action.c`：在动态封禁命中与信誉阈值阻断路径设置为 `BLOCK_BY_DYNAMIC_BLOCK`，并调整 `waf_log_flush_final` 提示字符串。
    - `src/core/ngx_http_waf_log.c`：`finalActionType` 字符串映射新增 `BLOCK_BY_DYNAMIC_BLOCK`。
    - `src/module/ngx_http_waf_utils.c`：`args` 解码与遍历强制要求传入请求池 `r->pool`（通过签名参数 `pool`），不再回退 `ngx_cycle->pool`。
  - 行为变更：
    - JSONL 中动态封禁来源与基于累计信誉阻断统一标识为 `BLOCK_BY_DYNAMIC_BLOCK`，与 `BLOCK_BY_REPUTATION` 明确区分。
    - 解码内存分配与请求生命周期一致，避免潜在泄漏与跨请求引用。
  - 默认值变更：无。
  - 测试：建议补充 `finalActionType` 区分与参数解码分配策略的回归测试。
  - 状态：已完成
