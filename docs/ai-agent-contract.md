## Nginx HTTP WAF v2 — AI Agent 执行规约（单一事实来源）

此文件定义 AI Agent（包括本助手）在本仓库参与设计/实现/编辑时必须遵循的“执行合同”。其目的是：固定术语、统一接口与职责、规范工具与流程，确保每次回答与改动稳定、一致、可复现。

### 1. 通用原则
- 使用中文沟通与中文注释。
- 不改动未触达的代码风格；保持原有缩进与空白字符风格。
- 只在必要的代码位置做“最小可行改动”；不随意重排代码。
- 设计为先，代码为后；若实现偏离既有文档，先更新文档，再实施代码。

### 2. 术语与命名（强制）
- 统一使用 `waf_enforce*` 家族：`waf_enforce`（基础入口）、`waf_enforce_block`、`waf_enforce_bypass`、`waf_enforce_log`、`waf_enforce_base_add`。
- 阶段返回枚举固定为 `waf_rc_e`，取值：`WAF_RC_CONTINUE|BYPASS|BLOCK|ASYNC|ERROR`。
- 仅在编排层使用 `WAF_STAGE(ctx, CALL)` 宏；阶段函数内部不使用该宏。
- 全局策略裁决仅在 action 层；module/阶段不读取全局策略，不返回 Nginx rc。

### 3. 分层职责（不可越界）
- module 层（`src/module/*`）：入口/指令/ACCESS 管线/请求体异步；只依赖 action/stage；通过 `WAF_STAGE` 做早退；尾部调用 `waf_action_finalize_allow`；不读写动态信誉与日志细节。
- action 层（`src/core/ngx_http_waf_action.[ch]`）：聚合“事件意图 × 全局策略”，必要时写 `ctx->final_*` 并在 BLOCK/BYPASS 立即落盘；输出 Nginx rc 给包装器；供阶段调用。
- 动态信誉层（`src/core/ngx_http_waf_dynamic_block.[ch]`）：共享内存、窗口/阈值/封禁；仅被 action 调用。
- 日志层（`src/core/ngx_http_waf_log.[ch]`）：事件聚合与 `waf_log_flush_final`；仅被 action/编排层调用。

### 4. 阶段函数与编排层写法（范式）
- 阶段函数：
  - 只返回 `waf_rc_e`；若需要执法/放行/记录，调用 `waf_enforce_*` 后 return `WAF_RC_BLOCK/BYPASS/CONTINUE/ERROR`。
  - 示例：
```c
static waf_rc_e waf_stage_illegal_method(ngx_http_request_t* r,
                                         ngx_http_waf_main_conf_t* mcf,
                                         ngx_http_waf_loc_conf_t*  lcf,
                                         ngx_http_waf_ctx_t*       ctx)
{
    if (!lcf->illegal_method_defense_enabled) return WAF_RC_CONTINUE;
    if (/* match */) {
        (void)waf_enforce_block(r, mcf, lcf, ctx, NGX_HTTP_FORBIDDEN, 0, lcf->illegal_method_score);
        return WAF_RC_BLOCK;
    }
    return WAF_RC_CONTINUE;
}
```
- 编排层（handler/回调）：
  - 用 `WAF_STAGE(ctx, waf_stage_xxx(...))` 串联流水线；未早退时尾部调用 `waf_action_finalize_allow`。

### 5. 宏与返回值
- `WAF_STAGE(ctx, CALL)`：只在编排层使用；根据 `waf_rc_e` 统一映射到 Nginx rc 并早退；不做任何 flush。
- `waf_enforce*`：返回 Nginx rc，但阶段函数不应向外传播该 rc，仅用来驱动内部日志/评分/最终态；阶段函数统一返回 `waf_rc_e`。

### 6. 文档与实现的一致性
- 若出现“文档中的 `waf_action_enforce` 与实现中的 `waf_enforce*` 不一致”的情况，以本规约为准，统一替换为 `waf_enforce*`。
- 在 `docs/refactor-plan-v2.md` 与 `docs/后续详细设计.md` 内保持：
  - `WAF_STAGE(ctx, CALL)` 的定义与用法不在阶段函数中出现。
  - 动作层接口以 `waf_enforce*` 为唯一表述。

### 7. 变更流程（AI 专用）
- 任何编辑前，先检索定位命名与接口引用的现状；批量替换需分步、最小化改动范围；优先文档，再代码。
- 进行改动后：
  - 若涉及新/改头文件：检查包含关系是否引入循环或路径不一致；
  - 执行规范化命名与示例更新；
  - 对照里程碑文件 `docs/milestones_new.md` 更新 DoD 或依赖；
  - 如新增/重命名 API，补充“职责边界”与“正反例”。

### 8. 里程碑驱动
- 优先遵循 `docs/milestones_new.md` 的阶段推进顺序；
- 若某项工作跨越多个里程碑，先落最小可用子集，保留接口不破坏现有编译；
- 对动态信誉（M5）与 ACCESS 管线（M4）允许并行，但不得改变分层职责边界。

### 9. 代码风格要点（补充）
- switch/case：`case XXX:;` 后新声明，避免额外花括号。
- 早返回与错误优先；避免深层嵌套；只在必要处加注释，解释“为什么”。

---

本规约若与其他文档冲突，以本规约为准；如需偏离，必须在 PR 中先更新本文件并给出理由。




