### 面向过程的整体调用流程（从入口到产物）
- 调用入口: `ngx_http_waf_json_load_and_merge(pool, log, base_dir, entry_path, max_depth, err)`
  1) 解析入口文件绝对路径: `ngx_http_waf_resolve_path`（相对/根/基准目录拼接 + Nginx 前缀展开 + 规范化）。
  2) 初始化可变 JSON 文档 `ctx.out_doc`，准备承载所有生成的规则对象。
  3) 递归收集规则: 调用 `waf_collect_rules(&ctx, &abs, 0, &rules)`
  4) 构造最终对象: 建一个可变根对象与 `rules` 可变数组，把 `rules` 中的每个 `entry.rule` 逐个 append。
  5) 透传入口文件的 `version`/`meta`/`policies`（只从入口文件拷贝）。
  6) 把可变文档复制成不可变文档 `yyjson_mut_doc_imut_copy` 并返回。

- 递归收集: `waf_collect_rules(ctx, abs_path, depth, out_rules)`
  1) 深度/环检测: `ctx.max_depth`、`ctx.stack`（`ngx_http_waf_path_in_stack`/`ngx_http_waf_push_path`）。
  2) 读文件: `ngx_http_waf_json_read_single`（宽容读取，失败填充 `err`）。
  3) 取重复策略: `waf_parse_duplicate_policy`（默认 warn_skip）。
  4) 解析 `meta.extends`:
     - 对每个 extends 元素:
       - 解析路径 `ngx_http_waf_resolve_path`（以当前文件目录为基准）。
       - 解析重写计划（若是对象语法）: `waf_parse_rewrite_plan` → 生成 `waf_rewrite_plan_t`（两类规则：按 tag / 按 ids）。
       - 递归收集子规则: `waf_collect_rules(child, depth+1, &child_rules)`.
       - 应用重写计划（若存在）: `waf_apply_rewrite_plan`（按 tag/ids 改写 target）。
       - 累加到 `imported`（先收齐所有导入集）: `waf_merge_append_array`.
  5) 解析禁用: `disableById` / `disableByTag`，先过滤 `imported`。
  6) 合并导入集到 `result`（按重复策略）: `waf_append_rule_with_policy`.
  7) 解析本地 `rules`（当前文件）:
     - 对每个 rule 调 `waf_parse_rule`（强校验 + 规范化 + 生成可变 `yyjson_mut_val*`）；
     - 按重复策略并入 `result`: `waf_append_rule_with_policy`.
  8) 返回 `result`（类型为 `ngx_array_t`，元素是 `waf_rule_entry_t`）。

### 关键依赖关系（谁调用谁）
- 入口 `ngx_http_waf_json_load_and_merge` → `ngx_http_waf_resolve_path`、`waf_collect_rules`、yyjson 构造与拷贝。
- `waf_collect_rules` → 读文件、取策略、处理 extends（递归自身 + `waf_parse_rewrite_plan` + `waf_apply_rewrite_plan`）、处理禁用（`waf_rule_match_disable_id/tag`）、解析本地规则（`waf_parse_rule`）、合并策略（`waf_append_rule_with_policy`）。
- `waf_parse_rule` → 字段合法性校验（`waf_validate_additional_properties`、`waf_match_validate`、`waf_action_validate`、`waf_phase_validate` 等）、target 解析（`waf_parse_target_value` → `waf_target_code_from_string`/`waf_target_list_expand_and_add`）、target 回写（`waf_assign_target_to_rule` → `waf_build_target_mut_value`），标签复制（`waf_copy_tags_array`）。
- 路径与错误工具：`ngx_http_waf_dirname`、`ngx_http_waf_join_path`、`ngx_http_waf_normalize_path`、`waf_json_set_error` 等被上述流程穿插调用。

### 核心数据结构做什么用
- `waf_dup_policy_e`: 重复策略（warn_skip / warn_keep_last / error）。
- `waf_target_e`: 目标字段枚举（`CLIENT_IP`/`URI`/`ALL_PARAMS`/`ARGS_*`/`BODY`/`HEADER`）。
- `waf_target_list_t`: 解析并归一化后的目标列表（去重、展开 `ALL_PARAMS`、记录是否包含 `HEADER`）。
- `waf_rule_entry_t`:
  - `id`: 规则 ID（用于去重策略与筛选）。
  - `rule`: 指向构造好的可变 JSON 规则对象（属于 `ctx.out_doc`）。
  - `file`/`pointer`: 源文件和 JSON Pointer，用于错误/警告信息指向源头。
- `waf_rewrite_tag_rule_t` / `waf_rewrite_ids_rule_t`: “重写计划”中的两类规则定义（按 tag 或按 ids 重写 target）。
- `waf_rewrite_plan_t`: 收集重写规则集合（两个 `ngx_array`）。
- `waf_merge_ctx_t`: 合并上下文（内存池、日志、错误对象、深度限制、环检测栈、`jsons_root`、可变输出文档 `out_doc`）。

### 为什么不是直接往最终 rules 数组推，而要有 `waf_rule_entry_t` 和 `ngx_array`
- “先收集到内存、再一次性落入最终文档”的原因：
  - 需要先遍历整个 extends 链并处理“重写计划”（可能改写已解析的子规则 target）。
  - 需要先全局应用禁用策略（`disableById`/`disableByTag`），剔除导入集的一部分。
  - 需要按重复策略在“全量集合层面”去重（可能覆盖之前的同 ID 规则或跳过），这要求能在内存中线性查找/替换。
- `waf_rule_entry_t.rule` 已经是“可变 doc”上的规则节点（`yyjson_mut_val*`），因此最终阶段只是把这些节点 append 到 `rules` 数组即可，无需再重新构造。
- 使用 `ngx_array`（Nginx 动态数组）来暂存：
  - `imported`：聚合所有 child 的结果；
  - `result`：最终（导入+本地）按重复策略处理后的集合；
  - 这种暂存能在合并、筛选、重写、去重的多阶段之间做到内存连续、操作简单且具备良好性能。

### target/HEADER/ALL_PARAMS 的处理要点
- `ALL_PARAMS` 会被展开为 `URI`/`ARGS_COMBINED`/`BODY`。
- 一旦包含 `HEADER`：
  - 必须同时提供 `headerName`；
  - 且不允许与其他 target 混用。
- 解析 `target` 支持字符串或字符串数组；最终回写时会被规范为字符串（单项）或字符串数组（多项）。

### 错误定位与路径解析
- 每当出现错误，`waf_json_set_error` 会带上文件路径、JSON Pointer 与中文错误描述；`waf_rule_entry_t` 的 `file/pointer` 用于在合并/去重等阶段也能给出可追溯的位置。
- 引用路径（extends）按“绝对路径优先；`.` 开头相对当前文件目录；否则相对 `jsons_root`；无根配置时按原样”拼装，再走 Nginx 前缀展开与规范化。

### 最终产物如何构造
- 所有规则在解析时就已构造成 `ctx.out_doc` 上的可变节点（`yyjson_mut_val*`）。
- 递归+重写+禁用+去重完成后，把 `result` 数组里的 `entry.rule` 逐个 append 到最终的 `rules` 数组里。
- 完成后把可变文档变为不可变文档返回；外部只看到一个标准 JSON 文档，规则在一个 `rules` 数组中。

### 一个极简“时序”视图
- load_and_merge
  - resolve_path(entry)
  - collect_rules(entry, 0)
    - check depth/cycle → read_single → parse dupPolicy
    - for each extends:
      - resolve_path(child) → collect_rules(child, d+1)
      - parse_rewrite_plan(object extends) → apply_rewrite_plan(child_rules)
      - merge_append_array(imported, child_rules)
    - filter imported (disableById/Tag) → append to result with dupPolicy
    - for each local rule: parse_rule → append to result with dupPolicy
  - build root + rules_arr → append result[i].rule
  - passthrough version/meta/policies → imut_copy → return

若你需要，我可以把上述流程以注释“索引跳转”形式嵌入到文件顶部，或再画一张更详细的时序图帮助你在 IDE 中快速定位对应实现。