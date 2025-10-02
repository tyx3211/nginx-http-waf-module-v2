# Nginx HTTP WAF v2 项目现状分析与推进计划

## 项目理解总结

基于对详细设计文档（`后续详细设计.md`）的深入学习，我对您的 Nginx HTTP WAF v2 项目有了准确的理解。该项目是对 v1 版本的重构升级，旨在支持可视化管理系统（Vue3 前端 + NestJS 后端）。

### 核心设计理念（基于详细设计澄清）

v2 版本采用了以下关键设计原则：

1. **破坏性变更**：完全移除行级 DSL，采用结构化 JSON 规则工件
2. **严格分层架构**：`module → action → {dynamic, log}`，禁止跨层调用
3. **统一动作层是核心**：所有执法决策必须通过 `waf_enforce_*` 族函数
4. **WAF_STAGE宏编排**：module层使用WAF_STAGE处理早退，不做flush
5. **可视化友好**：JSON 格式便于前端管理界面操作
6. **规则继承机制**：支持 `extends`、禁用、重写等复杂合并策略
7. **JSONL事件聚合**：一请求一行，包含decisive标记和详细事件链

## 当前实现状态

### 已完成里程碑

根据分析，项目当前已完成：

**✅ M0：骨架与工具链**
- 最小模块骨架可编译
- yyjson/uthash 第三方库已集成
- clangd 开发环境配置完成

**✅ M1：JSON 解析与合并（部分完成）**
- 基础 JSON 解析功能已实现
- `extends` 递归机制已实现
- 规则合并逻辑已实现
- 导入级重写功能已实现
- 错误定位机制已实现

**🔄 M2.5：核心模块存根（部分完成）**
- action 模块接口已定义，存根实现完成
- log 模块接口已定义，存根实现完成
- dynamic_block 模块框架已搭建
- 统一的 WAF_STAGE 宏已实现

**🔄 M3：指令与装配（部分完成）**
- 基础指令（`waf_rules_json`、`waf_jsons_dir` 等）已实现
- 配置解析与合并逻辑已实现
- 共享内存区域创建已实现

### 当前代码质量评估

#### 优点
1. **架构框架完整**：严格遵循详细设计文档的分层结构
2. **接口设计正确**：action 层的 `waf_enforce_*` 族函数接口符合设计要求
3. **错误处理完善**：JSON 解析有详细的错误定位
4. **存根策略明智**：M2.5 存根实现保证编译通过，为后续开发提供稳定基础
5. **头文件组织合理**：`ngx_http_waf_types.h` 设计避免了循环包含

#### 关键改进要点（基于详细设计澄清）
1. **统一action层需要完整实现**：当前存根需要按详细设计文档实现intent参数处理
2. **WAF_STAGE宏使用需要规范**：确保module层只做编排，不做flush
3. **动态封禁集成待实现**：累积评分触发封禁机制需要在action层集成
4. **JSONL格式需要精确实现**：decisive事件标记、finalActionType等关键字段
5. **异步请求体处理需要完善**：严格按照回调函数的错误处理逻辑

## v1 vs v2 关键差异分析

### 需要复刻的 v1 功能

1. **核心防御能力**
   - SQL注入检测（基于规则引擎）
   - XSS检测（基于规则引擎）
   - 目录遍历防护
   - 恶意User-Agent检测
   - 非法HTTP方法检测
   - CSRF防护机制
   - Cookie防护机制

2. **动态封禁系统**
   - 基于共享内存的IP评分机制
   - 红黑树 + LRU队列的高效存储
   - 滑动窗口评分算法
   - 阈值触发的自动封禁
   - X-Forwarded-For支持

3. **规则引擎**
   - 多目标匹配（URI、ARGS、BODY、HEADER等）
   - CONTAINS/REGEX匹配类型
   - 规则优先级和分值系统

4. **灵活的动作策略**
   - BLOCK/LOG全局策略切换
   - 柔性评分机制（score_multiplier）
   - 基于规则的动作覆盖

### v2 的架构改进

1. **JSON规则工件**
   - 结构化配置替代行级DSL
   - 支持规则继承与合并
   - 便于可视化界面管理

2. **统一动作层**
   - 所有执法决策统一管理
   - 全局策略与规则意图的智能组合
   - 更清晰的责任边界

3. **JSONL日志系统**
   - 结构化日志输出
   - 一请求一行的事件聚合
   - 便于日志分析和可视化

## 后续推进计划（基于详细设计文档）

### 阶段一：统一action层实现（预计2-3天）⭐最高优先级

**核心任务：按详细设计文档实现action层**
- 实现 `waf_enforce(...)` 统一入口函数的intent参数处理逻辑
- 实现 `waf_enforce_base_add` 的累积评分触发封禁机制
- 实现BLOCK/BYPASS立即调用 `waf_log_flush_final` 的逻辑
- 集成全局策略BLOCK/LOG的正确应用
- 确保所有阶段函数返回 `waf_rc_e` 枚举

**关键验收**：
- 所有执法决策都通过action层统一处理
- 累积评分能触发动态封禁（配合全局BLOCK策略）
- 错误处理使用 `ngx_http_finalize_request(r, 500)` 符合最佳实践

### 阶段二：核心引擎填充（预计2-3天）

**优先级2：M2 编译期快照**
- 实现规则校验与phase推断逻辑
- 实现REGEX/CONTAINS/CIDR预编译
- 实现分桶索引（按phase+target分类）
- 创建只读的编译快照结构

**优先级3：完善M4 执行管线**
- 实现5段流水线与WAF_STAGE宏的严格配合
- 实现目标提取器（URI、ARGS、BODY、HEADER）
- 实现异步请求体处理的精确回调流程
- 确保module层只做编排，不做flush

### 阶段二：动态封禁系统（预计2-3天）

**优先级3：M5 动态封禁落地**
- 迁移v1的共享内存管理逻辑
- 实现红黑树+LRU队列结构
- 实现评分窗口与阈值触发机制
- 集成到统一action层

### 阶段三：JSONL日志系统（预计1-2天）

**优先级4：M6 精确JSONL实现**
- 实现decisive事件标记：首次BLOCK时标记decisive=true
- 实现finalActionType枚举：BLOCK_BY_RULE|BLOCK_BY_REPUTATION|BYPASS_BY_*|ALLOW
- 实现final_action=None语义：空事件ALLOW不落盘，有事件按级别决定
- 实现级别控制：BLOCK必落盘(alert)，BYPASS/ALLOW按waf_json_log_level
- 实现ctx->log_flushed防重复落盘机制

### 阶段四：功能验证与优化（预计2-3天）

**优先级5：M7 测试回归**
- 功能对比测试（确保与v1核心防御能力对齐）
- 验证累积评分触发封禁的正确性
- 验证JSONL格式的完整性
- 性能基准测试
- gotestwaf回归测试

## 具体实现建议

### 1. 立即优先的任务（基于详细设计澄清）

```bash
# 1. 实现action层统一执法 - 最关键
src/core/ngx_http_waf_action.c
- 实现waf_enforce的intent参数处理逻辑（BLOCK=1, LOG=0, BYPASS=2）
- 实现waf_enforce_base_add的累积评分触发封禁
- 实现BLOCK/BYPASS立即调用waf_log_flush_final
- 集成动态封禁检查：评分前后的双重检查
- 确保全局策略BLOCK/LOG的正确应用

# 2. 完善module层WAF_STAGE使用 - 关键
src/module/ngx_http_waf_module.c
- 确保所有阶段函数返回waf_rc_e枚举
- 确保module层只做编排，不做flush
- 实现异步请求体处理的精确回调流程
- 错误处理统一使用ngx_http_finalize_request(r, 500)

# 3. 实现编译器模块 - 基础设施
src/core/ngx_http_waf_compiler.c
- 实现waf_compile_rules_snapshot()函数
- 实现目标归一化与分桶逻辑
- 实现REGEX预编译与缓存
```

### 2. 关键设计决策（基于详细设计文档）

1. **严格分层架构**：`module → action → {dynamic, log}`，禁止跨层调用
2. **统一动作层是核心**：所有执法决策必须通过waf_enforce_*族函数
3. **累积评分机制**：配合全局BLOCK策略实现动态封禁
4. **JSONL精确格式**：必须实现decisive标记和finalActionType枚举
5. **保持v1防御能力**：确保SQLi、XSS等检测能力不退化

### 3. 风险点与对策

**风险1：性能退化**
- 对策：规则预编译 + 分桶索引优化查找效率
- 对策：共享内存结构复用v1经验

**风险2：功能遗漏**
- 对策：建立v1功能清单，逐项对齐验证
- 对策：保持gotestwaf测试套件通过

**风险3：复杂度管控**
- 对策：严格遵循分层架构，避免跨层依赖
- 对策：充分的中文注释与设计文档

## 结论

项目当前处于 **M2.5 存根实现完成，M4 执行管线框架搭建** 的状态。核心架构已经搭建完毕，接下来需要填充具体的业务逻辑。

我有信心按照上述计划稳步推进，在保持v1功能完整性的同时，实现v2的架构升级目标。关键是要确保每个阶段都有明确的验收标准，并保持与设计文档的一致性。

---

*本文档将随着项目推进持续更新*
