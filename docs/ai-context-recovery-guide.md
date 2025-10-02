# AI 上下文恢复指导文档

## 目的

当 AI 助手因上下文限制或重新开始对话时，本文档提供了快速恢复项目理解所需的关键信息和文档。

## 项目概览一句话

**Nginx HTTP WAF v2 是对 v1 的架构重构项目，采用 JSON 规则工件替代行级 DSL，实现严格分层架构（module → action → {dynamic, log}），支持可视化管理系统。**

## 快速上下文恢复清单

### 1. 必读核心文档（按优先级）

| 优先级 | 文档路径 | 关键内容 | 为什么重要 |
|-------|----------|----------|------------|
| ⭐⭐⭐ | `docs/后续详细设计.md` | 统一action层设计、WAF_STAGE宏、JSONL格式、异步处理流程 | **最关键**：包含所有架构细节和实现规范 |
| ⭐⭐ | `docs/project-status-analysis.md` | 当前实现状态、已完成里程碑、推进计划 | 了解项目现状和下一步工作 |
| ⭐⭐ | `docs/implementation-roadmap.md` | 详细的4阶段实施计划、验收标准 | 具体的工作规划和时间安排 |
| ⭐ | `docs/refactor-plan-v2.md` | v1→v2 重构思路、5段流水线设计 | 理解重构背景和设计思路 |

### 2. 关键代码文件状态

| 文件路径 | 当前状态 | 关键信息 |
|----------|----------|----------|
| `src/include/ngx_http_waf_types.h` | ✅ 已完成 | 公共枚举定义，避免循环包含 |
| `src/include/ngx_http_waf_action.h` | 🔄 接口已定义 | waf_enforce_*族函数声明 |
| `src/core/ngx_http_waf_action.c` | 🔄 存根实现 | **最关键模块**，需要按详细设计实现 |
| `src/core/ngx_http_waf_log.c` | 🔄 存根实现 | JSONL格式、decisive标记实现 |
| `src/core/ngx_http_waf_dynamic_block.c` | 🔄 框架存在 | 动态封禁、累积评分触发机制 |
| `src/module/ngx_http_waf_module.c` | 🔄 流水线框架 | WAF_STAGE宏使用、异步请求体处理 |

### 3. 核心设计决策（必须了解）

#### 架构原则
- **严格分层**：`module → action → {dynamic, log}`，禁止跨层调用
- **统一动作层**：所有执法决策必须通过 `waf_enforce_*` 族函数
- **WAF_STAGE宏编排**：module层使用WAF_STAGE处理早退，不做flush

#### 关键机制
- **累积评分触发封禁**：通过评分累积达到阈值触发封禁，受全局策略BLOCK控制
- **JSONL事件聚合**：一请求一行，包含decisive标记和finalActionType枚举
- **异步请求体处理**：使用回调函数，错误处理用 `ngx_http_finalize_request(r, 500)`

#### 重要接口
```c
// 统一执法入口
waf_rc_e waf_enforce(ngx_http_request_t* r,
                    ngx_http_waf_main_conf_t* mcf,
                    ngx_http_waf_loc_conf_t*  lcf,
                    ngx_http_waf_ctx_t*       ctx,
                    int intent_block_1_log_0_bypass_2,  // 关键参数
                    ngx_int_t http_status_if_block,
                    ngx_uint_t rule_id_or_0,
                    ngx_uint_t score_delta);

// 基础访问加分（可触发封禁）
waf_rc_e waf_enforce_base_add(...);
```

### 4. 当前项目状态快照

#### 已完成（约40-50%）
- ✅ M1：JSON解析与合并机制
- ✅ M0：基础骨架与工具链
- 🔄 M2.5：核心模块接口定义（存根实现）

#### 待实现（关键任务）
- ❌ **统一action层实现**（最高优先级）
- ❌ 规则编译器与分桶索引
- ❌ 动态封禁集成到action层
- ❌ JSONL格式的精确实现

### 5. 快速恢复步骤

#### 步骤1：阅读核心设计（5-10分钟）
1. 阅读 `docs/后续详细设计.md` 的前100行，重点关注：
   - "接口统一化调整"部分
   - "模块划分与职责边界"部分
   - WAF_STAGE宏定义

#### 步骤2：了解当前状态（3-5分钟）
1. 查看 `docs/project-status-analysis.md` 的"当前实现状态"部分
2. 查看 `src/include/ngx_http_waf_types.h` 了解公共枚举

#### 步骤3：确认下一步工作（2-3分钟）
1. 查看 `docs/implementation-roadmap.md` 的"第一阶段"任务
2. 重点关注"任务1.3：实现action统一执法"

### 6. 关键问题的已澄清答案

| 问题 | 答案 | 出处 |
|------|------|------|
| 累积评分是否触发封禁？ | 是的，只要全局策略为默认BLOCK | 用户澄清 |
| 使用ngx_http_finalize_request(r, 500)是否合适？ | 是当前可接受的实践 | 用户澄清 |
| ngx_http_waf_types.h应该包含什么？ | 当前设计已合理，无需大幅调整 | 用户澄清 |

### 7. 紧急恢复（30秒版本）

如果时间极其有限，只需要知道：

1. **这是什么项目**：Nginx WAF v2 重构，JSON规则替代DSL，支持可视化管理
2. **核心原则**：统一action层是架构核心，所有执法必须通过waf_enforce_*函数
3. **当前状态**：架构框架完成，存根实现待填充
4. **下一步**：实现action层的intent参数处理和累积评分触发封禁
5. **关键文档**：`docs/后续详细设计.md` 包含所有实现细节

## 使用建议

### 对于AI助手
- 优先阅读标记为⭐⭐⭐的文档
- 重点理解统一action层的设计理念
- 关注详细设计文档中的具体实现要求

### 对于用户
- 提供核心文档时，请按照优先级顺序
- 如有新的设计澄清，请更新本指导文档
- 重要决策变更时，请在"关键问题的已澄清答案"部分记录

---

*本文档将随项目推进持续更新，确保AI助手能快速、准确地恢复项目上下文*

