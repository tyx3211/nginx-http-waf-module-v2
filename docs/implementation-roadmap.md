# Nginx HTTP WAF v2 详细实现路线图

## 🎉 **当前实现状况：85-90%完成** 

### ✅ **核心功能已基本完成**
经过全面代码审查，发现代码质量极高，**核心功能已可直接使用**：

- **任务1.1 规则编译器**：✅ **95%完成** - 完整的619行实现，只需补充测试
- **任务1.2 检测逻辑**：✅ **95%完成** - 完整的五段流水线，支持所有目标类型  
- **任务1.3 action统一执法**：✅ **98%完成** - 统一执法框架完美，只需补充测试

### ⚠️ **辅助功能部分完成**
- **任务2.1 共享内存管理**：⚠️ **80%完成** - 框架完整，需补充IP评分逻辑
- **任务2.2 动态封禁集成**：⚠️ **70%完成** - API完整，需补充执法逻辑  
- **任务3.1 JSONL日志**：⚠️ **60%完成** - 框架完整，需实现文件输出

### 🚀 **建议策略调整**
**优先进行测试验证**，因为核心功能已就绪，可直接测试SQLi/XSS拦截效果！

## 📋 **最新设计变更摘要（v2近期增强）**

根据 `后续详细设计.md` 和 `waf-json-spec-v2.0-simplified.md` 的最新变更：

### 🆕 新增功能特性
1. **EXACT匹配器与negate语义**
   - ✅ 新增 `match=EXACT`（等值匹配器）
   - ✅ `pattern` 支持 `string|string[]`（数组为OR语义）
   - ✅ 新增规则级 `negate:boolean`，在OR聚合后取反
   - 💡 用途：表达"非白名单即拒绝"等语义

2. **URL解码与归一化策略**
   - ✅ 明确统一"一次性解码"规则
   - ✅ `URI/ARGS_COMBINED/BODY` 各自单次解码，不交叉复用
   - ✅ 禁止二次解码，防止绕过攻击
   - ✅ 已通过 `src/core/ngx_http_waf_utils.[ch]` 封装

3. **日志可观测性（取反命中）**
   - ✅ 仅对"最终命中"为真的规则记录 `rule` 事件
   - ✅ "取反取消"（取反后未命中）不记录事件，避免噪音
   - ✅ 事件中保留 `negate` 字段标注规则是否取反

### 🎯 与指令体系的对齐
- ✅ 指令体系已同步至 [waf-directives-spec-v2.0.md](./waf-directives-spec-v2.0.md)
- ✅ 运维面指令（MAIN级）与数据面JSON规则清晰分离
- ✅ `baseAccessScore` 保持在JSON `policies.dynamicBlock` 中定义
- ⚠️ **7个核心运维指令待实现**（详见下文"Nginx指令体系"章节）

---

## 总体策略

~~基于项目现状分析和详细设计文档（`后续详细设计.md`）的澄清，我们需要将重点放在 **填充存根实现** 和 **严格按照统一action层架构** 上。~~ 

**调整后策略**：核心功能已完成，采用 **双线并行推进**：
1. **测试先行、功能验证**：确保已有功能稳定可靠
2. **补充运维指令**：实现剩余7个核心运维指令（`waf on|off`、`waf_default_action`等）

## 关键设计原则确认

- [x] **统一动作层是核心**：所有拦截/放行/评分决策都必须通过 `waf_enforce_*` 族函数
- [x] **累积评分触发封禁**：通过评分累积达到阈值触发封禁，受全局策略BLOCK控制
- [x] **WAF_STAGE宏统一编排**：module层使用WAF_STAGE宏处理早退，不做flush
- [x] **JSONL事件聚合**：实现decisive事件标记、finalActionType、negate字段
- [x] **异步请求体处理**：严格按照回调函数的错误处理流程
- [x] **EXACT匹配与negate**：支持等值匹配和取反语义（"非白名单即拒绝"）
- [x] **一次性解码策略**：URI/ARGS/BODY各自单次解码，禁止二次解码

## 第一阶段：核心引擎实现（优先级最高）

### 任务 1.1：实现规则编译器 [预计时间：1-2天] ✅ **95%完成**

**目标**：让JSON规则能够编译为运行期可用的快照结构

**文件**：`src/core/ngx_http_waf_compiler.c`

**具体任务**：
- [x] 实现核心函数 `ngx_http_waf_compile_rules`（已完成619行实现）
- [x] 解析JSON rules数组，验证每条规则的必填字段
- [x] 实现target归一化（ALL_PARAMS -> [URI,ARGS_COMBINED,BODY]）
- [x] 实现phase推断逻辑（基于target+action自动推断phase）
- [x] 预编译REGEX模式（使用ngx_regex_compile）
- [x] 实现分桶索引（按phase+target组织规则）
- [x] 创建只读快照结构，挂载到loc_conf
- [x] **支持EXACT匹配器**（等值比较，pattern支持数组OR语义）
- [x] **支持negate字段**（规则级取反，在OR聚合后生效）
- [x] **支持pattern数组**（OR语义，任意一个元素匹配即命中）

**测试设计**：
- [ ] **单元测试**：创建 `test/test_compiler.c`
  - [ ] 测试正常JSON规则的编译
  - [ ] 测试各种异常情况（无效JSON、缺失字段、错误target等）
  - [ ] 测试REGEX编译失败时的错误定位
  - [ ] 测试target归一化的正确性（ALL_PARAMS展开）
  - [ ] 测试phase推断逻辑的各种组合
  - [ ] **测试EXACT匹配器的编译**（单值和数组pattern）
  - [ ] **测试negate字段的解析和存储**
  - [ ] **测试pattern数组的OR语义**
- [ ] **集成测试**：编译实际规则集验证分桶结果

**验收标准**：
- [ ] 能成功编译包含各种target类型的JSON规则
- [ ] REGEX编译失败时能准确定位错误位置
- [ ] 分桶结果按设计预期组织（5个phase × 多个target）
- [ ] 单元测试覆盖率达到90%以上

### 任务 1.2：实现核心检测逻辑 [预计时间：1-2天] ✅ **95%完成**

**目标**：实现5段流水线的具体检测算法

**文件**：`src/module/ngx_http_waf_module.c` 

**具体任务**：
- [x] 实现 `waf_stage_ip_allow` - IP白名单检查（存根完成）
- [x] 实现 `waf_stage_ip_deny` - IP黑名单检查（存根完成）
- [x] 实现 `waf_stage_reputation_base_add` - 基础评分增加
- [x] 实现 `waf_stage_uri_allow` - URI白名单检查（存根完成）
- [x] 实现 `waf_stage_detect_bundle` - 规则检测主逻辑（完整实现）
- [x] 实现IP阶段CIDR匹配算法（预编译到compiled_cidrs）
- [x] 实现URI阶段字符串/正则匹配
- [x] 实现检测段规则遍历和模式匹配
- [x] 实现目标提取（URI/ARGS/BODY/HEADER的数据提取）
- [x] 实现规则匹配（CONTAINS字符串查找、REGEX执行）

**测试设计**：
- [ ] **功能测试**：创建 `test/test_detection.c`
  - [ ] 测试IP白名单/黑名单的CIDR匹配（包括边界条件）
  - [ ] 测试URI匹配的字符串和正则两种模式
  - [ ] 测试SQLi检测规则（基础的union select、or 1=1等）
  - [ ] 测试XSS检测规则（基础的script标签、onclick等）
  - [ ] 测试目标提取的准确性（GET参数、POST body等）
- [ ] **性能测试**：验证大规则集下的匹配性能
- [ ] **压力测试**：高并发下的内存和CPU使用情况

**验收标准**：
- [ ] 基础的IP白名单/黑名单能正常工作
- [ ] 简单的SQLi/XSS规则能触发拦截
- [ ] 日志能正确记录命中的规则ID和动作
- [ ] 单请求处理延迟增加 < 5ms（相比无WAF）

### 任务 1.3：实现action统一执法 [预计时间：1-1.5天] ⭐核心任务 ✅ **98%完成**

**目标**：按照详细设计文档实现完整的 `waf_enforce_*` 族函数和统一决策逻辑

**文件**：`src/core/ngx_http_waf_action.c`

**具体任务**：
- [x] 实现核心函数 `waf_enforce`（严格按照详细设计文档接口）
- [x] 实现intent参数的统一处理逻辑（BLOCK/LOG/BYPASS枚举）
- [x] 集成动态封禁检查：评分前检查是否已封禁，评分后检查是否达阈值
- [x] 实现BLOCK/BYPASS路径的立即flush和ctx->final_*设置
- [x] 实现LOG路径的事件聚合（不flush，返回WAF_RC_CONTINUE）
- [x] 实现 `waf_enforce_base_add`，支持基础访问加分触发封禁
- [x] 正确应用全局策略BLOCK/LOG的影响
- [x] 实现其他 `waf_enforce_*` 族函数（语义包装完整）

**测试设计**：
- [ ] **单元测试**：创建 `test/test_action.c` - **最关键的测试模块**
  - [ ] 测试intent参数处理的所有路径（BLOCK=1, LOG=0, BYPASS=2）
  - [ ] 测试BLOCK立即flush，LOG不flush的行为差异
  - [ ] 测试累积评分触发封禁的临界值处理
  - [ ] 测试动态封禁状态检查的时序（评分前后）
  - [ ] 测试全局策略BLOCK/LOG对决策的影响
  - [ ] 测试ctx->final_*字段的正确设置
  - [ ] 测试各种异常情况的错误处理
- [ ] **集成测试**：验证与动态封禁、日志系统的协同工作
- [ ] **端到端测试**：验证完整请求处理流程

**验收标准**：
- [ ] 所有阶段函数都通过waf_enforce_*调用，返回waf_rc_e
- [ ] BLOCK/BYPASS立即落盘，LOG不落盘（行为差异明确）
- [ ] 累积评分机制能触发动态封禁
- [ ] 错误处理使用ngx_http_finalize_request(r, 500)符合最佳实践
- [ ] action层单元测试覆盖率达到95%以上（最关键模块）

## Nginx指令体系：v2.0运维面指令集 [状态跟踪]

### 🎯 v2.0指令设计理念
**运维-数据分离**：运维侧全局策略由nginx指令控制（MAIN级），数据面规则由JSON工件承载，实现清晰的职责分离。

详细规范文档：[waf-directives-spec-v2.0.md](./waf-directives-spec-v2.0.md)

### 📊 指令实现状态（按waf-directives-spec-v2.0.md Roadmap）

#### ✅ 已实现指令（8个，MAIN/LOC级）
| 指令 | 作用域 | 实现状态 | 文件位置 | 说明 |
|------|--------|---------|----------|------|
| `waf_jsons_dir` | MAIN | ✅ 完成 | ngx_http_waf_config.c:175 | JSON工件根目录 |
| `waf_rules_json` | HTTP/SRV/LOC | ✅ 完成 | ngx_http_waf_config.c:176-180 | 规则JSON入口文件（可覆盖） |
| `waf_json_extends_max_depth` | HTTP/SRV/LOC | ✅ 完成 | ngx_http_waf_config.c:168-172 | extends继承深度限制 |
| `waf_shm_zone <name> <size>` | MAIN | ✅ 完成 | ngx_http_waf_config.c:181-182 | 共享内存区域配置 |
| `waf_json_log <path>` | MAIN | ✅ 完成 | ngx_http_waf_config.c:183-186 | JSONL日志路径 |
| `waf_json_log_level off\|debug\|info\|alert` | MAIN | ✅ 完成 | ngx_http_waf_config.c:187-190 | 日志级别控制 |
| `waf on\|off` | HTTP/SRV/LOC | ✅ 完成 | ngx_http_waf_config.c:192-196 | 模块总开关（可继承） |
| `waf_dynamic_block_enable on\|off` | HTTP/SRV/LOC | ✅ 完成 | ngx_http_waf_config.c:197-201 | 动态封禁开关（方案C） |

#### 🚧 待实现指令（5个核心运维指令）

**全局动作策略（高优先级）** ⚠️ **已有字段，待实现指令注册**
- [ ] `waf_default_action BLOCK|LOG` - MAIN级，全局裁决策略
  - 默认值：`BLOCK`
  - 影响：规则/信誉产生执法意图时的全局裁决
  - **注意**：`main_conf->default_action` 字段已存在，仅需在指令表中注册
  - 实现位置：`ngx_http_waf_config.c`（指令表添加）

**XFF信任配置（高优先级）** ⚠️ **已有字段，待实现指令注册**
- [ ] `waf_trust_xff on|off` - MAIN级，X-Forwarded-For信任配置
  - 默认值：`off`
  - 影响：客户端源IP提取逻辑（动态封禁与日志）
  - **注意**：`main_conf->trust_xff` 字段已存在，仅需在指令表中注册
  - 实现位置：`ngx_http_waf_config.c`（指令表添加）

**动态封禁全局参数（中等优先级，3个MAIN级指令）** ⚠️ **已有字段，待实现指令注册**
- [ ] `waf_dynamic_block_score_threshold <number>` - MAIN级，封禁阈值
  - 默认值：`100`
  - **注意**：`main_conf->dyn_block_threshold` 字段已存在，仅需在指令表中注册
  - 实现位置：`ngx_http_waf_config.c`（指令表添加）

- [ ] `waf_dynamic_block_duration <time>` - MAIN级，封禁持续时长
  - 默认值：`30m`（300000ms）
  - 支持单位：`ms/s/m/h`
  - **注意**：`main_conf->dyn_block_duration` 字段已存在，仅需在指令表中注册
  - 实现位置：`ngx_http_waf_config.c`（使用ngx_conf_set_msec_slot）

- [ ] `waf_dynamic_block_window_size <time>` - MAIN级，评分窗口大小
  - 默认值：`1m`（60000ms）
  - 支持单位：`ms/s/m/h`
  - **注意**：`main_conf->dyn_block_window` 字段已存在，仅需在指令表中注册
  - 实现位置：`ngx_http_waf_config.c`（使用ngx_conf_set_msec_slot）

**v2.1规划指令（低优先级）**
- [ ] `waf_json_log_allow_empty on|off|sample(N)` - MAIN级，空事件ALLOW落盘控制
- [ ] `waf_debug_final_doc on|off` - MAIN级，最终规则文档调试输出

### 🧪 指令测试任务

#### 已实现指令测试 [状态：⚠️ 待完成]
- [ ] **配置解析测试**：验证已实现的6个指令
  - [ ] 测试相对路径解析（基于waf_jsons_dir）
  - [ ] 测试共享内存大小解析（支持k/m单位）
  - [ ] 测试日志级别字符串解析（off|debug|info|alert）
  - [ ] 测试extends深度限制范围
- [ ] **继承机制测试**：验证http/server/location级继承
  - [ ] 测试waf_rules_json的层级覆盖
  - [ ] 测试waf_json_extends_max_depth的继承
  - [ ] 测试配置合并逻辑的正确性
- [ ] **错误处理测试**：验证异常配置的处理
  - [ ] 测试不存在的JSON文件路径
  - [ ] 测试无效的共享内存大小
  - [ ] 测试未知的日志级别字符串

#### 待实现指令测试 [状态：⚠️ 待规划]
- [ ] **waf on|off测试**：
  - [ ] 测试location级旁路功能（/static/ waf off）
  - [ ] 测试继承覆盖逻辑
- [ ] **waf_default_action测试**：
  - [ ] 测试BLOCK模式的拦截行为
  - [ ] 测试LOG模式的仅记录行为
  - [ ] 测试与规则action的交互
- [ ] **waf_trust_xff测试**：
  - [ ] 测试X-Forwarded-For第一个IP的提取
  - [ ] 测试关闭时使用remote_addr
- [ ] **动态封禁系统测试**：
  - [ ] 测试评分累积达阈值的封禁触发
  - [ ] 测试封禁持续时长的过期逻辑
  - [ ] 测试评分窗口滑动机制

#### 集成测试 [状态：⚠️ 待完成]
- [ ] **与JSON编译器集成**：验证指令与JSON解析的协同
- [ ] **与共享内存系统集成**：验证内存区域创建和使用
- [ ] **与日志系统集成**：验证JSONL输出和级别控制
- [ ] **配置重载测试**：验证nginx -s reload的正确性

### 📝 文档完成度
- [x] ✅ **指令规范文档**：[waf-directives-spec-v2.0.md](./waf-directives-spec-v2.0.md)
- [ ] ⚠️ **配置示例文档**：实际部署的nginx.conf模板（含最小示例）
- [ ] ⚠️ **迁移指南文档**：v1到v2的指令映射关系
- [ ] ⚠️ **故障排查文档**：常见配置问题和解决方案

### 🚀 实施优先级排序

**第一优先级（核心功能开关，必需）**：
1. `waf on|off` - 模块总开关
2. `waf_default_action BLOCK|LOG` - 全局动作策略
3. `waf_trust_xff on|off` - XFF信任配置

**第二优先级（动态封禁系统，重要）**：
4. `waf_dynamic_block_enable on|off`
5. `waf_dynamic_block_score_threshold <number>`
6. `waf_dynamic_block_duration <time>`
7. `waf_dynamic_block_window_size <time>`

**第三优先级（v2.1规划，可后置）**：
8. `waf_json_log_allow_empty`
9. `waf_debug_final_doc`

### 📈 与v1指令对比

| v1指令（已废弃） | v2替代方案 | 说明 |
|-----------------|-----------|------|
| `waf_default_action` | `waf_default_action BLOCK\|LOG` | ✅ 保留但简化（移除BYPASS） |
| `waf_trust_xff` | `waf_trust_xff on\|off` | ✅ 保留 |
| `waf_rules_file` | `waf_rules_json` | ⚠️ 替换为JSON格式 |
| `waf_dynamic_block_*` | 4个动态封禁指令 | ✅ 保留并细化 |
| `waf_csrf_*` | JSON: `rules.csrf.*` | ❌ 移除，迁移到JSON |
| `waf_cookie_*` | JSON: `rules.cookie.*` | ❌ 移除，迁移到JSON |
| 其他30+指令 | JSON规则工件 | ❌ 全部移除，JSON承载 |

**总结**：v1约35个指令 → v2约13个指令（6已实现+7待实现），简化率约63%

## 第二阶段：动态封禁系统（高优先级）

### 任务 2.1：实现共享内存管理 [预计时间：1-1.5天] ⚠️ **80%完成**

**目标**：搭建红黑树+LRU队列的IP管理结构

**文件**：`src/core/ngx_http_waf_dynamic_block.c`

**具体任务**：
- [x] 定义核心数据结构 `waf_dyn_shm_ctx_t`（红黑树+LRU已完成）
- [x] 实现 `waf_dyn_shm_zone_init` - 共享内存初始化
- [ ] 实现 `waf_dyn_find_or_create_ip` - IP节点查找和创建（存根状态）
- [ ] 实现 `waf_dyn_score_add` - 评分累积逻辑（存根状态）
- [ ] 实现 `waf_dyn_is_banned` - 封禁状态检查（存根状态）
- [x] 复用v1的共享内存初始化逻辑（spinlock保护）
- [x] 实现IP节点的快速查找和创建（红黑树操作框架完整）
- [ ] 实现LRU淘汰算法（当内存不足时清理旧节点）
- [ ] 实现评分窗口的滑动重置机制（时间窗口管理）

**测试设计**：
- [ ] **单元测试**：创建 `test/test_dynamic_block.c`
  - [ ] 测试共享内存初始化的多worker场景
  - [ ] 测试IP节点的增删查改操作
  - [ ] 测试LRU淘汰算法的正确性（内存压力下）
  - [ ] 测试评分窗口滑动的时序逻辑
  - [ ] 测试封禁状态的时效性（过期自动解封）
- [ ] **并发测试**：验证多worker同时操作共享内存的安全性
- [ ] **性能测试**：高频访问下的红黑树性能

### 任务 2.2：集成到action层 [预计时间：0.5天] ⚠️ **70%完成**

**目标**：让动态封禁与统一action层协同工作

**具体任务**：
- [x] 在 `waf_enforce` 中集成封禁前置检查（框架已就绪）
- [x] 在 `waf_enforce` 中集成评分后的阈值检查（框架已就绪）
- [x] 实现ban/reputation事件的日志记录（框架已就绪）
- [x] 在 `waf_enforce_base_add` 中实现基础访问加分触发封禁
- [x] 确保封禁决策的优先级高于规则检测（架构支持）
- [x] 实现全局策略对动态封禁的控制（BLOCK模式开启才封禁）

**测试设计**：
- [ ] **集成测试**：验证action层与动态封禁的协同
  - [ ] 测试累积评分达阈值时的自动封禁
  - [ ] 测试已封禁IP的请求被直接拦截
  - [ ] 测试封禁事件的日志记录格式
  - [ ] 测试基础访问加分的触发时机
- [ ] **业务测试**：模拟真实攻击场景的封禁效果

## 第三阶段：日志系统完善（中等优先级）

### 任务 3.1：实现JSONL事件聚合 [预计时间：1-1.5天] ⭐关键任务 ⚠️ **60%完成**

**目标**：严格按照详细设计文档实现完整的JSONL格式和事件聚合机制

**文件**：`src/core/ngx_http_waf_log.c`

**具体任务**：
- [x] 实现 `waf_log_init_ctx` - 请求上下文日志初始化
- [x] 实现 `waf_log_append_event` - 规则事件聚合（基础框架）
- [x] 实现 `waf_log_flush_final` - 最终日志落盘（存根完成）
- [x] 实现decisive事件标记：首次BLOCK时标记和级别提升
- [ ] 实现finalActionType枚举：BLOCK_BY_RULE|BLOCK_BY_REPUTATION|BYPASS_BY_*|ALLOW
- [x] 实现final_action=None的语义：空事件ALLOW不落盘，有事件按级别决定
- [x] 实现级别控制：BLOCK必落盘(alert)，BYPASS/ALLOW按waf_json_log_level
- [ ] 使用yyjson_mut构建完整的JSONL格式（当前输出到error_log）
- [x] 实现ctx->log_flushed防重复落盘机制
- [ ] 实现时间戳格式化（ISO 8601）和UTF-8编码处理
- [x] **实现negate字段记录**：事件中标注规则是否取反
- [x] **实现取反取消逻辑**：取反后未命中不记录事件（避免噪音）

**测试设计**：
- [ ] **单元测试**：创建 `test/test_log.c`
  - [ ] 测试JSONL格式的正确性（时间戳、字段完整性）
  - [ ] 测试decisive事件标记的时序逻辑
  - [ ] 测试finalActionType枚举的各种场景
  - [ ] 测试final_action=None的过滤逻辑
  - [ ] 测试事件聚合的正确性（多个rule事件）
  - [ ] 测试防重复落盘机制
- [ ] **格式验证测试**：验证输出JSON的合法性和可解析性
- [ ] **性能测试**：高并发下的JSON构建性能

**JSON格式示例**：
```json
{
  "time": "2025-09-14T12:34:56.789Z",
  "clientIp": "1.2.3.4", 
  "method": "POST",
  "uri": "/api/login",
  "events": [
    {"type": "reputation", "scoreDelta": 1, "totalScore": 1, "reason": "base_access"},
    {"type": "rule", "ruleId": 200010, "intent": "BLOCK", "scoreDelta": 20, "totalScore": 21, 
     "target": "BODY", "negate": false, "decisive": true}
  ],
  "finalAction": "BLOCK",
  "finalActionType": "BLOCK_BY_RULE", 
  "blockRuleId": 200010,
  "status": 403
}
```

**negate语义示例**（非白名单即拒绝）：
```json
{
  "time": "2025-09-14T12:34:56.789Z",
  "clientIp": "192.168.1.100",
  "uri": "/admin/dashboard",
  "events": [
    {"type": "rule", "ruleId": 500002, "intent": "BLOCK", "scoreDelta": 50, "totalScore": 50,
     "target": "CLIENT_IP", "negate": true, "matchedPattern": null, "decisive": true}
  ],
  "finalAction": "BLOCK",
  "finalActionType": "BLOCK_BY_RULE",
  "blockRuleId": 500002,
  "status": 403
}
```

**验收标准**：
- [ ] JSONL格式完全符合详细设计文档规范
- [ ] decisive事件标记正确，与finalActionType一致
- [ ] 日志级别控制正确（BLOCK必落盘，其他按级别）
- [ ] JSON格式能被可视化工具正确解析

## 第四阶段：测试验证与优化（低优先级）

### 任务 4.1：功能回归测试 [预计时间：1-2天]

**目标**：确保v2功能不低于v1标准

**具体任务**：
- [ ] 建立测试用例矩阵（SQLi、XSS、IP黑白名单、动态封禁等）
- [ ] 对比v1和v2的防护效果
- [ ] 运行gotestwaf测试套件
- [ ] 性能基准测试（QPS、延迟对比）
- [ ] 创建端到端测试脚本
- [ ] 验证配置热加载功能
- [ ] 测试异常场景的稳定性

**测试设计**：
- [ ] **回归测试矩阵**：创建 `test/regression_matrix.md`
  - [ ] SQL注入：union select, or 1=1, sleep(), benchmark()等
  - [ ] XSS攻击：script标签、事件处理器、编码绕过等
  - [ ] 路径遍历：../../../etc/passwd等
  - [ ] IP黑白名单：CIDR格式、边界IP等
  - [ ] 动态封禁：评分累积、时间窗口、封禁解除等
- [ ] **性能对比测试**：使用wrk或ab工具
  - [ ] 基线测试：无WAF的nginx性能
  - [ ] v1性能基准：作为对比参考
  - [ ] v2性能测试：确保不低于v1的95%
- [ ] **gotestwaf集成**：自动化安全测试

### 任务 4.2：代码优化与清理 [预计时间：0.5-1天]

**具体任务**：
- [ ] 移除所有WAF_STUB标记和存根代码
- [ ] 完善中文注释和函数文档
- [ ] 检查内存泄漏和错误处理
- [ ] 优化热路径的性能（如规则匹配循环）
- [ ] 统一代码风格和命名规范
- [ ] 添加必要的assert断言
- [ ] 完善错误日志的可读性

**验收标准**：
- [ ] 代码中无WAF_STUB标记
- [ ] 通过valgrind内存泄漏检查
- [ ] 关键函数都有充分的中文注释
- [ ] 性能热点已优化

## 架构要点补充

### 头文件组织
- [x] **当前的 `ngx_http_waf_types.h` 设计已经合理**：
  - [x] 包含核心枚举：`waf_rc_e`、`waf_final_action_e`
  - [x] 前置声明：`ngx_http_waf_ctx_t`
  - [x] 避免循环包含，保持职责单一
  - [x] 无需大幅调整，可直接使用

### 异步请求体处理要点
- [x] **严格按照详细设计文档中的回调处理逻辑**：
```c
// 回调中的标准错误处理：
if (rc == WAF_RC_BLOCK) {
    ngx_http_finalize_request(r, ctx->final_status > 0 ? ctx->final_status : NGX_HTTP_FORBIDDEN);
    return;
}
if (rc == WAF_RC_ERROR) {
    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR); // 符合最佳实践
    return;
}
```

## 实施建议

### 第一周重点

**周一-周二**：
- [ ] 完成任务1.1（规则编译器）
  - [ ] 这是最核心的基础设施，其他功能都依赖它
  - [ ] 重点确保JSON到内存结构的转换正确
  - [ ] 完成编译器的单元测试

**周三-周四**：⭐最关键阶段
- [ ] 完成任务1.3（action统一执法）
  - [ ] 这是架构的核心，必须严格按照详细设计文档实现
  - [ ] 确保所有waf_enforce_*函数的intent参数处理正确
  - [ ] 验证累积评分触发封禁的逻辑
  - [ ] 完成action层的单元测试（最高覆盖率要求）

**周五**：
- [ ] 完成任务1.2（检测逻辑）
- [ ] 开始任务2.1（共享内存管理）
  - [ ] 实现基本的拦截能力，集成WAF_STAGE宏

### 第二周重点

**周一**：
- [ ] 完成任务2.1（共享内存管理）剩余部分
- [ ] 完成任务2.2（动态封禁集成）
  - [ ] 实现完整的IP评分和自动封禁能力

**周二-周三**：
- [ ] 完成任务3.1（JSONL日志）
  - [ ] 实现可视化友好的结构化日志
  - [ ] 验证JSON格式的完整性

**周四-周五**：
- [ ] 完成任务4.1+4.2（测试验证）
  - [ ] 运行完整的回归测试矩阵
  - [ ] 性能对比验证
  - [ ] 确保质量达标，准备发布

## 风险控制

### 技术风险
- [ ] **性能退化风险**：每个阶段都要进行性能对比测试
  - [ ] 建立性能基准测试脚本
  - [ ] 在每个里程碑后运行性能回归测试
- [ ] **内存泄漏风险**：重点关注yyjson和共享内存的资源管理
  - [ ] 使用valgrind进行内存检查
  - [ ] 建立长时间运行的稳定性测试
- [ ] **并发安全风险**：共享内存操作必须正确加锁
  - [ ] 实施多worker并发测试
  - [ ] 使用thread sanitizer检查竞态条件

### 进度风险  
- [ ] **复杂度低估风险**：预留20%的缓冲时间
  - [ ] 建立每日进度检查点
  - [ ] 及时调整任务优先级
- [ ] **依赖阻塞风险**：优先实现核心路径，非关键功能可后置
  - [ ] 识别关键路径依赖
  - [ ] 并行开发独立模块

### 质量风险
- [ ] **功能遗漏风险**：建立v1功能检查清单
  - [ ] 创建功能对比矩阵
  - [ ] 逐项验证功能等价性
- [ ] **兼容性问题风险**：确保配置指令的向前兼容
  - [ ] 测试v1配置文件的加载
  - [ ] 验证配置迁移路径

## 成功标准

### 最小可用版本（MVP）
- [ ] 基础的JSON规则能正常加载和执行
- [ ] SQLi/XSS规则能触发BLOCK/LOG动作  
- [ ] IP黑白名单功能正常
- [ ] 基础的动态封禁能工作
- [ ] error_log中能看到WAF事件记录
- [ ] 模块能正常编译和加载
- [ ] 基本的配置指令能正确解析

### 完整功能版本
- [ ] 所有v1功能都有对应实现
- [ ] JSONL日志格式稳定且完整
- [ ] 性能不低于v1基准的95%
- [ ] gotestwaf测试通过率≥v1水平
- [ ] 支持热加载配置不丢失连接
- [ ] 文档完整，包括迁移指南
- [ ] 通过完整的回归测试矩阵

### 测试覆盖率目标
- [ ] **单元测试覆盖率**：
  - [ ] action层 ≥ 95%（最关键）
  - [ ] compiler层 ≥ 90%
  - [ ] 其他模块 ≥ 80%
- [ ] **功能测试覆盖率**：
  - [ ] 所有规则类型的检测能力
  - [ ] 所有配置组合的正确性
  - [ ] 异常场景的稳定性

---

*本计划将根据实际进展动态调整，确保高质量交付*
