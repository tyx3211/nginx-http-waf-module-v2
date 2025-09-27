## 里程碑（v2-new）

说明：本文件与 `docs/milestones.md` 保持一致风格，但更贴合《后续详细设计.md》的分层与接口设计（action/log/dynamic/stage 宏）。每个里程碑包含范围、完成定义（DoD）、依赖与测试要求（含建议脚本/命令）。

### 已完成
- [x] M0：骨架与工具链（参考旧文档）
- [x] M1：JSON 合并与导入级重写（参考旧文档）

---

### [ ] M2：编译期快照（对齐 v2 设计）
- 范围：
  - 以 M1 输出的 `rules` 为输入，完成目标归一后快照编译（REGEX/CIDR 预编译，phase 推断/覆盖校验，分桶与去重）
  - 产出只读快照结构并挂载到 `loc_conf`
- DoD：
  - 编译失败错误定位到 ruleId 与源文件，给出 JSON pointer
  - 能被后续 M3/M4 加载执行
  - 性能：规则 5k 级别可在秒级完成编译
- 依赖：M1
- 测试：
  - 单测：
    - 正常/非法 REGEX、非法 CIDR 掩码、空 target、HEADER 组合非法
    - phase 推断冲突检测（显示覆盖 vs 推断）
  - 集成：
    - 通过 `nginx -t` 加载编译后的快照（由 M3 指令装配接入）

---

### [ ] M2.5：核心模块存根（action/log/shm 占位）
- 范围：
  - `src/include/ngx_http_waf_action.h/.c`：统一动作出口（BLOCK/BYPASS/LOG + `score_delta`），BLOCK/BYPASS 立即 `waf_log_flush_final`，LOG/加分不落盘
  - `src/include/ngx_http_waf_log.h/.c`：请求态聚合与最小 `error_log` 摘要；`waf_log_flush_final` 幂等输出一行
  - `src/include/ngx_http_waf_types.h`：公共枚举 `waf_rc_e`/`waf_final_action_e` 与 ctx 前置声明
- DoD：
  - 可编译、`nginx -t` 通过
  - 触发 BLOCK 时在 `error_log` 看到一行 `waf-stub-final` 摘要；BYPASS 同理；纯 LOG/加分仅在尾部 `ALLOW` 时落盘
- 依赖：M2
- 测试：
  - 手动：构造 `location`，用 `curl` 触发不同路径（GET/HEAD→ALLOW，POST→LOG，模拟 BLOCK 路径）
  - 验证 `error_log` 中仅一行最终摘要；重复调用 `waf_log_flush_final` 不重复落盘

---

### [ ] M3：指令与装配（入口/目录/深度）
- 范围：
  - 新指令最小集：`waf_rules_json`、`waf_jsons_dir`、`waf_json_extends_max_depth`、`waf_trust_xff`、`waf_shm_zone`
  - 在 `postconfiguration` 装配：解析入口 JSON → M1 合并 → M2 编译 → 快照挂入 `loc_conf`
- DoD：
  - `nginx -t` 通过；scope 继承/覆盖符合预期
  - 未配置 `waf_rules_json` 时模块仅输出最小日志，不报错
- 依赖：M2.5
- 测试：
  - 集成：三层 http/srv/loc 覆盖/继承用例，期望行为与文档一致
  - 错误路径：缺文件、循环 extends、深度上限超出、非法 target 配置

---

### [ ] M4：执行管线（ACCESS + STAGE 宏）
- 范围：
  - ACCESS 阶段“5 段流水线”：IP allow → IP deny → 信誉评分/封禁（base_add）→ URI allow → 检测段（SQLi/XSS/UA/非法方法/Cookie…）
  - `WAF_STAGE` 宏替换早退逻辑；handler/回调尾部统一 `waf_log_flush_final(...,"ALLOW")`
  - 请求体三段式与回调推进（同步 GET/HEAD vs 异步读体）
- DoD：
  - BYPASS/BLACKLIST 路径生效；未早退时尾部 `ALLOW` 落盘一次
  - 代码中不直接调用日志模块细节（仅 action + stage 宏）
- 依赖：M3
- 测试：
  - 集成：
    - GET/HEAD：无请求体，走完整 5 段，尾部落盘 `ALLOW`
    - POST 表单：异步回调内完成检测段与尾部落盘；并发 50 并保持稳定
  - 日志：校验 `error_log` 中的 `waf-stub-final` 输出次数为 1

---

### [ ] M5：动态信誉与封禁（shm）
- 范围：
  - 共享内存：`rbtree + queue(LRU) + slab`；窗口/阈值/过期；API：`waf_dyn_score_add`、`waf_dyn_is_banned`、`waf_dyn_ban`
  - 在 action 的 BLOCK 路径复检与落盘事件扩展：`finalActionType` 写为 `BLOCK_BY_REPUTATION`
- DoD：
  - 加分到阈值自动封禁；窗口外衰减
  - 并发与锁正确性基本验证
- 依赖：M4
- 测试：
  - 单/集成：
    - 连续 60s 每秒加分 1 达到阈值后封禁；窗口外恢复
    - 并发 100 客户端竞争写同一 IP，不死锁、无明显退化

---

### [ ] M6：日志 JSONL（结构化输出）
- 范围：
  - ctx 事件聚合；`waf_log_flush_final` 输出 JSONL；级别：`off|debug|info|alert(audit)`
  - `finalAction`/`finalActionType`/`status`；events 含 `rule`/`reputation`/`ban`/`bypass`/`base_access`
- DoD：
  - JSONL 格式稳定；大流量下性能无明显退化
  - 可配置最低落盘级别（阈值）
- 依赖：M4/M5
- 测试：
  - 集成：配置不同阈值，验证 BLOCK 必落盘、ALLOW/BYPASS 受阈值控制
  - 可靠性：重复 flush 仅一行；格式校验脚本 `dev/jsonl_validate.sh`

---

### [ ] M7：测试/回归/性能
- 范围：
  - 单测/集成/gotestwaf；对比 v1 性能
- DoD：
  - TP/FP 不退化；QPS/延迟在误差范围内
- 依赖：M4-M6
- 测试：
  - gotestwaf 基线报告；回归脚本 `dev/regression_v2.sh`

---

### [ ] M8：清理与交付
- 范围：
  - 删除旧路径/DSL；迁移指南；设计决策记录
- DoD：
  - 文档完整；版本打 tag；发布说明
- 依赖：全部
- 测试：
  - `nginx -t`、最小示例能跑通；文档检查脚本 `dev/doc_lint.sh`


