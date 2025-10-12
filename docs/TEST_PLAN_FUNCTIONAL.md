### 功能性测试计划（v2）

目标：优先覆盖“功能正确性”，暂不纳入兼容性/性能。用例聚焦：指令行为、日志 JSONL、一致性、动态封禁、规则引擎 BLOCK/LOG/BYPASS。

#### 1. 指令与继承（参考 `docs/waf-directives-spec-v2.0.md` 与 `src/module/ngx_http_waf_config.c`）
- `waf on|off`（LOC 可覆盖）
  - 场景：`http{ waf on; }`，在 `/static/` 显式 `waf off;` 应完全旁路（不加分、不封禁、不写 JSONL）。
- `waf_default_action BLOCK|LOG`
  - 场景：全局为 `LOG`，某子路径为 `BLOCK`，验证命中规则时的裁决差异与最终 `status`。
- `waf_rules_json` + `waf_jsons_dir` + `waf_json_extends_max_depth`
  - 场景：多层 extends、越界/循环报错、覆盖规则指针验证合并结果（M1/编译器已通过，回归一条 Happy path）。
- `waf_dynamic_block_enable on|off`
  - 场景：仅在 `http{}` 开启，局部关闭路径不触发动态加分与封禁。
- MAIN 级：`waf_json_log`、`waf_json_log_level`、`waf_trust_xff`、`waf_shm_zone`、`waf_dynamic_block_*`
  - 场景：不同级别阈值对 BYPASS/ALLOW 的落盘影响；`trust_xff` 生效的 IP 提取差异；缺少 `waf_shm_zone` 时动态封禁不生效。

执行建议：
- 用最小 `nginx.conf` 模板渲染多场景；启动 `nginx -t -q` 校验后回归请求。

#### 2. 日志 JSONL 行为（参考 `docs/waf-jsonl-spec-v2.0.md` 与 `src/core/ngx_http_waf_log.c`）
- BLOCK 必落盘且 `level>=ALERT`；记录 `finalActionType`、`blockRuleId`（规则阻断）。
- BYPASS 落盘受阈值控制；`decisive` 为最后一条 intent=BYPASS 的规则事件。
- ALLOW：有事件在 `info|debug` 打开时落盘；空事件不落盘。
- `currentGlobalAction` 与指令对齐；字段完整性与类型校验（JSON schema）。

#### 3. 动态封禁（参考 `src/core/ngx_http_waf_dynamic_block.c`）
- 开启 `waf_shm_zone` + `waf_dynamic_block_*` + `waf_dynamic_block_enable on`。
- 场景：
  - 连续 N 次请求累计分数超过阈值 → `ban` 事件 → 同 IP 后续请求 `BLOCK_BY_DYNAMIC_BLOCK`。
  - 窗口过期重置：产生 `reputation_window_reset` 事件（DEBUG 级，阈值放宽时可见）。
- 工具：
  - 使用 `ab` 或 `wrk` 生成高频访问；或在测试脚本内循环 curl；确保来自同一源 IP。

#### 4. 规则引擎 BLOCK/LOG/BYPASS（编译产出的只读快照）
- EXACT/REGEX/CONTAINS、negate 取反、ALL_PARAMS 展开（URI/ARGS/BODY 独立单次解码）。
- 典型用例：
  - SQLi 片段拦截（BLOCK / LOG）
  - UA 黑白名单
  - URI 白名单（BYPASS 短路）
  - CSRF Cookie 检查（如适用）
- 断言：最终 HTTP 状态、`finalAction`、相关事件存在且字段正确。

#### 5. 脚本与复用（参考 v1 `tests/` 与 `all.sh`）
- 复用思路：
  - `tests/run_waf_tests.sh` 作为驱动，接受场景名参数，渲染 `nginx.conf`、启动与回收 Nginx、执行请求、解析 JSONL。
  - 针对每个场景提供 `test_*.sh`，输出统一 PASS/FAIL。
- 最小样例：
  - `test_basic_directives.sh`：验证 `waf on/off` 与 `waf_default_action`。
  - `test_jsonl_block_logics.sh`：制造 BLOCK 与 BYPASS 请求，校验 JSONL。
  - `test_dynamic_block_ab.sh`：用 ab 触发封禁并验证后续阻断。

#### 6. 产出与分工
- 文档：本文件与 `waf-jsonl-spec-v2.0.md`。
- 脚本：在 `nginx-http-waf-module-v2/tests/` 下新增测试脚本骨架与样例。
- CI：新增 job 跑指定子集（功能性优先）。

---

### 7. 当前实现对齐与测试边界（务必先对齐后写测试）

本节将当前实现（以源码现状为准）与规范进行对齐，给出“纳入测试/暂不测试”的边界，避免测试与实现错位导致结论混淆。

7.1 已实现且纳入测试
- 核心指令与继承（参照 `docs/waf-directives-spec-v2.0.md`）
  - `waf on|off`（HTTP/SRV/LOC，LOC 可覆盖）
  - `waf_default_action BLOCK|LOG`（HTTP/SRV/LOC）
  - `waf_rules_json`（HTTP/SRV/LOC 覆盖生效）
  - `waf_json_log`（MAIN），`waf_json_log_level off|debug|info|alert|error`（MAIN）
  - `waf_shm_zone`（MAIN）
  - `waf_dynamic_block_enable on|off`（HTTP/SRV/LOC；推荐仅 http 级设置）
- JSON 规则（参照 `docs/waf-json-spec-v2.0-simplified.md`）
  - 入口 `rules` 加载；`meta.extends`（基础 happy path）与禁用 `disableById/disableByTag`；重复策略 `duplicatePolicy` 的 warn 行为
  - 匹配器：`CONTAINS|REGEX|CIDR|EXACT`；`caseless`；`negate`；`target: string|string[]`；`HEADER+headerName` 约束
  - `ALL_PARAMS` 展开语义与一次性解码策略（URI/ARGS_COMBINED/BODY）
- 请求期 JSONL（参照 `docs/waf-jsonl-spec-v2.0.md`）
  - 一次请求最多落盘一行；BLOCK 必落盘且至少 `ALERT`
  - 顶层字段：`finalAction`、`finalActionType`、`blockRuleId?`、`status?`、`currentGlobalAction`、`level`
  - 事件：`rule|reputation|ban|reputation_window_reset`；`decisive` 标记选择逻辑
  - ALLOW 的“空事件不落盘”，非空事件在 `info|debug` 下落盘
- 动态封禁（最小链路）
  - 评分累积→阈值命中→`ban` 事件→后续请求 `BLOCK_BY_DYNAMIC_BLOCK`
  - 窗口过期的 `reputation_window_reset` 事件（DEBUG 级可见）

7.2 暂未实现/暂不纳入测试（以避免误判）
- 指令 Roadmap 中标记“待注册/规划中”的：
  - `waf_trust_xff`（MAIN）
  - `waf_dynamic_block_score_threshold`、`waf_dynamic_block_duration`、`waf_dynamic_block_window_size` 的完整可调版本（若源码尚未接上）
  - `waf_json_log_allow_empty`、`waf_debug_final_doc`（v2.1 规划）
- 规则 JSON v2.1 扩展：
  - `waf-json-inheritance-merge-spec.md` 中的扩展与高级重写（如按标签/ID 批量重写 targets 的可视化增强）
- 观测与调试增强：
  - 请求日志“额外调试字段”与显式 `importedFrom` 溯源等控制台增强字段

7.3 测试配置与执行注意
- 测试 `nginx.conf` 中为避免权限干扰，允许：
  - `user root;`（仅测试环境）或将日志目录与文件属主/属组改为 Nginx 运行用户
  - 专用健康检查 `location = /health { waf off; return 200 "OK"; }` 以避免噪声
- 若需产生更丰富的 JSONL，请将 `waf_json_log_level` 提升至 `info` 或 `debug`。
- 动态封禁测试需确保同一源 IP（本地 curl、ab、wrk 均可），并预设共享内存：`waf_shm_zone waf_zone 8m;`。

7.4 用例分层（对齐到当前实现）
- 基础直通：`test_smoke_basic.sh`、`test_dynamic_block_minimal.sh`（已通过）
- 待补：
  - `test_basic_directives.sh`：`waf on/off` 与 `waf_default_action` 的覆盖校验
  - `test_jsonl_block_logics.sh`：构造 BLOCK/BYPASS/ALLOW 三类，校验 `finalActionType` 与 `decisive`
  - `test_dynamic_block_ab.sh`：高频请求触发 BAN，再次访问 403 与 JSONL 校验
- 暂不加入：涉及 v2.1 或 Roadmap 未完成能力的测试脚本（保持用例目录干净，避免红测）。

7.5 结论准则
- 若用例失败，先对照本节矩阵：
  - 不在“已实现且纳入测试”的范围 → 调整/搁置该测试
  - 在范围内 → 认定为实现/配置/脚本问题，继续定位修复

