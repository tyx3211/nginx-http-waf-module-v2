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
