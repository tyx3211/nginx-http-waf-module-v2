## v2 里程碑（顺序、范围、DoD、依赖与排期建议）

说明：以下为实现阶段的单一事实来源（SoT）。每个里程碑包含范围、完成定义（DoD）、主要依赖、建议投入与交付物。

### [x] M0：骨架与工具链
- 范围：
  - [x] 最小模块骨架可编译（config + module + include）
  - [x] vendored：yyjson/uthash 目录落地（可为空实现，但头/源路径正确）
  - [x] clangd 工作：`compile_commands.json` 可生成；符号跳转/包含路径解析正常
- DoD：
  - [x] `make modules` 通过，产出 `ngx_http_waf_module.so`
  - [x] `docs/clangd-setup.md` 可复现；`dev/setup-clangd.sh` 可一键生成 DB
  - [x] `README.md` 中有快速开始（构建/加载模块）
- 依赖：Nginx 1.24.0 源码与构建链（bear/openssl/zlib/pcre）
- 投入：1-2 人日
- 交付：骨架文件、config、文档与脚本

### [ ] M1：JSON 解析与合并（数据面）
- 范围：
  - [ ] 解析入口，错误定位到 JSON 路径
  - [ ] `extends` 递归 + 循环检测 + 深度上限
  - [ ] 过滤/禁用/追加与冲突策略
  - [ ] 产出 `final_mut_doc`
- DoD：
  - [ ] 单测覆盖：必填/类型/非法组合/循环/深度/冲突三模式
  - [ ] 大小写、尾逗号、注释等容错（按设计）
  - [ ] 失败信息含文件与 JSON pointer
- 依赖：M0
- 投入：3-5 人日
- 交付：`src/json/*` 最小实现 + 单测

### [ ] M2：编译期快照
- 范围：
  - [ ] 规则校验与 phase 推断/覆盖校验
  - [ ] REGEX/CONTAINS/CIDR 预编译
  - [ ] `id_map` 与分桶；loc_conf 快照；请求期零分配校验
- DoD：
  - [ ] 单测覆盖：分桶/排序/去重/空集行为；`ngx_array_create` 最小容量保证
  - [ ] REGEX 编译失败时定位具体规则与模式
- 依赖：M1
- 投入：4-6 人日
- 交付：`src/core/ngx_http_waf_compiler.*` + 相关工具

### [ ] M3：指令与路径解析
- 范围：
  - [ ] 新指令最小集；动态封禁组；`waf_trust_xff`、`waf_shm_zone`
  - [ ] JSON 路径解析与继承覆盖策略
- DoD：
  - [ ] `nginx -t` 通过；http/srv/loc 继承符合预期
  - [ ] 示例 `nginx.conf` 可跑通（无规则仅基础日志）
- 依赖：M2
- 投入：3-4 人日
- 交付：`src/module/*` 指令实现 + 示例配置

### [ ] M4：执行管线（ACCESS）
- 范围：
  - [ ] 入口与 5 段流水线；目标提取与短路
  - [ ] 请求体三段式 + 回调推进
- DoD：
  - [ ] 集成测试：GET/POST/大体；BYPASS/BLACKLIST 路径生效
  - [ ] 检测段遍历与优先级生效（可先少量规则）
- 依赖：M2（基础）与 M3（指令装配）
- 投入：4-6 人日
- 交付：`src/module/ngx_http_waf_module.c` 扩展 + 目标提取工具

### [ ] M5：动态封禁（并行推进，最小可用集）
- 范围：
  - [ ] shm 结构（rbtree+queue+slab）、窗口/过期/LRU
  - [ ] 评分/执法 API；统一动作出口复检与日志
- DoD：
  - [ ] 单/集成测试：加分到阈值自动封禁，窗口外衰减/过期
  - [ ] 并发与锁正确性（基本验证）
- 依赖：M3（指令）与 M4（事件触发点），但可与 M4 并行
- 投入：5-7 人日
- 交付：`src/core/ngx_http_waf_dynamic_block.*` + `src/core/ngx_http_waf_action.*`

### [ ] M6：日志 JSONL
- 范围：
  - [ ] ctx 事件聚合；`waf_log_flush` 输出；级别控制
- DoD：
  - [ ] JSONL 格式稳定；包含 rule/reputation/ban/bypass 事件
  - [ ] 性能基线下无明显退化
- 依赖：M4/M5
- 投入：2-3 人日
- 交付：`src/core/ngx_http_waf_log.*` + 文档

### [ ] M7：测试/回归/性能
- 范围：
  - [ ] 单测/集成/gotestwaf；性能对比 v1
- DoD：
  - [ ] TP/FP 不退化；QPS/延迟指标在误差范围内
- 依赖：M4-M6
- 投入：3-5 人日
- 交付：CI 脚本与报告

### [ ] M8：清理与交付
- 范围：
  - [ ] 删除旧 DSL/旧指令路径；迁移指南；设计决策记录
- DoD：
  - [ ] 文档完整；版本打 tag；发布说明
- 依赖：全部
- 投入：1-2 人日
- 交付：发布包与文档


