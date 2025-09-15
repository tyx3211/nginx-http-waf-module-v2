## 注意：内置工件优先哲学（置顶）

- 内置优先（优先 Nginx，其次系统）：路径/文件/正则/内存池/字符串/日志等复用内置 API。
- 不重复造轮子：无明确缺口不自研通用工具；有缺口需论证与测试。
- 保守处理：字符串仅做必要格式化；安全边界通过目录句柄 + `openat/fstatat` 等保障，不靠字符串归一。
- 一致性：`ngx_pool_t`/slab、`ngx_str_t`、`ngx_p[n]alloc`、`ngx_log_error` 等统一使用；与 Nginx 行为对齐。
- 功能不失：引入内置替换不改变既有语义；回归必须通过。

## 注意：编码偏好与装配脚本（置顶）

- 编码偏好（强制）
  - 头文件引入：禁止使用相对路径 include（如 `#include "third_party/yyjson/yyjson.h"`）；统一通过构建脚本配置头文件搜索路径，代码中使用 `<yyjson/yyjson.h>`、`<uthash/uthash.h>`、`"src/include/..."` 等标准形式。
  - 构建配置：在模块 `config`/`CFLAGS` 中追加 `-I$ngx_addon_dir/src/include -I$ngx_addon_dir/third_party/yyjson -I$ngx_addon_dir/third_party/uthash`，避免在源码里写相对路径 include。
  - 绝对路径优先：文档与脚本示例尽量给出绝对路径，命令行参数可覆盖默认路径。
  - 注释与沟通：统一中文注释与中文说明，函数/模块级注释强调“为什么”。

- 现有装配脚本（v1，参考）
  - `nginx-src/debug1.sh`：`make clean` → `./configure --with-compat --add-dynamic-module=...` → `make modules` → 将 `objs/ngx_http_waf_module.so` 拷贝到 `/usr/local/nginx/modules/`。
  - `nginx-src/debug2.sh`：删除 `objs/addon/src/*.o` 后 `make modules` → 拷贝 `.so`。
  - `nginx-src/debug3.sh`：`make clean` → `./configure` → `make` → `make install` → 拷贝 `.so`。

- v2 推荐装配脚本
  - 新增 `nginx-src/build_v2.sh`（封装上述流程，支持 preset 与细粒度步骤、`--bear`、`--jobs`、`--link-compile-db`）。
  - 常用示例：
    - `./build_v2.sh --preset debug1`
    - `./build_v2.sh --preset debug2`
    - `./build_v2.sh --preset debug3`
    - `./build_v2.sh --all --bear --link-compile-db --jobs 8`
  - 关键默认值：`prefix=/usr/local/nginx`，`module-dir=<repo>/nginx-http-waf-module-v2`，模块产物 `objs/ngx_http_waf_module.so` 拷贝到 `$prefix/modules/`。

## 注意：预置目录

- nginx源码目录：`/home/william/myNginxWorkspace/nginx-src`
- v2模块目录：`/home/william/myNginxWorkspace/nginx-http-waf-module-v2`
- v1模块目录：`/home/william/myNginxWorkspace/nginx-http-waf-module`
- nginx安装目录：`/usr/local/nginx`或者`/home/william/myNginxWorkspace/nginx-install`(软链接)

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

### [x] M1：JSON 解析与合并（数据面）
- 范围：
  - [x] 解析入口，错误定位到 JSON 路径
  - [x] `extends` 递归 + 循环检测 + 深度上限（支持 0=不限）
  - [x] 过滤/禁用/追加与冲突策略（include/excludeTags、disableById/Tag、extraRules、duplicatePolicy 三策略）
  - [x] 产出 `final_mut_doc`（以只读 `yyjson_doc` 返回）
  - [x] loc 合并后按“合并结果 max_depth”对本块 `waf_rules_json` 进行后置解析
- DoD：
  - [ ] 单测覆盖：必填/类型/非法组合/循环/深度/冲突三模式（待补充单测用例）
  - [x] 大小写、尾逗号、注释等容错（已启用 yyjson 相关 flags）
  - [x] 失败信息含文件与 JSON pointer（已在错误路径处填充）
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
  - [ ] 新指令最小集；`waf_json_extends_max_depth <number>`（http/server/location；0=不限）；动态封禁组；`waf_trust_xff`、`waf_shm_zone`
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


