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

### [ ] M1：JSON 合并与导入级重写（数据面 · v2.0 简化规范）
- 范围：
  - [ ] 解析入口 JSON（容错：注释/尾逗号等）
  - [ ] `meta.extends` 递归（左→右）+ 循环检测 + 深度上限（0=不限）
  - [ ] extends 元素支持 字符串路径 或 对象：
        - `file: string`（必填）
        - `rewriteTargetsForTag?: Record<string, Target[]>`
        - `rewriteTargetsForIds?: Array<{ ids: number[]; target: Target[] }>`
        - 重写仅作用当前层 imported_set；先按 tag 后按 ids 应用
  - [ ] imported_set 上禁用：`disableById:number[]`、`disableByTag:string[]`（仅移除父集，不影响本地 rules）
  - [ ] 目标归一化与校验：
        - `target: string|string[]`；加载期展开 `ALL_PARAMS` 为 `["URI","ARGS_COMBINED","BODY"]`
        - 若含 `HEADER`：数组长度必须为 1 且必须提供 `headerName`
        - 非法/空数组报错并定位 JSON 指针
  - [ ] 追加本地 `rules` 到集合尾部
  - [ ] 去重：按 `meta.duplicatePolicy`（默认 `warn_skip`）对“本层可见集合”基于 `id` 去重，支持 `error|warn_skip|warn_keep_last`
  - [ ] 最终产出：仅 `rules` 数组；从入口 JSON 透传 `version`、`meta.name`、`meta.versionId`、`policies`
  - [ ] v2.0 简化：不支持 `includeTags`/`excludeTags`/`extraRules`；`meta` 不跨层继承
  - [ ] 路径解析：绝对/相对/裸路径（相对 `waf_jsons_dir` 或 Nginx prefix）；错误信息含文件与 JSON pointer
- DoD（测试优先）：
  - [ ] 单测矩阵覆盖：
        1) 必填/类型校验与非法组合（`HEADER` 约束、`pattern[]` 非空、`caseless` 类型）
        2) `extends`：递归顺序、循环、深度上限
        3) 导入级重写：按 tag 和按 ids 均生效；非法 target 值与 `HEADER` 组合报错；`ALL_PARAMS` 展开
        4) 禁用作用域：仅影响 imported_set；本地 `rules` 不受影响
        5) 去重三策略：`error`/`warn_skip`/`warn_keep_last` 的顺序与结果
        6) 路径解析：绝对/相对/裸路径与 `waf_jsons_dir`；错误指针定位
        7) 兼容性：注释/尾逗号解析成功
  - [ ] 用例目录与脚本：
        - `WAF_RULES_JSON/` 新增：`rewrite_tags.json`、`rewrite_ids.json`、`invalid_target_combo.json`、`header_array_invalid.json`、`all_params_expand.json`、`disable_scope.json`、`duplicate_policy_{error,warn_skip,warn_keep_last}.json` 等
        - 更新 `dev/m1_json_merge_tests.sh`：新增用例并校验退出码与 stdout 片段
  - [ ] 返回 `yyjson_doc`（只读）且内存安全；日志包含必要 `WARN/ERR`
- 依赖：M0
- 投入：4-6 人日
- 交付：
  - `src/json/ngx_http_waf_json.c` 完成上述合并/重写/校验逻辑
  - 测试用 JSON 与脚本
  - 文档：`docs/waf-json-spec-v2.0-simplified.md`（已对齐）

### [ ] M2：编译期快照
- 范围：
  - [ ] 规则校验与 phase 推断/覆盖校验
  - [ ] REGEX/CONTAINS/CIDR 预编译
  - [ ] 唯一性校验与分桶（uthash 仅编译期临时使用；运行期 loc_conf 仅保留 `ngx_array` 分桶；可选 debug 只读 `id_index`）
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


