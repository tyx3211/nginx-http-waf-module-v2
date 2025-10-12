## 测试里程碑（milestones）

### 概览
- [x] M2 编译与配置校验（11/11 通过）
- [x] M1 规则 JSON 合并（26/26 通过）
- [ ] M3 运行期行为与动作验证（阻断/放行/重写/旁路）
- [ ] 性能基准（QPS、延迟 p50/p95/p99、CPU/内存占用）
- [ ] 兼容性矩阵（nginx 版本、Linux 发行版、PCRE2/OpenSSL 版本）
- [ ] 配置热更新与平滑重载（reload 无中断、状态保持）
- [ ] 动态封禁能力验证（含可选外部依赖，如 Redis/共享内存）
- [ ] 可观测性与日志语义（error_log、计数器、指标导出）
- [ ] 规则覆盖与边界测试（恶意样本库、等价类/边界值）
- [ ] 稳定性与内存安全（ASAN/UBSAN、泄漏/悬挂指针）
- [ ] 压力与 DoS 抗性（巨型头/长路径/重复参数/畸形输入）
- [ ] 协议兼容性（HTTP/2、gRPC、WebSocket，如适用）

### 已完成
- M2 编译与配置校验
  - 脚本：`dev/m2_compiler_tests.sh`
  - 结果：PASS=11 FAIL=0
  - 覆盖：规则编译、正则错误、CIDR 解析错误、空规则集、Header 目标合法性、全量参数展开、策略直通等
- M1 规则 JSON 合并
  - 脚本：`dev/m1_json_merge_tests.sh`
  - 结果：All cases passed（26/26）
  - 覆盖：
    - 循环继承检测、层级深度限制
    - 重复策略（报错/跳过/保留最后/默认 warn_skip）
    - 必填项缺失（id/target）、字段类型错误、越界/非法取值
    - Header 目标与其它目标混用、Header 缺少名称
    - EXACT/REGEX 匹配、取反语义、空模式数组
    - 通过 tag/ids 重写 targets（数量不变）

### 执行方式
- Nginx 源码构建脚本：`nginx-src/build_v2.sh`（内含详细用法）
- 运行测试：
  - M2：`CLEAN=1 bash nginx-http-waf-module-v2/dev/m2_compiler_tests.sh`
  - M1：`bash nginx-http-waf-module-v2/dev/m1_json_merge_tests.sh`
- 安装前缀：工作区中 `nginx-install` 软链接指向 `/usr/local/nginx`

### 下一步里程碑（计划）
- M3 运行期行为：验证各阶段拦截/放行/重写/旁路动作与日志
- 性能与资源：固定规则集大小下的吞吐与延迟基准；内存/CPU 画像
- 兼容性：不同 nginx 主版本/小版本、Linux 发行版、PCRE2/OpenSSL 版本
- 热更新与重载：`nginx -s reload` 行为、内存稳定性与无中断保证
- 稳定性与安全：长时间压力、模糊测试、ASAN/UBSAN、内存泄漏回归
- 边界与样本：引入通用恶意样本库与自研边界用例，扩展等价类覆盖

### 备注
- 近期目录调整：JSON 逻辑位于 `src/json/ngx_http_waf_json.c`，核心能力在 `src/core/*`；请以当前源码结构为准。
- 若需要在 CI 或本地隔离环境运行，可通过环境变量覆盖 `NGINX_PREFIX`/`NGINX_SBIN`，默认仍使用系统安装以与现有环境一致。
