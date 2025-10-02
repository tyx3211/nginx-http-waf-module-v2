### Nginx 指令规范 v2.0（运维面）

说明：本规范定义运维侧可在 `nginx.conf` 中配置的指令与行为边界，覆盖全局动作策略、JSON 日志、动态封禁、共享内存与规则工件加载等。与规则 JSON v2.0 互补：数据面匹配/策略由 JSON 工件描述，控制面全局策略与运行期设施由本指令集控制。

---

## 1. 作用域与继承规则

- 仅允许出现在 HTTP 级（MAIN）的指令：不允许继承，避免歧义。
  - `waf_default_action`
  - `waf_json_log`
  - `waf_json_log_level`
  - `waf_json_log_allow_empty`（移至 v2.1 规划，不在 v2.0 提供）
  - `waf_trust_xff`
  - `waf_shm_zone`
  - 动态封禁基线：`waf_dynamic_block_enable`、`waf_dynamic_block_score_threshold`、`waf_dynamic_block_duration`、`waf_dynamic_block_window_size`

- 允许在 `http/server/location` 出现并遵循 Nginx 继承/合并语义的指令：
  - `waf_rules_json`（可多层覆盖，最终以 loc 有效）
  - `waf_json_extends_max_depth`（loc 可覆盖 main 缺省）
  - `waf_jsons_dir`（MAIN：JSON 工件根目录）

- 与 JSON 工件关系（v2.0 采用方案A）：
  - 动态封禁的 `baseAccessScore` 仅在规则 JSON 顶层 `policies.dynamicBlock.baseAccessScore` 定义；本版本不提供任何指令覆盖，且不参与 Nginx 层级继承/合并（透传）。
  - 其余动态封禁的“时效/阈值/窗口/开关”由指令统一控制。

---

## 2. 指令一览（v2.0）

### 2.1 全局动作策略（MAIN）

- 名称：`waf_default_action BLOCK | LOG`
- 作用域：`http`（MAIN）
- 默认值：`BLOCK`
- 说明：当规则/信誉产生“执法意图”时的全局裁决。`BLOCK` 表示直接阻断并返回 `403`（或规则指定状态）；`LOG` 表示仅记录事件，放行请求。
- 示例：
  ```nginx
  waf_default_action BLOCK;
  ```

### 2.2 JSON 请求日志（MAIN）

- 名称：`waf_json_log <path>`
- 作用域：`http`（MAIN）
- 默认值：空（禁用输出）
- 说明：设置请求期 JSONL 日志文件路径。BLOCK/BYPASS/ALLOW 的最终落盘由 action/log 层统一控制（去重写出）。
- 示例：
  ```nginx
  waf_json_log  logs/waf_json.log;
  ```

- 名称：`waf_json_log_level off | debug | info | alert`
- 作用域：`http`（MAIN）
- 默认值：`off`
- 说明：控制 BYPASS/ALLOW 的落盘阈值；`BLOCK` 至少提升到 `alert` 并必落盘。

- 名称（规划中）：`waf_json_log_allow_empty on | off | sample(<N>)`
- 作用域：`http`（MAIN）
- 默认值：`off`
- 说明：是否对“无事件的 ALLOW”进行落盘或抽样落盘；默认不写以降低噪音。

### 2.3 动态封禁（MAIN）

- 名称：`waf_shm_zone <name> <size>`
- 作用域：`http`（MAIN）
- 默认值：无（必配）
- 说明：为动态封禁等共享状态分配共享内存区域；`<size>` 支持 `k/m` 后缀。
- 示例：
  ```nginx
  waf_shm_zone waf_block_zone 10m;
  ```

- 名称：`waf_dynamic_block_enable on | off`
- 作用域：`http`（MAIN）
- 默认值：`off`
- 说明：开关动态 IP 封禁能力（评分、阈值、禁用期等随下列指令生效）。

- 名称：`waf_dynamic_block_score_threshold <number>`
- 作用域：`http`（MAIN）
- 默认值：`100`
- 说明：当某 IP 累计分达到阈值即进入封禁。

- 名称：`waf_dynamic_block_duration <time>`
- 作用域：`http`（MAIN）
- 默认值：`30m`
- 说明：封禁持续时长；支持 `ms/s/m/h`。

- 名称：`waf_dynamic_block_window_size <time>`
- 作用域：`http`（MAIN）
- 默认值：`1m`
- 说明：评分滑动窗口大小；窗口外分值自然过期。

- 备注：`baseAccessScore` 保持在 JSON 工件 `policies.dynamicBlock.baseAccessScore` 中定义；与上述 MAIN 指令无继承/合并关系。

### 2.4 XFF 信任（MAIN）

- 名称：`waf_trust_xff on | off`
- 作用域：`http`（MAIN）
- 默认值：`off`
- 说明：是否信任 `X-Forwarded-For` 的第一个 IP 作为客户端源 IP；影响动态封禁与日志。

### 2.5 模块总开关（HTTP/SRV/LOC）

- 名称：`waf on | off`
- 作用域：`http/server/location`
- 默认值：`on`
- 说明：控制本模块是否在对应作用域启用。遵循 Nginx 继承语义，`location` 可覆盖上层。`off` 时本模块在该作用域完全旁路：不检查、不加分、不封禁、不写入请求 JSONL 日志。
- 示例：
  ```nginx
  server {
      waf on;
      location /static/ { waf off; }
  }
  ```

### 2.6 规则工件加载与编译（MAIN/SRV/LOC）

- 名称：`waf_rules_json <path>`
- 作用域：`http/server/location`
- 默认值：无
- 说明：指定规则 JSON 工件路径（可多层覆盖，最终以 `location` 有效）；合并由编译器执行 `extends/禁用/去重` 后产生只读快照。

- 名称：`waf_jsons_dir <dir>`
- 作用域：`http`（MAIN）
- 默认值：空
- 说明：作为 JSON 工件的根目录，便于在规则中使用相对路径 `extends`。

- 名称：`waf_json_extends_max_depth <uint>`
- 作用域：`http/server/location`
- 默认值：`5`
- 说明：限制 JSON `extends` 的最大深度；`location` 可覆盖上层，未设置时继承 MAIN 的缺省值。

### 2.7 调试与排障（MAIN，v2.1 规划）

- 名称：`waf_debug_final_doc on | off`
- 作用域：`http`（MAIN）
- 默认值：`off`
- 说明：将合并后的最终规则文档以单行 JSON 形式输出到 `error_log`（仅用于排障，生产建议关闭）。

---

## 3. 冲突与优先级

- 全局动作优先级：`BLOCK` 行为由 action 层即时落盘并终止；当全局设置为 `LOG` 时，规则触发仅记录事件，不中断请求，但动态封禁到达阈值仍可导致后续请求被阻断。
- JSON 与指令边界：运维面参数以指令为准（MAIN），数据面策略以 JSON 为准。两者不重复配置相同含义的字段（例如仅 JSON 定义 `baseAccessScore`）。

---

## 4. 兼容性与迁移（v1 → v2）

- v1 中的多数组合指令（如各类 `*_rules_file`、`*_defense_enabled`）在 v2 被 JSON 工件统一承载。
- v1 的 `waf on|off` 可选在 v2 以同名指令保留（规划中），也可通过是否提供 `waf_rules_json` 决定启用范围；最终以 Roadmap 公布为准。

---

## 5. 最小示例

```nginx
http {
    # 模块开关（可在 http/server/location 任意层使用，loc 可覆盖）
    waf on;

    waf_default_action BLOCK;

    # JSON 请求日志
    waf_json_log        logs/waf_json.log;
    waf_json_log_level  info;

    # 动态封禁与共享内存
    waf_shm_zone                        waf_block_zone 10m;
    waf_dynamic_block_enable            on;
    waf_dynamic_block_score_threshold   100;
    waf_dynamic_block_duration          30m;
    waf_dynamic_block_window_size       1m;

    # XFF
    waf_trust_xff on;

    # 规则工件
    waf_jsons_dir       ../WAF_RULES;
    waf_json_extends_max_depth 5;
    server {
        listen 8080;
        location / {
            waf_rules_json  ../WAF_RULES/core.json;  # v2 规则工件
        }
        location /static/ {
            waf off;  # 静态路径完全旁路 WAF
        }
    }
}
```


