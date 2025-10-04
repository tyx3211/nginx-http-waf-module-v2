### Nginx 指令规范 v2.0（运维面）

说明：本规范定义运维侧可在 `nginx.conf` 中配置的指令与行为边界，覆盖全局动作策略、JSON 日志、动态封禁、共享内存与规则工件加载等。与规则 JSON v2.0 互补：数据面匹配/策略由 JSON 工件描述，控制面全局策略与运行期设施由本指令集控制。

### 指令支持 Roadmap（v2.0 运维面）

- [x] `waf_jsons_dir`（MAIN）
- [x] `waf_rules_json`（HTTP/SRV/LOC，可覆盖）
- [x] `waf_json_extends_max_depth`（HTTP/SRV/LOC，loc 覆盖）
- [x] `waf_shm_zone <name> <size>`（MAIN）
- [x] `waf_json_log <path>`（MAIN）
- [x] `waf_json_log_level off|debug|info|alert`（MAIN）
- [x] `waf on|off`（HTTP/SRV/LOC，loc 可覆盖；off 完全旁路）✅ 已实现
- [x] `waf_default_action BLOCK|LOG`（HTTP/SRV/LOC，loc 可覆盖）✅ 已实现
- [ ] `waf_trust_xff on|off`（MAIN）⚠️ 字段已存在，待注册指令
- [x] `waf_dynamic_block_enable on|off`（HTTP/SRV/LOC，推荐仅在 http 设置，方案C）✅ 已实现
- [ ] `waf_dynamic_block_score_threshold <num>`（MAIN）⚠️ 字段已存在，待注册指令
- [ ] `waf_dynamic_block_duration <time>`（MAIN）⚠️ 字段已存在，待注册指令
- [ ] `waf_dynamic_block_window_size <time>`（MAIN）⚠️ 字段已存在，待注册指令
- [ ] `waf_json_log_allow_empty on|off|sample(N)`（MAIN，v2.1 规划，目前版本不考虑）
- [ ] `waf_debug_final_doc on|off`（MAIN，v2.1 规划，目前版本不考虑）

---

## 1. 作用域与继承规则

### 1.1 配置层级说明

本模块采用 Nginx 标准的双层配置模型：

- **`main_conf`（HTTP_MAIN_CONF）**：全局单例配置，仅在 `http {}` 块中设置，**不参与继承**，所有 `location` 共享同一实例。
- **`loc_conf`（HTTP_LOC_CONF）**：可在 `http/server/location` 层级设置，遵循 Nginx 标准继承/合并语义，子级可覆盖父级。

---

### 1.2 MAIN级指令（存储在 `main_conf`，全局单例，不继承）

以下指令**仅允许出现在 `http {}` 块**，不支持在 `server/location` 覆盖：

| 指令 | 默认值 | 作用 |
|------|--------|------|
| `waf_trust_xff` | `off` | 是否信任 X-Forwarded-For |
| `waf_jsons_dir` | 空 | JSON 工件根目录 |
| `waf_json_log` | 空 | JSONL 日志路径 |
| `waf_json_log_level` | `off` | 日志级别 |
| `waf_shm_zone` | 无 | 共享内存区域名称与大小 |
| `waf_dynamic_block_score_threshold` | `100` | 封禁评分阈值 |
| `waf_dynamic_block_duration` | `30m` | 封禁持续时长 |
| `waf_dynamic_block_window_size` | `1m` | 评分滑动窗口 |

**设计理由**：这些指令控制全局运行时基础设施（共享内存、日志文件、JSON 工件根目录、XFF 信任策略、动态封禁全局参数），允许继承会导致语义歧义（例如不同 `location` 使用不同的 `waf_trust_xff` 会导致同一 IP 在不同路径被识别为不同客户端）。

**重要说明**：本模块会自动跳过内部请求（`r->internal == 1`）和子请求（`r != r->main`），无需额外配置。这意味着即使 `waf on`，`error_page` 重定向、`try_files` 跳转、`auth_request` 子请求等都会被自动过滤，不会触发 WAF 检测。

---

### 1.3 LOC级指令（存储在 `loc_conf`，可继承/覆盖）

以下指令**可在 `http/server/location` 任意层级设置**，遵循 Nginx 标准继承语义：

| 指令 | 默认值 | 继承语义 |
|------|--------|----------|
| `waf on\|off` | `on` | 模块总开关；`location` 可覆盖上层（用于静态路径白名单） |
| `waf_default_action` | `BLOCK` | 执法策略（BLOCK/LOG）；`location` 可覆盖上层（用于敏感路径强制拦截或放宽策略） |
| `waf_dynamic_block_enable` | `off` | 动态封禁开关；**推荐仅在 `http {}` 设置一次**，让所有路径统一继承 |
| `waf_rules_json` | 空 | 规则入口 JSON 路径；子级覆盖父级 |
| `waf_json_extends_max_depth` | `5` | JSON 合并最大深度；子级覆盖父级 |

**最佳实践**：`waf_dynamic_block_enable` 虽然支持 `location` 级覆盖，但**强烈建议仅在 `http {}` 块设置一次**，让所有路径统一继承。仅在极特殊场景（如静态资源目录 `/static/`、健康检查端点 `/health`）才考虑显式关闭。不建议在敏感路径（如 `/api/`, `/admin/`）关闭动态封禁。

---

### 1.4 特殊说明：JSON 工件与指令分界

- **`baseAccessScore`（规则工件）**：仅在 JSON 的 `policies.dynamicBlock.baseAccessScore` 定义，不提供对应指令，不参与 Nginx 层级继承（透传给运行时）。
- **其他动态封禁参数（指令）**：`threshold/duration/window_size/enable` 等由指令统一控制（存储在 `main_conf`）。

---

## 2. 指令一览（v2.0）

### 2.1 执法动作策略（HTTP/SRV/LOC）

- 名称：`waf_default_action BLOCK | LOG`
- 作用域：`http/server/location`
- 默认值：`BLOCK`
- 说明：当规则/信誉产生"执法意图"时的裁决策略。`BLOCK` 表示直接阻断并返回 `403`（或规则指定状态）；`LOG` 表示仅记录事件，放行请求。遵循 Nginx 标准继承语义，`location` 可覆盖上层。
- **典型场景**：
  - 在 `http {}` 设置为 `BLOCK` 作为默认策略
  - 在测试环境的 `server {}` 中覆盖为 `LOG` 以观察告警
  - 在敏感路径（如 `/admin/`）强制为 `BLOCK` 确保安全
  - 在开发/灰度环境的特定 `location` 中设置为 `LOG` 降低误杀风险
- 示例：
  ```nginx
  http {
      waf_default_action BLOCK;  # 默认拦截
      
      server {
          listen 8080;
          
          location /admin/ {
              waf_default_action BLOCK;  # 敏感路径强制拦截
          }
          
          location /api/v2/ {
              waf_default_action LOG;  # 新版API仅记录，不拦截
          }
      }
  }
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

### 2.4 动态封禁开关（HTTP/SRV/LOC）

- 名称：`waf_dynamic_block_enable on | off`
- 作用域：`http/server/location`
- 默认值：`off`
- 说明：控制动态 IP 封禁能力在当前作用域是否生效。遵循 Nginx 继承语义，`location` 可覆盖上层。
- **最佳实践**：推荐仅在 `http {}` 块设置一次为 `on`，让所有路径统一继承。仅在极特殊场景（静态资源、健康检查）考虑在 `location` 显式关闭。
- **重要**：动态封禁仅针对主请求（main request）的客户端 IP。内部请求和子请求会被自动过滤，不会触发评分或封禁逻辑。
- 示例：
  ```nginx
  http {
      waf_dynamic_block_enable on;  # 全局开启，所有 location 继承
      
      location /static/ {
          waf_dynamic_block_enable off;  # 静态资源不参与动态封禁
      }
  }
  ```

### 2.5 动态封禁全局参数（MAIN）

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

### 2.6 XFF 信任（MAIN）

- 名称：`waf_trust_xff on | off`
- 作用域：`http`（MAIN）
- 默认值：`off`
- 说明：是否信任 `X-Forwarded-For` 的第一个 IP 作为客户端源 IP；影响动态封禁与日志。

### 2.7 模块总开关（HTTP/SRV/LOC）

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

**重要行为说明**：

1. **内部请求与子请求自动过滤**  
   本模块会自动跳过以下类型的请求：
   - **内部请求**（`r->internal == 1`）：如 `error_page` 重定向、`try_files` 内部跳转等
   - **子请求**（`r != r->main`）：如 `auth_request`、SSI `include`、`mirror` 等

2. **过滤理由**：
   - 内部请求已被主请求的 WAF 检查覆盖，重复检测无意义
   - 子请求通常是内部功能逻辑（鉴权、负载均衡），不应独立触发 WAF
   - 避免重复检测，提升性能

3. **调试支持**：
   在 Nginx `error_log` 设置为 `debug` 级别时，可看到过滤日志：
   ```
   [debug] WAF: skip internal request
   [debug] WAF: skip subrequest
   ```

4. **典型场景**：
   ```nginx
   location /api/ {
       waf on;
       error_page 403 /error403.html;  # 内部重定向，WAF 自动跳过
   }

   location / {
       waf on;
       auth_request /auth;  # 子请求验证，WAF 自动跳过
   }
   ```

### 2.8 规则工件加载与编译（MAIN/SRV/LOC）

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

### 2.9 调试与排障（MAIN，v2.1 规划）

- 名称：`waf_debug_final_doc on | off`
- 作用域：`http`（MAIN）
- 默认值：`off`
- 说明：将合并后的最终规则文档以单行 JSON 形式输出到 `error_log`（仅用于排障，生产建议关闭）。

---

## 3. 冲突与优先级

- 动作优先级：`BLOCK` 行为由 action 层即时落盘并终止；当设置为 `LOG` 时，规则触发仅记录事件，不中断请求，但动态封禁到达阈值仍可导致后续请求被阻断。
- 继承覆盖：`waf_default_action` 遵循 Nginx 标准继承语义，子级（location）可完全覆盖父级（http/server）设置。
- JSON 与指令边界：运维面参数以指令为准，数据面策略以 JSON 为准。两者不重复配置相同含义的字段（例如仅 JSON 定义 `baseAccessScore`）。

---

## 4. 兼容性与迁移（v1 → v2）

- v1 中的多数组合指令（如各类 `*_rules_file`、`*_defense_enabled`）在 v2 被 JSON 工件统一承载。
- v1 的 `waf on|off` 可选在 v2 以同名指令保留（规划中），也可通过是否提供 `waf_rules_json` 决定启用范围；最终以 Roadmap 公布为准。

---

## 5. 最小示例

```nginx
http {
    # 模块总开关（推荐在 http 级设置，location 可覆盖）
    waf on;

    # 执法策略（LOC 级，推荐在 http 设置默认值，location 可覆盖）
    waf_default_action BLOCK;

    # JSON 请求日志
    waf_json_log        logs/waf_json.log;
    waf_json_log_level  info;

    # 动态封禁：共享内存 + 全局参数（MAIN 级）
    waf_shm_zone                        waf_block_zone 10m;
    waf_dynamic_block_score_threshold   100;
    waf_dynamic_block_duration          30m;
    waf_dynamic_block_window_size       1m;

    # 动态封禁开关（LOC 级，推荐仅在 http 设置一次）
    waf_dynamic_block_enable            on;

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
            # waf_dynamic_block_enable 也会被自动禁用（因为 waf off 优先级更高）
        }
        
        location /health {
            # 健康检查：仅关闭动态封禁，但仍执行 WAF 规则检查
            waf_dynamic_block_enable off;
        }
        
        location /api/beta/ {
            # Beta API：仅记录，不拦截（用于灰度观察）
            waf_default_action LOG;
        }
    }
}
```


