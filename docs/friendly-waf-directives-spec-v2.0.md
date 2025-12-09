# Nginx WAF v2 配置指令完全指南 (Friendly Spec)

> 💡 **写在前面**：
> Nginx 的配置文件是运维工程师的画板。V2 版本的指令设计遵循“**极简主义**”与“**原生体验**”。
> 我们尽量复用了 Nginx 的标准行为（如继承规则），让配置直观、可预测。
> 本文档将带大家了解如何通过简单的指令，掌控这套强大的安全系统。

---

## 0. 极速上手：全功能配置模板

不想看长篇大论？直接复制这份配置，根据注释微调即可。它涵盖了绝大多数生产环境的需求。

```nginx
http {
    # =========================================================
    # [全局基础设施] 仅在 http 块定义，全局单例
    # =========================================================

    # 1. 规则仓库根目录
    #    所有规则 JSON 中的相对路径（extends/file）都将以此为基准。
    waf_jsons_dir /usr/local/nginx/WAF_RULES_JSON;

    # 2. 审计日志 (JSONL)
    #    极为详细的结构化日志，建议通过 Filebeat/Vector 采集。
    waf_json_log logs/waf.jsonl;
    waf_json_log_level info;  # debug|info|alert|error|off

    # 3. 动态信誉子系统 (Dynamic Reputation)
    #    必须分配一块共享内存，用于跨 Worker 共享 IP 评分与黑名单。
    waf_shm_zone waf_shm_zone 10m;
    
    #    封禁阈值：累计分超过 1000 即封禁（需配合 dynamic_block_enable 使用）
    waf_dynamic_block_score_threshold 1000;
    waf_dynamic_block_duration 30m;      # 封禁时长
    waf_dynamic_block_window_size 1m;    # 评分滑动窗口

    # 4. 信任代理
    #    如果是部署在 CDN/LB 后，请开启此项以提取真实 Client IP。
    waf_trust_xff on;

    # =========================================================
    # [业务策略] 可在 http/server/location 继承与覆盖
    # =========================================================

    # 5. 模块总开关
    waf on;

    # 6. 执法力度
    #    BLOCK: 发现威胁直接拦截 (返回 403)
    #    LOG:   仅记录日志，放行请求 (适合灰度上线)
    waf_default_action BLOCK;

    # 7. 动态封禁开关
    #    建议在 http 层全局开启，让所有业务共享 IP 信誉防御能力。
    waf_dynamic_block_enable on;

    # 8. 规则入口文件
    #    指向具体的业务规则集。推荐按业务线拆分。
    waf_rules_json user/global_rules.json;

    # 9. 继承深度保护
    waf_json_extends_max_depth 5;

    server {
        listen 80;
        server_name example.com;

        # 继承 http 级的 waf on, BLOCK 等配置...

        location /api/upload {
            # 针对上传接口加载更严格的规则
            waf_rules_json user/upload_strict_rules.json;
        }

        location /static/ {
            # 静态资源完全关闭 WAF，极致性能
            waf off;
        }

        location /admin/ {
            # 敏感区域：强制开启封禁，即使上层关了
            waf_dynamic_block_enable on;
        }
    }
}
```

---

## 1. 核心机制：作用域与继承

理解 Nginx 的继承规则是配置成功的关键。本模块严格遵循 Nginx 标准的双层配置模型：

### 1.1 双层模型 (The Two Layers)

*   **MAIN 级指令**：
    *   **只能**在 `http {}` 块中定义。
    *   **全局单例**：所有 `server` 和 `location` 共享同一份配置（如内存区、日志文件）。
    *   **不参与继承**：它们定义的是“物理基础设施”。

*   **LOC 级指令**：
    *   可以在 `http`、`server` 或 `location` 块中定义。
    *   **支持继承与覆盖**：子级（location）的配置会完全覆盖父级（server/http）。
    *   这赋予了你极大的灵活性——可以为不同的域名、路径定制完全不同的防御策略。

---

## 2. 执法与开关指令 (LOC 级)

这些指令决定了 WAF “怎么管” 你的流量。

### 2.1 模块总开关：`waf`

| 属性 | 说明 |
| :--- | :--- |
| **语法** | `waf on | off` |
| **默认** | `on` |
| **作用域** | `http`, `server`, `location` |

*   **`on` (开启)**：WAF 正常工作，执行检测、记录日志、动态评分。
*   **`off` (关闭)**：**完全旁路模式**。请求就像没有经过 WAF 模块一样，零性能损耗。
    *   **最佳实践**：在静态资源目录（如 `/static/`, `/images/`, `.css`, `.js`）显式设置为 `off`，把 CPU 留给动态接口。

    ```nginx
    location /static/ {
        waf off; # 静态资源旁路，极致性能
    }
    ```

> **💡 智能过滤机制**：
> 你不需要为 `error_page` 跳转或 `auth_request` 子请求手动关闭 WAF。
> 模块内置了智能识别，会自动跳过 **内部请求 (Internal Requests)** 和 **子请求 (Subrequests)**。
> *如何验证？* 将 Nginx 日志级别设为 `debug`，你会在日志中看到 `[debug] WAF: skip internal request` 或 `skip subrequest` 的提示。

### 2.2 执法力度：`waf_default_action`

| 属性 | 说明 |
| :--- | :--- |
| **语法** | `waf_default_action BLOCK | LOG` |
| **默认** | `BLOCK` |
| **作用域** | `http`, `server`, `location` |

这是 WAF 的“扳机”。当规则引擎判定请求有害（Action=DENY）时，该指令决定最终的命运。

*   **`BLOCK` (拦截)**：
    *   **真·拦截**。立即终止请求，返回 403 Forbidden（或规则指定的状态码）。
    *   **必写日志**。强制写入一条 ALERT 级别的告警日志。
    *   **场景**：生产环境的标准配置。
*   **`LOG` (观察/放行)**：
    *   **假·拦截**。即使检测到攻击，也只在日志中记录“意图拦截”，但实际上**放行**请求。
    *   **场景**：
        *   **灰度上线**：新上了一批规则，怕误杀？先开 LOG 跑几天。
        *   **蜜罐/攻防演练**：想看看攻击者到底想干什么，而不惊动他们。

### 2.3 动态防御开关：`waf_dynamic_block_enable`

| 属性 | 说明 |
| :--- | :--- |
| **语法** | `waf_dynamic_block_enable on | off` |
| **默认** | `off` (安全起见默认为关，建议显式开启) |
| **作用域** | `http`, `server`, `location` |

这是 V2 版本的核心武器——**基于信誉的动态封禁**。

*   **开启后 (`on`)**：
    *   WAF 会跟踪每个 Client IP 的行为。
    *   触发规则会扣分，分值累积到共享内存中。
    *   一旦总分超过阈值（`waf_dynamic_block_score_threshold`），该 IP 会被**秒杀**（直接封禁一段时间）。
*   **最佳实践**：
    *   **强烈建议**在 `http {}` 块中全局设置为 `on`。
    *   让所有 `server` 和 `location` 共享同一个 IP 信誉库，形成联防联控。
    *   仅在极少数特殊场景（如公司内部 IP 白名单网段、健康检查接口）在 location 中覆盖为 `off`。

---

## 3. 规则加载指令 (LOC 级)

这些指令告诉 WAF “查什么”。

### 3.1 规则入口：`waf_rules_json`

| 属性 | 说明 |
| :--- | :--- |
| **语法** | `waf_rules_json <path>` |
| **默认** | (无) |
| **作用域** | `http`, `server`, `location` |

*   **作用**：指定当前作用域生效的规则集文件。
*   **路径解析**：
    *   如果是相对路径，将相对于 `waf_jsons_dir`（见下文）解析。
    *   如果是绝对路径，则直接使用。
*   **覆盖逻辑**：子级 `location` 定义的文件会**完全替换**父级定义的规则集（而不是合并）。如果你想复用父级规则，请在新文件中使用 `extends` 继承。

### 3.2 继承深度保护：`waf_json_extends_max_depth`

| 属性 | 说明 |
| :--- | :--- |
| **语法** | `waf_json_extends_max_depth <number>` |
| **默认** | `5` |
| **作用域** | `http`, `server`, `location` |

*   **作用**：防止规则文件出现恶意的“无限递归”引用（A extends B, B extends A）。
*   **说明**：通常默认值 5 层已经绰绰有余。如果你的规则组织结构特别复杂，可以适当调大。

---

## 4. 基础设施指令 (MAIN 级)

这些指令搭建了 WAF 运行的物理基石。**只能在 `http {}` 块配置**。

### 4.1 规则根目录：`waf_jsons_dir`

| 属性 | 说明 |
| :--- | :--- |
| **语法** | `waf_jsons_dir <directory_path>` |
| **默认** | (空) |
| **作用域** | `http` (MAIN) |

*   **作用**：定义规则文件的“家”。
*   **便利性**：设置后，`waf_rules_json` 和规则文件内部的 `extends` 都可以写简洁的相对路径。

### 4.2 共享内存区：`waf_shm_zone`

| 属性 | 说明 |
| :--- | :--- |
| **语法** | `waf_shm_zone <name> <size>` |
| **默认** | (无，必须配置) |
| **作用域** | `http` (MAIN) |

*   **作用**：划拨一块操作系统共享内存，用于存储 IP 信誉分、黑名单状态。
*   **参数**：
    *   `<name>`: 区域名称（任意字符串，如 `waf_shm`）。
    *   `<size>`: 内存大小（支持 `k`, `m` 单位）。
*   **建议**：一般 `10m` 到 `50m` 足以存储数万个并发 IP 的状态。红黑树结构非常节省内存。

### 4.3 审计日志：`waf_json_log` & `level`

| 属性 | 说明 |
| :--- | :--- |
| **语法** | `waf_json_log <file_path>` <br> `waf_json_log_level <level>` |
| **默认** | (空) / `off` |
| **作用域** | `http` (MAIN) |

*   **`waf_json_log`**：指定 JSONL 格式日志的落盘路径。
*   **`waf_json_log_level`**：控制日志的详细程度。
    *   **`off`**: 关闭日志（除非发生 BLOCK）。
    *   **`alert`**: 仅记录 BLOCK 拦截事件。
    *   **`info`**: 记录 BLOCK 和重要的 BYPASS/LOG 事件（推荐生产使用）。
    *   **`debug`**: 记录所有细节（包括每一条命中的规则），日志量巨大，仅供排障。

> **💡 日志原则**：
> `BLOCK` 事件是最高优先级（ALERT），无论级别怎么设，只要拦截了就一定会写日志。

**日志级别的内部机制（进阶理解）**：

对于想深入了解底层的朋友，这里解释一下日志级别的完整语义：

*   **级别顺序**：`none < debug < info < alert < error < off`
*   **`none` 的角色**：这是一个特殊的内部占位符（不可配置），用作请求上下文的初始值。它的存在是为了区分"这个请求还没产生任何事件"和"这个请求产生了低级别事件"。只有当请求真正触发了规则或被提升级别时，才会产生日志，避免正常请求产生噪音。
*   **`off` vs `none`**：`off` 是配置选项，表示"除 BLOCK 外都不写日志"；`none` 是运行时状态，表示"尚未发生任何值得记录的事情"。

### 4.4 动态封禁参数三剑客

| 指令 | 默认 | 说明 |
| :--- | :--- | :--- |
| **`waf_dynamic_block_score_threshold`** | `1000` | **红线**。IP 累计分超过此值立即封禁。 |
| **`waf_dynamic_block_duration`** | `30m` | **刑期**。封禁持续多长时间（支持 `s/m/h`）。 |
| **`waf_dynamic_block_window_size`** | `1m` | **记忆**。评分的滑动窗口，超过时间的旧分值会被遗忘。 |

*   **作用域**：均为 `http` (MAIN)。
*   **调优建议**：
    *   默认 `1000` 分配合规则的平均分值（如 SQL注入=50分），意味着允许约 20 次高危攻击尝试。
    *   如果是高安全需求场景，可降低至 `200`（约 4 次尝试即封禁）。

### 4.5 信任代理：`waf_trust_xff`

| 属性 | 说明 |
| :--- | :--- |
| **语法** | `waf_trust_xff on | off` |
| **默认** | `off` |
| **作用域** | `http` (MAIN) |

*   **场景**：当 Nginx 部署在 CDN、SLB 或其他反向代理**之后**时。
*   **`off`**：使用 TCP 连接的源 IP（Peer IP）。如果是 CDN 回源，这将是 CDN 的 IP。**千万别封 CDN IP！**
*   **`on`**：解析 `X-Forwarded-For` 头部，提取第一个合法的 IP 作为真实客户端 IP。
    *   **注意**：开启此项前，请确保你的 Nginx 前端确实有可信的代理服务器在清洗和添加 XFF 头，否则可能被伪造 IP 绕过。

---

## 5. 进阶话题

### 5.1 JSON 工件与指令的边界

在设计时，我们刻意区分了"运维面"和"数据面"的职责：

*   **Nginx 指令（运维面）**：控制全局行为、基础设施——共享内存、日志路径、封禁阈值等。
*   **JSON 工件（数据面）**：承载业务规则逻辑——规则定义、评分策略、继承关系等。

一个典型的例子是 `baseAccessScore`（基础访问分）：

> **❓ 为什么 `baseAccessScore` 不是一个 Nginx 指令？**
>
> 因为它是业务层面的"规则策略"，不是运维层面的"基础设施"。
> `baseAccessScore` 定义在 JSON 的 `policies.dynamicBlock.baseAccessScore` 中，每个规则文件可以有自己的策略。
> 这让规则文件成为一个**自包含的可移植工件**——带上它，策略就跟着走。

**边界原则**：

| 类型 | 配置位置 | 示例 |
| :--- | :--- | :--- |
| 物理基础设施 | Nginx 指令 | `waf_shm_zone`, `waf_json_log` |
| 全局行为开关 | Nginx 指令 | `waf`, `waf_default_action` |
| 业务规则逻辑 | JSON 工件 | `rules`, `extends`, `policies` |
| 评分策略 | JSON 工件 | `score`, `baseAccessScore` |

### 5.2 冲突与优先级

当不同层级、不同机制同时生效时，模块遵循以下优先级原则：

1.  **动作优先级**：
    *   `BLOCK` 行为具有最高优先级——一旦触发，动作层会**立即落盘日志并终止请求**，不再检查后续规则。
    *   `LOG` 模式下，规则触发仅记录事件，请求继续流转。但如果动态封禁累计分达到阈值，**后续请求**仍会被阻断。

2.  **继承覆盖**：
    *   所有 LOC 级指令（如 `waf_default_action`）遵循 Nginx 标准继承语义。
    *   子级（`location`）配置会**完全覆盖**父级（`http/server`）配置。
    *   **注意**：是"覆盖"而非"合并"——如果子级只写了 `waf off`，不会继承父级的 `waf_rules_json`。

3.  **规则与指令边界**：
    *   运维面参数以 Nginx 指令为准（如 `waf_dynamic_block_score_threshold`）。
    *   数据面策略以 JSON 为准（如 `baseAccessScore`）。
    *   两者不重复配置相同含义的字段，避免歧义。

### 5.3 调试与排障 (v2.1 规划)

以下指令计划在 v2.1 版本提供，当前版本暂不可用：

| 指令 | 默认 | 说明 |
| :--- | :--- | :--- |
| `waf_debug_final_doc` | `off` | 将编译后的最终规则文档以单行 JSON 输出到 `error_log` |
| `waf_json_log_allow_empty` | `off` | 是否对"无事件的 ALLOW"进行落盘或抽样 |

> **🔧 当前排障技巧**：
> 在 v2.0 中，可以通过将 `waf_json_log_level` 设为 `debug` 来查看详细的规则匹配过程。
> 配合 Nginx 的 `error_log ... debug;`，可以看到内部请求/子请求过滤、规则编译等信息。

---

## 6. 从 v1 迁移到 v2

如果你之前使用过 v1 版本，这里是一些迁移要点：

### 6.1 指令变化

| v1 指令 | v2 等价物 | 说明 |
| :--- | :--- | :--- |
| `sqli_rules_file` | `waf_rules_json` | 统一用 JSON 承载所有规则类型 |
| `xss_defense_enabled` | JSON `rules` 数组 | 规则启用/禁用在 JSON 中控制 |
| `ip_whitelist_file` | JSON `extends` + IP 规则 | IP 白名单也是规则的一种 |

### 6.2 设计理念的变化

*   **v1**：每种规则类型（SQLi/XSS/IP/UA）有独立的指令和文件格式。
*   **v2**：所有规则统一为 JSON 格式，通过 `extends` 机制实现复用和继承。

### 6.3 迁移建议

1.  **保留 v1 规则逻辑**：先将 v1 的规则模式翻译成 v2 的 JSON 格式。
2.  **利用继承机制**：将通用规则（如核心 SQLi/XSS 检测）放入 `core/` 目录，业务规则 `extends` 继承它们。
3.  **灰度上线**：使用 `waf_default_action LOG` 先观察，确认无误杀后再切换为 `BLOCK`。

---

## 7. 常见问题 (FAQ)

**Q: 为什么 `waf_shm_zone` 必须定义在 http 块？**
A: 因为内存是所有 Worker 进程共享的物理资源。如果每个 location 都能定义一块内存，不仅管理混乱，还会导致 IP 状态无法跨域名共享。

**Q: 我在 server A 开了动态封禁，server B 没开，同一个 IP 攻击了 A 会被 B 拦截吗？**
A: 会！只要它们共享同一个 `http` 块（共享同一块内存）。
如果攻击者在 A 积累了足够的分数触发了封禁，他的 IP 就会被加入共享内存的黑名单。当他随后访问 B 时，虽然 B 没开“计分”，但 B 会检查“黑名单”，发现该 IP 已入狱，直接拦截。这就是**联防联控**的威力。

**Q: `waf off` 和 `waf_default_action LOG` 有什么区别？**
A:
*   `waf off`: **彻底关机**。不检测、不计分、不记日志、不耗 CPU。
*   `waf_default_action LOG`: **空包弹演习**。全力检测、照常计分（可能触发动态封禁）、详细记录日志，只是最后不拦截。适合观察流量。

**Q: 修改了配置需要重启吗？**
A: 不需要重启进程，只需要 **Reload**。
执行 `nginx -s reload`，WAF 会重新读取配置、重新编译规则 JSON，无缝切换到新策略。
