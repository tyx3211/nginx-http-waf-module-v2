# Nginx HTTP WAF v2 开发者完全指南 (The Real Hacker's Guide)

> 🚀 **写给未来的核心开发者**：
> 欢迎来到 v2 的源码世界！这不是一份冷冰冰的“企业级文档”，而是一份带你直接上手的“入坑指南”。
> 我们花了无数个日夜打磨这套架构，就是为了让它既**足够强壮**（生产级稳定性），又**足够好玩**（Geek 精神）。
>
> 目标很明确：**读完这篇文档，你不仅能看懂代码，甚至可以直接提 PR 修改核心逻辑。**
>
> *注意：本文档完全基于当前 `v2` 分支的真实 C 源码（Real Implementation）编写。若与其他过程性文档冲突，请以本文（及源码）为准。*

---

## 第一部分：世界观与地图 (Architecture & Map)

### 1. 项目定位：不仅仅是模块

这不仅仅是一个 Nginx 动态模块，它是一个**内嵌了完整规则引擎的安全子系统**。
它不依赖外部数据库，不依赖 Lua，不依赖 Node.js。它就像一个精密的瑞士军刀，插在 Nginx 上，用 C 语言的高效性解决 Web 安全问题。

**核心哲学**：
1.  **原生至上 (Native First)**：能用 Nginx API 绝不造轮子（内存池、字符串、日志）。
2.  **胖数据面 (Fat Data Plane)**：把复杂的规则继承、去重逻辑放在 Nginx 启动阶段（配置期），换取运行期的极致速度与零依赖。
3.  **配置即代码 (Configuration as Code)**：所有策略都定义在 JSON 里，支持 Git 版本管理。

---

## 2. 目录结构详解：你的作战地图

我们的代码组织非常扁平，按**功能职责**切分，而不是按“MVC”这种死板套路。

```bash
nginx-http-waf-module-v2/
├── src/
│   ├── module/                 # [入口] Nginx 模块的骨架
│   │   ├── ngx_http_waf_module.c    # 模块注册、指令定义、阶段挂载 (The Main Entry)
│   │   ├── ngx_http_waf_config.c    # 配置解析与合并 (Configuration Parser)
│   │   └── ngx_http_waf_utils.c     # 运行期工具 (XFF提取, URI解码等)
│   │
│   ├── json/                   # [大脑] 规则解析引擎 (Configuration Phase Only)
│   │   └── ngx_http_waf_json.c      # 处理 JSON 解析、继承(extends)、去重、禁用 (The Hard Work)
│   │
│   ├── core/                   # [心脏] 核心业务逻辑
│   │   ├── ngx_http_waf_compiler.c  # 编译器：把 JSON 变成运行期快照 (Snapshot Builder)
│   │   ├── ngx_http_waf_action.c    # 执法层：统一处理 BLOCK/LOG/BYPASS (The Judge)
│   │   ├── ngx_http_waf_dynamic_block.c # 动态信誉：共享内存、封禁逻辑 (Memory & State)
│   │   ├── ngx_http_waf_log.c       # 日志层：事件聚合与 JSONL 输出 (The Scribe)
│   │   └── ngx_http_waf_utils.c     # (部分工具函数共享)
│   │
│   └── include/                # [契约] 头文件
│       ├── ngx_http_waf_module_v2.h # 模块核心结构体定义 (ctx, conf)
│       ├── ngx_http_waf_stage.h     # 流水线阶段宏与返回码 (WAF_STAGE)
│       └── ... (对应各 .c 的头文件)
│
├── third_party/                # [外援] 只有两个最精简的依赖
│   ├── yyjson/                 # 最快的 C JSON 库 (用于解析规则)
│   └── uthash/                 # 单头文件哈希表 (仅编译期用于规则去重)
│
└── config                      # Nginx 模块编译脚本 (Make rules)
```

### 2.1 模块依赖金字塔 (The Dependency Pyramid)

为了不让代码变成一团乱麻，我们严格遵守分层依赖原则。这种结构清晰地体现在代码的 include 关系和执行流中：

*   **Layer 3: 接口层 (Interface) - `src/module/`**
    *   **职责**：负责和 Nginx 核心“外交”。处理指令解析、挂载 Hook、读取 Body。
    *   **依赖**：它调用 `core` 层的 API（如 `waf_compile_rules`, `waf_enforce`），但绝不关心红黑树怎么插、JSON 怎么解。
*   **Layer 2: 核心业务层 (Core Business) - `src/core/`**
    *   **职责**：WAF 的灵魂。
        *   `Action`: 统一裁决逻辑（Block/Log/Bypass）。
        *   `Compiler`: 将配置转化为内存快照。
        *   `Dynamic`: 管理共享内存状态。
    *   **依赖**：它调用 `json` 和 `utils` 层。它不知道自己是跑在 OpenResty 还是 Tengine 上，它只处理业务。
*   **Layer 1: 基础能力层 (Foundation) - `src/json/`, `src/utils/`, `third_party/`**
    *   **职责**：纯粹的数据处理（JSON 解析、IP 转换、字符串操作）。
    *   **特点**：这里只有单纯的函数，没有复杂的上下文状态。

**代码执行流的体现 (The Flow of Dependencies)**：

我们设计了严格的单向依赖链，确保每个文件只做一件事，且依赖关系清晰可追踪：

1.  **配置加载期 (Configuration Phase)**：
    *   `module (ngx_http_waf_config.c)`：作为 Nginx 的配置解析入口，它解析指令（如 `waf_rules_json`）。
    *   **➔** 调用 `compiler (ngx_http_waf_compiler.c)`：指令告诉编译器去哪里找规则。
    *   **➔** 调用 `json (ngx_http_waf_json.c)`：编译器委托 JSON 解析器去加载、解析、合并文件。
    *   **➔** `yyjson`：解析器调用底层库处理原始 JSON。
    *   **依赖链**：`Config` -> `Compiler` -> `Json` -> `ThirdParty`。

2.  **请求处理期 (Runtime Phase)**：
    *   `module (ngx_http_waf_module.c)`：作为 HTTP 请求拦截入口，它控制流水线。
    *   **➔** 调用 `action (ngx_http_waf_action.c)`：每当规则命中，模块请求动作层进行裁决。
    *   **➔** 调用 `dynamic (ngx_http_waf_dynamic_block.c)`：动作层查询动态信誉（是否封禁？是否加分？）。 / 调用 `log (ngx_http_waf_log.c)`：动作层将事件记录到日志缓冲区。
    *   **依赖链**：`Module` -> `Action` -> `Dynamic` / `Log`。

---

## 3. Nginx 的两重天：配置期 vs 运行期

> 📘 **指引**：关于配置指令的完整规范与默认值，请参阅 [friendly-waf-directives-spec-v2.0.md](./friendly-waf-directives-spec-v2.0.md)。

作为一个 Nginx 模块开发者，你必须时刻清醒地知道自己身处哪个“时空”。V2 的架构在这两个阶段做的事情截然不同。

### 阶段一：配置加载期 (Configuration Phase)
**“把复杂留给自己”**

当用户执行 `nginx -t` 或 `nginx -s reload` 时，我们在做什么？
**我们在做编译！** 我们把人类写的、充满继承关系的 JSON 规则，编译成机器喜欢的高效内存快照。

*   **负责模块**：
    *   `module/ngx_http_waf_config.c` (指挥官)
    *   `json/ngx_http_waf_json.c` (解析工)
    *   `core/ngx_http_waf_compiler.c` (建筑师)
*   **发生的事情**：
    1.  **指令解析**：读取 `nginx.conf`，拿到 `waf_rules_json` 的路径。
    2.  **规则加载**：`ngx_http_waf_json.c` 开始工作。它会递归加载 JSON，处理 `extends`，处理 `disableById`，处理 `rewriteTargets`，最后吐出一个**巨大、扁平、无重复**的规则数组。
    3.  **快照编译**：`ngx_http_waf_compiler.c` 接手。它遍历这个数组：
        *   把 `REGEX` 规则预编译成 `ngx_regex_t`。
        *   把 `CIDR` 规则计算成二进制掩码。
        *   把规则按 `Phase` (IP/URI/Detect) 和 `Target` (ARGS/HEADERS...) 分桶。
        *   **最酷的一点**：它会对桶里的规则按 `priority` 进行**稳定排序**。
    4.  **挂载**：生成的 `waf_compiled_snapshot_t` 被挂载到 `loc_conf` 上。

> **🛑 关键原则**：在这个阶段，我们可以用一点点 CPU 和内存（比如 `uthash`），只要能生成完美的运行期快照，一切都是值得的。

---

### 阶段二：请求处理期 (Runtime Phase)
**“把速度留给用户”**

当请求真正到来时，我们已经不需要解析 JSON 了，也不需要查哈希表了。我们只需要**查表**。

*   **负责模块**：
    *   `module/ngx_http_waf_module.c` (流水线入口)
    *   `core/ngx_http_waf_action.c` (执法)
    *   `core/ngx_http_waf_dynamic_block.c` (信誉)
*   **发生的事情**：
    1.  **上下文创建**：为每个请求创建一个 `ctx`。
    2.  **五段流水线**：IP白 -> IP黑 -> 信誉检查 -> URI白 -> 深度检测。
    3.  **零拷贝**：在检测过程中，我们尽量不拷贝字符串，直接在 Nginx 的内存池里操作。
    4.  **无锁设计**：除了动态信誉（需要操作共享内存），其他的规则匹配全是只读的，无锁，飞快。

---


---

## 4. 大脑：规则引擎与解析器 (The Rule Engine)

> 📘 **指引**：关于 JSON 规则文件的完整字段、继承重写逻辑，请参阅 [friendly-waf-json-spec-v2.0.md](./friendly-waf-json-spec-v2.0.md)。

> **位置**：`src/json/ngx_http_waf_json.c`
> **阶段**：配置加载期 (Configuration Phase)

这是 V2 版本最引以为傲的“胖数据面”核心。我们将极其复杂的规则继承、重写、去重逻辑全部放在了 C 代码中实现，而不是依赖外部脚本。

### 4.1 为什么是 yyjson？

在 V1 版本中，我们解析配置文件很痛苦。在 V2 中，我们引入了 [yyjson](https://github.com/ibireme/yyjson)。
*   **极速**：它是目前 C 语言最快的 JSON 库之一。
*   **DOM API**：我们需要在内存中频繁修改、拷贝 JSON 对象（比如重写 target），yyjson 的 Mutable API 非常好用。

### 4.2 递归合并算法 (The Merge Logic)

`ngx_http_waf_json_load_and_merge` 是入口函数。它的工作流程像一个**递归的爬虫**：

1.  **加载**：读取入口 JSON 文件。
2.  **递归 (Recursion)**：发现 `meta.extends`，立即暂停当前文件处理，递归调用 `waf_collect_rules` 去加载父文件。
    *   *环检测*：我们维护了一个 `stack`，如果发现循环引用（A extends B, B extends A），立即报错。
    *   *深度限制*：防止栈溢出，默认为 5 层。
3.  **展平 (Flattening)**：父文件返回的是一个已经处理好的 `rules` 数组。我们将它合并到当前集合中。
4.  **重写 (Rewrite)**：这是 V2 的杀手级特性。
    *   在 `extends` 中，你可以传入一个对象而不是字符串：
        ```json
        {
          "file": "../core/core_xss_rules.json",
          "rewriteTargetsForTag": { "xss-strict": ["URI", "BODY"] }
        }
        ```
    *   解析器会在合并父规则**之前**，动态修改父规则内存中的 `target` 字段。这意味着父文件在磁盘上没变，但在我们的内存视图中变了。
5.  **禁用 (Disable)**：根据 `disableById` 和 `disableByTag`，将不需要的规则从数组中剔除。
    *   **注意**：禁用仅针对**继承进来的规则集合 (Imported Set)**。这给了用户极大的灵活性：你可以继承一个庞大的规则集，然后精准剔除其中几条不适合的。
6.  **追加 (Append)**：将当前文件本地定义的 `rules` 数组追加到继承并处理后的集合尾部。本地规则永远拥有最高的话语权（除非 ID 冲突被策略覆盖）。
7.  **去重 (De-duplication)**：
    *   我们使用 `uthash` 维护了一个 `id -> index` 的哈希表。
    *   根据 `duplicatePolicy` (`warn_skip`, `warn_keep_last`, `error`) 决定遇到 ID 冲突时是保留旧的、覆盖旧的还是报错。

**最终产物**：一个巨大、扁平、无重复的 `yyjson_doc`，里面包含了成百上千条规则， ready for compilation。

### 4.3 为什么不用外部 CLI？(The "No CLI" Philosophy)

你可能会问：*为什么不写一个 Python/JS 脚本在外面把 JSON 合并好，再喂给 Nginx？*

问得好。我们选择 **Fat Data Plane (C 实现)** 有几个关键理由：
1.  **部署复杂度**：如果依赖外部脚本，用户需要安装 Python/Node 环境，CI/CD 流程会变复杂。现在，用户只需 `nginx -t`，一切自动完成。
2.  **动态路径解析**：我们的 `extends` 支持相对路径（相对于 `waf_jsons_dir` 或当前文件）。这种路径解析逻辑如果脱离 Nginx 的配置上下文（prefix, conf_prefix）很难在外部脚本中完美复刻。
3.  **一致性**：解析逻辑和运行逻辑在同一个二进制文件中，永远不会出现“脚本生成的规则 Nginx 读不懂”的情况。

---

## 5. 建筑师：编译器 (The Compiler)

> **位置**：`src/core/ngx_http_waf_compiler.c`
> **阶段**：配置加载期 (Configuration Phase)

拿到 JSON 文档后，我们不能直接在请求处理时查 JSON（那太慢了）。编译器负责将 JSON 对象转换为 C 语言的高效结构体 `waf_compiled_rule_t`。

### 5.1 预计算 (Pre-computation)

编译器不仅仅是拷贝数据，它在做大量的**预计算**工作，把运行时的负担降到最低：

*   **正则预编译**：调用 Nginx 的 `ngx_regex_compile`，将字符串 pattern 编译成 `ngx_regex_t`。运行时直接以此执行正则匹配。
*   **CIDR 预计算**：将 IP 段字符串（如 `192.168.1.0/24`）解析为二进制掩码（mask）和网络号（addr），运行时只需做位运算。
*   **Phase 推断**：如果 JSON 中没写 `phase`，编译器会根据 target 和 action 智能推断（例如 `CLIENT_IP` + `DENY` -> `IP_BLOCK` 阶段）。

### 5.2 分桶与排序 (Bucketing & Sorting)

为了进一步加速，我们将规则按 **阶段 (Phase)** 和 **目标 (Target)** 进行分桶。

`snap->buckets[PHASE][TARGET]` 是一个二维数组。
*   当请求到达 `IP_BLOCK` 阶段时，我们只需要遍历 `buckets[IP_BLOCK][CLIENT_IP]` 里的规则。
*   当检测 `URI` 时，我们只需要看 `buckets[DETECT][URI]`。

**稳定排序 (Stable Sort)**：
在每个桶内部，我们对规则按 `priority` 字段进行**稳定排序**。
*   这是一个插入排序实现（因为通常桶内规则已部分有序）。
*   这保证了高优先级的规则先执行，同优先级的规则保持文件中的书写顺序。

**最终产物**：`waf_compiled_snapshot_t`。这是一个**只读的内存快照**，挂载在 `loc_conf` 上。Worker 进程启动后，无需任何锁即可并发读取它。

---

## 6. 记忆体：动态信誉 (Dynamic Reputation)

> **位置**：`src/core/ngx_http_waf_dynamic_block.c`
> **阶段**：运行期 (Runtime Phase)
> **关键技术**：Shared Memory, Rbtree, LRU Queue, Atomics

这是 V2 中最复杂的状态管理部分，因为它涉及到跨 Worker 进程的通信。

### 6.1 共享内存架构 (The Shared Memory Layout)

所有的动态信誉数据都存储在 Nginx 的共享内存区（Shared Memory Zone）中。这意味着：
*   所有 Worker 进程看到的 IP 评分是统一的。
*   一个 Worker 封禁了 IP，所有 Worker 立即生效。

我们在共享内存里维护了三个核心数据结构：

1.  **Slab Pool**：内存分配器。我们不使用 `malloc`，而是从这块预分配的共享内存中切分对象。
2.  **红黑树 (Rbtree)**：索引。
    *   **Key**: 客户端 IP (uint32_t)。
    *   **Value**: 指向 `waf_dyn_ip_node_t` 的指针。
    *   用途：`O(log N)` 快速查找 IP 是否存在。
3.  **LRU 队列 (Queue)**：淘汰策略。
    *   一个双向链表，按“最近使用时间”排序。
    *   每次访问 IP，将其移到队头。
    *   内存满时，从队尾淘汰最久未使用的节点（但在封禁期内的 IP 不会淘汰）。

### 6.2 并发控制 (Concurrency)

*   **结构变更（加锁）**：插入新 IP、删除 IP、LRU 移动需要修改红黑树和链表指针，必须加互斥锁 `ngx_shmtx_lock(&shpool->mutex)`。
*   **评分累加（无锁/原子）**：
    *   更新 IP 分数是最频繁的操作。
    *   我们使用 `ngx_atomic_fetch_add(&ip_node->score, delta)`。
    *   **亮点**：即使在持有锁之外读取分数（例如日志记录），也能拿到最终一致的数据，极大减少了锁竞争。

### 6.3 封禁逻辑 (The Ban Hammer)

当 `waf_dyn_score_add` 被调用时：
1.  在共享内存中找到（或创建）IP 节点。
2.  原子累加分数。
3.  检查 `new_score > threshold`。
4.  如果触发阈值，设置 `block_expiry = now + duration`。

整个过程对 Nginx 核心性能影响微乎其微，却实现了强大的全自动防御。

---

## 7. 引擎：请求处理流水线 (The Pipeline)

> **位置**：`src/module/ngx_http_waf_module.c`
> **阶段**：运行期 (Runtime Phase)

当一个请求到达 Nginx，`ngx_http_waf_access_handler` 会被调用。这是 WAF 介入的第一现场。

### 7.1 自动过滤 (Auto-Filter)

为了性能和逻辑正确性，我们第一件事就是**踢皮球**：
*   **内部请求 (Internal Requests)**：`error_page`、`try_files` 产生的内部跳转。
*   **子请求 (Subrequests)**：`auth_request`、`SSI` 产生的子请求。

这些请求通常由主请求触发，主请求已经检查过了，没必要浪费 CPU 再查一次。

### 7.2 五段流水线 (The 5-Stage Pipeline)

如果请求通过了初筛，它将进入严密的五级安检。每一级都是一个 `WAF_STAGE`，如果前一级返回 `BLOCK` 或 `BYPASS`，后续阶段直接跳过。

1.  **IP Allow**：检查 IP 白名单（`CLIENT_IP` + `BYPASS`）。
2.  **IP Deny**：检查 IP 黑名单（`CLIENT_IP` + `DENY`）。
3.  **Reputation Base**：
    *   检查动态信誉开关。
    *   给当前 IP 加上 `baseAccessScore`（基础分）。
    *   **关键点**：如果此时 IP 总分超过阈值，直接阻断！这就是动态封禁生效的地方。
4.  **URI Allow**：检查 URI 白名单（`URI` + `BYPASS`）。
5.  **Detect Bundle (深度检测)**：
    *   这是最耗时的一步。
    *   如果请求是 GET/HEAD 且无 Body，立即执行。
    *   如果有 Body，我们会挂载 `ngx_http_read_client_request_body`，在回调中执行，确保 Body 已完整读取。
    *   检测范围：URI, Args, Headers, Body。

### 7.3 核心机制：短路控制流 (The Short-Circuit Logic)

你会在源码（尤其是 `module.c` 和 `stage.h`）中看到大量的 `rc` 状态码检查，甚至我们还专门编写了宏（Macro）来封装它。这看起来很繁琐，但它是 WAF 高性能与逻辑正确性的**生命线**。

为什么这么痛苦？因为 WAF 的执行流是一个 **"检测 ➔ 意图 ➔ 裁决 ➔ 响应"** 的微循环，而且每一级都可能触发“熔断”。

**微观执行流 (The Micro-Loop)**：

1.  **Rule Loop (桶内循环)**：我们在一个 `for` 循环里遍历当前桶的规则。
2.  **Match (匹配)**：计算正则、字符串是否匹配。命中？继续。
3.  **Enforce (请示)**：调用 `waf_enforce`。这时候动作层介入（它会看全局配置 `BLOCK/LOG`，会看动态封禁状态）。
4.  **Feedback (反馈)**：`waf_enforce` 返回一个状态码 `waf_rc_e`：
    *   `WAF_RC_BLOCK`: **真要拦截了！** (Global Block is ON)
    *   `WAF_RC_BYPASS`: **白名单放行！** (Action is BYPASS)
    *   `WAF_RC_CONTINUE`: 只是记录了一下（LOG 模式），或者什么都没发生，继续下一条。
5.  **Short Circuit (短路)**：
    *   一旦收到 `BLOCK` 或 `BYPASS`，**立即 return**。
    *   跳出规则循环 ➔ 跳出阶段函数 ➔ 跳出流水线 ➔ **Nginx 结束请求 (Finalize)**。

**宏的封装 (The Macro)**：
为了不让代码写成“if-else 地狱”，我们在 `stage.h` 中定义了这样的宏：

```c
#define WAF_STAGE(ctx, call) \
    rc = call; \
    if (rc == WAF_RC_BLOCK || rc == WAF_RC_BYPASS || rc == WAF_RC_ERROR) return rc;
```

这就是你在 `ngx_http_waf_access_handler` 看到的那一排整齐的调用。这正是“短路”精神的体现：**一旦前一个阶段决定了请求的命运（杀或放），后续所有计算资源（正则、解码、查找）全部节省下来。**

### 7.4 零拷贝解码 (Zero-Copy Decoding)

在检测 URL 参数（`ARGS_COMBINED`）时，我们需要对其进行 URL Decode。
为了避免对每个规则都解码一次（那太蠢了），我们在 `ctx` 中引入了 Request-Level Cache。
*   第一次需要解码参数时，分配内存、解码、缓存。
*   后续规则直接使用缓存的解码结果。

---

## 7.5 数据归一化细节 (Normalization & Negate)

为了保证匹配的准确性和日志的纯净，我们在数据处理层面做了精细的控制。这是你在写规则时必须知道的“潜规则”。

### 1. 严格的一次性解码 (Strict One-Pass Decoding)

我们奉行 **"Just One Pass"** 原则。所有的解码逻辑都是惰性的、单次的、不交叉的。

*   **URI**: 直接使用 Nginx 核心已经解码好的 `r->uri`。我们**不做二次解码**。
*   **Query Args (ARGS_COMBINED)**: 采用 **Request-Level Cache**。第一个需要查参数的规则触发解码，后续规则直接复用。只解一次，不重复造轮子。
*   **BODY**:
    *   仅当 `Content-Type` 为 `application/x-www-form-urlencoded` 时，我们会进行 **URL Decode**（且仅解码一次）。
    *   对于其他类型（如 JSON, XML, Multipart），我们**保持原样 (Raw Body)** 进行匹配。不要指望 WAF 帮你把 JSON 展开成键值对，那是业务层的事。

### 2. 取反逻辑与日志降噪 (Negate & Noise Reduction)

`negate: true` 是一个强大的特性，特别是用于 Referer 检查等“白名单式”场景（例如：只要 Referer 不是我的域名，就拦截）。

**日志的哲学**：
我们只记录**麻烦**。

*   **场景 A**：规则匹配成功 (Match=True)，取反后变为 False (最终未命中)。
    *   **结果**：WAF 认为没事发生。
    *   **日志**：**不记录**。不要把日志塞满“由于是白名单所以放行了”的废话。
*   **场景 B**：规则匹配失败 (Match=False)，取反后变为 True (最终命中)。
    *   **结果**：WAF 认为命中了规则。
    *   **日志**：**记录事件**。这才是我们需要关注的异常。

这种设计让你在写 CSRF 防护规则时非常舒服：写一个正则匹配合法的 Referer，加上 `negate: true`，动作设为 `DENY`。只有当 Referer **不**合法时，WAF 才会报警并拦截。

---

## 7.6 异步时序：请求体怎么读？(The Async Body Flow)

Nginx 的世界是异步非阻塞的。读取请求体（Body）是一个可能发生 I/O 等待的操作，所以我们不能在主线程里傻等。

我们在 `module/ngx_http_waf_module.c` 中处理了两种完全不同的时序：

### 路径 A：无 Body 请求 (GET/HEAD)
非常简单，一气呵成。
1.  `waf_access_handler` 被调用。
2.  跑完前四段流水线（IP/URI）。
3.  发现没 Body，直接跑第五段 `detect_bundle`。
4.  收尾 `finalize_allow`。
5.  返回 `NGX_DECLINED`（进入下一个 Nginx 模块）。

### 路径 B：有 Body 请求 (POST/PUT)
这里涉及到了回调地狱（其实只有一层），请跟紧：

1.  **Phase 1 (主线程)**：
    *   `waf_access_handler` 被调用。
    *   跑完前四段流水线。
    *   调用 `ngx_http_read_client_request_body(r, callback)`。
    *   **立即返回 `NGX_DONE`**。这告诉 Nginx：“我这儿挂起了，你去忙别的吧，数据到了叫我。”
2.  **Wait (I/O)**：Nginx 事件循环负责读取网络数据。
3.  **Phase 2 (回调时刻)**：
    *   数据读完了，Nginx 调用我们的回调 `ngx_http_waf_post_read_body_handler`。
    *   **此时才执行**第五段 `detect_bundle`（读取并匹配 Body）。
    *   收尾 `finalize_allow`。
    *   **关键一步**：手动调用 `r->phase_handler++` 和 `ngx_http_core_run_phases(r)`。这相当于手动推了一把，让请求继续往下走。

---

## 8. 执法者：动作层 (The Enforcer)

> **位置**：`src/core/ngx_http_waf_action.c`
> **阶段**：运行期 (Runtime Phase)

规则引擎只负责“发现问题”，动作层负责“解决问题”。`waf_enforce` 函数是这里的最高法官。

### 8.1 意图与策略 (Intent vs Policy)

当规则匹配时，它会产生一个 **意图 (Intent)**：`BLOCK`, `LOG`, 或 `BYPASS`。
但是，意图不等于最终结果。动作层会结合 **全局策略 (Global Policy)** 进行裁决。

*   **Intent = BLOCK**:
    *   如果 `waf_default_action` 是 `BLOCK` -> **真拦截** (返回 403)。
    *   如果 `waf_default_action` 是 `LOG` -> **假拦截** (放行，但记一条高危日志)。这用于“观察模式”。
*   **Intent = BYPASS**:
    *   无视全局策略，直接放行。这是白名单的特权。

### 8.2 动态封禁的联动

动作层与动态信誉紧密配合。
*   每次请求进来，先算分（`waf_dyn_score_add`）。
*   算分后，立即检查是否超阈值。
*   如果超了，触发 `BLOCK_BY_DYNAMIC_BLOCK`。

---

## 9. 书记员：JSONL 日志系统 (The Scribe)

> 📘 **指引**：关于 JSONL 日志格式、字段定义与 decisive 判定逻辑，请参阅 [friendly-waf-jsonl-spec-v2.0.md](./friendly-waf-jsonl-spec-v2.0.md)。

> **位置**：`src/core/ngx_http_waf_log.c`
> **阶段**：运行期 (Runtime Phase)

我们要记录的不是一行简单的文本，而是一个结构化的 JSON 对象。

### 9.1 事件聚合 (Event Aggregation)

在请求处理过程中，可能触发多个事件（比如命中了一条 SQL 注入规则，同时触发了 IP 动态封禁）。
我们不会每触发一个事件就写一行日志（那会把磁盘写爆）。
我们在 `ctx` 中维护了一个 `yyjson_mut_doc`，里面有一个 `events` 数组。
*   规则命中 -> `waf_log_append_rule_event` -> push to `events` array.
*   信誉加分 -> `waf_log_append_reputation_event` -> push to `events` array.

### 9.2 决定性时刻 (The Decisive Moment)

一个请求可能触发了 10 条规则，但只有一条是“压死骆驼的稻草”。
在日志落盘前（`waf_log_flush_final`），我们会遍历 `events` 数组，找出那个 **Decisive Event** 并打上标记：
*   如果是 **BLOCK**：找 `blockRuleId` 对应的事件，或者最后一条动态封禁事件。
*   如果是 **BYPASS**：找最后一条 BYPASS 规则事件。

### 9.3 最终落盘 (The Final Flush)

当请求结束时（或者决定 BLOCK 时），我们将整个 JSON 对象序列化为一行字符串，写入日志文件。
*   **文件句柄**：`mcf->json_log_of`。这个文件是在 Master 进程启动时打开的，所有 Worker 共享。
*   **原子写入**：使用 `ngx_write_fd`。对于短日志（小于 `PIPE_BUF`, 通常 4KB），内核保证写入是原子的，不会交错。

---

## 结语：欢迎来到数据面

现在，你已经拿到了通往 V2 核心的钥匙。
*   你知道了 JSON 是怎么变成内存快照的。
*   你知道了请求是怎么在流水线上被层层安检的。
*   你知道了动态信誉是怎么跨进程共享的。

去读代码吧，去修改它，去创造更强大的规则。
**The code is yours.**

