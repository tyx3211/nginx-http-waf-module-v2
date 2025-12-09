# Nginx WAF v2 JSON 规则编写指南 (Friendly Spec)

> 💡 **写在前面**：
> 欢迎来到规则编写的世界！V2 版本的核心理念是 **"Configuration as Code"**。
> 我们不再使用晦涩难懂的专有语法，而是拥抱 **JSON** —— 结构化、可读性强、天然支持 Git 版本管理。
> 无论你是手写规则，还是通过 Web 控制台生成，这份指南都将是你最好的参考。

---

## 0. 快速上手：一个真实的规则文件

让我们先看一个完整的例子。它展示了规则编写中最常用的功能：继承、重写、禁用、定义新规则、以及策略配置。

```json
{
  "version": 1,
  
  "meta": {
    "name": "My-App-Security-Policy", // JSON 规则工件 name，仅标识，可选（不写没关系）
    "tags": ["prod", "public-facing"], // 文件级 tags，仅标识，目前无相关特殊处理逻辑，可选（不写没关系）
    
    /* 1. 继承机制：站在巨人的肩膀上（可选） */
    "extends": [
      /* 裸路径：相对 waf_jsons_dir 解析 */
      "core/core_sqli_rules.json",
      
      /* 高级玩法：继承 XSS 规则集，但做一点微调 */
      {
        "file": "../core/core_xss_rules.json",
        /* 按标签批量重写检测目标 */
        "rewriteTargetsForTag": {
          "xss-strict": ["URI", "ARGS_COMBINED", "BODY"]
        },
        /* 按 ID 精准重写 */
        "rewriteTargetsForIds": [
          { "ids": [2001, 2002], "target": ["HEADER"], "headerName": "User-Agent" }
        ]
      }
    ],

    /* 2. 去重策略：ID 冲突了听谁的？默认 warn_skip */
    "duplicatePolicy": "warn_skip" // 也可置成warn_keep_last，逻辑不一样，见下文详解
  },

  /* 3. 禁用机制：剔除继承来的不适合的规则 */
  "disableById": [1001, 1005],
  "disableByTag": ["legacy", "beta"],

  /* 4. 动态封禁策略 (仅入口文件生效，不会被继承) */
  "policies": {
    "dynamicBlock": {
      "baseAccessScore": 1
    }
  },

  /* 5. 本地规则：定义针对业务特性的防御 */
  "rules": [
    /* 示例 A: 基础正则拦截 */
    {
      "id": 90001,
      "tags": ["custom", "sql-patch"],
      "target": "ARGS_COMBINED",
      "match": "REGEX",
      "pattern": "(?i)union\\s+select.*from",
      "action": "DENY",
      "score": 50
    },
    /* 示例 B: 字符串精确匹配 (性能极高) */
    {
      "id": 90002,
      "target": "URI",
      "match": "EXACT",
      "pattern": "/admin/hidden_backdoor",
      "action": "DENY",
      "score": 100
    },
    /* 示例 C: 多模式匹配 (数组 = OR 关系) */
    {
      "id": 90003,
      "target": "BODY",
      "match": "CONTAINS",
      "pattern": ["<script>", "javascript:", "onload="],
      "caseless": true,
      "action": "DENY",
      "score": 20
    },
    /* 示例 D: IP 白名单 (使用 BYPASS 跳过后续检查) */
    {
      "id": 90004,
      "target": "CLIENT_IP",
      "match": "CIDR",
      "pattern": ["192.168.0.0/16", "10.0.0.0/8"],
      "action": "BYPASS"
    },
    /* 示例 E: 健康检查路径白名单 */
    {
      "id": 90005,
      "target": "URI",
      "match": "EXACT",
      "pattern": "/health",
      "action": "BYPASS"
    }
  ]
}
```

> **💡 小贴士**：JSON 标准不支持注释，但本模块使用了 `yyjson` 库，**允许** `/* */` 风格的注释和尾逗号。
> 不过，为了更好的兼容性（比如用 IDE 校验），正式的规则文件建议去掉注释。

---

## 1. 核心概念：结构与合并

规则文件就像乐高积木。你可以把小的规则集拼装成大的策略。

### 1.1 文件结构一览

一个标准的规则 JSON 包含以下几个部分：

| 部分 | 字段 | 说明 |
| :--- | :--- | :--- |
| **版本** | `version` | 规则文件格式版本，目前固定为 `1`（可选，不写时最终json也将没有该字段，但逻辑上认定为 1（NestJS 后端对接时请注意，无该字段就视为 1 ）） |
| **元数据** | `meta` | 定义我是谁、我继承了谁、以及合并策略（仅入口生效，不继承） |
| **裁剪** | `disableById`, `disableByTag` | 修剪继承来的"枝叶" |
| **策略** | `policies` | 动态封禁等运行时策略（仅入口文件生效，不继承） |
| **规则** | `rules` | 当前文件特有的规则定义（**唯一支持继承合并的字段**） |

### 1.2 合并流水线 (The Merge Pipeline)

当 Nginx 加载这个文件时，会发生什么？请注意，**只有 `rules` 数组**会经历这个复杂的合并过程。其他字段（如 `meta.tags`、`policies`、`version`）都**只读取入口文件**，被继承文件中的这些字段会被**直接忽略**。

1.  **加载父级**：先递归加载 `extends` 中的所有文件，把它们拼成一个巨大的 **Imported Set (导入集)**。
2.  **应用重写**：如果在 `extends` 里定义了 `rewriteTargets`，就在导入集上修改规则的目标（比如把检查 
URI 改成检查 BODY）。
3.  **执行裁剪**：根据 `disableById/ByTag`，从导入集中删除不需要的规则。
4.  **追加本地**：把当前文件的 `rules` 数组追加到导入集的末尾。
5.  **最终去重**：如果发现重复的 ID，根据 `duplicatePolicy` 决定保留哪一个（通常是保留最后一个，也就是当
前文件定义的）

图示的话，就是按照以下顺序处理：

```
┌──────────────────────────────────────────────────────────────────┐
│  Step 1: 加载父级                                                 │
│  递归加载 extends 中的所有文件，按声明顺序（左→右）拼成导入集     │
└──────────────────────────────┬───────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 2: 应用重写                                                 │
│  若定义了 rewriteTargetsForTag/ForIds，修改导入集中规则的目标     │
└──────────────────────────────┬───────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 3: 执行裁剪                                                 │
│  根据 disableById/ByTag，从导入集中移除不需要的规则               │
│  ⚠️ 裁剪只作用于导入集，不影响本地 rules！                        │
└──────────────────────────────┬───────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 4: 追加本地规则                                             │
│  把当前文件的 rules 数组追加到导入集的末尾                        │
└──────────────────────────────┬───────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 5: 最终去重                                                 │
│  根据 duplicatePolicy 处理重复 ID（推荐 warn_keep_last）          │
└──────────────────────────────────────────────────────────────────┘
```

**一句话总结**：`继承 → 重写 → 裁剪 → 追加 → 去重`

---

## 2. 继承机制详解

继承是 V2 规则系统的核心能力。它让规则可以像代码一样模块化、可复用。

### 2.1 路径解析：三种模式 ⭐

这是一个非常重要的细节！`extends` 中的路径有**三种**解析方式：

| 路径形式 | 解析规则 | 示例 |
| :--- | :--- | :--- |
| **绝对路径** | 原样使用 | `/etc/nginx/waf/core.json` |
| **带 `./` 或 `../`** | 相对于**当前 JSON 文件**所在目录 | `./base.json`, `../core/sqli.json` |
| **裸路径**（不带前缀） | 相对于 **`waf_jsons_dir`** 指令设置的目录 | `core/sqli.json` |

来看几个具体例子。假设我们有这样的目录结构：

```
/usr/local/nginx/WAF_RULES_JSON/     <- waf_jsons_dir 指向这里
├── core/
│   ├── core_sqli_rules.json
│   └── core_xss_rules.json
└── user/
    └── my_rules.json                 <- 我们正在编辑这个文件
```

在 `my_rules.json` 中：

```json
{
  "meta": {
    "extends": [
      "core/core_sqli_rules.json",    /* 裸路径 → 相对 waf_jsons_dir */
      "../core/core_xss_rules.json",  /* 带 ../ → 相对当前文件目录 */
      "./local_helper.json"           /* 带 ./ → 相对当前文件目录 */
    ]
  }
}
```

> **💡 最佳实践**：
> *   对于核心规则集（`core/`），推荐使用**裸路径**，这样不管用户规则放在哪个子目录，引用方式都是一致的。
> *   对于同目录下的辅助文件，使用 `./` 明确表意。

### 2.2 简单继承 vs 高级继承

**简单模式**：字符串数组，直接引用

```json
{
  "meta": {
    "extends": [
      "core/core_sqli_rules.json",
      "core/core_xss_rules.json"
    ]
  }
}
```

**高级模式**：对象数组，支持"导入级重写"

```json
{
  "meta": {
    "extends": [
      {
        "file": "core/core_xss_rules.json",
        /* 方式 1: 按标签批量重写 */
        "rewriteTargetsForTag": {
          "xss-strict": ["URI", "ARGS_COMBINED", "BODY"]
        },
        /* 方式 2: 按 ID 精准重写 */
        "rewriteTargetsForIds": [
          { "ids": [2001, 2002], "target": ["HEADER"], "headerName": "User-Agent" }
        ]
      }
    ]
  }
}
```

**这有什么用？**
1.  **场景一**：官方 XSS 规则集只检查 URI，但业务需要更严格——也检查 POST Body。
2.  **场景二**：某条特定的 SQLi 规则误报了，你想把它限制在只检查 Query 参数，不检查 Body。

用"导入级重写"，可以**不修改原始规则文件**，就改变规则的行为。这对于使用第三方规则集非常有用。

### 2.3 继承示例：从零到一

让我们通过一个完整的例子来理解继承是怎么工作的。

**Step 1：核心规则集** (`core/base.json`)

```json
{
  "rules": [
    { "id": 100, "tags": ["xss"], "target": "URI", "match": "CONTAINS", "pattern": "<script>", "action": "DENY", "score": 20 },
    { "id": 200, "tags": ["legacy"], "target": "URI", "match": "CONTAINS", "pattern": "old_vuln", "action": "DENY", "score": 10 }
  ]
}
```

**Step 2：扩展规则集** (`core/extended.json`)

```json
{
  "meta": {
    "extends": ["./base.json"]
  },
  "rules": [
    { "id": 300, "tags": ["xss"], "target": "BODY", "match": "CONTAINS", "pattern": "<script>", "action": "DENY", "score": 20 },
    { "id": 200, "tags": ["xss"], "target": "BODY", "match": "CONTAINS", "pattern": "updated_vuln", "action": "DENY", "score": 15 }
  ]
}
```

**Step 3：业务入口** (`user/my_app.json`)

```json
{
  "meta": {
    "extends": ["../core/extended.json"],
    "duplicatePolicy": "warn_keep_last"
  },
  "disableByTag": ["legacy"],
  "rules": [
    { "id": 400, "tags": ["custom"], "target": "URI", "match": "EXACT", "pattern": "/admin/secret", "action": "DENY", "score": 100 }
  ]
}
```

**合并过程详解**：

1.  **加载 `extended.json`**（它继承了 `base.json`）
    *   base.json 的规则：`[100, 200(legacy)]`
    *   extended.json 本地规则追加：`[100, 200(legacy), 300, 200(xss)]`
    *   去重（默认 warn_skip，保留先出现的）：`[100, 200(legacy), 300]`

2.  **加载 `my_app.json`**（它继承了 `extended.json` 的最终结果）
    *   导入集：`[100, 200(legacy), 300]`
    *   执行 `disableByTag: ["legacy"]`：移除 200(legacy) → `[100, 300]`
    *   追加本地规则：`[100, 300, 400]`

3.  **最终结果**：3 条规则 `[100, 300, 400]`

### 2.4 裁剪机制：`disableById` / `disableByTag`

这两个字段用于"修剪"继承进来的规则。

```json
{
  "disableById": [1001, 1005],
  "disableByTag": ["experimental", "beta"]
}
```

*   **`disableById`**：精确移除指定 ID 的规则。
*   **`disableByTag`**：移除包含**任意一个**禁用标签的规则（OR 语义）。

> **⚠️ 重要**：裁剪**只作用于导入集（继承来的规则）**，不影响本地 `rules` 中定义的规则。
> 如果不想要某条本地规则，直接删掉就行，不用 disable。

### 2.5 冲突处理：`meta.duplicatePolicy`

当多个规则有相同的 ID 时，谁说了算？

| 策略 | 行为 | 适用场景 |
| :--- | :--- | :--- |
| `warn_skip` | 保留**最先出现**的，跳过后面的 | 默认值。强调"先定义优先" |
| `warn_keep_last` | 保留**最后出现**的，覆盖之前的 | **推荐**。符合直觉——"我的配置覆盖父级" |
| `error` | 发现重复直接报错，Nginx 启动失败 | 对配置严谨性要求极高的场景 |

**推荐做法**：在入口文件设置 `"duplicatePolicy": "warn_keep_last"`。
这样，如果想覆盖父级的某条规则，只需要在本地 `rules` 中定义一个相同 ID 的规则即可。

---

## 3. 规则字段详解 (Rule Object)

这是定义每一条防御逻辑的地方。

### 3.1 身份标识

*   **`id`** (必填): 唯一整数。建议规划好 ID 段（如 1000-1999 为 SQLi，9000+ 为自定义）。
*   **`tags`** (可选): 字符串数组。给规则打标签（如 `["sqli", "owasp"]`），方便后续管理和禁用。

### 3.2 匹配条件 (Match Criteria)

#### 3.2.1 检测目标：`target`

*   **单值模式**：`"target": "URI"` —— 检查请求路径
*   **多值模式**：`"target": ["URI", "BODY"]` —— 同时检查多个位置（任一命中即触发）

| 目标值 | 说明 | 示例场景 |
| :--- | :--- | :--- |
| `URI` | 请求路径（已解码） | 检测路径遍历 `../` |
| `ARGS_COMBINED` | URL 查询参数的合并值 | 检测 SQLi 参数 |
| `BODY` | 请求体（自动处理表单解码） | 检测 POST 中的 XSS |
| `HEADER` | 请求头（需配合 `headerName`） | 检测恶意 User-Agent |
| `CLIENT_IP` | 客户端 IP | IP 黑白名单 |
| `ALL_PARAMS` | 语法糖，等价于 `["URI", "ARGS_COMBINED", "BODY"]` | 全面检测 |

> **⚠️ 特殊约束**：当 `target` 包含 `HEADER` 时，**数组长度必须为 1**，且必须同时提供 `headerName` 字段。

```json
{
  "id": 3001,
  "target": "HEADER",
  "headerName": "User-Agent",
  "match": "CONTAINS",
  "pattern": "BadBot",
  "action": "DENY"
}
```

#### 3.2.2 匹配类型：`match`

| 类型 | 说明 | 性能 |
| :--- | :--- | :--- |
| `CONTAINS` | 包含子串 | ⭐⭐⭐ 最快 |
| `EXACT` | 完全相等 | ⭐⭐⭐ 最快 |
| `REGEX` | 正则表达式 (使用 Nginx 预编译) | ⭐⭐ 较慢但功能强大 |
| `CIDR` | IP 网段匹配（**仅限** `target=CLIENT_IP`） | ⭐⭐⭐ 高效 |

#### 3.2.3 匹配模式：`pattern`

*   **单值**：`"pattern": "<script>"`
*   **多值**：`"pattern": ["<script>", "javascript:", "onload="]`

> **多值语义**：**OR（或）** 关系。任意一个模式匹配上，规则就被触发。

#### 3.2.4 大小写与取反

*   **`caseless`** (可选，默认 `false`)：设为 `true` 时忽略大小写。
*   **`negate`** (可选，默认 `false`)：设为 `true` 时**取反**——**不匹配**才算命中。

**取反的妙用**：配合 `CIDR` 实现"仅允许指定 IP，其他全拒绝"：

```json
{
  "id": 8001,
  "target": "CLIENT_IP",
  "match": "CIDR",
  "pattern": ["10.0.0.0/8", "192.168.0.0/16"],
  "negate": true,
  "action": "DENY"
}
```

### 3.3 处置动作 (Action)

*   **`action`** (必填):

| 动作 | 说明 |
| :--- | :--- |
| `DENY` | 拒绝请求，返回 403 |
| `LOG` | 仅记录日志，放行请求 |
| `BYPASS` | **白名单放行**，跳过后续所有 WAF 检查 |

*   **`score`** (可选，默认 `10`)：扣分值。用于动态封禁，分值越高 IP 被封禁得越快。建议高危规则设为 50-100。

### 3.4 规则阶段：`phase`

*   **`phase`** (可选)：通常**不需要手动设置**，编译器会根据 `target` 和 `action` 自动推断。

| 阶段 | 自动推断条件 |
| :--- | :--- |
| `ip_allow` | `target=CLIENT_IP` + `action=BYPASS` |
| `ip_block` | `target=CLIENT_IP` + `action=DENY` |
| `uri_allow` | `target=URI` + `action=BYPASS` |
| `detect` | 其他所有情况 |

---

## 4. 策略字段：`policies`

`policies` 用于配置运行时策略，目前主要用于动态封禁。

```json
{
  "policies": {
    "dynamicBlock": {
      "baseAccessScore": 1
    }
  }
}
```

*   **`baseAccessScore`**：每次访问的基础得分。默认 `0`。设为 `1` 意味着即使没触发任何规则，每次访问也会累加 1 分。

> **⚠️ 重要**：`policies` **仅在入口文件生效，完全不参与继承**。
> 编译器只读取入口 JSON 中的这个字段，所有被 `extends` 继承的文件中的 `policies` 都会被**直接忽略**。

---

## 5. 解码与归一化策略

在匹配之前，WAF 会对不同目标的值进行适当的解码处理：

| 目标 | 解码策略 |
| :--- | :--- |
| `URI` | 使用 Nginx 已解码的 URI，不重复解码 |
| `ARGS_COMBINED` | 对原始查询字符串做一次 URL 解码 |
| `BODY` | 当 `Content-Type=application/x-www-form-urlencoded` 时做一次 URL 解码；其他类型（JSON/二进制）按原文匹配 |
| `HEADER` | 按原文匹配，不做 URL 解码 |
| `CLIENT_IP` | 原始 IP 地址字符串 |

---

## 6. 最佳实践 (Best Practices)

### 6.1 规则文件组织

推荐的目录结构：

```
WAF_RULES_JSON/
├── core/                    # 通用规则集（可共享）
│   ├── core_sqli_rules.json
│   ├── core_xss_rules.json
│   └── core_rce_rules.json
└── user/                    # 业务规则（继承 core）
    ├── api_rules.json
    └── admin_rules.json
```

### 6.2 ID 规划

约定好 ID 段，避免冲突：

| ID 范围 | 用途 |
| :--- | :--- |
| 1000-1999 | 通用 SQLi 规则 |
| 2000-2999 | 通用 XSS 规则 |
| 3000-3999 | 目录遍历/LFI |
| 4000-4999 | RCE 命令注入 |
| 5000-5999 | User-Agent 检测 |
| 9000+ | 业务自定义规则 |

### 6.3 性能优化

*   优先使用 `CONTAINS` 和 `EXACT`，它们比 `REGEX` 快得多。
*   利用 `pattern` 数组合并相似规则，减少规则条目数。
*   IP 白名单使用 `BYPASS` 动作，让可信 IP 跳过后续检查。

### 6.4 灰度上线

上线新规则前，先设为 `"action": "LOG"`，跑几天日志，确认没有误报后再改为 `DENY`。

---

## 7. 常见问题 (FAQ)

**Q: `target` 为数组时，是 AND 还是 OR？**

A: 是**独立评估**。`["URI", "BODY"]` 意味着规则会在 URI 上跑一次，也会在 BODY 上跑一次。只要**任意一个**位置命中了，规则就被触发。

---

**Q: `rewriteTargets` 是怎么工作的？**

A: 它在内存中动态修改了父级规则的 `target` 字段。比如父级规则只查 URI，你可以重写让它也查 BODY。这对于强化官方规则集非常有用，而不需要复制粘贴修改代码。

重写**只影响当前层的导入集**，不会修改原始规则文件。

---

**Q: 我可以用 `rewriteTargets` 修改规则的 action 或 score 吗？**

A: **不行**。顾名思义，它只能重写检测目标 (`target`)。
如果你需要修改规则的动作（比如把 DENY 改成 LOG），最规范的做法是 **“禁用 + 新增”**：
1.  在 `disableById` 中禁用原规则的 ID。
2.  在本地 `rules` 中定义一条新规则（可以使用相同的 ID），填入你想要的动作。

> 虽然使用 `duplicatePolicy: warn_keep_last` 也能通过“本地覆盖”达到类似效果，但这通常用于处理意外的 ID 冲突，而且会产生警告日志。对于有意的修改，"禁用 + 新增" 语义更清晰。

---

**Q: 如何写一个 IP 白名单？**

A: 使用 `BYPASS` 动作：

```json
{
  "id": 8888,
  "target": "CLIENT_IP",
  "match": "CIDR",
  "pattern": ["10.0.0.0/8", "192.168.1.100/32"],
  "action": "BYPASS"
}
```

当这条规则命中时，请求会直接放行，跳过后续所有 WAF 检查。

---

**Q: 如何只允许指定 IP，拒绝其他所有？**

A: 使用 `negate: true`：

```json
{
  "id": 8889,
  "target": "CLIENT_IP",
  "match": "CIDR",
  "pattern": ["10.0.0.0/8", "192.168.0.0/16"],
  "negate": true,
  "action": "DENY"
}
```

---

**Q: 修改了规则 JSON 后需要重启 Nginx 吗？**

A: 不需要重启，但需要 **Reload**：`nginx -s reload`。
规则文件在 Nginx 启动/Reload 时被编译成内存中的只读快照，运行时不会动态监听文件变化。

---

**Q: `duplicatePolicy` 的 `warn_skip` 和 `warn_keep_last` 有什么区别？**

A: 假设继承链中有两个 ID=100 的规则：

*   `warn_skip`：保留**第一个**出现的（来自父级），忽略后面的。
*   `warn_keep_last`：保留**最后一个**出现的（来自本地），覆盖之前的。

推荐使用 `warn_keep_last`，这样本地规则可以轻松覆盖父级规则。

---

## 8. 从 v1 迁移到 v2

如果之前使用过 v1 版本的行级 DSL 格式，这里提供一些迁移对照：

### 8.1 字段映射

| v1 语法 | v2 字段 |
| :--- | :--- |
| `200004: ALL_PARAMS CONTAINS "eval(" DENY 20` | `{ "id": 200004, "target": "ALL_PARAMS", "match": "CONTAINS", "pattern": "eval(", "action": "DENY", "score": 20 }` |
| `HEADER "User-Agent" CONTAINS "BadBot"` | `{ "target": "HEADER", "headerName": "User-Agent", "match": "CONTAINS", "pattern": "BadBot" }` |
| `URI REGEX "(?i)select.*from"` | `{ "target": "URI", "match": "REGEX", "pattern": "select.*from", "caseless": true }` |
| `CASELESS` 标记 | `"caseless": true` |

### 8.2 迁移建议

1.  **保留规则逻辑**：将 v1 的规则模式翻译成 v2 的 JSON 格式。
2.  **利用继承**：将通用规则放入 `core/`，业务规则 `extends` 继承它们。
3.  **补充 tags**：为规则添加标签，便于后续管理。
4.  **灰度上线**：先用 `"action": "LOG"` 观察，确认无误杀后再切换为 `DENY`。
