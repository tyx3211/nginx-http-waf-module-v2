# Nginx WAF v2 审计日志详解 (Friendly Spec)

> 💡 **写在前面**：
> 日志是安全的眼睛。V2 版本的日志不再是难以解析的文本行，而是**标准的 JSON Lines (JSONL)**。
> 每一行都是一个完整的 JSON 对象，包含了请求的来龙去脉、触发的所有事件、以及最终的裁决结果。
> 这对机器极其友好，您可以直接把它喂给 ELK, Splunk, ClickHouse 或任何日志分析平台。

---

## 0. 快速预览：一条日志里有什么？

这是一条经过格式化（Pretty Print）的日志。
**注意**：实际文件中，它是**压缩为一行**的。

```json
{
  /* === 1. 基础信息区 === */
  "time": "2025-10-12T08:00:00Z",          /* 发生时间 (ISO8601) */
  "clientIp": "192.168.1.105",             /* 谁来的？(已处理 XFF) */
  "method": "POST",                        /* 干什么？ */
  "host": "api.example.com",               /* 可选，若请求有 Host 头才出现 */
  "uri": "/login?user=admin",              /* 访问哪里？ */
  "status": 403,                           /* HTTP 状态码 (仅 BLOCK/BYPASS 时出现) */
  
  /* === 2. 裁决结果区 (The Verdict) === */
  "finalAction": "BLOCK",                  /* 最终结局：拦截 */
  "finalActionType": "BLOCK_BY_RULE",      /* 原因：因为命中了规则 */
  "currentGlobalAction": "BLOCK",          /* 当时的全局策略是啥？ */
  "blockRuleId": 200010,                   /* 是哪条规则"杀"死了请求？ */
  "level": "ALERT",                        /* 日志级别 */
  
  /* === 3. 案发现场 (The Evidence) === */
  "events": [
    /* 事件 A: 访问基础分 (+1分) */
    { 
      "type": "reputation", 
      "scoreDelta": 1, 
      "totalScore": 101,                   /* IP当前总分 */
      "reason": "base_access" 
    },
    
    /* 事件 B: 命中 SQL 注入规则 (+20分) */
    { 
      "type": "rule", 
      "ruleId": 200010, 
      "intent": "BLOCK",                   /* 这条规则想拦截 */
      "scoreDelta": 20, 
      "totalScore": 121,                   /* 加分后的总分 */
      "target": "ARGS_COMBINED",           /* 哪里有毒？URL参数 */
      "matchedPattern": "union select",    /* 抓到的毒刺 */
      "decisive": true                     /* ★ 致命一击！是它导致了最终拦截 */
    },
    
    /* 事件 C: 触发动态封禁 (总分 121 > 阈值 100) */
    { 
      "type": "ban", 
      "window": 60000                      /* 关进小黑屋 60秒 */
    }
  ]
}
```

---

## 1. 顶层字段：请求画像

这些字段描述了"谁、什么时候、对什么资源"发起了请求，以及最终的处理结果。

| 字段 | 类型 | 必填 | 说明 |
| :--- | :--- | :---: | :--- |
| `time` | string | ✅ | 请求时间，UTC ISO8601 格式（`%Y-%m-%dT%H:%M:%SZ`）。 |
| `clientIp` | string | ✅ | 客户端 IP（文本格式，当前实现：IPv4）。如果开了 `waf_trust_xff`，这就是真实的源 IP。 |
| `method` | string | ✅ | HTTP 方法 (GET, POST...)。 |
| `host` | string | ⚪ | Host 头部。**可选**，若请求中存在该头部才输出。 |
| `uri` | string | ✅ | 请求 URI（`r->uri` 原文，包含 Query String）。 |
| `status` | uint | ⚪ | 最终返回给客户端的 HTTP 状态码。**仅 BLOCK/BYPASS 路径会设置此字段**。 |
| `level` | string | ✅ | 日志级别，取值：`DEBUG`、`INFO`、`ALERT`、`ERROR`。（内部还有 `NONE` 作为初始值，但不会出现在日志中） |

---

## 2. 裁决字段：判决书

这些字段告诉你 WAF 对这个请求做了什么。

### 2.1 `finalAction`：最终动作

**最关键的字段**，取值：

| 值 | 说明 |
| :--- | :--- |
| `BLOCK` | 拦截了。请求被终止，返回 403（或规则指定的状态码）。 |
| `BYPASS` | 白名单放行。跳过了后续的 WAF 检查。 |
| `ALLOW` | 正常通过。WAF 检查完毕，没有发现问题（或发现了但全局策略是 LOG）。 |

### 2.2 `finalActionType`：具体原因

更细粒度地告诉你是**为什么**得到了上述结果：

| 值 | 说明 |
| :--- | :--- |
| `ALLOW` | 正常通过，没触发任何拦截。 |
| `BYPASS_BY_IP_WHITELIST` | 因为 IP 白名单规则放行。 |
| `BYPASS_BY_URI_WHITELIST` | 因为 URI 白名单规则放行。 |
| `BLOCK_BY_RULE` | 因为命中了某条检测规则被拦截。 |
| `BLOCK_BY_REPUTATION` | 因为 IP 信誉评分机制（非动态封禁）触发拦截。 |
| `BLOCK_BY_IP_BLACKLIST` | 因为 IP 黑名单规则拦截。 |
| `BLOCK_BY_DYNAMIC_BLOCK` | 因为**动态封禁**——该 IP 累计分数已超阈值，被关进"小黑屋"。 |

### 2.3 其他裁决字段

| 字段 | 说明 |
| :--- | :--- |
| `currentGlobalAction` | 记录当时的 `waf_default_action` 配置（`BLOCK` 或 `LOG`）。用于事后审计"当时是不是开着观察模式？" |
| `blockRuleId` | **仅当 `finalActionType=BLOCK_BY_RULE` 时出现**。记录导致拦截的**"致命一击"**规则 ID。 |

---

## 3. Events 数组：案发录像

WAF 的处理过程不是单点的，而是一个流。`events` 数组记录了处理过程中发生的所有**重要节点**。

### 3.1 规则命中事件 (`type: "rule"`)

当任意一条规则（Rule）被触发时，产生此事件。

| 字段 | 类型 | 必填 | 说明 |
| :--- | :--- | :---: | :--- |
| `type` | string | ✅ | 固定为 `"rule"`。 |
| `ruleId` | uint | ✅ | 规则 ID。 |
| `intent` | string | ⚪ | 规则的**意图**：`BLOCK`、`LOG`、`BYPASS`。注意：意图不等于最终结果！ |
| `target` | string | ⚪ | 命中的目标位置 (如 `ARGS_COMBINED`, `URI`, `BODY`)。 |
| `matchedPattern` | string | ⚪ | 命中的具体字符串（证据）。 |
| `patternIndex` | uint | ⚪ | 如果 `pattern` 是数组，这里记录命中的是第几个模式（从 0 开始）。 |
| `negate` | bool | ⚪ | 如果规则使用了取反逻辑（`negate: true`），这里会标记出来。 |
| `scoreDelta` | uint | ⚪ | 这条规则扣了多少分。 |
| `totalScore` | uint | ✅ | 扣分后的 IP 总分。 |
| `decisive` | bool | ⚪ | 如果为 `true`，说明**就是这条事件导致了最终的拦截/放行**。 |

### 3.2 信誉事件 (`type: "reputation"`)

当 IP 分数发生变化时产生（如访问基础分）。

| 字段 | 类型 | 说明 |
| :--- | :--- | :--- |
| `type` | string | 固定为 `"reputation"`。 |
| `reason` | string | 原因（如 `base_access` 表示访问基础分）。 |
| `scoreDelta` | uint | 变化的分数。 |
| `totalScore` | uint | 变化后的总分。 |

### 3.3 封禁事件 (`type: "ban"`)

当 IP 触发动态封禁阈值时产生。

| 字段 | 类型 | 说明 |
| :--- | :--- | :--- |
| `type` | string | 固定为 `"ban"`。 |
| `window` | uint | 封禁时长（毫秒）。 |

### 3.4 窗口重置事件 (`type: "reputation_window_reset"`)

当 IP 的评分滑动窗口到期，分数归零时产生。

| 字段 | 类型 | 说明 |
| :--- | :--- | :--- |
| `type` | string | 固定为 `"reputation_window_reset"`。 |
| `prevScore` | uint | 重置前的分数。 |
| `windowStartMs` | uint | 窗口开始时间（毫秒时间戳）。 |
| `windowEndMs` | uint | 窗口结束时间（毫秒时间戳）。 |
| `reason` | string | 固定为 `"window_expired"`。 |
| `category` | string | 固定为 `"reputation/dyn_block"`。 |

---

## 4. `decisive` 标记：谁是"真凶"？

当一个请求触发了多条规则时，`decisive: true` 会标记在**导致最终结果的那个事件**上。整个请求**最多只有一个事件**会被标记为 decisive。

**选择逻辑**：

1.  **BLOCK 情况**：
    *   如果 `finalActionType = BLOCK_BY_DYNAMIC_BLOCK`：优先选择最后一条 `ban` 事件；若无，则回退到 `rule` 事件。
    *   如果 `finalActionType = BLOCK_BY_RULE`：优先匹配 `blockRuleId` 对应的 `rule` 事件；否则回退到最后一条 `intent=BLOCK` 的规则事件。

2.  **BYPASS 情况**：选择最后一条 `intent=BYPASS` 的规则事件。

> **排障技巧**：在一堆事件中找原因，认准 `decisive: true`！

---

## 5. 日志级别与落盘策略

WAF 每天可能处理数亿请求，我们不想把磁盘填满。V2 内置了智能的日志策略。

### 5.1 级别顺序

从低到高：`none < debug < info < alert < error < off`

*   **`none`**：内部初始值，不可配置。表示"这个请求还没产生任何值得记录的事件"。
*   **`off`**：配置选项，表示"除了 BLOCK 都不写"。

### 5.2 落盘规则

| 情况 | 是否落盘 | 说明 |
| :--- | :---: | :--- |
| `finalAction = BLOCK` | ✅ 必写 | 无论配置什么级别，**强制写入**，且级别至少提升到 `ALERT`。这是安全底线。 |
| `finalAction = BYPASS/ALLOW` | 看配置 | 如果 `effective_level >= waf_json_log_level`，则落盘。 |
| `finalAction = ALLOW` 且无任何事件 | ❌ 不写 | **静默通过**。正常请求不产生日志，降噪。 |

### 5.3 配置建议

*   **生产环境**：`waf_json_log_level info;` —— 记录所有拦截 + 所有高危预警。
*   **排障/测试**：`waf_json_log_level debug;` —— 记录所有细节（日志量大）。

---

## 6. 常见问题 (FAQ)

**Q: 为什么 `events` 里有 `"intent": "BLOCK"`，但 `finalAction` 却是 `"ALLOW"`？**

A: 说明 `waf_default_action` 设置为了 `LOG`（观察模式）。WAF 告诉你"我想拦"，但受限于全局策略"不能拦"。这是灰度上线新规则时的常见场景。

---

**Q: `totalScore` 是怎么算的？**

A: 它是该 IP 在当前滑动窗口（由 `waf_dynamic_block_window_size` 控制，默认 1 分钟）内的累计扣分。每次请求的基础分、每条规则触发的扣分都会累加。超出窗口的旧分数会被遗忘。

---

**Q: 我怎么知道是哪个规则导致了拦截？**

A: 有两个途径：
1.  看顶层的 `blockRuleId` 字段。
2.  在 `events` 数组中找 `decisive: true` 的那个事件，它的 `ruleId` 就是罪魁祸首。

---

**Q: 为什么有的日志没有 `status` 字段？**

A: `status` 字段只在 `BLOCK` 或 `BYPASS` 路径下才会设置。如果是 `ALLOW`（正常放行），WAF 不会修改响应状态码，因此不记录。

---

**Q: `host` 字段为什么有时候不存在？**

A: `host` 字段只有在请求中包含 `Host` 头部时才会输出。虽然现代浏览器都会发送，但某些 CLI 工具或畸形请求可能没有。

---

**Q: 日志文件会无限增长吗？**

A: WAF 本身不做日志轮转。建议使用 `logrotate` 或日志采集工具（如 Filebeat）配合定期清理策略。
