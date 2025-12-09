### WAF 请求日志 JSONL 规范 v2.0（实现抽离版）

说明：本规范对应 v2 当前实现。**日志文件为 JSON Lines 格式，即一次请求对应一行完整的 JSON 对象**。

### 0. 完整日志示例

为了便于阅读，以下示例进行了格式化展示。**实际落盘时，每条日志将压缩为单行。**

```json
{
  "time": "2025-10-12T08:00:00Z",          /* 请求时间 (UTC ISO8601) */
  "clientIp": "192.168.1.105",             /* 客户端 IP */
  "method": "POST",                        /* HTTP 方法 */
  "host": "api.example.com",               /* Host 头 */
  "uri": "/login?user=admin",              /* 请求 URI (含 Query) */
  "status": 403,                           /* 返回给客户端的 HTTP 状态码 */
  
  /* -------------------------------------------------------------
     决策结果区
     ------------------------------------------------------------- */
  "finalAction": "BLOCK",                  /* 最终动作: BLOCK | BYPASS | ALLOW */
  "finalActionType": "BLOCK_BY_RULE",      /* 具体原因类型 */
  "currentGlobalAction": "BLOCK",          /* 当前配置的全局默认动作 */
  "blockRuleId": 200010,                   /* (仅 BLOCK_BY_RULE) 导致阻断的规则 ID */
  "level": "ALERT",                        /* 日志级别: ALERT | ERROR | INFO | DEBUG */
  
  /* -------------------------------------------------------------
     事件详情区 (记录触发的所有规则/信誉变动)
     ------------------------------------------------------------- */
  "events": [
    /* 事件 1: 访问基础分 (每次请求 +1) */
    { 
      "type": "reputation", 
      "scoreDelta": 1, 
      "totalScore": 101,                   /* 触发时的累积总分 (信誉分仅在此处体现) */
      "reason": "base_access" 
    },
    
    /* 事件 2: 命中 SQL 注入规则 */
    { 
      "type": "rule", 
      "ruleId": 200010, 
      "intent": "BLOCK",                   /* 规则意图拦截 */
      "scoreDelta": 20, 
      "totalScore": 121,                   /* 触发该规则后的即刻 IP 总分 */
      "target": "ARGS_COMBINED",           /* 命中目标 */
      "matchedPattern": "union select",    /* (可选) 命中的特征串 */
      "decisive": true                     /* 关键标记: 导致 finalAction 的决定性事件 */
    },
    
    /* 事件 3: 触发动态封禁 (因总分 121 > 阈值 100) */
    { 
      "type": "ban", 
      "window": 60000                      /* 封禁时长 (ms) */
    }
  ]
}
```

---

#### 1. 顶层字段
- `time:string`：UTC ISO8601（`%Y-%m-%dT%H:%M:%SZ`）
- `clientIp:string`：文本 IP（当前实现：IPv4）
- `method:string`：HTTP 方法
- `host?:string`：HTTP Host 头（可选，若请求中存在）
- `uri:string`：`r->uri` 原文
- `events:array<object>`：事件数组（见第 2 节）
- `finalAction:string`：`BLOCK|BYPASS|ALLOW`
- `finalActionType:string`：
  - `ALLOW`
  - `BYPASS_BY_IP_WHITELIST|BYPASS_BY_URI_WHITELIST`
  - `BLOCK_BY_RULE|BLOCK_BY_REPUTATION|BLOCK_BY_IP_BLACKLIST|BLOCK_BY_DYNAMIC_BLOCK`
- `currentGlobalAction:string`：当前作用域的全局策略，`BLOCK|LOG`
- `blockRuleId?:uint`：当 `finalActionType=BLOCK_BY_RULE` 时出现
- `status?:uint`：最终 HTTP 状态（仅 BLOCK/BYPASS 路径会被设置）
- `level:string`：最终日志级别文本，取值 `DEBUG|INFO|ALERT|ERROR|NONE`

约束：
- 仅 BLOCK 强制落盘并至少提升至 `ALERT`；BYPASS/ALLOW 受 `waf_json_log_level` 控制。
- 若无任何事件且最终为 ALLOW，则不落盘（降噪）。

#### 2. events 事件
- 通用：每个事件至少包含 `type:string`；常见取值：
  - `rule`：规则命中
    - 字段：`ruleId:uint`、`intent:"BLOCK|LOG|BYPASS"?`、`scoreDelta?:uint`、`totalScore:uint`
    - 可选匹配细节：`matchedPattern?:string`、`patternIndex?:uint`、`target?:string`、`negate?:bool`
  - `reputation`：信誉加分
    - 字段：`scoreDelta?:uint`、`totalScore:uint`、`reason?:string`
  - `ban`：进入封禁窗口
    - 字段：`window:uint(ms)`
  - `reputation_window_reset`：窗口到期归零
    - 字段：`prevScore:uint`、`windowStartMs:uint`、`windowEndMs:uint`、`reason:string="window_expired"`、`category:string="reputation/dyn_block"`

- `decisive?:bool`：仅在最终 `finalAction=BLOCK` 或 `finalAction=BYPASS` 的决定性事件上标记，且同一请求最多 1 次。
  - BLOCK 情况：
    - `finalActionType=BLOCK_BY_DYNAMIC_BLOCK` 优先选择最后一条 `ban` 事件；若无，则回退到 `rule` 事件。
    - `finalActionType=BLOCK_BY_RULE` 优先匹配 `blockRuleId` 对应的 `rule` 事件；否则回退到“最后一条 intent=BLOCK 的规则事件”。
  - BYPASS 情况：选择“最后一条 intent=BYPASS 的规则事件”。

#### 3. 级别与落盘
- 配置级别：`waf_json_log_level off|debug|info|alert|error`；内部还存在 `none`（初始值，不可配置）。
- 级别顺序：`none < debug < info < alert < error < off`。
- 落盘策略：
  - `finalAction=BLOCK`：必落盘（至少 `alert`）。
  - `finalAction=BYPASS|ALLOW`：若 `effective_level >= waf_json_log_level` 则落盘。

#### 4. 测试要点
- 断言仅一行 JSONL/请求；BLOCK 必落盘；BYPASS/ALLOW 随阈值。
- 验证 `decisive` 选择逻辑与 `blockRuleId` 联动。
- 验证空事件 ALLOW 不落盘；有事件但未执法在 `info|debug` 打开时落盘。
- 验证 `currentGlobalAction` 与指令 `waf_default_action` 的对应。
- 动态封禁：达到阈值→`ban` 事件→`finalActionType=BLOCK_BY_DYNAMIC_BLOCK`。
