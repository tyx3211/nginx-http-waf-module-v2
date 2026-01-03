# WAF v2 快速实现与接入说明（临时交付版）

本文档总结本次快速实现的目标、包含内容与后续演进建议，便于上线与后续重构。

## 目标
- 提供 `$waf_*` 变量用于 `access_log` JSON 输出，支撑「近5分钟/近1小时/近24小时」滑窗统计。
- 提供可 `include` 的最小化配置片段：`waf_access_log.conf`（仅用于访问日志 JSONL 输出）。
- 保持与模块内部 JSONL (`waf_json_log`) 的对齐：`finalAction/finalActionType/blockRuleId` 语义一致。

## 本次实现要点
1. 在模块 `postconfiguration` 注册 5 个只读变量：
   - `$waf_blocked`：0|1（最终是否阻断）
   - `$waf_action`：`BLOCK|BYPASS|ALLOW`
   - `$waf_rule_id`：当 `finalActionType=BLOCK_BY_RULE` 时输出对应 `ruleId`，否则为空
   - `$waf_attack_type`：按规则 tags 推断的攻击类型（大屏/审计聚合用，含 SQL_INJECTION/XSS/...，动态封禁/黑名单输出固定枚举）
   - `$waf_attack_category`：`ALLOW|BYPASS_BY_*|BLOCK_BY_*`（旧语义保留，用于兼容）
2. 变量 `get_handler` 在 log 阶段读取请求主上下文 `ctx`（`r->main`），确保取到“最终动作”。
3. 提供 `waf_access_log.conf`（建议安装至 `/usr/local/nginx/conf/waf/`）：
   - 定义 `log_format waf_json` 并输出至 `/usr/local/nginx/logs/access_waf.jsonl`。
   - 字段包含 `ts/$msec`、`status`、`blocked`、`waf_*`，以及增强字段 `host/scheme/up_status/up_rt/req_len`（用于大屏与审计统计）。
   - 仓库内模板位于 `conf-template/waf/waf_access_log.conf`。

## Nginx include 用法
在 `http {}` 中加入：
```
include waf/waf_access_log.conf;  # 用于大屏统计（JSONL，每请求一行）
```

## 后端滑窗统计建议
- 从 `/usr/local/nginx/logs/access_waf.jsonl` 增量读取（`tail -F` 或 inotify），以 `$msec` 作为时间戳。
- 建议维护：
  - 近 5 分钟：按秒 300 桶（req/block/4xx/5xx）
  - 近 1 小时：按分 60 桶
  - 近 24 小时：按分 1440 桶
  - UV/攻击 IP：每桶可用 HyperLogLog 或限长集合（后续演进）。

## 与 JSONL 的关系
- `access_waf.jsonl`：面向实时指标的高吞吐简日志（每请求一行，固定字段）。
- `waf.jsonl`（`waf_json_log`）：面向审计回放的丰富事件日志（一次请求最多一行，含 events）。
- 两者字段对齐：
  - `$waf_action` ← `finalAction`
  - `$waf_attack_category` ← `finalActionType`（旧语义）
  - `$waf_attack_type` ← `attackType`（规则 tags 推断，供大屏/审计聚合）
  - `$waf_rule_id` ← `blockRuleId`

## 后续重构方向
- 共享内存计数器：在模块内维护滑窗计数与 HLL，暴露 `/waf_status` 接口，降低 IO 成本。
- 变量补充：按需增加 `$waf_score_total/$waf_status` 等指标变量（需评估安全与性能）。
- IPv6 支持与客户端 IP 归并策略优化（与 `waf_trust_xff` 搭配）。
- 日志落盘优化：异步队列/批量写/可选择压缩。

## 验收清单
- `$waf_*` 变量在 BLOCK/BYPASS/ALLOW 路径正确输出。
- `include waf/waf_access_log.conf` 后生成 `access_waf.jsonl`，可按窗口聚合得到近 5 分钟/1 小时/24 小时指标。
- `waf_json_log` 正常输出 JSONL，字段对齐无冲突。
