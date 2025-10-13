#include "ngx_http_waf_action.h"
#include "ngx_http_waf_dynamic_block.h"
#include "ngx_http_waf_log.h"

/*
 * ================================================================
 *  完整实现：统一动作执法层
 *  - 接入动态封禁前置检查和评分后阈值检查
 *  - 根据全局策略BLOCK/LOG决定最终动作
 *  - BLOCK路径立即flush，LOG路径仅累积事件
 *  - BYPASS路径立即flush并早退
 * ================================================================
 */

/*
 * 内部辅助：记录rule事件并累积评分
 */
static void waf_record_rule_event(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                                  ngx_http_waf_ctx_t *ctx, waf_intent_e intent, ngx_uint_t rule_id,
                                  ngx_uint_t score_delta, const waf_event_details_t *details)
{
  if (ctx == NULL)
    return;

  /* 累积评分（无论是否实际封禁） */
  if (score_delta > 0) {
    ctx->total_score += score_delta;
  }

  /* 记录详细的规则事件 */
  const char *intent_str = (intent == WAF_INTENT_BLOCK)    ? "BLOCK"
                           : (intent == WAF_INTENT_BYPASS) ? "BYPASS"
                                                           : "LOG";

  /* 统一收集：规则事件一律 COLLECT_ALWAYS；级别：BLOCK->ALERT，BYPASS/LOG->INFO */
  waf_log_level_e lv = (intent == WAF_INTENT_BLOCK) ? WAF_LOG_ALERT : WAF_LOG_INFO;
  waf_log_collect_mode_e mode = WAF_LOG_COLLECT_ALWAYS;

  waf_log_append_rule_event(r, mcf, ctx, rule_id, intent_str, score_delta,
                            details, mode, lv);
}

/*
 * 核心函数：waf_enforce
 * 功能：统一执法入口，处理BLOCK/LOG/BYPASS意图
 * 返回：waf_rc_e（BLOCK/BYPASS/CONTINUE/ERROR）
 */
waf_rc_e waf_enforce(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                     ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx, waf_intent_e intent,
                     ngx_int_t http_status, ngx_uint_t rule_id_or_0, ngx_uint_t score_delta,
                     const waf_event_details_t *details, const waf_final_action_type_e *final_type_hint)
{
  if (ctx == NULL) {
    return WAF_RC_ERROR;
  }

  /* 1. 事件采集与最终动作解耦：事件只做追加，decisive 由 flush 阶段统一判定 */

  /* 全局执法策略 */
  ngx_uint_t global_block_enabled =
  (lcf && lcf->default_action == WAF_DEFAULT_ACTION_BLOCK) ? 1 : 0;

  ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "waf-debug: enforce enter intent=%ui http_status=%i ruleId=%ui scoreDelta=%ui global=%s",
                (ngx_uint_t)intent, (ngx_int_t)http_status, (ngx_uint_t)rule_id_or_0,
                (ngx_uint_t)score_delta, global_block_enabled ? "BLOCK" : "LOG");

  if (intent != WAF_INTENT_BYPASS) {
    /* 2. 动态封禁：先增量计分，再检查是否已被封禁（与v1一致） */
    if (score_delta > 0) {
      waf_dyn_score_add(r, score_delta);
    }

    /* 3. 评分后阈值检查：达到阈值则触发封禁（依赖全局BLOCK策略） */

    /* 4. 若已处于封禁窗口内：按全局策略决定是否阻断（规则事件与 ban 事件均可记录） */
    if (waf_dyn_is_banned(r)) {
      ngx_msec_t window = (mcf && mcf->dyn_block_window > 0) ? mcf->dyn_block_window : 60000;
      if (global_block_enabled) {
        /* 记录规则事件（若存在） */
        waf_record_rule_event(r, mcf, ctx, intent, rule_id_or_0, score_delta, details);

        /* 设置最终动作为 BLOCK（动态封禁） */
        ctx->final_action = WAF_FINAL_BLOCK;
        ctx->final_action_type = (final_type_hint != NULL)
                                    ? *final_type_hint
                                    : WAF_FINAL_ACTION_TYPE_BLOCK_BY_DYNAMIC_BLOCK;
        ctx->final_status = NGX_HTTP_FORBIDDEN;
        ctx->effective_level = WAF_LOG_ALERT;

        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "waf-debug: dynamic-ban BLOCK window=%ui finalType=%ui",
                      (ngx_uint_t)window, (ngx_uint_t)ctx->final_action_type);

        /* 记录 ban 事件（decisive 将在 flush 阶段自判） */
        waf_log_append_ban_event(r, mcf, ctx, window, WAF_LOG_COLLECT_ALWAYS, WAF_LOG_ALERT);

        waf_log_flush_final(r, mcf, lcf, ctx, "BLOCK_BY_DYNAMIC_BLOCK");
        return WAF_RC_BLOCK;
      } else {
        /* 全局策略为 LOG：不阻断。记录规则事件与 ban 事件，继续流水 */
        ctx->final_action = WAF_FINAL_NONE;
        ctx->final_action_type = WAF_FINAL_ACTION_TYPE_ALLOW;
        ctx->final_status = 0;
        /* 记录规则事件（仅审计） */
        waf_record_rule_event(r, mcf, ctx, intent, rule_id_or_0, score_delta, details);
        /* 记录 ban 事件（表明处于封禁窗口，但全局为 LOG） */
        waf_log_append_ban_event(r, mcf, ctx, window, WAF_LOG_COLLECT_ALWAYS, WAF_LOG_INFO);
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "waf-debug: dynamic-ban SUPPRESSED_BY_GLOBAL_LOG window=%ui", (ngx_uint_t)window);
        return WAF_RC_CONTINUE;
      }
    }
  }

  /* 5. 处理意图 */
  if (http_status <= 0) {
    http_status = NGX_HTTP_FORBIDDEN;
  }

  switch (intent) {
    case WAF_INTENT_BLOCK:
      /* BLOCK意图：受全局策略控制 */
      if (global_block_enabled) {
        /* 真实阻断：设置最终动作 */
        ctx->final_action = WAF_FINAL_BLOCK;
        ctx->final_action_type = (final_type_hint != NULL)
                                     ? *final_type_hint
                                     : WAF_FINAL_ACTION_TYPE_BLOCK_BY_RULE;
        ctx->final_status = (ngx_uint_t)http_status;
        if (rule_id_or_0 > 0) {
          ctx->block_rule_id = rule_id_or_0;
        }
        if (ctx->effective_level < WAF_LOG_ALERT) {
          ctx->effective_level = WAF_LOG_ALERT;
        }

        /* 记录规则事件（decisive 将由 flush 阶段判定） */
        waf_record_rule_event(r, mcf, ctx, intent, rule_id_or_0, score_delta, details);

        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "waf-debug: BLOCK commit ruleId=%ui status=%ui finalType=%ui",
                      (ngx_uint_t)ctx->block_rule_id, (ngx_uint_t)ctx->final_status,
                      (ngx_uint_t)ctx->final_action_type);

        waf_log_flush_final(r, mcf, lcf, ctx, "BLOCK");

        return WAF_RC_BLOCK;
      } else {
        /* 执法策略LOG模式：仅记录，不阻断 */
        ctx->final_action = WAF_FINAL_NONE;
        ctx->final_action_type = WAF_FINAL_ACTION_TYPE_ALLOW;
        ctx->final_status = 0;
        /* 记录规则事件 */
        waf_record_rule_event(r, mcf, ctx, intent, rule_id_or_0, score_delta, details);
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "waf-debug: BLOCK suppressed by global LOG ruleId=%ui",
                      (ngx_uint_t)rule_id_or_0);
        /* 继续后续检测 */
        return WAF_RC_CONTINUE;
      }

    case WAF_INTENT_BYPASS:
      /* BYPASS意图：立即通过，flush并早退 */
      ctx->final_action = WAF_FINAL_BYPASS;
      ctx->final_action_type = (final_type_hint != NULL)
                                   ? *final_type_hint
                                   : WAF_FINAL_ACTION_TYPE_BYPASS_BY_URI_WHITELIST; /* 默认URI白名单 */
      ctx->final_status = 0;
      /* 记录规则事件（BYPASS） */
      waf_record_rule_event(r, mcf, ctx, intent, rule_id_or_0, score_delta, details);
      ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                    "waf-debug: BYPASS commit ruleId=%ui finalType=%ui",
                    (ngx_uint_t)rule_id_or_0, (ngx_uint_t)ctx->final_action_type);
      waf_log_flush_final(r, mcf, lcf, ctx, "BYPASS");
      return WAF_RC_BYPASS;

    case WAF_INTENT_LOG:
    default:
      /* LOG意图：仅记录，继续检测 */
      ctx->final_action = WAF_FINAL_NONE;
      ctx->final_action_type = WAF_FINAL_ACTION_TYPE_ALLOW;
      ctx->final_status = 0;
      /* 记录规则事件（LOG） */
      waf_record_rule_event(r, mcf, ctx, intent, rule_id_or_0, score_delta, details);
      ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                    "waf-debug: LOG record ruleId=%ui scoreDelta=%ui",
                    (ngx_uint_t)rule_id_or_0, (ngx_uint_t)score_delta);
      return WAF_RC_CONTINUE;
  }
}

/*
 * 包装函数：waf_enforce_block
 */
waf_rc_e waf_enforce_block(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                           ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx,
                           ngx_int_t http_status, ngx_uint_t rule_id, ngx_uint_t score_delta,
                           const waf_event_details_t *details)
{
  return waf_enforce(r, mcf, lcf, ctx, WAF_INTENT_BLOCK, http_status, rule_id, score_delta,
                     details, NULL);
}

/* 带 hint 的阻断封装：用于指定最终动作来源类型（如 IP 黑名单/动态封禁） */
waf_rc_e waf_enforce_block_hint(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                                ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx,
                                ngx_int_t http_status, ngx_uint_t rule_id, ngx_uint_t score_delta,
                                const waf_event_details_t *details,
                                const waf_final_action_type_e *final_type_hint)
{
  return waf_enforce(r, mcf, lcf, ctx, WAF_INTENT_BLOCK, http_status, rule_id, score_delta,
                     details, final_type_hint);
}

/*
 * 包装函数：waf_enforce_bypass
 */
waf_rc_e waf_enforce_bypass(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                            ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx,
                            ngx_uint_t rule_id, const waf_event_details_t *details,
                            const waf_final_action_type_e *final_type_hint)
{
  return waf_enforce(r, mcf, lcf, ctx, WAF_INTENT_BYPASS, NGX_DECLINED, rule_id, 0,
                     details, final_type_hint);
}

/*
 * 包装函数：waf_enforce_log
 */
waf_rc_e waf_enforce_log(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                         ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx, ngx_uint_t rule_id,
                         ngx_uint_t score_delta, const waf_event_details_t *details)
{
  return waf_enforce(r, mcf, lcf, ctx, WAF_INTENT_LOG, NGX_DECLINED, rule_id, score_delta,
                     details, NULL);
}

/*
 * 基础访问加分（reputation评分）
 */
waf_rc_e waf_enforce_base_add(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                              ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx,
                              ngx_uint_t score_delta)
{
  if (ctx == NULL) {
    return WAF_RC_ERROR;
  }

  /* 累积基础评分（请求内总分） */
  if (score_delta > 0) {
    ctx->total_score += score_delta;

    /* 先增量计分，再检查封禁（v1 顺序语义） */
    waf_dyn_score_add(r, score_delta);

    /* 记录reputation事件：base_access 改为 ALWAYS 且 INFO 级 */
    waf_log_append_reputation_event(r, mcf, ctx, score_delta, "base_access",
                                    WAF_LOG_COLLECT_ALWAYS, WAF_LOG_INFO);

    /* 检查是否达阈值 */
    ngx_uint_t threshold = (mcf && mcf->dyn_block_threshold > 0) ? mcf->dyn_block_threshold : 100;
    ngx_uint_t global_block_enabled =
        (lcf && lcf->default_action == WAF_DEFAULT_ACTION_BLOCK) ? 1 : 0;

    /* 已在共享层置位封禁时，遵循全局策略 */
    if (waf_dyn_is_banned(r)) {
      ngx_msec_t window = (mcf && mcf->dyn_block_window > 0) ? mcf->dyn_block_window : 60000;
      if (global_block_enabled) {
        waf_log_append_ban_event(r, mcf, ctx, window, WAF_LOG_COLLECT_ALWAYS, WAF_LOG_ALERT);
        ctx->final_action = WAF_FINAL_BLOCK;
        ctx->final_action_type = WAF_FINAL_ACTION_TYPE_BLOCK_BY_DYNAMIC_BLOCK;
        ctx->final_status = NGX_HTTP_FORBIDDEN;
        ctx->effective_level = WAF_LOG_ALERT;
        waf_log_flush_final(r, mcf, lcf, ctx, "BLOCK_BY_DYNAMIC_BLOCK");
        return WAF_RC_BLOCK;
      } else {
        waf_log_append_ban_event(r, mcf, ctx, window, WAF_LOG_COLLECT_LEVEL_GATED, WAF_LOG_INFO);
        return WAF_RC_CONTINUE;
      }
    }

    if (global_block_enabled && ctx->total_score >= threshold) {
      /* 达到阈值：当前请求按信誉来源直接阻断（共享层已在增量计分时设置封禁状态） */
      ctx->final_action = WAF_FINAL_BLOCK;
      ctx->final_action_type = WAF_FINAL_ACTION_TYPE_BLOCK_BY_DYNAMIC_BLOCK;
      ctx->final_status = NGX_HTTP_FORBIDDEN;
      ctx->effective_level = WAF_LOG_ALERT;

      /* 记录ban事件（decisive） */
      ngx_msec_t window = (mcf && mcf->dyn_block_window > 0) ? mcf->dyn_block_window : 60000;
      waf_log_append_ban_event(r, mcf, ctx, window, WAF_LOG_COLLECT_ALWAYS, WAF_LOG_ALERT);

      waf_log_flush_final(r, mcf, lcf, ctx, "BLOCK_BY_DYNAMIC_BLOCK");
      return WAF_RC_BLOCK;
    }
  }

  return WAF_RC_CONTINUE;
}

/* 事件包装：窗口重置（动态信誉窗口过期） */
void waf_action_log_window_reset(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                                 ngx_http_waf_ctx_t *ctx, ngx_uint_t prev_score,
                                 ngx_msec_t window_start_ms, ngx_msec_t window_end_ms,
                                 waf_log_collect_mode_e collect_mode, waf_log_level_e level)
{
  if (ctx == NULL) return;
  if (prev_score == 0) return;
  waf_log_append_window_reset_event(r, mcf, ctx, prev_score, window_start_ms, window_end_ms,
                                    collect_mode, level);
}

/*
 * 最终ALLOW落盘
 */
void waf_action_finalize_allow(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                               ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx)
{
  if (ctx == NULL)
    return;

  /* 如果未设置final_action，表示ALLOW */
  if (ctx->final_action == WAF_FINAL_NONE) {
    ctx->final_status = 0;
    ctx->final_action_type = WAF_FINAL_ACTION_TYPE_ALLOW;
  }

  waf_log_flush_final(r, mcf, lcf, ctx, "ALLOW");
}
