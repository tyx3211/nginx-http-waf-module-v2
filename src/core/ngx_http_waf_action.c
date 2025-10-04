#include "ngx_http_waf_action.h"
#include "ngx_http_waf_dynamic_block.h"

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
static void waf_record_rule_event(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx,
                                  waf_intent_e intent, ngx_uint_t rule_id, ngx_uint_t score_delta,
                                  ngx_flag_t decisive)
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

  waf_log_append_rule_event(r, ctx, rule_id, NULL, /* target_tag */
                            intent_str, score_delta, NULL, /* matched_pattern */
                            0,                             /* pattern_index */
                            0,                             /* negate */
                            decisive);

  /* 记录事件：BLOCK提升为INFO，其他为DEBUG */
  waf_log_append_event(r, ctx, (intent == WAF_INTENT_BLOCK) ? WAF_LOG_INFO : WAF_LOG_DEBUG);
}

/*
 * 核心函数：waf_enforce
 * 功能：统一执法入口，处理BLOCK/LOG/BYPASS意图
 * 返回：waf_rc_e（BLOCK/BYPASS/CONTINUE/ERROR）
 */
waf_rc_e waf_enforce(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                     ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx, waf_intent_e intent,
                     ngx_int_t http_status, ngx_uint_t rule_id_or_0, ngx_uint_t score_delta)
{
  if (ctx == NULL) {
    return WAF_RC_ERROR;
  }

  /* 1. 动态封禁前置检查：已封禁IP直接拦截 */
  if (waf_dyn_is_banned(r)) {
    ctx->final_action = WAF_FINAL_BLOCK;
    ctx->final_action_type = WAF_FINAL_ACTION_TYPE_BLOCK_BY_REPUTATION;
    ctx->final_status = NGX_HTTP_FORBIDDEN;
    ctx->effective_level = WAF_LOG_ALERT;
    waf_log_flush_final(r, mcf, lcf, ctx, "BLOCK_BY_REPUTATION");
    return WAF_RC_BLOCK;
  }

  /* 2. 记录事件并累积评分（暂不设置decisive，后续根据执法结果判断） */
  waf_record_rule_event(r, ctx, intent, rule_id_or_0, score_delta, 0);

  /* 3. 评分后阈值检查：达到阈值则触发封禁（依赖全局BLOCK策略） */
  ngx_uint_t threshold = (mcf && mcf->dyn_block_threshold > 0) ? mcf->dyn_block_threshold : 100;

  /* 4. 获取执法策略（默认BLOCK） */
  ngx_uint_t global_block_enabled =
      (lcf && lcf->default_action == WAF_DEFAULT_ACTION_BLOCK) ? 1 : 0;

  /* 5. 处理意图 */
  if (http_status <= 0) {
    http_status = NGX_HTTP_FORBIDDEN;
  }

  switch (intent) {
    case WAF_INTENT_BLOCK:
      /* BLOCK意图：受全局策略控制 */
      if (global_block_enabled) {
        /* 真实阻断 */
        ctx->final_action = WAF_FINAL_BLOCK;
        ctx->final_action_type = WAF_FINAL_ACTION_TYPE_BLOCK_BY_RULE;
        ctx->final_status = (ngx_uint_t)http_status;
        if (rule_id_or_0 > 0) {
          ctx->block_rule_id = rule_id_or_0;
        }
        if (ctx->effective_level < WAF_LOG_ALERT) {
          ctx->effective_level = WAF_LOG_ALERT;
        }

        /* 记录decisive事件（首次BLOCK） */
        if (!ctx->decisive_set && rule_id_or_0 > 0) {
          waf_record_rule_event(r, ctx, intent, rule_id_or_0, 0, 1); /* decisive=1 */
        }

        waf_log_flush_final(r, mcf, lcf, ctx, "BLOCK");

        /* 如果评分达阈值，添加到动态封禁 */
        if (ctx->total_score >= threshold) {
          waf_dyn_score_add(r, ctx->total_score);
        }

        return WAF_RC_BLOCK;
      } else {
        /* 执法策略LOG模式：仅记录，不阻断 */
        ctx->final_action = WAF_FINAL_NONE;
        ctx->final_action_type = WAF_FINAL_ACTION_TYPE_ALLOW;
        ctx->final_status = 0;
        /* 继续后续检测 */
        return WAF_RC_CONTINUE;
      }

    case WAF_INTENT_BYPASS:
      /* BYPASS意图：立即通过，flush并早退 */
      ctx->final_action = WAF_FINAL_BYPASS;
      ctx->final_action_type = WAF_FINAL_ACTION_TYPE_BYPASS_BY_URI_WHITELIST; /* 默认URI白名单 */
      ctx->final_status = 0;
      waf_log_flush_final(r, mcf, lcf, ctx, "BYPASS");
      return WAF_RC_BYPASS;

    case WAF_INTENT_LOG:
    default:
      /* LOG意图：仅记录，继续检测 */
      ctx->final_action = WAF_FINAL_NONE;
      ctx->final_action_type = WAF_FINAL_ACTION_TYPE_ALLOW;
      ctx->final_status = 0;
      return WAF_RC_CONTINUE;
  }
}

/*
 * 包装函数：waf_enforce_block
 */
waf_rc_e waf_enforce_block(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                           ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx,
                           ngx_int_t http_status, ngx_uint_t rule_id, ngx_uint_t score_delta)
{
  return waf_enforce(r, mcf, lcf, ctx, WAF_INTENT_BLOCK, http_status, rule_id, score_delta);
}

/*
 * 包装函数：waf_enforce_bypass
 */
waf_rc_e waf_enforce_bypass(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                            ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx,
                            ngx_uint_t rule_id)
{
  return waf_enforce(r, mcf, lcf, ctx, WAF_INTENT_BYPASS, NGX_DECLINED, rule_id, 0);
}

/*
 * 包装函数：waf_enforce_log
 */
waf_rc_e waf_enforce_log(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                         ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx, ngx_uint_t rule_id,
                         ngx_uint_t score_delta)
{
  return waf_enforce(r, mcf, lcf, ctx, WAF_INTENT_LOG, NGX_DECLINED, rule_id, score_delta);
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

  /* 检查是否已封禁 */
  if (waf_dyn_is_banned(r)) {
    ctx->final_action = WAF_FINAL_BLOCK;
    ctx->final_action_type = WAF_FINAL_ACTION_TYPE_BLOCK_BY_REPUTATION;
    ctx->final_status = NGX_HTTP_FORBIDDEN;
    ctx->effective_level = WAF_LOG_ALERT;
    waf_log_flush_final(r, mcf, lcf, ctx, "BLOCK_BY_REPUTATION");
    return WAF_RC_BLOCK;
  }

  /* 累积基础评分 */
  if (score_delta > 0) {
    ctx->total_score += score_delta;

    /* 记录reputation事件 */
    waf_log_append_reputation_event(r, ctx, score_delta, "base_access");
    waf_log_append_event(r, ctx, WAF_LOG_DEBUG);

    /* 检查是否达阈值 */
    ngx_uint_t threshold = (mcf && mcf->dyn_block_threshold > 0) ? mcf->dyn_block_threshold : 100;
    ngx_uint_t global_block_enabled =
        (lcf && lcf->default_action == WAF_DEFAULT_ACTION_BLOCK) ? 1 : 0;

    if (global_block_enabled && ctx->total_score >= threshold) {
      /* 触发封禁 */
      waf_dyn_score_add(r, ctx->total_score);
      ctx->final_action = WAF_FINAL_BLOCK;
      ctx->final_action_type = WAF_FINAL_ACTION_TYPE_BLOCK_BY_REPUTATION;
      ctx->final_status = NGX_HTTP_FORBIDDEN;
      ctx->effective_level = WAF_LOG_ALERT;

      /* 记录ban事件（decisive） */
      ngx_msec_t window = (mcf && mcf->dyn_block_window > 0) ? mcf->dyn_block_window : 60000;
      waf_log_append_ban_event(r, ctx, window);

      waf_log_flush_final(r, mcf, lcf, ctx, "BLOCK_BY_REPUTATION");
      return WAF_RC_BLOCK;
    }
  }

  return WAF_RC_CONTINUE;
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
