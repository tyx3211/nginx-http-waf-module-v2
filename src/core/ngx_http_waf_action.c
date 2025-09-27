#include "ngx_http_waf_action.h"

/*
 * ================================================================
 *  STUB IMPLEMENTATION (M2.5)
 *  统一动作存根：
 *  - 合并全局策略与事件意图
 *  - BLOCK 路径返回 http_status（默认 403）
 *  - 非阻断返回 NGX_DECLINED
 *  - 同时提升 ctx 日志级别并在最终动作处交给 waf_log_flush
 *  - M5：接入动态信誉评分/封禁与共享内存复检
 * ================================================================
 */

/* 存根：占位：全局默认策略（M3 指令接入后从 conf 读取）
 * 0=LOG-only, 1=BLOCK-enable
 */
static ngx_uint_t waf_global_block_policy_enabled = 1;

static void waf_record_event(ngx_http_request_t* r,
                             ngx_http_waf_ctx_t* ctx,
                             waf_intent_e intent,
                             ngx_uint_t rule_id_or_0,
                             ngx_uint_t score_delta) {
    if (ctx == NULL) return;
    /* 存根：仅提升日志级别，记录为 INFO（命中）或 DEBUG（普通） */
    waf_log_append_event(r, ctx, (intent == WAF_INTENT_BLOCK) ? WAF_LOG_INFO : WAF_LOG_DEBUG);
    (void)rule_id_or_0;
    if (score_delta > 0) {
        ctx->total_score += score_delta;
    }
}

ngx_int_t waf_enforce(ngx_http_request_t* r,
                      ngx_http_waf_main_conf_t* mcf,
                      ngx_http_waf_loc_conf_t* lcf,
                      ngx_http_waf_ctx_t* ctx,
                      waf_intent_e intent,
                      ngx_int_t http_status,
                      ngx_uint_t rule_id_or_0,
                      ngx_uint_t score_delta) {
    (void)mcf; (void)lcf; /* 存根阶段未用 */

    if (http_status <= 0) {
        http_status = NGX_HTTP_FORBIDDEN;
    }

    waf_record_event(r, ctx, intent, rule_id_or_0, score_delta);

    /* 策略：当全局策略 BLOCK 且意图 BLOCK → 实际阻断 */
    if (waf_global_block_policy_enabled && intent == WAF_INTENT_BLOCK) {
        if (ctx) {
            ctx->final_action = 1; /* BLOCK */
            ctx->final_status = (ngx_uint_t)http_status;
            if (ctx->effective_level < WAF_LOG_ALERT) {
                ctx->effective_level = WAF_LOG_ALERT;
            }
        }
        /* 在最终动作处强制 FINAL flush（BLOCK） */
        waf_log_flush_final(r, mcf, lcf, ctx, "BLOCK");
        return http_status;
    }

    /* 非阻断路径：仅标注最终动作为 LOG 或 BYPASS，占位为 2/3 */
    if (ctx) {
        ctx->final_action = (intent == WAF_INTENT_BYPASS) ? 3 : 2;
        ctx->final_status = 0;
        if (intent == WAF_INTENT_BYPASS) {
            waf_log_flush_final(r, mcf, lcf, ctx, "BYPASS");
        }
    }
    return NGX_DECLINED;
}


/* 基础访问加分（可触发封禁）：返回 waf_rc_e */
waf_rc_e
waf_enforce_base_add(ngx_http_request_t* r,
                     ngx_http_waf_main_conf_t* mcf,
                     ngx_http_waf_loc_conf_t*  lcf,
                     ngx_http_waf_ctx_t*       ctx,
                     ngx_uint_t                 score_delta)
{
    (void)waf_enforce(r, mcf, lcf, ctx, WAF_INTENT_LOG, NGX_DECLINED, 0, score_delta);
    /* 存根阶段不触发封禁，直接继续 */
    return WAF_RC_CONTINUE;
}


