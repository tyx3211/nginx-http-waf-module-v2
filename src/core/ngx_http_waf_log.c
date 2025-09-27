#include "ngx_http_waf_log.h"

/*
 * ================================================================
 *  STUB IMPLEMENTATION (M2.5)
 *  日志模块存根：仅维护请求态级别与在 error_log 输出摘要。
 *  - M6 将实现 JSONL 文件落盘与完整事件结构
 * ================================================================
 */

static const char* waf_log_level_str(waf_log_level_e lv) {
    switch (lv) {
    case WAF_LOG_DEBUG: return "DEBUG";
    case WAF_LOG_INFO:  return "INFO";
    case WAF_LOG_ALERT: return "ALERT";
    case WAF_LOG_ERROR: return "ERROR";
    default:            return "NONE";
    }
}

void waf_log_init_request(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx) {
    if (ctx == NULL) return;
    ctx->log_doc = NULL;
    ctx->events = NULL;
    ctx->effective_level = WAF_LOG_NONE;
    ctx->total_score = 0;
    ctx->final_status = 0;
    ctx->final_action = 0;
    ctx->has_complete_events = 0;
    ctx->log_flushed = 0;
}

static void waf_log_raise_effective_level(ngx_http_waf_ctx_t* ctx, waf_log_level_e lv) {
    if (ctx == NULL) return;
    if ((int)lv > (int)ctx->effective_level) {
        ctx->effective_level = lv;
    }
}

void waf_log_append_event_complete(ngx_http_request_t* r,
                                   ngx_http_waf_ctx_t* ctx,
                                   waf_log_level_e level) {
    if (ctx == NULL) return;
    waf_log_raise_effective_level(ctx, level);
    ctx->has_complete_events = 1;
}

void waf_log_append_event(ngx_http_request_t* r,
                          ngx_http_waf_ctx_t* ctx,
                          waf_log_level_e level) {
    if (ctx == NULL) return;
    waf_log_raise_effective_level(ctx, level);
}

void waf_log_flush(ngx_http_request_t* r,
                   ngx_http_waf_main_conf_t* mcf,
                   ngx_http_waf_loc_conf_t* lcf,
                   ngx_http_waf_ctx_t* ctx) {
    if (r == NULL || ctx == NULL) return;

    /* 存根阶段：统一输出一行 error_log 日志，包含最终状态/动作/级别/score */
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "waf-stub-log: final_status=%ui final_action=%ui level=%s total_score=%ui uri=\"%V\"",
                  ctx->final_status,
                  ctx->final_action,
                  waf_log_level_str(ctx->effective_level),
                  ctx->total_score,
                  &r->uri);
}

void waf_log_flush_final(ngx_http_request_t* r,
                         ngx_http_waf_main_conf_t* mcf,
                         ngx_http_waf_loc_conf_t*  lcf,
                         ngx_http_waf_ctx_t*       ctx,
                         const char* final_action_hint) {
    if (r == NULL || ctx == NULL) return;
    if (ctx->log_flushed) return;

    /* 存根：复用 waf_log_flush 行为，附带 hint 输出 */
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "waf-stub-final: hint=%s final_status=%ui final_action=%ui level=%s total_score=%ui uri=\"%V\"",
                  (final_action_hint ? final_action_hint : ""),
                  ctx->final_status,
                  ctx->final_action,
                  waf_log_level_str(ctx->effective_level),
                  ctx->total_score,
                  &r->uri);
    ctx->log_flushed = 1;
    (void)mcf; (void)lcf;
}


