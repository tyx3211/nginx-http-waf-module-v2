#ifndef NGX_HTTP_WAF_ACTION_H
#define NGX_HTTP_WAF_ACTION_H

#include "ngx_http_waf_log.h"
#include "ngx_http_waf_module_v2.h"
#include "ngx_http_waf_types.h"
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * ================================================================
 *  完整实现：统一动作执法层
 *  - 接入动态封禁前置检查与评分后阈值检查（封禁条件：score > threshold）
 *  - 根据全局策略 BLOCK/LOG 决定最终动作；BYPASS 立即落盘
 *  - BLOCK/BYPASS 路径在动作时 final flush，ALLOW 于尾部统一 flush
 * ================================================================
 */

typedef enum { WAF_INTENT_BLOCK,
               WAF_INTENT_LOG,
               WAF_INTENT_BYPASS } waf_intent_e;

/* 返回值约定（存根阶段）：统一返回 waf_rc_e，由 STAGE 宏映射为 Nginx rc。
 * - BLOCK  → 返回 WAF_RC_BLOCK（精确 http_status 存入 ctx->final_status）
 * - BYPASS → 返回 WAF_RC_BYPASS（动作层立即 final 日志）
 * - LOG    → 返回 WAF_RC_CONTINUE（仅记录事件，不改变控制流）
 */
waf_rc_e waf_enforce(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                     ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx, waf_intent_e intent,
                     ngx_int_t http_status, ngx_uint_t rule_id_or_0, ngx_uint_t score_delta,
                     const waf_event_details_t *details, const waf_final_action_type_e *final_type_hint);

/* 语义包装：BLOCK/LOG/BYPASS（声明） */
waf_rc_e waf_enforce_block(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                           ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx,
                           ngx_int_t http_status, ngx_uint_t rule_id_or_0, ngx_uint_t score_delta,
                           const waf_event_details_t *details);

/* 新增：带 final_type_hint 的阻断封装（用于来源区分，如IP黑名单/动态封禁） */
waf_rc_e waf_enforce_block_hint(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                                ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx,
                                ngx_int_t http_status, ngx_uint_t rule_id_or_0, ngx_uint_t score_delta,
                                const waf_event_details_t *details,
                                const waf_final_action_type_e *final_type_hint);

waf_rc_e waf_enforce_log(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                         ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx,
                         ngx_uint_t rule_id_or_0, ngx_uint_t score_delta,
                         const waf_event_details_t *details);

waf_rc_e waf_enforce_bypass(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                            ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx,
                            ngx_uint_t rule_id_or_0, const waf_event_details_t *details,
                            const waf_final_action_type_e *final_type_hint);

/* 基础访问加分（可触发封禁）：返回 waf_rc_e 以便被 STAGE 宏统一处理 */
waf_rc_e waf_enforce_base_add(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                              ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx,
                              ngx_uint_t score_delta);

/* 尾部 FINAL（ALLOW）统一出口，由 module 在 handler/回调尾部调用 */
void waf_action_finalize_allow(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                               ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx);

/* 日志事件包装：窗口重置（将调用日志模块，并应用写入模式与级别） */
void waf_action_log_window_reset(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                                 ngx_http_waf_ctx_t *ctx, ngx_uint_t prev_score,
                                 ngx_msec_t window_start_ms, ngx_msec_t window_end_ms,
                                 waf_log_collect_mode_e collect_mode, waf_log_level_e level);

#endif /* NGX_HTTP_WAF_ACTION_H */
