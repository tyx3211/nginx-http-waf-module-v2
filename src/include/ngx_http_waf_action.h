#ifndef NGX_HTTP_WAF_ACTION_H
#define NGX_HTTP_WAF_ACTION_H

#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_waf_module_v2.h"
#include "ngx_http_waf_log.h"

/*
 * ================================================================
 *  STUB IMPLEMENTATION (M2.5)
 *  本文件为“统一动作模块”的存根接口声明：
 *  - 统一聚合意图（BLOCK/LOG/BYPASS）并触发日志
 *  - 真实评分/封禁与共享内存复检在 M5 实现
 * ================================================================
 */

typedef enum {
    WAF_INTENT_BLOCK,
    WAF_INTENT_LOG,
    WAF_INTENT_BYPASS
} waf_intent_e;

/* 返回值约定（存根阶段）：
 * - BLOCK → 返回 NGX_HTTP_FORBIDDEN（或 http_status）
 * - 其他 → 返回 NGX_DECLINED
 */
ngx_int_t waf_enforce(ngx_http_request_t* r,
                      ngx_http_waf_main_conf_t* mcf,
                      ngx_http_waf_loc_conf_t* lcf,
                      ngx_http_waf_ctx_t* ctx,
                      waf_intent_e intent,
                      ngx_int_t http_status,
                      ngx_uint_t rule_id_or_0);

#endif /* NGX_HTTP_WAF_ACTION_H */


